-- vim: ts=4 sts=4 sw=4 et:

local utils = require("kong.resty.dns_client.utils")
local mlcache = require("kong.resty.mlcache")
local resolver = require("resty.dns.resolver")

local math_min = math.min
local math_random = math.random
local table_insert = table.insert
local table_remove = table.remove
local string_lower = string.lower
local deep_copy = function (t) return t end -- TODO require("kong.tools.utils").deep_copy

-- debug
local json = require("cjson").encode

local logerr = function (...) ngx.log(ngx.ERR, "+ debug:", ...) end
local log = table_insert

-- Constants and default values
local DEFAULT_ERROR_TTL = 1     -- unit: second
local DEFAULT_STALE_TTL = 4
local DEFAULT_EMPTY_TTL = 30

local DEFAULT_ORDER = { "LAST", "SRV", "A", "AAAA", "CNAME" }

local TYPE_LAST = -1

local valid_types = {
    SRV = resolver.TYPE_SRV,
    A = resolver.TYPE_A,
    AAAA = resolver.TYPE_AAAA,
    CNAME = resolver.TYPE_CNAME,
    LAST = TYPE_LAST,
}

local hitstrs = {
    [1] = "hit/lru",
    [2] = "hit/shdict",
}

local client_errors = {     -- client specific errors
    [100] = "cache only lookup failed",
    [101] = "empty record received",
    [102] = "invalid name, bad IPv4",
    [103] = "invalid name, bad IPv6",
}


--- APIs
local _M = {}
local mt = { __index = _M }


local function insert_last_type(cache, name, qtype)
    cache:set(name .. ":l", { ttl = 0 }, qtype)
end


local function get_last_type(cache, name)
    return cache:get(name .. ":l")
end


-- insert hosts into cache
local function init_hosts(cache, path, preferred_ip_type)
    local hosts, err = utils.parse_hosts(path)
    if not hosts then
        ngx.log(ngx.WARN, "Invalid hosts file: ", err)
        hosts = {}
    end

    if not hosts.localhost then
        hosts.localhost = {
          ipv4 = "127.0.0.1",
          ipv6 = "[::1]",
        }
        ngx.log(ngx.WARN, "Insert : ipv4/6")
    end

    local function insert_answer(name, qtype, address)
        if not address then
            return
        end

        local key = name .. ":" .. qtype
        local answers = {{
            name = name,
            type = qtype,
            address = address,
            class = 1,
            ttl = 0,
        }}
        cache:set(key, { ttl = 0 }, answers)
    end

    for name, address in pairs(hosts) do
        name = name:lower()
        if address.ipv4 then
            insert_answer(name, resolver.TYPE_A, address.ipv4)
            insert_last_type(cache, name, resolver.TYPE_A)
        end
        if address.ipv6 then
            insert_answer(name, resolver.TYPE_AAAA, address.ipv6)
            if not address.ipv4 or preferred_ip_type == resolver.TYPE_AAAA then
                insert_last_type(cache, name, resolver.TYPE_AAAA)
            end
        end
    end

    return hosts
end


function _M.new(opts)
    if not opts then
        return nil, "no options table specified"
    end

    -- parse resolv.conf
    local resolv, err = utils.parse_resolv_conf(opts.resolv_conf, enable_ipv6)
    if not resolv then
        ngx.log(ngx.WARN, "Invalid resolv.conf: ", err)
        resolv = { options = {} }
    end

	-- init the resolver options for lua-resty-dns
    local nameservers = opts.nameservers or resolv.nameservers
    if not nameservers or #nameservers == 0 then
        ngx.log(ngx.WARN, "Invalid configuration, no nameservers specified")
    end

    local r_opts = {
        nameservers = nameservers,
        retrans = opts.retrans or resolv.options.attempts or 5,
        timeout = opts.timeout or resolv.options.timeout or 2000,   -- ms
        no_random = opts.no_random or not resolv.options.rotate,
    }

    -- init the mlcache
    local lock_timeout = r_opts.timeout / 1000 * r_opts.retrans + 1 -- s

    local cache, err = mlcache.new("dns_cache", "kong_dns_cache", {
        lru_size = opts.cache_size or 10000,
        ipc_shm = "kong_dns_cache_ipc",
        resty_lock_opts = {
            timeout = lock_timeout,
            exptimeout = lock_timeout + 1,
        },
    })
    if not cache then
        return nil, "could not create mlcache: " .. err
    end

    cache:purge(true)

    -- parse order
    local search_types = {}
    local order = opts.order or DEFAULT_ORDER
    local preferred_ip_type
    for _, typstr in ipairs(order) do
        local qtype = valid_types[typstr:upper()]
        if not qtype then
            return nil, "Invalid dns record type in order array: " .. typstr
        end
        table_insert(search_types, qtype)
        if (qtype == resolver.TYPE_A or qtype == resolver.TYPE_AAAA) and
            not preferred_ip_type
        then
            preferred_ip_type = qtype
        end
    end

    if #search_types == 0 then
        return nil, "Invalid order array: empty record types"
    end

    preferred_ip_type = preferred_ip_type or resolver.TYPE_A

    -- parse hosts
    local hosts = init_hosts(cache, opts.hosts, preferred_ip_type)

    return setmetatable({
        r_opts = r_opts,
        cache = cache,
        valid_ttl = opts.valid_ttl,
        error_ttl = opts.error_ttl or DEFAULT_ERROR_TTL,
        stale_ttl = opts.stale_ttl or DEFAULT_STALE_TTL,
        empty_ttl = opts.empty_ttl or DEFAULT_EMPTY_TTL,
        resolv = opts._resolv or resolv,
        hosts = hosts,
        enable_ipv6 = enable_ipv6,
        search_types = search_types,
    }, mt)
end


local function filter_unmatched_answers(qname, qtype, answers)
    if qname:sub(-1) == "." then
        qname = qname:sub(1, -2)
    end

    local unmatched = {}    -- table contains unmatched <key, answers>

    for i = #answers, 1, -1 do
        local answer = answers[i]

        if answer.name ~= qname or answer.type ~= qtype then
            -- insert to unmatched
            local key = answer.name .. ":" .. answer.type
            if not unmatched[key] then
                unmatched[key] = {}
            end
            table_insert(unmatched[key], 1, answer)
            -- remove from answers
            table_remove(answers, i)
        end
    end

    return unmatched
end


local function process_answers_fields(self, answers)
    local errcode = answers.errcode
    if not errcode then
        local ttl = answers[1].ttl

        for _, answer in ipairs(answers) do
            -- A compromise regarding https://github.com/Kong/kong/pull/3088
            if answer.type == resolver.TYPE_AAAA then
                answer.address = utils.ipv6_bracket(answer.address)
            elseif answer.type == resolver.TYPE_SRV then
                answer.target = utils.ipv6_brakcet(answer.target)
            end

            ttl = math_min(ttl, answer.ttl)
        end

        answers.ttl = self.valid_ttl or ttl

    elseif errcode == 3 or errcode == 101 then
        answers.ttl = self.empty_ttl

    else
        answers.ttl = self.error_ttl
    end
end


-- NOTE: it might insert unmatched answers into cache
local function process_answers(self, qname, qtype, answers)
    if not answers.errcode then
        local unmatched = filter_unmatched_answers(qname, qtype, answers)
        for k, a in pairs(unmatched) do
            process_answers_fields(self, a)
            self.cache:set(k, { ttl = a.ttl }, a)
        end

        if #answers == 0 then
            answers.errcode = 101
            answers.errstr = client_errors[101]
        end
    end

    process_answers_fields(self, answers)
end


local function resolve_query(self, name, qtype, tries)
    log(tries, "query")

    local r, err = resolver:new(self.r_opts)
    if not r then
        return nil, "failed to instantiate the resolver: " .. err
    end

    logerr("query:", name)
    local options = { additional_section = true, qtype = qtype }
    local answers, err, q_tries = r:query(name, options, {})
    if r.destroy then
        r:destroy()
    end

    if not answers then
        log(tries, q_tries)
        return nil, "DNS server error: " .. (err or "unknown")
    end

    process_answers(self, name, qtype, answers)
    log(tries, answers.errstr or #answers)

    return answers, nil, answers.ttl
end


local function start_stale_update_task(self, key, name, qtype)
    timer_at(0, function (premature)
        if not premature then
            local answer = resolve_query(self, name, qtype, {})
            if answers and not answers.errcode then
                self.cache:set(key, { ttl = answers.ttl }, answers)
            end
        end
    end)
end


local function resolve_name_type_callback(self, name, qtype, opts, tries)
    logerr("cb:", name, qtype)
    local key = name .. ":" .. qtype

    local ttl, err, answers, stale = self.cache:peek(key, true)
    if answers and stale then
        ttl = (ttl or 0) + self.stale_ttl
        if ttl > 0 then
            log(tries, "stale")
            if not answers.stale then     -- first-time use, update it
                start_stale_update_task(self, key, name, qtype)
                answers.stale = true
            end
            return answers, nil, ttl
        end
    end

    if opts.cache_only then
        return { errcode = 100, errstr = client_errors[100] }, nil, -1
    end

    return resolve_query(self, name, qtype, tries)
end


local function detect_recursion(opts, key)
    local rn = opts.resolved_names
    if not rn then
        rn = {}
        opts.resolved_names = rn
    end
    local detected = rn[key]
    -- TODO delete
    if detected then
        ngx.log(ngx.ALERT, "detect recursion for name:", key)
    end
    rn[key] = true
    return detected
end


local function resolve_name_type(self, name, qtype, opts, tries)
    local key = name .. ":" .. qtype
    log(tries, key)

    if detect_recursion(opts, key) then
        return nil, "recursion detected for name: " .. name
    end

    logerr("l2 cache get:", key)
    local answers, err, hit_level = self.cache:get(key, nil,
                                                resolve_name_type_callback,
                                                self, name, qtype, opts, tries)
    if err and err:sub(1, #"callback") == "callback" then
        ngx.log(ngx.ALERT, err)
    end

    if hit_level and hit_level < 3 then
        log(tries, hitstrs[hit_level])
    end

    assert(answers or err)

    return answers, err
end


local function search_types(self, name)
    local types = {}
    local checked_types = {}

    for _, qtype in ipairs(self.search_types) do
        if qtype == TYPE_LAST then
            qtype = get_last_type(self.cache, name)
        end
        if qtype and not checked_types[qtype] then
            table.insert(types, qtype)
            checked_types[qtype] = true
        end
    end

    logerr("search types:", json(types))
    return types
end


local function resolve_names_and_types(self, name, opts, tries)
    local types = search_types(self, name)
    local names = utils.search_names(name, self.resolv, self.hosts)
    local answers, err

    for _, qtype in ipairs(types) do
        for _, qname in ipairs(names) do
            logerr(" resovle_name_type:", qname .. ":" .. qtype)
            answers, err = resolve_name_type(self, qname, qtype, opts, tries)
            logerr(" resolve_name_tyep return: ", json(answers), " :", err)

            -- severe error occurred
            if not answers then
                return nil, err, tries
            end

            if not answers.errcode then
                insert_last_type(self.cache, qtype) -- cache the TYPE_LAST
                return answers, nil, tries
            end
        end
    end

    -- not found in the search iteration
    return nil, "no available records", tries
end


local function resolve_all(self, name, opts, tries)
    if detect_recursion(opts, name) then
        return nil, "recursion detected for name: " .. name
    end

    log(tries, name)

    -- lookup fastly: no callback, which is only used for real network query
    local answers, err, hit_level = self.cache:get(name)
    if not answers then
        answers, err, tries = resolve_names_and_types(self, name, opts, tries)
        if answers then
            self.cache:set(name, { ttl = answers.ttl }, answers)
        end

    else
        log(tries, hitstrs[hit_level])
    end

    -- dereference CNAME
    if answers and answers[1].type == resolver.TYPE_CNAME then
        log(tries, "cname")
        return resolve_all(self, answers[1].cname, opts, tries)
    end

    return answers, err, tries
end


-- resolve all `name`s and `type`s combinations and return first usable answers
--   `name`s: produced by resolv.conf options: `search`, `ndots` and `domain`
--   `type`s: SRV, A, AAAA, CNAME
--
-- @opts:
--   `return_random`: default `false`, return only one random IP address
--   `cache_only`: default `false`, retrieve data only from the internal cache
function _M:resolve(name, opts, tries)
    local opts = opts or {}
    local tries = tries or {}
    assert(tries and opts)
    --ngx.log(ngx.ERR, "resolve: ", name, ":", json(opts))
    local answers, err, tries = resolve_all(self, name, opts, tries)
    if not answers or not opts.return_random then
        return answers, err, tries
    end

    -- option: return_random
    if answers[1].type == resolver.TYPE_SRV then
        local answer = utils.get_wrr_ans(answers)
        opts.port = answer.port ~= 0 and answer.port or opts.port
        return self:resolve(answer.target, opts, tries)
    end

    return utils.get_rr_ans(answers).address, opts.port, tries
end


-- compatible with original DNS client library
-- These APIs will be deprecated if fully replacing original DNS client library.
local dns_client

function _M.init(opts)
    opts.valid_ttl = opts.validTtl
    opts.error_ttl = opts.badTtl
    opts.stale_ttl = opts.staleTtl
    opts.cache_size = opts.cacheSize

    local client, err = _M.new(opts)
    if not client then
        return nil, err
    end
    dns_client = client
    return true
end


-- New and old libraries have the same function name.
_M._resolve = _M.resolve

function _M.resolve(name, r_opts, cache_only, tries)
    ngx.log(ngx.ERR, "name:", json(name))
    local opts = { cache_only = cache_only }
    return dns_client:_resolve(name, opts, tries)
end


function _M.toip(name, port, cache_only, tries)
    local opts = { cache_only = cache_only, return_random = true , port = port }
    return dns_client:_resolve(name, opts, tries)
end


-- For testing
if package.loaded.busted then
    function _M.getcache()
        return dns_client.cache
    end
    function _M:insert_last_type(name, qtype)
        insert_last_type(self.cache, name, qtype)
    end
end


return _M
