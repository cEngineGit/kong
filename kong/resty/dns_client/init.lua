-- vim: ts=4 sts=4 sw=4 et:

local mlcache = require("resty.mlcache")
local resolver = require("resty.dns.resolver")
local utils = require("dns_client/utils")  -- TODO

local math_min = math.min
local math_random = math.random
local table_insert = table.insert
local table_remove = table.remove
local deep_copy = function (t) return t end -- TODO require("kong.tools.utils").deep_copy

-- debug
local json = require("cjson").encode

local log = table_insert

-- Constants and default values
local DEFAULT_ERROR_TTL = 1     -- unit: second
local DEFAULT_STALE_TTL = 4
local DEFAULT_EMPTY_TTL = 30

local DEFAULT_TYPES = {         -- default order to query
    resolver.TYPE_SRV,
    resolver.TYPE_A,
    resolver.TYPE_AAAA,
    resolver.TYPE_CNAME,
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


function _M.new(opts)
    if not opts then
        return nil, "no options table specified"
    end

    local enable_ipv6 = opts.enable_ipv6 or true

    -- parse hosts and resolv.conf

    local hosts = utils.parse_hosts(opts.hosts, enable_ipv6)
    local resolv = utils.parse_resolv_conf(opts.resolv_conf, enable_ipv6)

	-- init the resolver options for lua-resty-dns
    local nameservers = opts.nameservers or resolv.nameservers
    if not nameservers or #nameservers == 0 then
        return nil, "no nameservers specified"
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
        lru_size = 1000,
        ipc_shm = "kong_dns_cache_ipc",
        resty_lock_opts = {
            timeout = lock_timeout,
            exptimeout = lock_timeout + 1,
        },
    })
    if not cache then
        return nil, "could not create mlcache: " .. err
    end

    return setmetatable({
        r_opts = r_opts,
        cache = cache,
        valid_ttl = opts.valid_ttl,
        error_ttl = opts.error_ttl or DEFAULT_ERROR_TTL,
        stale_ttl = opts.stale_ttl or DEFAULT_STALE_TTL,
        empty_ttl = opts.empty_ttl or DEFAULT_EMPTY_TTL,
        hosts = opts._hosts or hosts,
        resolv = opts._resolv or resolv,
        enable_ipv6 = enable_ipv6,
        types = DEFAULT_TYPES,
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
    end

    if #answers == 0 then
        answers.errcode = 101
        answers.errstr = client_errors[101]
    end

    process_answers_fields(self, answers)
end


local function query(self, name, qtype, tries)
    log(tries, "query")

    local r, err = resolver:new(self.r_opts)
    if not r then
        return nil, "failed to instantiate the resolver: " .. err
    end

    local options = { additional_section = true, qtype = qtype }
    local answers, err, q_tries = r:query(name, options, {})
    if r.destroy then
        r:destroy()
    end
    assert(answers or err)

    if not answers then
        log(tries, q_tries)
        return nil, "DNS server error:" .. (err or "unknown")
    end

    process_answers(self, name, qtype, answers)
    log(tries, answers.errstr or #answers)

    return answers, nil, answers.ttl
end


local function start_stale_update_task(self, key, name, qtype)
    timer_at(0, function (premature)
        if not premature then
            local answer = query(self, name, qtype, {})
            if answers and not answers.errcode then
                self.cache:set(key, { ttl = answers.ttl }, answers)
            end
        end
    end)
end


local function resolve_name_type_callback(self, name, qtype, opts, tries)
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

    return query(self, name, qtype, tries)
end


local function detect_recursion(opts, key)
    if not opts.resolved_names then
        opts.resolved_names = {}
    end
    local detected = opts.resolved_names[key]
    opts.resolved_names[key] = true
    return detected
end


local function resolve_name_type(self, name, qtype, opts, tries)
    local key = name .. ":" .. qtype
    log(tries, key)

    if detect_recursion(opts, key) then
        return nil, "recursion detected for name: " .. name
    end

    local answers, err, hit_level = self.cache:get(key, nil,
                                                resolve_name_type_callback,
                                                self, name, qtype, opts, tries)
    if err and string.sub(err, 1, #"callback") == "callback" then
        ngx.log(ngx.ALERT, err)
    end

    if hit_level and hit_level < 3 then
        log(tries, hitstrs[hit_level])
    end

    assert(answers or err)

    return answers, err, tries
end


local function resolve_names_and_types(self, name, opts, tries)
    local types = self.types
    local names = utils.search_names(name, self.resolv)
    local answers, err, qname

    for _, qtype in ipairs(types) do
        for _, qname in ipairs(names) do
            answers, err, tries = resolve_name_type(self, qname, qtype, opts, tries)
            if answers and not answers.errcode then
                return answers, nil, tries
            end
        end
    end

    return answers, err, tries
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
    if answers and not answers.errcode and answers[1].type == resolver.TYPE_CNAME then
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
--   `return_random`: default `false`, return only one random IP addreas
--   `cache_only`: default `false`, retrieve data only from the internal cache
function _M:resolve(name, opts, tries)
    local answers, err, tries = resolve_all(self, name, opts or {}, tries or {})

    if opts.return_random and answers and not answers.errcode then
        return answers[math_random(1, #answers)], nil, tries
    end

    return answers, err, tries
end


return _M
