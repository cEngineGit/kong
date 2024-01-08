-- vim: ts=4 sts=4 sw=4 et:

local mlcache = require("resty.mlcache")
local resolver = require("resty.dns.resolver")
local utils = require("dns_client/utils")  -- TODO:

local math_min = math.min
local table_insert = table.insert
local table_remove = table.remove
--local json = require("cjson").encode


-- Constants and default values
local DEFAULT_HOSTS_FILE = "/etc/hosts"
local DEFAULT_RESOLV_CONF = "/etc/resolv.conf"

local DEFAULT_ERROR_TTL = 1     -- unit: second
local DEFAULT_STALE_TTL = 4
local DEFAULT_NOT_FOUND_TTL = 30

local DEFAULT_TYPES = {         -- default order to query
    resolver.TYPE_SRV,
    resolver.TYPE_A,
    resolver.TYPE_AAAA,
    resolver.TYPE_CNAME,
}

local client_errors = {     -- client specific errors
    [100] = "cache only lookup failed",
    [101] = "empty record received",
    [102] = "invalid name, bad IPv4",
    [103] = "invalid name, bad IPv6",
}


local _M = {}
local mt = { __index = _M }


function _M.new(opts)
    if not opts then
        return nil, "no options table specified"
    end

    local enable_ipv6 = opts.enable_ipv6 or true

    -- parse hosts and resolv.conf
    local hosts_file = opts.hosts or DEFAULT_HOSTS_FILE
    local resolv_conf = opts.resolv_conf or DEFAULT_RESOLV_CONF

    local hosts = utils.parse_hosts(hosts_file, enable_ipv6)
    local resolv = utils.parse_resolv_conf(resolv_conf, enable_ipv6)

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
        cache_only = opts.cache_only or false,
        valid_ttl = opts.valid_ttl,
        error_ttl = opts.error_ttl or DEFAULT_ERROR_TTL,
        stale_ttl = opts.stale_ttl or DEFAULT_STALE_TTL,
        not_found_ttl = opts.not_found_ttl or DEFAULT_NOT_FOUND_TTL,
        return_random = opts.return_random or true,
        enable_ipv6 = enable_ipv6,
        types = DEFAULT_TYPES,
    }, mt)
end


local function answers_min_ttl(answers)
    local ttl = answers[1].ttl
    for i = 2, #answers do
        ttl = math_min(ttl, answers[i].ttl)
    end
    return ttl
end


local function process_answers_remove_unmatched(qname, qtype, answers)
    if qname:sub(-1) == "." then
        qname = qname:sub(1, -2)
    end

    local others = {}    -- table contains other <key, unmatched answers> pairs

    for i = #answers, 1, -1 do
        local answer = answers[i]

        if answer.name ~= qname or answer.type ~= qtype then
            -- insert to others
            local key = answers.name .. ":" .. answers.type
            if not others[key] then
                others[key] = {}
            end
            table_insert(others[key], 1, answer)
            -- remove from answers
            table_remove(answers, i)
        end
    end

    if #answers == 0 then
        answers.errcode = 101
        answers.errstr = client_errors[101]
    end

    -- TODO: insert answers in others into cache
end


local function process_answers(self, qname, qtype, answers)
    if not answers.errcode then
        process_answers_remove_unmatched(qname, qtype, answers)
    end

    local errcode = answers.errcode
    if errcode == 3 or errcode == 101 then
        answers.ttl = self.not_found_ttl
    elseif errcode then
        answers.ttl = self.error_ttl
    else
        answers.ttl = self.valid_ttl or answers_min_ttl(answers)
    end
end


local function query(self, name, opts, tries)
    table_insert(tries, "query")

    local r, err = resolver:new(self.r_opts)
    if not r then
        return nil, "failed to instantiate the resolver: " .. err
    end

    local answers, err, q_tries = r:query(name, opts, {})
    assert(answers or err)

    if r.destroy then
        r:destroy()
    end

    if not answers then
        table_insert(tries, q_tries)
        return nil, "DNS server error:" .. (err or "unknown")
    end

    process_answers(self, name, opts.qtype, answers)

    return answers, nil, answers.ttl
end


local function query_task(premature, self, opts)
    if not premature then
        query(self, name, opts)
    end
end


local function resolve_name_type_callback(self, name, opts, tries)
    local key = name .. ":" .. opts.qtype
    local ttl, err, answers, went_stale = self.cache:peek(key, true)

    if answers and went_stale then
        ttl = (ttl or 0) + self.stale_ttl

        if ttl > 0 then
            table_insert(tries, "stale")
            opts = opts -- TODO: deep copy
            timer_at(0, query_task, self, opts)
            return answers, nil, ttl
        end
    end

    return query(self, name, opts, tries)
end


function _M:resolve_name_type(name, opts, tries)
    tries = tries or {}
    if #tries > 50 then
        error("recursion detected")
    end

    if not opts.qtype then
        opts.qtype = resolver.TYPE_A
    end

    local key = name .. ":" .. opts.qtype
    table_insert(tries, key)

    local answers, err, hit_level = self.cache:get(key, nil,
                                                   resolve_name_type_callback,
                                                   self, name, opts, tries)
    if hit_level and hit_level < 3 then
        table_insert(tries, "hit/L" .. hit_level)   -- "hit/L1" or "hit/L2"
    end

    -- TODO: dereference CNAME & SRV

    assert(answers or err)

    return answers, err, tries
end


local function resolve_names_and_types(self, name, opts, tries)

    --TODO: construct <names, types> from opts.search/ndots/domain
    local names = { name }
    local types = self.types
    local answers, err

    for _, qname in ipairs(names) do
        for _, qtype in ipairs(types) do
            opts.qtype = qtype
            --print("+ r:", qname, ":", opts)
            answers, err, tries = self:resolve_name_type(qname, opts, tries)
            --print("+r -> ", json(nil), " :err ", err)
            if answers and #answers > 0 then
                return answers, nil, tries
            end
        end
    end

    --print(" not found:", json(answers), " :err:", err)
    return answers, err, tries
end


local function resolve_callback(self, name, opts, tries)
    local ttl, err, value, went_stale = self.cache:peek(name, true)
    if value and went_stale then
        ttl = (ttl or 0) + self.stale_ttl

        if ttl > 0 then
            table_insert(tries, "stale")

            timer_at(0, function (premature)
                if premature then return end
                query(name, self.r_opts)
            end)

            return value, nil, ttl
        end
    end

    return resolve_names_and_types(self, name, opts, tries)
end


-- resolve all combinations of `name`s and `type`s, and return first usable
-- answers
--   `name`: produced by @name and the options in resolv.conf: `search`, `ndots`
--           and `domain`
--   `type`: SRV, A, AAAA
function _M:resolve(name, opts, tries)

    --[[
    if name:sub(-1) == "." then
        name = name:sub(1, -2)
    end
    ]]

    opts = opts or {}
    tries = tries or {}

    -- TODO: handle opts.cache_only

    local answers, err, hit_level = self.cache:get(name, nil,
                                                   resolve_callback,
                                                   self, name, opts, tries)
    if hit_level and hit_level < 3 then
        table_insert(tries, "hit/L" .. hit_level)   -- "hit/L1" or "hit/L2"
    end

    assert(answers or err)

    -- TODO: handle opts.return_random

    return answers, err, tries
end


return _M
