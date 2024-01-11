-- vim: ts=4 sts=4 sw=4 et:


local utils = require("kong.resty.dns.utils")

local table_insert = table.insert

local DEFAULT_HOSTS_FILE = "/etc/hosts"
local DEFAULT_RESOLV_CONF = "/etc/resolv.conf"


local _M = {}

-- TODO: need to rewrite it instead of calling parseHosts
function _M.parse_hosts(path, enable_ipv6)
    local t, l_or_err = utils.parseHosts(path or DEFAULT_HOSTS_FILE)
    if not t then
        return nil, l_or_err
    end
    return t
end


-- TODO: need to rewrite it instead of calling parseResolvConf
function _M.parse_resolv_conf(path, enable_ipv6)
    local resolv, err = utils.parseResolvConf(path or DEFAULT_RESOLV_CONF)
    if not resolv then
        return nil, err
    end
    resolv.options = resolv.options or {}
    resolv.ndots = resolv.options.ndots or 1
    resolv.search = resolv.search or (resolv.domain and { resolv.domain })
    return resolv
end


function _M.is_fqdn(name, ndots)
    local _, dot_count = name:gsub("%.", "")
    return (dot_count >= ndots) or (name:sub(-1) == ".")
end


-- construct <names, types> from resolv options: search/ndots and domain
function _M.search_names(name, resolv)
    if not resolv.search or _M.is_fqdn(name, resolv.ndots) then
        return { name }
    end

    local names = {}
    for _, suffix in ipairs(resolv.search) do
        table_insert(names, name .. "." .. suffix)
    end
    return names
end


function _M.ipv6_bracket(name)
    if name:match("^[^[].*:") then  -- not rigorous, but sufficient
        name = "[" .. name .. "]"
    end
    return name
end


-- util APIs to balance @answers

function _M.get_rr_ans(answers)
  answers.last = (answers.last or 0) % #answers + 1
  return answers[answers.last]
end


-- TODO
function _M.get_rrw_ans(answers)
  return 1
end


return _M
