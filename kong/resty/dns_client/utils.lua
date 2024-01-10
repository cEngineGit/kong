-- vim: ts=4 sts=4 sw=4 et:

local table_insert = table.insert

local DEFAULT_HOSTS_FILE = "/etc/hosts"
local DEFAULT_RESOLV_CONF = "/etc/resolv.conf"


local function parse_hosts(path, enable_ipv6)
    path = path or DEFAULT_HOSTS_FILE
    return {
        path = path,
    }
end


local function parse_resolv_conf(path, enable_ipv6)
    path = path or DEFAULT_RESOLV_CONF
    return {
        options = {},
        path = path,
    }
end


local function is_fqdn(name, ndots)
    local _, dot_count = name:gsub("%.", "")
    return (dot_count >= ndots) or (name:sub(-1) == ".")
end


-- construct <names, types> from resolv options: search/ndots and domain
local function search_names(name, resolv)
    if not resolv.ndots or is_fqdn(name, resolv.ndots) then
        return { name }
    end

    local names = {}
    for _, suffix in ipairs(resolv.search) do
        table_insert(names, name .. "." .. suffix)
    end
    return names
end


return {
  parse_hosts = parse_hosts,
  parse_resolv_conf = parse_resolv_conf,
  search_names = search_names,
}
