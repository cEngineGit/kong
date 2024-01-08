-- vim: ts=4 sts=4 sw=4 et:


local function parse_hosts(path, enable_ipv6)
    return {}
end


local function parse_resolv_conf(path, enable_ipv6)
    return {
        options = {},
    }
end


return {
  parse_hosts = parse_hosts,
  parse_resolv_conf = parse_resolv_conf,
}
