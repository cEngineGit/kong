-- vim: ts=4 sts=4 sw=4 et:


local utils = require("kong.resty.dns.utils")

local math_random = math.random
local table_insert = table.insert
local table_remove = table.remove

local DEFAULT_HOSTS_FILE = "/etc/hosts"
local DEFAULT_RESOLV_CONF = "/etc/resolv.conf"


local _M = {}

-- TODO: need to rewrite it instead of calling parseHosts
function _M.parse_hosts(path, enable_ipv6)
    local hosts, l_or_err = utils.parseHosts(path or DEFAULT_HOSTS_FILE)
    if not hosts then
        return nil, l_or_err
    end
    return hosts
end


-- TODO: need to rewrite it instead of calling parseResolvConf
function _M.parse_resolv_conf(path, enable_ipv6)
    local resolv, err = utils.parseResolvConf(path or DEFAULT_RESOLV_CONF)
    if not resolv then
        return nil, err
    end
    resolv = utils.applyEnv(resolv)
    resolv.options = resolv.options or {}
    resolv.ndots = resolv.options.ndots or 1
    resolv.search = resolv.search or (resolv.domain and { resolv.domain })
    -- remove special domain like "."
    if resolv.search then
        for i = #resolv.search, 1, -1 do
            if resolv.search[i] == "." then
                table_remove(resolv.search, i)
            end
        end
    end
    -- nameservers
    if resolv.nameserver then
        local nameservers = {}
        for _, address in ipairs(resolv.nameserver) do
            local ip, port, t = utils.parseHostname(address)
            if t == "ipv4" or
                (t == "ipv6" and not ip:find([[%]], nil, true) and enable_ipv6)
            then
                table_insert(nameservers, port and { ip, port } or ip)
            end
        end
        resolv.nameservers = nameservers
    end
    return resolv
end


function _M.is_fqdn(name, ndots)
    local _, dot_count = name:gsub("%.", "")
    return (dot_count >= ndots) or (name:sub(-1) == ".")
end


-- construct names from resolv options: search, ndots and domain
function _M.search_names(name, resolv)
    if not resolv.search or _M.is_fqdn(name, resolv.ndots) then
        return { name }
    end

    local names = {}
    for _, suffix in ipairs(resolv.search) do
        table_insert(names, name .. "." .. suffix)
    end
    table_insert(names, name)
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


-- based on the Nginx's SWRR algorithm and lua-resty-balancer
local function swrr_next(answers)
    local total = 0
    local best = nil    -- best answer in answers[]

    for _, answer in ipairs(answers) do
        local w = answer.weight
        local cw = answer.cw + w
        answer.cw = cw
        if not best or cw > best.cw then
            best = answer
        end
        total = total + w
    end

    best.cw = best.cw - total
    return best
end


local function swrr_init(answers)
    for _, answer in ipairs(answers) do
        answer.cw = 0   -- current weight
    end
    -- random start
    for _ = 1, math_random(#answers) do
        swrr_next(answers)
    end
end


-- gather all records with the lowest priority into one array (answers.l)
-- and return it
local function filter_lowest_priority_answers(answers)
    local lowest_priority = answers[1].priority
    local l = {}    -- lowest priority list

    for _, answer in ipairs(answers) do
        if answer.priority < lowest_priority then
            lowest_priority = answer.priority
            l = { answer }
        elseif answer.priority == lowest_priority then
            table.insert(l, answer)
        end
    end

    answers.l = l
    return l
end


function _M.get_wrr_ans(answers)
    local l = answers.l or filter_lowest_priority_answers(answers)

    -- perform round robin selection on lowest priority answers @l
    if not l[1].cw then
        swrr_init(l)
    end

    return swrr_next(l)
end


return _M
