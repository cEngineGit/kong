local _writefile = require("pl.utils").writefile
local tmpname = require("pl.path").tmpname
local pretty = require("pl.pretty").write

-- hosted in Route53 in the AWS sandbox
local TEST_DOMAIN="kong-gateway-testing.link"
local TEST_NS = { "198.51.100.0:53" }
local TEST_NS = { "192.168.5.2:53" }  -- Kong local official env

local logerr = function(...)
  ngx.log(ngx.ERR, ...)
end


local dump = function(...)
  print(pretty({...}))
end

describe("[DNS client]", function()

  local resolver, client, query_func, old_udp, receive_func

  local resolv_path, hosts_path

  local function writefile(path, text)
    _writefile(path, type(text) == "table" and table.concat(text, "\n") or text)
  end

  local function client_new(opts)
    opts = opts or {}
    opts.resolv_conf = resolv_path
    opts.hosts = hosts_path
    return client.new(opts)
  end

  lazy_setup(function()
    -- create temp resolv.conf and hosts
    resolv_path = tmpname()
    hosts_path = tmpname()
    ngx.log(ngx.DEBUG, "create temp resolv.conf:", resolv_path,
                       " hosts:", hosts_path)

    -- hook sock:receive to do timeout test
    old_udp = ngx.socket.udp

    _G.ngx.socket.udp = function (...)
      local sock = old_udp(...)

      local old_receive = sock.receive

      sock.receive = function (...)
        if receive_func then
          receive_func(...)
        end
        return old_receive(...)
      end

      return sock
    end

  end)

  lazy_teardown(function()
    if resolv_path then
      os.remove(resolv_path)
    end
    if hosts_path then
      os.remove(hosts_path)
    end

    _G.ngx.socket.udp = old_udp
  end)

  before_each(function()
    -- inject r.query
    package.loaded["resty.dns.resolver"] = nil
    resolver = require("resty.dns.resolver")

    -- replace this `query_func` upvalue to spy on resolver query calls.
    query_func = function(self, original_query_func, name, options)
      return original_query_func(self, name, options)
    end

    local old_new = resolver.new
    resolver.new = function(...)
      local r, err = old_new(...)
      if not r then
        return nil, err
      end
      local original_query_func = r.query
      r.query = function(self, ...)
        return query_func(self, original_query_func, ...)
      end
      return r
    end

    -- restore its API overlapped by the compatible layer
    package.loaded["kong.resty.dns_client"] = nil
    client = require("kong.resty.dns_client")
    client.resolve = client._resolve
  end)

  after_each(function()
    package.loaded["resty.dns.resolver"] = nil
    resolver = nil
    query_func = nil

    package.loaded["kong.resty.dns.client"] = nil
    client = nil

    receive_func = nil
  end)


  describe("initialization", function()

    it("succeeds if hosts/resolv.conf fails #ttt", function()
      local cli, err = client.new({
          nameservers = TEST_NS,
          hosts = "non/existent/file",
          resolv_conf = "non/exitent/file",
      })
      assert.is.Nil(err)
      assert.same(cli.r_opts.nameservers, TEST_NS)
    end)

    describe("inject localhost", function()

      it("if absent #ttt", function()
        writefile(resolv_path, "")
        writefile(hosts_path, "") -- empty hosts

        local cli = assert(client_new())
        local answers = cli.cache:get("localhost:28")
        assert.equal("[::1]", answers[1].address)

        answers = cli.cache:get("localhost:1")
        assert.equal("127.0.0.1", answers[1].address)

        assert.same(cli:resolve("localhost"), {{
          ["address"] = '127.0.0.1',
          ["name"] = 'localhost',
          ["class"] = 1,
          ["type"] = 1,
          ["ttl"] = 0,
        }})
      end)

      it("not if ipv4 exists #ttt", function()
        writefile(hosts_path, "1.2.3.4 localhost")

        local cli = assert(client_new())

        -- IPv6 is not defined
        local answers = cli.cache:get("localhost:28")
        assert.is_nil(answers)

        -- IPv4 is not overwritten
        answers = cli.cache:get("localhost:1")
        assert.equal("1.2.3.4", answers[1].address)
      end)

      it("not if ipv6 exists #ttt", function()
        writefile(hosts_path, "::1:2:3:4 localhost")
        local cli = assert(client_new())

        -- IPv6 is not overwritten
        answers = cli.cache:get("localhost:28")
        assert.equal("[::1:2:3:4]", answers[1].address)

        -- IPv4 is not defined
        answers = cli.cache:get("localhost:1")
        assert.is_nil(answers)
      end)
    end)
  end)


  describe("iterating searches", function()
    local function hook_query_func_get_list()
      local list = {}
      query_func = function(self, original_query_func, name, options)
        table.insert(list, name .. ":" .. options.qtype)
        return {} -- empty answers
      end
      return list
    end

    describe("without type", function()
      it("works with a 'search' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host")

        assert.same(answers, nil)
        assert.same(err, "no available records")
        assert.same({
          'host.one.com:33',
          'host.two.com:33',
          'host:33',
          'host.one.com:1',
          'host.two.com:1',
          'host:1',
          'host.one.com:28',
          'host.two.com:28',
          'host:28',
          'host.one.com:5',
          'host.two.com:5',
          'host:5',
        }, list)
      end)

      it("works with a 'search .' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search .",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host")

        assert.same(answers, nil)
        assert.same(err, "no available records")
        assert.same({
          'host:33',
          'host:1',
          'host:28',
          'host:5',
        }, list)
      end)

      it("works with a 'domain' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "domain local.domain.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host")

        assert.same(answers, nil)
        assert.same(err, "no available records")
        assert.same({
          'host.local.domain.com:33',
          'host:33',
          'host.local.domain.com:1',
          'host:1',
          'host.local.domain.com:28',
          'host:28',
          'host.local.domain.com:5',
          'host:5',
        }, list)
      end)

      it("handles last successful type #ttt", function()
        writefile(resolv_path, {
            "nameserver 198.51.100.0",
            "search one.com two.com",
            "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        cli:insert_last_type("host", resolver.TYPE_CNAME)

        local answers, err = cli:resolve("host")

        assert.same({
          'host.one.com:5',
          'host.two.com:5',
          'host:5',
          'host.one.com:33',
          'host.two.com:33',
          'host:33',
          'host.one.com:1',
          'host.two.com:1',
          'host:1',
          'host.one.com:28',
          'host.two.com:28',
          'host:28',
        }, list)
      end)
    end)

    describe("FQDN without type", function()
      it("works with a 'search' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host.")

        assert.same({
            'host.:33',
            'host.:1',
            'host.:28',
            'host.:5',
          }, list)
      end)

      it("works with a 'search .' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search .",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host.")

        assert.same({
            'host.:33',
            'host.:1',
            'host.:28',
            'host.:5',
          }, list)
      end)

      it("works with a 'domain' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "domain local.domain.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        local answers, err = cli:resolve("host.")

        assert.same({
          'host.:33',
          'host.:1',
          'host.:28',
          'host.:5',
        }, list)
      end)

      it("handles last successful type #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new())
        cli:insert_last_type("host.", resolver.TYPE_CNAME)

        local answers, err = cli:resolve("host.")
        assert.same({
            'host.:5',
            'host.:33',
            'host.:1',
            'host.:28',
          }, list)
      end)

    end)

    describe("with type", function()
      it("works with a 'search' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        local answers, err = cli:resolve("host")

        assert.same({
            'host.one.com:28',
            'host.two.com:28',
            'host:28',
          }, list)
      end)

      it("works with a 'domain' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "domain local.domain.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        local answers, err = cli:resolve("host")

        assert.same({
          'host.local.domain.com:28',
          'host:28',
        }, list)
      end)

      it("ignores last successful type #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        cli:insert_last_type("host", resolver.TYPE_CNAME)

        local answers, err = cli:resolve("host")
        assert.same({
            'host.one.com:28',
            'host.two.com:28',
            'host:28',
          }, list)
      end)

    end)

    describe("FQDN with type", function()
      it("works with a 'search' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        local answers, err = cli:resolve("host.")
        assert.same({
            'host.:28',
          }, list)
      end)

      it("works with a 'domain' option #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "domain local.domain.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        local answers, err = cli:resolve("host.")

        assert.same({
          'host.:28',
        }, list)
      end)

      it("ignores last successful type #ttt", function()
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "search one.com two.com",
          "options ndots:1",
        })

        local list = hook_query_func_get_list()
        local cli = assert(client_new({ order = { "AAAA" } }))  -- IPv6 type
        cli:insert_last_type("host", resolver.TYPE_CNAME)

        local answers, err = cli:resolve("host.")

        assert.same({
            'host.:28',
          }, list)
      end)
    end)

    it("honours 'ndots' #ttt", function()
      writefile(resolv_path, {
        "nameserver 198.51.100.0",
        "search one.com two.com",
        "options ndots:1",
      })

      local list = hook_query_func_get_list()
      local cli = assert(client_new())
      local answers, err = cli:resolve("local.host")

      assert.same({
        'local.host:33',
        'local.host:1',
        'local.host:28',
        'local.host:5',
      }, list)
    end)

    it("hosts file always resolves first, overriding `ndots` #ttt", function()
      writefile(resolv_path, {
        "nameserver 198.51.100.0",
        "search one.com two.com",
        "options ndots:1",
      })
      writefile(hosts_path, {
        "127.0.0.1 host",
        "::1 host",
      })

      local list = hook_query_func_get_list()
      -- perferred IP type: IPv4 (A takes priority in order)
      local cli = assert(client_new({ order = { "LAST", "SRV", "A", "AAAA" } }))
      local answers, err = cli:resolve("host")
      assert.same(answers[1].address, "127.0.0.1")
      assert.same({}, list) -- hit on cache, so no query to the nameserver

      -- perferred IP type: IPv6 (AAAA takes priority in order)
      local cli = assert(client_new({ order = { "LAST", "SRV", "AAAA", "A" } }))
      local answers, err = cli:resolve("host")
      assert.same(answers[1].address, "[::1]")
      assert.same({}, list)
    end)
  end)

  -- This test will report an alert-level error message, ignore it.
  it("low-level callback error #ttt", function()
    receive_func = function(...)
      error("CALLBACK")
    end

    local cli = assert(client_new())
    local answers, err = cli:resolve("srv.timeout.com")
    assert.is_nil(answers)
    assert.match("callback threw an error:.*CALLBACK", err)
  end)

  describe("timeout", function ()
    it("dont try other types with the low-level error #ttt", function()
      -- KAG-2300 https://github.com/Kong/kong/issues/10182
      -- When timed out, don't keep trying with other answers types.
      writefile(resolv_path, {
        "nameserver 198.51.100.0",
        "options timeout:1",
        "options attempts:3",
      })

      local query_count = 0
      query_func = function(self, original_query_func, name, options)
        assert(options.qtype == resolver.TYPE_SRV)
        query_count = query_count + 1
        return original_query_func(self, name, options)
      end

      local receive_count = 0
      receive_func = function(...)
        receive_count = receive_count + 1
        return nil, "timeout"
      end

      local cli = assert(client_new())
      assert.same(cli.r_opts.retrans, 3)
      assert.same(cli.r_opts.timeout, 1)

      local answers, err = cli:resolve("srv.timeout.com")
      assert.is_nil(answers)
      assert.match("DNS server error: failed to receive reply from UDP server .*: timeout", err)
      assert.same(receive_count, 3)
      assert.same(query_count, 1)
    end)

    -- KAG-2300 - https://github.com/Kong/kong/issues/10182
    -- If we encounter a timeout while talking to the DNS server,
    -- expect the total timeout to be close to timeout * attemps parameters
    for _, attempts in ipairs({1, 2}) do
    for _, timeout in ipairs({1, 2}) do
      it("options: timeout: " .. timeout .. " seconds, attempts: " .. attempts .. " times", function()
        query_func = function(self, original_query_func, name, options)
          ngx.sleep(math.min(timeout, 5))
          return nil, "timeout" .. timeout .. attempts
        end
        writefile(resolv_path, {
          "nameserver 198.51.100.0",
          "options timeout:" .. timeout,
          "options attempts:" .. attempts,
        })
        local cli = assert(client_new())
        assert.same(cli.r_opts.retrans, attempts)
        assert.same(cli.r_opts.timeout, timeout)

        local start_time = ngx.now()
        local answers, err = cli:resolve("timeout.com")
        assert.is.Nil(answers)
        assert.is("DNS server error: timeout" .. timeout .. attempts)
        local duration = ngx.now() - start_time
        assert.truthy(duration < (timeout * attempts + 1))
      end)
    end
    end

  end)

  it("fetching answers without nameservers errors #ttt", function()
    writefile(resolv_path, "")
    local host = TEST_DOMAIN
    local typ = resolver.TYPE_A

    local cli = assert(client_new())
    local answers, err = cli:resolve(host, { qtype = typ })
    assert.is_nil(answers)
    assert.same(err, "failed to instantiate the resolver: no nameservers specified")
  end)

  it("fetching CNAME answers #ttt", function()
    local host = "smtp."..TEST_DOMAIN
    local typ = resolver.TYPE_CNAME

    local cli = assert(client_new({ nameservers = TEST_NS }))
    local answers, _, tries = cli:resolve(host, { qtype = typ })

    assert.are.equal(host, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(#answers, 1)
  end)

  it("fetching a CNAME answers FQDN", function()
    assert(client.init())

    local host = "smtp."..TEST_DOMAIN
    local typ = resolver.TYPE_CNAME

    local answers = assert(client.resolve(host .. ".", { qtype = typ }))
    assert.are.equal(host, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(#answers, 1)
  end)

  it("expire and touch times", function()
    assert(client.init())

    local host = "txttest."..TEST_DOMAIN
    local typ = resolver.TYPE_TXT

    local answers, _, _ = assert(client.resolve(host, { qtype = typ }))

    local now = gettime()
    local touch_diff = math.abs(now - answers.touch)
    local ttl_diff = math.abs((now + answers[1].ttl) - answers.expire)
    assert(touch_diff < 0.01, "Expected difference to be near 0; "..
    tostring(touch_diff))
    assert(ttl_diff < 0.01, "Expected difference to be near 0; "..
    tostring(ttl_diff))

    sleep(1)

    -- fetch again, now from cache
    local oldtouch = answers.touch
    local answers2 = assert(client.resolve(host, { qtype = typ }))

    assert.are.equal(answers, answers2) -- cached table, so must be same
    assert.are.not_equal(oldtouch, answers.touch)

    now = gettime()
    touch_diff = math.abs(now - answers.touch)
    ttl_diff = math.abs((now + answers[1].ttl) - answers.expire)
    assert(touch_diff < 0.01, "Expected difference to be near 0; "..
    tostring(touch_diff))
    assert((0.990 < ttl_diff) and (ttl_diff < 1.01),
    "Expected difference to be near 1; "..tostring(ttl_diff))

  end)

  it("fetching names case insensitive", function()
    assert(client.init())

    query_func = function(self, original_query_func, name, options)
      return {
        {
          name = "some.UPPER.case",
          type = resolver.TYPE_A,
          ttl = 30,
        }
      }
    end

    local res, _, _ = client.resolve(
    "some.upper.CASE",
    { qtype = resolver.TYPE_A },
    false)
    assert.equal(1, #res)
    assert.equal("some.upper.case", res[1].name)
  end)

  it("fetching multiple A answerss", function()
    assert(client.init())

    local host = "atest."..TEST_DOMAIN
    local typ = resolver.TYPE_A

    local answers = assert(client.resolve(host, { qtype = typ }))
    assert.are.equal(#answers, 2)
    assert.are.equal(host, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(host, answers[2].name)
    assert.are.equal(typ, answers[2].type)
  end)

  it("fetching multiple A answerss FQDN", function()
    assert(client.init())

    local host = "atest."..TEST_DOMAIN
    local typ = resolver.TYPE_A

    local answers = assert(client.resolve(host .. ".", { qtype = typ }))
    assert.are.equal(#answers, 2)
    assert.are.equal(host, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(host, answers[2].name)
    assert.are.equal(typ, answers[2].type)
  end)

  it("fetching A answers redirected through 2 CNAME answerss (un-typed)", function()
    assert(client.init({ search = {}, }))
    local lrucache = cli.cache

    --[[
    This test might fail. Recurse flag is on by default. This means that the first return
    includes the cname answerss, but the second one (within the ttl) will only include the
    A-answers.
    Note that this is not up to the client code, but it's done out of our control by the
    dns server.
    If we turn on the 'no_recurse = true' option, then the dns server might refuse the request
    (error nr 5).
    So effectively the first time the test runs, it's ok. Immediately running it again will
    make it fail. Wait for the ttl to expire, then it will work again.

    This does not affect client side code, as the result is always the final A answers.
    --]]

    local host = "smtp."..TEST_DOMAIN
    local typ = resolver.TYPE_A
    local answers, _, _ = assert(client.resolve(host))

    -- check first CNAME
    local key1 = resolver.TYPE_CNAME..":"..host
    local entry1 = lrucache:get(key1)
    assert.are.equal(host, entry1[1].name)       -- the 1st answers is the original 'smtp.'..TEST_DOMAIN
    assert.are.equal(resolver.TYPE_CNAME, entry1[1].type) -- and that is a CNAME

    -- check second CNAME
    local key2 = resolver.TYPE_CNAME..":"..entry1[1].cname
    local entry2 = lrucache:get(key2)
    assert.are.equal(entry1[1].cname, entry2[1].name) -- the 2nd is the middle 'thuis.'..TEST_DOMAIN
    assert.are.equal(resolver.TYPE_CNAME, entry2[1].type) -- and that is also a CNAME

    -- check second target to match final answers
    assert.are.equal(entry2[1].cname, answers[1].name)
    assert.are.not_equal(host, answers[1].name)  -- we got final name 'wdnaste.duckdns.org'
    assert.are.equal(typ, answers[1].type)       -- we got a final A type answers
    assert.are.equal(#answers, 1)

    -- check last successful lookup references
    local lastsuccess3 = lrucache:get(answers[1].name)
    local lastsuccess2 = lrucache:get(entry2[1].name)
    local lastsuccess1 = lrucache:get(entry1[1].name)
    assert.are.equal(resolver.TYPE_A, lastsuccess3)
    assert.are.equal(resolver.TYPE_CNAME, lastsuccess2)
    assert.are.equal(resolver.TYPE_CNAME, lastsuccess1)

  end)

  it("fetching multiple SRV answerss (un-typed)", function()
    assert(client.init())

    local host = "srvtest."..TEST_DOMAIN
    local typ = resolver.TYPE_SRV

    -- un-typed lookup
    local answers = assert(client.resolve(host))
    assert.are.equal(host, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(host, answers[2].name)
    assert.are.equal(typ, answers[2].type)
    assert.are.equal(host, answers[3].name)
    assert.are.equal(typ, answers[3].type)
    assert.are.equal(#answers, 3)
  end)

  it("fetching multiple SRV answerss through CNAME (un-typed)", function()
    assert(client.init({ search = {}, }))
    local lrucache = cli.cache

    local host = "cname2srv."..TEST_DOMAIN
    local typ = resolver.TYPE_SRV

    -- un-typed lookup
    local answers = assert(client.resolve(host))

    -- first check CNAME
    local key = resolver.TYPE_CNAME..":"..host
    local entry = lrucache:get(key)
    assert.are.equal(host, entry[1].name)
    assert.are.equal(resolver.TYPE_CNAME, entry[1].type)

    -- check final target
    assert.are.equal(entry[1].cname, answers[1].name)
    assert.are.equal(typ, answers[1].type)
    assert.are.equal(entry[1].cname, answers[2].name)
    assert.are.equal(typ, answers[2].type)
    assert.are.equal(entry[1].cname, answers[3].name)
    assert.are.equal(typ, answers[3].type)
    assert.are.equal(#answers, 3)
  end)

  it("fetching non-type-matching answerss", function()
    assert(client.init({
      -- don't supply resolvConf and fallback to default resolver
      -- so that CI and docker can have reliable results
      -- but remove `search` and `domain`
      search = {},
    }))

    local host = "srvtest."..TEST_DOMAIN
    local typ = resolver.TYPE_A   --> the entry is SRV not A

    local answers, err, _ = client.resolve(host, {qtype = typ})
    assert.is_nil(answers)  -- returns nil
    assert.equal(EMPTY_ERROR, err)
  end)

  it("fetching non-existing answerss", function()
    assert(client.init({
      -- don't supply resolvConf and fallback to default resolver
      -- so that CI and docker can have reliable results
      -- but remove `search` and `domain`
      search = {},
    }))

    local host = "IsNotHere."..TEST_DOMAIN

    local answers, err, _ = client.resolve(host)
    assert.is_nil(answers)
    assert.equal(NOT_FOUND_ERROR, err)
  end)

  it("fetching IPv4 address as A type", function()
    assert(client.init())
    local lrucache = cli.cache

    local host = "1.2.3.4"

    local answers = assert(client.resolve(host, { qtype = resolver.TYPE_A }))
    assert.are.equal(#answers, 1)
    assert.are.equal(resolver.TYPE_A, answers[1].type)
    assert.are.equal(10*365*24*60*60, answers[1].ttl)  -- 10 year ttl

    assert.equal(resolver.TYPE_A, lrucache:get(host))
  end)

  it("fetching IPv4 address as SRV type", function()
    assert(client.init())

    local callcount = 0
    query_func = function(self, original_query_func, name, options)
      callcount = callcount + 1
      return original_query_func(self, name, options)
    end

    local _, err, _ = client.resolve(
    "1.2.3.4",
    { qtype = resolver.TYPE_SRV },
    false
    )
    assert.equal(0, callcount)
    assert.equal(BAD_IPV4_ERROR, err)
  end)

  it("fetching IPv6 address as AAAA type", function()
    assert(client.init())

    local host = "[1:2::3:4]"

    local answers = assert(client.resolve(host, { qtype = resolver.TYPE_AAAA }))
    assert.are.equal(#answers, 1)
    assert.are.equal(resolver.TYPE_AAAA, answers[1].type)
    assert.are.equal(10*365*24*60*60, answers[1].ttl)  -- 10 year ttl
    assert.are.equal(host, answers[1].address)

    local lrucache = cli.cache
    assert.equal(resolver.TYPE_AAAA, lrucache:get(host))
  end)

  it("fetching IPv6 address as AAAA type (without brackets)", function()
    assert(client.init())

    local host = "1:2::3:4"

    local answers = assert(client.resolve(host, { qtype = resolver.TYPE_AAAA }))
    assert.are.equal(#answers, 1)
    assert.are.equal(resolver.TYPE_AAAA, answers[1].type)
    assert.are.equal(10*365*24*60*60, answers[1].ttl)  -- 10 year ttl
    assert.are.equal("["..host.."]", answers[1].address) -- brackets added

    local lrucache = cli.cache
    assert.equal(resolver.TYPE_AAAA, lrucache:get(host))
  end)

  it("fetching IPv6 address as SRV type", function()
    assert(client.init())

    local callcount = 0
    query_func = function(self, original_query_func, name, options)
      callcount = callcount + 1
      return original_query_func(self, name, options)
    end

    local _, err, _ = client.resolve(
    "[1:2::3:4]",
    { qtype = resolver.TYPE_SRV },
    false
    )
    assert.equal(0, callcount)
    assert.equal(BAD_IPV6_ERROR, err)
  end)

  it("fetching invalid IPv6 address", function()
    assert(client.init({
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))

    local host = "[1::2:3::4]"  -- 2x double colons

    local answers, err, history = client.resolve(host)
    assert.is_nil(answers)
    assert.equal(BAD_IPV6_ERROR, err)
    assert(tostring(history):find("bad IPv6", nil, true))
  end)

  it("fetching IPv6 in an SRV answers adds brackets",function()
    assert(client.init())
    local host = "hello.world"
    local address = "::1"
    local entry = {
      {
        type = resolver.TYPE_SRV,
        target = address,
        port = 321,
        weight = 10,
        priority = 10,
        class = 1,
        name = host,
        ttl = 10,
      },
    }

    query_func = function(self, original_query_func, name, options)
      if name == host and options.qtype == resolver.TYPE_SRV then
        return entry
      end
      return original_query_func(self, name, options)
    end

    local res, _, _ = client.resolve(
    host,
    { qtype = resolver.TYPE_SRV },
    false
    )
    assert.equal("["..address.."]", res[1].target)

  end)

  it("recursive lookups failure - single resolve", function()
    assert(client.init({
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))
    query_func = function(self, original_query_func, name, opts)
      if name ~= "hello.world" and (opts or {}).qtype ~= resolver.TYPE_CNAME then
        return original_query_func(self, name, opts)
      end
      return {
        {
          type = resolver.TYPE_CNAME,
          cname = "hello.world",
          class = 1,
          name = "hello.world",
          ttl = 30,
        },
      }
    end

    local cli, err, _ = client.resolve("hello.world")
    assert.is_nil(cli)
    assert.are.equal("recursion detected", err)
  end)

  it("recursive lookups failure - single", function()
    assert(client.init({
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))
    local lrucache = cli.cache
    local entry1 = {
      {
        type = resolver.TYPE_CNAME,
        cname = "hello.world",
        class = 1,
        name = "hello.world",
        ttl = 0,
      },
      touch = 0,
      expire = 0,
    }
    -- insert in the cache
    lrucache:set(entry1[1].type..":"..entry1[1].name, entry1)

    -- Note: the bad case would be that the below lookup would hang due to round-robin on an empty table
    local cli, err, _ = client.resolve("hello.world", nil, true)
    assert.is_nil(cli)
    assert.are.equal("recursion detected", err)
  end)

  it("recursive lookups failure - multi", function()
    assert(client.init({
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))
    local lrucache = cli.cache
    local entry1 = {
      {
        type = resolver.TYPE_CNAME,
        cname = "bye.bye.world",
        class = 1,
        name = "hello.world",
        ttl = 0,
      },
      touch = 0,
      expire = 0,
    }
    local entry2 = {
      {
        type = resolver.TYPE_CNAME,
        cname = "hello.world",
        class = 1,
        name = "bye.bye.world",
        ttl = 0,
      },
      touch = 0,
      expire = 0,
    }
    -- insert in the cache
    lrucache:set(entry1[1].type..":"..entry1[1].name, entry1)
    lrucache:set(entry2[1].type..":"..entry2[1].name, entry2)

    -- Note: the bad case would be that the below lookup would hang due to round-robin on an empty table
    local cli, err, _ = client.resolve("hello.world", nil, true)
    assert.is_nil(cli)
    assert.are.equal("recursion detected", err)
  end)

  it("resolving from the /etc/hosts file; preferred A or AAAA order", function()
    local f = tempfilename()
    writefile(f, [[
    127.3.2.1 localhost
    1::2 localhost
    ]])
    assert(client.init(
    {
      hosts = f,
      order = {"SRV", "CNAME", "A", "AAAA"},
    }))

    local lrucache = cli.cache
    assert.equal(resolver.TYPE_A, lrucache:get("localhost")) -- success set to A as it is the preferred option

    assert(client.init(
    {
      hosts = f,
      order = {"SRV", "CNAME", "AAAA", "A"},
    }))

    lrucache = cli.cache
    assert.equal(resolver.TYPE_AAAA, lrucache:get("localhost")) -- success set to AAAA as it is the preferred option
  end)


  it("resolving from the /etc/hosts file", function()
    local f = tempfilename()
    writefile(f, [[
    127.3.2.1 localhost
    1::2 localhost

    123.123.123.123 mashape
    1234::1234 kong.for.president
    ]])

    assert(client.init({ hosts = f }))
    os.remove(f)

    local answers, err = client.resolve("localhost", {qtype = resolver.TYPE_A})
    assert.is.Nil(err)
    assert.are.equal(answers[1].address, "127.3.2.1")

    answers, err = client.resolve("localhost", {qtype = resolver.TYPE_AAAA})
    assert.is.Nil(err)
    assert.are.equal(answers[1].address, "[1::2]")

    answers, err = client.resolve("mashape", {qtype = resolver.TYPE_A})
    assert.is.Nil(err)
    assert.are.equal(answers[1].address, "123.123.123.123")

    answers, err = client.resolve("kong.for.president", {qtype = resolver.TYPE_AAAA})
    assert.is.Nil(err)
    assert.are.equal(answers[1].address, "[1234::1234]")
  end)

  describe("toip() function", function()
    it("A/AAAA-answers, round-robin",function()
      assert(client.init({ search = {}, }))
      local host = "atest."..TEST_DOMAIN
      local answers = assert(client.resolve(host))
      answers.last_index = nil -- make sure to clean
      local ips = {}
      for _,rec in ipairs(answers) do ips[rec.address] = true end
      local order = {}
      for n = 1, #answers do
        local ip = client.toip(host)
        ips[ip] = nil
        order[n] = ip
      end
      -- this table should be empty again
      assert.is_nil(next(ips))
      -- do again, and check same order
      for n = 1, #order do
        local ip = client.toip(host)
        assert.same(order[n], ip)
      end
    end)
    it("SRV-answers, round-robin on lowest prio",function()
      assert(client.init())
      local lrucache = cli.cache
      local host = "hello.world.test"
      local entry = {
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.4",
          port = 8000,
          weight = 5,
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.4",
          port = 8001,
          weight = 5,
          priority = 20,
          class = 1,
          name = host,
          ttl = 10,
        },
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.4",
          port = 8002,
          weight = 5,
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10,
      }
      -- insert in the cache
      lrucache:set(entry[1].type..":"..entry[1].name, entry)

      local results = {}
      for _ = 1,20 do
        local _, port = client.toip(host)
        results[port] = (results[port] or 0) + 1
      end

      -- 20 passes, each should get 10
      assert.equal(0, results[8001] or 0) --priority 20, no hits
      assert.equal(10, results[8000] or 0) --priority 10, 50% of hits
      assert.equal(10, results[8002] or 0) --priority 10, 50% of hits
    end)
    it("SRV-answers with 1 entry, round-robin",function()
      assert(client.init())
      local lrucache = cli.cache
      local host = "hello.world"
      local entry = {
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.4",
          port = 321,
          weight = 10,
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10,
      }
      -- insert in the cache
      lrucache:set(entry[1].type..":"..entry[1].name, entry)

      -- repeated lookups, as the first will simply serve the first entry
      -- and the only second will setup the round-robin scheme, this is
      -- specific for the SRV answers type, due to the weights
      for _ = 1 , 10 do
        local ip, port = assert(client.toip(host))
        assert.equal("1.2.3.4", ip)
        assert.equal(321, port)
      end
    end)
    it("SRV-answers with 0-weight, round-robin",function()
      assert(client.init())
      local lrucache = cli.cache
      local host = "hello.world"
      local entry = {
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.4",
          port = 321,
          weight = 0,   --> weight 0
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.5",
          port = 321,
          weight = 50,   --> weight 50
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        {
          type = resolver.TYPE_SRV,
          target = "1.2.3.6",
          port = 321,
          weight = 50,   --> weight 50
          priority = 10,
          class = 1,
          name = host,
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10,
      }
      -- insert in the cache
      lrucache:set(entry[1].type..":"..entry[1].name, entry)

      -- weight 0 will be weight 1, without any reduction in weight
      -- of the other ones.
      local track = {}
      for _ = 1 , 202 do  --> run around twice
        local ip, _ = assert(client.toip(host))
        track[ip] = (track[ip] or 0) + 1
      end
      assert.equal(100, track["1.2.3.5"])
      assert.equal(100, track["1.2.3.6"])
      assert.equal(2, track["1.2.3.4"])
    end)
    it("port passing",function()
      assert(client.init())
      local lrucache = cli.cache
      local entry_a = {
        {
          type = resolver.TYPE_A,
          address = "1.2.3.4",
          class = 1,
          name = "a.answers.test",
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10,
      }
      local entry_srv = {
        {
          type = resolver.TYPE_SRV,
          target = "a.answers.test",
          port = 8001,
          weight = 5,
          priority = 20,
          class = 1,
          name = "srv.answers.test",
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10,
      }
      -- insert in the cache
      lrucache:set(entry_a[1].type..":"..entry_a[1].name, entry_a)
      lrucache:set(entry_srv[1].type..":"..entry_srv[1].name, entry_srv)
      local ip, port
      local host = "a.answers.test"
      ip,port = client.toip(host)
      assert.is_string(ip)
      assert.is_nil(port)

      ip, port = client.toip(host, 1234)
      assert.is_string(ip)
      assert.equal(1234, port)

      host = "srv.answers.test"
      ip, port = client.toip(host)
      assert.is_string(ip)
      assert.is_number(port)

      ip, port = client.toip(host, 0)
      assert.is_string(ip)
      assert.is_number(port)
      assert.is_not.equal(0, port)
    end)

    it("port passing if SRV port=0",function()
      assert(client.init({ search = {}, }))
      local ip, port, host

      host = "srvport0."..TEST_DOMAIN
      ip, port = client.toip(host, 10)
      assert.is_string(ip)
      assert.is_number(port)
      assert.is_equal(10, port)

      ip, port = client.toip(host)
      assert.is_string(ip)
      assert.is_nil(port)
    end)

    it("recursive SRV pointing to itself",function()
      assert(client.init({ search = {}, }))
      local ip, answers, port, host, err, _
      host = "srvrecurse."..TEST_DOMAIN

      -- resolve SRV specific should return the answers including its
      -- recursive entry
      answers, err, _ = client.resolve(host, { qtype = resolver.TYPE_SRV })
      assert.is_table(answers)
      assert.equal(1, #answers)
      assert.equal(host, answers[1].target)
      assert.equal(host, answers[1].name)
      assert.is_nil(err)

      -- default order, SRV, A; the recursive SRV answers fails, and it falls
      -- back to the IP4 address
      ip, port, _ = client.toip(host)
      assert.is_string(ip)
      assert.is_equal("10.0.0.44", ip)
      assert.is_nil(port)
    end)
    it("resolving in correct answers-type order",function()
      local function config()
        -- function to insert 2 answerss in the cache
        local A_entry = {
          {
            type = resolver.TYPE_A,
            address = "5.6.7.8",
            class = 1,
            name = "hello.world",
            ttl = 10,
          },
          touch = 0,
          expire = gettime()+10,  -- active
        }
        local AAAA_entry = {
          {
            type = resolver.TYPE_AAAA,
            address = "::1",
            class = 1,
            name = "hello.world",
            ttl = 10,
          },
          touch = 0,
          expire = gettime()+10,  -- active
        }
        -- insert in the cache
        local lrucache = cli.cache
        lrucache:set(A_entry[1].type..":"..A_entry[1].name, A_entry)
        lrucache:set(AAAA_entry[1].type..":"..AAAA_entry[1].name, AAAA_entry)
      end
      assert(client.init({order = {"AAAA", "A"}}))
      config()
      local ip = client.toip("hello.world")
      assert.equals(ip, "::1")
      assert(client.init({order = {"A", "AAAA"}}))
      config()
      ip = client.toip("hello.world")
      assert.equals(ip, "5.6.7.8")
    end)
    it("handling of empty responses", function()
      assert(client.init())
      local empty_entry = {
        touch = 0,
        expire = 0,
      }
      -- insert in the cache
      cli.cache[resolver.TYPE_A..":".."hello.world"] = empty_entry

      -- Note: the bad case would be that the below lookup would hang due to round-robin on an empty table
      local ip, port = client.toip("hello.world", 123, true)
      assert.is_nil(ip)
      assert.is.string(port)  -- error message
    end)
    it("recursive lookups failure", function()
      assert(client.init({
        resolvConf = {
          -- resolv.conf without `search` and `domain` options
          "nameserver 198.51.100.0",
        },
      }))
      local lrucache = cli.cache
      local entry1 = {
        {
          type = resolver.TYPE_CNAME,
          cname = "bye.bye.world",
          class = 1,
          name = "hello.world",
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10, -- active
      }
      local entry2 = {
        {
          type = resolver.TYPE_CNAME,
          cname = "hello.world",
          class = 1,
          name = "bye.bye.world",
          ttl = 10,
        },
        touch = 0,
        expire = gettime()+10, -- active
      }
      -- insert in the cache
      lrucache:set(entry1[1].type..":"..entry1[1].name, entry1)
      lrucache:set(entry2[1].type..":"..entry2[1].name, entry2)

      -- Note: the bad case would be that the below lookup would hang due to round-robin on an empty table
      local ip, port, _ = client.toip("hello.world", 123, true)
      assert.is_nil(ip)
      assert.are.equal("recursion detected", port)
    end)
  end)

  it("verifies validTtl", function()
    local validTtl = 0.1
    local emptyTtl = 0.1
    local staleTtl = 0.1
    local qname = "konghq.com"
    assert(client.init({
      emptyTtl = emptyTtl,
      staleTtl = staleTtl,
      validTtl = validTtl,
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))

    -- mock query function to return a default answers
    query_func = function(self, original_query_func, name, options)
      return  {
        {
          type = resolver.TYPE_A,
          address = "5.6.7.8",
          class = 1,
          name = qname,
          ttl = 10,   -- should be overridden by the validTtl setting
        },
      }
    end

    -- do a query
    local res1, _, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )

    assert.equal(validTtl, res1[1].ttl)
    assert.is_near(validTtl, res1.expire - gettime(), 0.1)
  end)

  it("verifies ttl and caching of empty responses and name errors", function()
    --empty/error responses should be cached for a configurable time
    local emptyTtl = 0.1
    local staleTtl = 0.1
    local qname = "really.really.really.does.not.exist."..TEST_DOMAIN
    assert(client.init({
      emptyTtl = emptyTtl,
      staleTtl = staleTtl,
      -- don't supply resolvConf and fallback to default resolver
      -- so that CI and docker can have reliable results
      -- but remove `search` and `domain`
      search = {},
    }))

    -- mock query function to count calls
    local call_count = 0
    query_func = function(self, original_query_func, name, options)
      call_count = call_count + 1
      return original_query_func(self, name, options)
    end


    -- make a first request, populating the cache
    local res1, res2, err1, err2, _
    res1, err1, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res1)
    assert.are.equal(1, call_count)
    assert.are.equal(NOT_FOUND_ERROR, err1)
    res1 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))


    -- make a second request, result from cache, still called only once
    res2, err2, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(1, call_count)
    assert.are.equal(NOT_FOUND_ERROR, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.equal(res1, res2)
    assert.falsy(res2.expired)


    -- wait for expiry of Ttl and retry, still called only once
    sleep(emptyTtl+0.5 * staleTtl)
    res2, err2 = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(1, call_count)
    assert.are.equal(NOT_FOUND_ERROR, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.equal(res1, res2)
    assert.is_true(res2.expired)  -- by now, answers is marked as expired


    -- wait for expiry of staleTtl and retry, should be called twice now
    sleep(0.75 * staleTtl)
    res2, err2 = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(2, call_count)
    assert.are.equal(NOT_FOUND_ERROR, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.not_equal(res1, res2)
    assert.falsy(res2.expired)  -- new answers, not expired
  end)

  it("verifies ttl and caching of (other) dns errors", function()
    --empty responses should be cached for a configurable time
    local badTtl = 0.1
    local staleTtl = 0.1
    local qname = "realname.com"
    assert(client.init({
      badTtl = badTtl,
      staleTtl = staleTtl,
      resolvConf = {
        -- resolv.conf without `search` and `domain` options
        "nameserver 198.51.100.0",
      },
    }))

    -- mock query function to count calls, and return errors
    local call_count = 0
    query_func = function(self, original_query_func, name, options)
      call_count = call_count + 1
      return { errcode = 5, errstr = "refused" }
    end


    -- initial request to populate the cache
    local res1, res2, err1, err2, _
    res1, err1, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res1)
    assert.are.equal(1, call_count)
    assert.are.equal("dns server error: 5 refused", err1)
    res1 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))


    -- try again, from cache, should still be called only once
    res2, err2, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(call_count, 1)
    assert.are.equal(err1, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.are.equal(res1, res2)
    assert.falsy(res1.expired)


    -- wait for expiry of ttl and retry, still 1 call, but now stale result
    sleep(badTtl + 0.5 * staleTtl)
    res2, err2, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(call_count, 1)
    assert.are.equal(err1, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.are.equal(res1, res2)
    assert.is_true(res2.expired)

    -- wait for expiry of staleTtl and retry, 2 calls, new result
    sleep(0.75 * staleTtl)
    res2, err2, _ = client.resolve(
    qname,
    { qtype = resolver.TYPE_A }
    )
    assert.is_nil(res2)
    assert.are.equal(call_count, 2)  -- 2 calls now
    assert.are.equal(err1, err2)
    res2 = assert(cli.cache:get(resolver.TYPE_A..":"..qname))
    assert.are_not.equal(res1, res2)  -- a new answers
    assert.falsy(res2.expired)
  end)

  describe("verifies the polling of dns queries, retries, and wait times", function()

    it("simultaneous lookups are synchronized to 1 lookup", function()
      assert(client.init())
      local coros = {}
      local results = {}

      local call_count = 0
      query_func = function(self, original_query_func, name, options)
        call_count = call_count + 1
        sleep(0.5) -- make sure we take enough time so the other threads
        -- will be waiting behind this one
        return original_query_func(self, name, options)
      end

      -- we're going to schedule a whole bunch of queries, all of this
      -- function, which does the same lookup and stores the result
      local x = function()
        -- the function is ran when started. So we must immediately yield
        -- so the scheduler loop can first schedule them all before actually
        -- starting resolving
        coroutine.yield(coroutine.running())
        local result, _, _ = client.resolve(
        TEST_DOMAIN,
        { qtype = resolver.TYPE_A }
        )
        table.insert(results, result)
      end

      -- schedule a bunch of the same lookups
      for _ = 1, 10 do
        local co = ngx.thread.spawn(x)
        table.insert(coros, co)
      end

      -- all scheduled and waiting to start due to the yielding done.
      -- now start them all
      for i = 1, #coros do
        ngx.thread.wait(coros[i]) -- this wait will resume the scheduled ones
      end

      -- now count the unique responses we got
      local counters = {}
      for _, r in ipairs(results) do
        r = tostring(r)
        counters[r] = (counters[r] or 0) + 1
      end
      local count = 0
      for _ in pairs(counters) do count = count + 1 end

      -- we should have a single result table, as all threads are supposed to
      -- return the exact same table.
      assert.equal(1,count)
    end)

    it("timeout while waiting", function()

      local timeout = 500
      local ip = "1.4.2.3"
      -- basically the local function _synchronized_query
      assert(client.init({
        timeout = timeout,
        retrans = 1,
        resolvConf = {
          -- resolv.conf without `search` and `domain` options
          "nameserver 198.51.100.0",
        },
      }))

      -- insert a stub thats waits and returns a fixed answers
      local name = TEST_DOMAIN
      query_func = function()
        local ip = ip
        local entry = {
          {
            type = resolver.TYPE_A,
            address = ip,
            class = 1,
            name = name,
            ttl = 10,
          },
          touch = 0,
          expire = gettime() + 10,
        }
        -- wait before we return the results
        -- `+ 2` s ensures that the semaphore:wait() expires
        sleep(timeout/1000 + 2)
        return entry
      end

      local coros = {}
      local results = {}

      -- we're going to schedule a whole bunch of queries, all of this
      -- function, which does the same lookup and stores the result
      local x = function()
        -- the function is ran when started. So we must immediately yield
        -- so the scheduler loop can first schedule them all before actually
        -- starting resolving
        coroutine.yield(coroutine.running())
        local result, err, _ = client.resolve(name, {qtype = resolver.TYPE_A})
        table.insert(results, (result or err))
      end

      -- schedule a bunch of the same lookups
      for _ = 1, 10 do
        local co = ngx.thread.spawn(x)
        table.insert(coros, co)
      end

      -- all scheduled and waiting to start due to the yielding done.
      -- now start them all
      for i = 1, #coros do
        ngx.thread.wait(coros[i]) -- this wait will resume the scheduled ones
      end

      -- results[1~9] are equal, as they all will wait for the first response
      for i = 1, 9 do
        assert.equal("timeout", results[i])
      end
      -- results[10] comes from synchronous DNS access of the first request
      assert.equal(ip, results[10][1]["address"])
    end)
  end)

end)
