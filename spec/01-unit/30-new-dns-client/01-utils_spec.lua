local utils = require "kong.resty.dns_client.utils"
local splitlines = require("pl.stringx").splitlines
local writefile = require("pl.utils").writefile
local tempfilename = require("pl.path").tmpname

local sleep
if ngx then
  gettime = ngx.now                -- luacheck: ignore
  sleep = ngx.sleep
else
  local socket = require("socket")
  gettime = socket.gettime         -- luacheck: ignore
  sleep = socket.sleep
end

describe("[utils]", function ()

  describe("is_fqdn(name, ndots)", function ()
    it("test @name: end with `.`", function ()
      assert.is_true(utils.is_fqdn("www.", 2))
      assert.is_true(utils.is_fqdn("www.example.", 3))
      assert.is_true(utils.is_fqdn("www.example.com.", 4))
    end)

    it("test @ndots", function ()
      assert.is_true(utils.is_fqdn("www", 0))

      assert.is_false(utils.is_fqdn("www", 1))
      assert.is_true(utils.is_fqdn("www.example", 1))
      assert.is_true(utils.is_fqdn("www.example.com", 1))

      assert.is_false(utils.is_fqdn("www", 2))
      assert.is_false(utils.is_fqdn("www.example", 2))
      assert.is_true(utils.is_fqdn("www.example.com", 2))
      assert.is_true(utils.is_fqdn("www1.www2.example.com", 2))
    end)
  end)

  describe("search_names()", function ()
    it("empty resolv, not apply the search list", function ()
      local resolv = {}
      local names = utils.search_names("www.example.com", resolv)
      assert.same(names, { "www.example.com" })
    end)

    it("FQDN name: end with `.`, not apply the search list", function ()
      local names = utils.search_names("www.example.com.", { ndots = 1 })
      assert.same(names, { "www.example.com." })
      -- name with 3 dots, and ndots=4 > 3
      local names = utils.search_names("www.example.com.", { ndots = 4 })
      assert.same(names, { "www.example.com." })
    end)

    it("name dots number >= ndots, not apply the search list", function ()
      local resolv = {
        ndots = 1,
        search = { "example.net" },
      }
      local names = utils.search_names("www.example.com", resolv)
      assert.same(names, { "www.example.com" })

      local names = utils.search_names("example.com", resolv)
      assert.same(names, { "example.com" })
    end)

    it("name dots number <= ndots, apply the search list", function ()
      local resolv = {
        ndots = 2,
        search = { "example.net" },
      }
      local names = utils.search_names("www", resolv)
      assert.same(names, { "www.example.net" })

      local names = utils.search_names("www1.www2", resolv)
      assert.same(names, { "www1.www2.example.net" })

      local names = utils.search_names("www1.www2.www3", resolv)
      assert.same(names, { "www1.www2.www3" })  -- not apply

      local resolv = {
        ndots = 2,
        search = { "example.net", "example.com" },
      }
      local names = utils.search_names("www", resolv)
      assert.same(names, { "www.example.net", "www.example.com" })

      local names = utils.search_names("www1.www2", resolv)
      assert.same(names, { "www1.www2.example.net", "www1.www2.example.com" })

      local names = utils.search_names("www1.www2.www3", resolv)
      assert.same(names, { "www1.www2.www3" })  -- not apply
    end)

  end)

end)
