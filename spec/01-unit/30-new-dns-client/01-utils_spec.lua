local utils = require "kong.resty.dns_client.utils"

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

  describe("round robin getion", function ()

    local function get_and_count(answers, n, get_ans)
      local count = {}
      for _ = 1, n do
        local answer = get_ans(answers)
        count[answer.target] = (count[answer.target] or 0) + 1
      end
      return count
    end

    it("rr", function ()
      local answers = {
        { target = "1" },   -- 25%
        { target = "2" },   -- 25%
        { target = "3" },   -- 25%
        { target = "4" },   -- 25%
      }
      local count = get_and_count(answers, 100, utils.get_rr_ans)
      assert.same(count, { ["1"] = 25, ["2"] = 25, ["3"] = 25, ["4"] = 25 })
    end)

    it("swrr", function ()
      -- simple one
      local answers = {
        { target = "w5-p10-a", weight = 5, priority = 10, },  -- hit 100%
      }
      local count = get_and_count(answers, 20, utils.get_wrr_ans)
      assert.same(count, { ["w5-p10-a"] = 20 })

      -- only get the lowest priority
      local answers = {
        { target = "w5-p10-a", weight = 5, priority = 10, },  -- hit 50%
        { target = "w5-p20", weight = 5, priority = 20, },    -- hit 0%
        { target = "w5-p10-b", weight = 5, priority = 10, },  -- hit 50%
        { target = "w0-p10", weight = 0, priority = 10, },    -- hit 0%
      }
      local count = get_and_count(answers, 20, utils.get_wrr_ans)
      assert.same(count, { ["w5-p10-a"] = 10, ["w5-p10-b"] = 10 })

      -- weight: 6, 3, 1
      local answers = {
        { target = "w6", weight = 6, priority = 10, },  -- hit 60%
        { target = "w3", weight = 3, priority = 10, },  -- hit 30%
        { target = "w1", weight = 1, priority = 10, },  -- hit 10%
      }
      local count = get_and_count(answers, 100 * 1000, utils.get_wrr_ans)
      assert.same(count, { ["w6"] = 60000, ["w3"] = 30000, ["w1"] = 10000 })

      -- random start
      _G.math.native_randomseed(9975098)  -- math.randomseed() ignores @seed
      local answers1 = {
        { target = "1", weight = 1, priority = 10, },
        { target = "2", weight = 1, priority = 10, },
        { target = "3", weight = 1, priority = 10, },
        { target = "4", weight = 1, priority = 10, },
      }
      local answers2 = {
        { target = "1", weight = 1, priority = 10, },
        { target = "2", weight = 1, priority = 10, },
        { target = "3", weight = 1, priority = 10, },
        { target = "4", weight = 1, priority = 10, },
      }

      local a1 = utils.get_wrr_ans(answers1)
      local a2 = utils.get_wrr_ans(answers2)
      assert.not_equal(a1.target, a2.target)

      -- weight 0
      local answers = {
        { target = "w0", weight = 0, priority = 10, },
        { target = "w1", weight = 1, priority = 10, },  -- hit 100%
        { target = "w2", weight = 0, priority = 10, },
        { target = "w3", weight = 0, priority = 10, },
      }
      local count = get_and_count(answers, 100, utils.get_wrr_ans)
      assert.same(count, { ["w1"] = 100 })

      -- weight 0 and lowest priority
      local answers = {
        { target = "w0-a", weight = 0, priority = 0, }, -- hit 100%
        { target = "w1", weight = 1, priority = 10, },
        { target = "w0-b", weight = 0, priority = 0, },
        { target = "w0-c", weight = 0, priority = 0, },
      }
      local count = get_and_count(answers, 100, utils.get_wrr_ans)
      assert.same(count, { ["w0-a"] = 100 })

      -- all weights are 0
      local answers = {
        { target = "1", weight = 0, priority = 10, },
        { target = "2", weight = 0, priority = 10, },
        { target = "3", weight = 0, priority = 10, },
        { target = "4", weight = 0, priority = 10, },
      }
      local count = get_and_count(answers, 100, utils.get_wrr_ans)
      assert.same(count, { ["1"] = 100 })

    end)
  end)

end)
