local PLUGIN_NAME = "ai-request-transformer"


-- helper function to validate data against a schema
local validate do
  local validate_entity = require("spec.helpers").validate_plugin_config_schema
  local plugin_schema = require("kong.plugins."..PLUGIN_NAME..".schema")

  function validate(data)
    return validate_entity(data, plugin_schema)
  end
end

describe(PLUGIN_NAME .. ": (schema)", function()
  it("must be 'llm/v1/chat' route type", function()
    local config = {
      llm = {
        route_type = "llm/v1/completions",
        auth = {
          header_name = "Authorization",
          header_value = "Bearer token",
        },
        model = {
          name = "llama-2-7b-chat-hf",
          provider = "llama2",
          options = {
            max_tokens = 256,
            temperature = 1.0,
            llama2_format = "raw",
            upstream_url = "http://kong"
          },
        },
      },
    }

    local ok, err = validate(config)

    assert.not_nil(err)

    assert.same({
      ["@entity"] = {
        [1] = "'config.llm.route_type' must be 'llm/v1/chat' for AI transformer plugins"
      },
      config = {
        llm = {
          route_type = "value must be llm/v1/chat",
        },
        prompt = "required field missing",
      }}, err)
    assert.is_falsy(ok)
  end)
end)
