-- luacheck configuration for HAProxy Lua scripts

std = "lua54"

-- HAProxy injects `core` into the global environment at load time.
globals = { "core" }

-- Unused argument warnings are noise in HAProxy action callbacks.
ignore = { "212" }

-- Test files use busted framework globals and mock os.getenv.
files["haproxy/lua/jwt_auth_test.lua"] = {
  globals = {
    "describe", "context",
    "it", "test",
    "before_each", "after_each", "before_all", "after_all",
    "setup", "teardown",
    "assert",
  },
  -- 142: setting read-only field (os.getenv mock)
  -- 143: setting undefined field of global (assert.is_true etc.)
  ignore = { "142", "143" },
}
