-- jwt_auth_test.lua — busted tests for jwt_auth.lua
--
-- Run from project root: busted --pattern "_test" haproxy/lua/
-- Requires: openssl CLI, base64 CLI (coreutils), busted luarock.
--
-- jwt_auth.lua is loaded via dofile() which returns check_jwt directly,
-- so no HAProxy `core` global is needed in the test environment.

local TEST_SECRET = "test-secret-that-is-at-least-32ch"

-- Load the script under test. dofile returns check_jwt (the action function).
local script_dir = debug.getinfo(1, "S").source:match("^@(.+/)") or "./"
local check_jwt = dofile(script_dir .. "jwt_auth.lua")

-- ── Test-only JWT generator (uses openssl + base64 CLI) ───────────────────────

local function b64url(s)
  local h = io.popen(string.format("printf '%%s' '%s' | base64 -w0 2>/dev/null", s))
  local r = h:read("*a"):gsub("%s+$", "")
  h:close()
  return (r:gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
end

local function make_jwt(sub, teams, exp_delta)
  local now    = os.time()
  local header = b64url('{"alg":"HS256","typ":"JWT"}')
  local teams_json = '["' .. table.concat(teams, '","') .. '"]'
  local payload = b64url(string.format(
    '{"sub":"%s","teams":%s,"iat":%d,"exp":%d}',
    sub, teams_json, now, now + exp_delta
  ))
  local si  = header .. "." .. payload
  local cmd = string.format(
    "printf '%%s' '%s' | openssl dgst -sha256 -hmac '%s' -binary | base64 -w0 2>/dev/null",
    si, TEST_SECRET
  )
  local h = io.popen(cmd)
  local sig = h:read("*a"):gsub("%s+$", "")
  h:close()
  sig = (sig:gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
  return si .. "." .. sig
end

-- ── Txn mock factory ──────────────────────────────────────────────────────────

local function make_txn(cookie_value)
  local vars = {}
  local txn = {
    http = {
      req_get_headers = function()
        if cookie_value then
          return { cookie = { [0] = "_auth=" .. cookie_value } }
        end
        return {}
      end,
    },
    set_var = function(_self, name, value)
      vars[name] = value
    end,
  }
  return txn, vars
end

-- ── Tests ─────────────────────────────────────────────────────────────────────

describe("check_jwt", function()
  local orig_getenv = os.getenv

  before_each(function()
    os.getenv = function(key) -- luacheck: ignore 122
      if key == "JWT_SECRET" then return TEST_SECRET end
      return orig_getenv(key)
    end
  end)

  after_each(function()
    os.getenv = orig_getenv -- luacheck: ignore 122
  end)

  it("sets jwt_valid=true and teams for a valid token", function()
    local token = make_jwt("octocat", {"myorg/admins", "myorg/devs"}, 28800)
    local txn, vars = make_txn(token)

    check_jwt(txn)

    assert.is_true(vars["txn.jwt_valid"])
    assert.equals("myorg/admins,myorg/devs", vars["txn.teams"])
  end)

  it("sets jwt_valid=false for a bad signature", function()
    local token = make_jwt("octocat", {"myorg/admins"}, 28800)
    -- Corrupt the last 4 chars of the signature
    local bad = token:sub(1, -5) .. "XXXX"
    local txn, vars = make_txn(bad)

    check_jwt(txn)

    assert.is_false(vars["txn.jwt_valid"])
  end)

  it("sets jwt_valid=false for an expired token", function()
    local token = make_jwt("octocat", {"myorg/admins"}, -3600)
    local txn, vars = make_txn(token)

    check_jwt(txn)

    assert.is_false(vars["txn.jwt_valid"])
  end)

  it("sets jwt_valid=false when no _auth cookie is present", function()
    local txn, vars = make_txn(nil)

    check_jwt(txn)

    assert.is_false(vars["txn.jwt_valid"])
  end)

  it("sets jwt_valid=false when JWT_SECRET is not set", function()
    os.getenv = function(_key) return nil end -- luacheck: ignore 122
    local token = make_jwt("octocat", {"myorg/admins"}, 28800)
    local txn, vars = make_txn(token)

    check_jwt(txn)

    assert.is_false(vars["txn.jwt_valid"])
  end)
end)
