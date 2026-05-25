--[[
  jwt_auth.lua — HAProxy Lua script for JWT cookie validation.

  Sets on the transaction:
    txn.jwt_valid  (bool)   — true if cookie present and signature valid and not expired
    txn.teams      (string) — comma-separated "org/team-slug" values from JWT claims

  Requires: HAProxy 2.6+.
  The JWT_SECRET env var must match the OAuth app's JWT_SECRET.
--]]

-- JSON decoder: prefer cjson (bundled with most HAProxy builds); fall back to
-- a minimal pure-Lua decoder that covers the subset needed for JWT payloads.
local ok, _cjson = pcall(require, "cjson")
local json_decode
if ok then
  json_decode = _cjson.decode
else
  -- Minimal decoder: handles flat objects with string, number, and string-array values.
  json_decode = function(s)
    local obj = {}
    local body = s:match("^%s*{(.*)}%s*$")
    if not body then return nil end
    -- String arrays: "key":["v1","v2"]
    for k, arr in body:gmatch('"([^"]+)"%s*:%s*(%b[])') do
      local items = {}
      for v in arr:gmatch('"([^"]+)"') do items[#items + 1] = v end
      obj[k] = items
    end
    -- String values: "key":"value"
    for k, v in body:gmatch('"([^"]+)"%s*:%s*"([^"]+)"') do
      if obj[k] == nil then obj[k] = v end
    end
    -- Number values: "key":number
    for k, v in body:gmatch('"([^"]+)"%s*:%s*(%-?%d+)') do
      if obj[k] == nil then obj[k] = tonumber(v) end
    end
    return obj
  end
end

-- base64url-decode a JWT segment to raw bytes.
local function b64url_decode(s)
  s = s:gsub("%-", "+"):gsub("_", "/")
  local pad = 4 - (#s % 4)
  if pad ~= 4 then s = s .. string.rep("=", pad) end
  if core and core.b64dec then
    return core.b64dec(s)
  end
  -- Shell fallback for non-HAProxy environments (tests).
  -- JWT segments are base64 ASCII — safe in single-quoted shell argument.
  local h = io.popen(string.format("printf '%%s' '%s' | base64 -d 2>/dev/null", s))
  local result = h:read("*a")
  h:close()
  return result
end

-- Compute HMAC-SHA256(secret, data) and return as base64url (no padding).
-- Signing input is base64url ASCII — safe in single-quoted shell arguments.
local function hmac_sha256_b64url(secret, data)
  if core and core.openssl and core.b64enc then
    local raw = core.openssl.hmac(secret, data, "SHA256")
    local b64 = core.b64enc(raw)
    return (b64:gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
  end
  -- Shell fallback: binary HMAC output pipes directly into base64 — no
  -- null-byte truncation because the pipe is binary-safe.
  local cmd = string.format(
    "printf '%%s' '%s' | openssl dgst -sha256 -hmac '%s' -binary | base64 -w0 2>/dev/null",
    data, secret:gsub("'", "'\\''")
  )
  local h = io.popen(cmd)
  local b64 = h:read("*a"):gsub("%s+$", "")
  h:close()
  return (b64:gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
end

-- Extract a named cookie value from a Cookie header string.
local function get_cookie(header, name)
  if not header then return nil end
  for k, v in header:gmatch("([^=;%s]+)%s*=%s*([^;]+)") do
    if k == name then return v:match("^%s*(.-)%s*$") end
  end
  return nil
end

-- Main action: called via `http-request lua.check_jwt` in haproxy.cfg.
local function check_jwt(txn)
  txn:set_var("txn.jwt_valid", false)
  txn:set_var("txn.teams", "")

  local secret = os.getenv("JWT_SECRET")
  if not secret or secret == "" then
    if core then core.Warning("jwt_auth: JWT_SECRET not set") end
    return
  end

  local headers = txn.http:req_get_headers()
  local cookie_header = headers["cookie"]
  if not cookie_header then return end
  if type(cookie_header) == "table" then cookie_header = cookie_header[0] end
  if not cookie_header then return end

  local token = get_cookie(cookie_header, "_auth")
  if not token then return end

  local header_b64, payload_b64, sig_b64 = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  if not header_b64 then
    if core then core.Debug("jwt_auth: malformed token") end
    return
  end

  local signing_input = header_b64 .. "." .. payload_b64
  local expected_sig  = hmac_sha256_b64url(secret, signing_input)
  if expected_sig ~= sig_b64 then
    if core then core.Debug("jwt_auth: signature mismatch") end
    return
  end

  local payload_json = b64url_decode(payload_b64)
  if not payload_json or payload_json == "" then
    if core then core.Debug("jwt_auth: failed to decode payload") end
    return
  end

  local payload = json_decode(payload_json)
  if not payload then
    if core then core.Debug("jwt_auth: failed to parse payload JSON") end
    return
  end

  local exp = payload.exp
  if type(exp) == "number" and os.time() > exp then
    if core then core.Debug("jwt_auth: token expired") end
    return
  end

  local teams = ""
  if type(payload.teams) == "table" then
    teams = table.concat(payload.teams, ",")
  end

  txn:set_var("txn.jwt_valid", true)
  txn:set_var("txn.teams", teams)
end

if core then
  core.register_action("check_jwt", {"http-req"}, check_jwt)
end

-- Return function for direct testing via dofile().
return check_jwt
