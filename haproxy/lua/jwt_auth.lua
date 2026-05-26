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
  local h = io.popen(string.format("printf '%%s' '%s' | base64 -d 2>/dev/null", s))
  if not h then return nil end
  local result = h:read("*a")
  h:close()
  return result
end

-- base64-encode raw bytes (standard alphabet with padding).
local function b64_encode(s)
  local t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local r = {}
  for i = 1, #s, 3 do
    local a, b, c = string.byte(s, i, i + 2)
    b, c = b or 0, c or 0
    local n = (a << 16) | (b << 8) | c
    r[#r+1] = t:sub(((n>>18)&63)+1, ((n>>18)&63)+1)
    r[#r+1] = t:sub(((n>>12)&63)+1, ((n>>12)&63)+1)
    r[#r+1] = (i+1 <= #s) and t:sub(((n>>6)&63)+1, ((n>>6)&63)+1) or "="
    r[#r+1] = (i+2 <= #s) and t:sub((n&63)+1, (n&63)+1) or "="
  end
  return table.concat(r)
end

-- Pure-Lua SHA-256 + HMAC-SHA256 (Lua 5.3+ bitwise operators, 32-bit mask).
local sha256_raw, hmac_sha256_raw
do
  local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  }
  local function rotr(x, n) return ((x >> n) | (x << (32-n))) & 0xFFFFFFFF end
  local function add32(a, b) return (a + b) & 0xFFFFFFFF end

  sha256_raw = function(msg)
    local len = #msg
    msg = msg .. "\x80"
    while #msg % 64 ~= 56 do msg = msg .. "\x00" end
    local bits = len * 8
    local hi, lo = (bits >> 32) & 0xFFFFFFFF, bits & 0xFFFFFFFF
    for s = 24, 0, -8 do msg = msg .. string.char((hi >> s) & 0xFF) end
    for s = 24, 0, -8 do msg = msg .. string.char((lo >> s) & 0xFF) end

    local h0,h1,h2,h3,h4,h5,h6,h7 =
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

    local W = {}
    for blk = 1, #msg, 64 do
      for i = 0, 15 do
        local o = blk + i*4
        W[i] = (string.byte(msg,o) << 24) | (string.byte(msg,o+1) << 16)
             | (string.byte(msg,o+2) << 8)  |  string.byte(msg,o+3)
      end
      for i = 16, 63 do
        local s0 = rotr(W[i-15],7)  ~ rotr(W[i-15],18) ~ (W[i-15] >> 3)
        local s1 = rotr(W[i-2], 17) ~ rotr(W[i-2], 19) ~ (W[i-2]  >> 10)
        W[i] = add32(add32(W[i-16], s0), add32(W[i-7], s1))
      end
      local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
      for i = 0, 63 do
        local S1 = rotr(e,6)  ~ rotr(e,11) ~ rotr(e,25)
        local ch = ((e & f) ~ (~e & g)) & 0xFFFFFFFF
        local t1 = add32(add32(add32(add32(h, S1), ch), K[i+1]), W[i])
        local S0 = rotr(a,2)  ~ rotr(a,13) ~ rotr(a,22)
        local mj = ((a & b) ~ (a & c) ~ (b & c)) & 0xFFFFFFFF
        local t2 = add32(S0, mj)
        h=g; g=f; f=e; e=add32(d,t1); d=c; c=b; b=a; a=add32(t1,t2)
      end
      h0=add32(h0,a); h1=add32(h1,b); h2=add32(h2,c); h3=add32(h3,d)
      h4=add32(h4,e); h5=add32(h5,f); h6=add32(h6,g); h7=add32(h7,h)
    end

    local out = ""
    for _,v in ipairs({h0,h1,h2,h3,h4,h5,h6,h7}) do
      for s = 24, 0, -8 do out = out .. string.char((v >> s) & 0xFF) end
    end
    return out
  end

  hmac_sha256_raw = function(key, data)
    if #key > 64 then key = sha256_raw(key) end
    key = key .. string.rep("\x00", 64 - #key)
    local ipad = key:gsub(".", function(c)
      return string.char(string.byte(c) ~ 0x36)
    end)
    local opad = key:gsub(".", function(c)
      return string.char(string.byte(c) ~ 0x5C)
    end)
    return sha256_raw(opad .. sha256_raw(ipad .. data))
  end
end

-- Compute HMAC-SHA256(secret, data) and return as base64url (no padding).
local function hmac_sha256_b64url(secret, data)
  -- HAProxy 2.8+ native path: avoids Lua computation entirely.
  if core
    and type(core.openssl) == "table"
    and type(core.openssl.hmac) == "function"
    and type(core.b64enc) == "function"
  then
    local hmac_ok, raw = pcall(core.openssl.hmac, secret, data, "SHA256")
    if hmac_ok and raw then
      local b64 = core.b64enc(raw)
      return (b64:gsub("=+$", ""):gsub("+", "-"):gsub("/", "_"))
    end
    if core then core.Warning("jwt_auth: core.openssl.hmac failed") end
  end
  -- Pure-Lua fallback: works in HAProxy 2.6 and test environments.
  local raw = hmac_sha256_raw(secret, data)
  if not raw then return nil end
  local b64
  if core and type(core.b64enc) == "function" then
    b64 = core.b64enc(raw)
  else
    b64 = b64_encode(raw)
  end
  if b64 == "" then return nil end
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
