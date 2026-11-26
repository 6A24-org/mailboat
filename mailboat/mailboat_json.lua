-- SPDX-License-Identifier: GPL-2.0-or-later
-- Copyright (C) 2026 6A24 Technologies
-- mailboat_json.lua -- a strict JSON (RFC 8259) decoder for HAProxy's Lua.
--
-- Mailboat routes on named fields of a JSON body. A proxy that routes on a
-- different reading of a body than the backend executes is a smuggling
-- hazard, so this decoder REFUSES anything two parsers could read
-- differently, instead of picking an interpretation:
--
--   * duplicate keys in an object (compared after unescaping, so "a" and
--     "\u0061" are the same key)
--   * invalid UTF-8, overlong encodings, UTF-8-encoded surrogates, and
--     lone or mis-paired \u surrogate escapes
--   * unescaped control characters in strings
--   * anything RFC 8259 does not allow: comments, trailing commas, single
--     quotes, NaN/Infinity, leading zeros, a byte-order mark, trailing data
--
-- It also caps nesting depth and input size, so a body cannot exhaust memory
-- or the C stack.
--
-- The decoder never re-encodes: mailboat forwards the original body bytes,
-- so whatever the backend receives is exactly what the sender sent.
--
-- Usage:
--   local json = require("mailboat_json")
--   local value, err = json.decode(body, { max_depth = 32, max_bytes = 65536 })
--   if value == nil then -- err is "offset N: reason"
--
-- Pass opts.spans = {} to learn where each TOP-LEVEL member's value sits in
-- the original bytes: spans[key] = { offset = <0-based>, length = <bytes> }.
-- That is how a nested message is forwarded byte for byte, never re-encoded.
--
-- Objects are tables with metatable json.OBJECT; arrays are tables with
-- metatable json.ARRAY and a field n (their length, since null elements are
-- json.null). json.kind(v) returns "object", "array", "string", "number",
-- "boolean" or "null".

local M = {}

M.OBJECT = { __name = "json.object" }
M.ARRAY = { __name = "json.array" }
M.null = setmetatable({}, { __name = "json.null", __tostring = function() return "null" end })

local DEFAULT_MAX_DEPTH = 32
local DEFAULT_MAX_BYTES = 65536

local byte, sub, find, char = string.byte, string.sub, string.find, string.char

function M.kind(v)
  local t = type(v)
  if t == "table" then
    if v == M.null then return "null" end
    local mt = getmetatable(v)
    if mt == M.OBJECT then return "object" end
    if mt == M.ARRAY then return "array" end
    return nil
  end
  if t == "string" or t == "number" or t == "boolean" then return t end
  return nil
end

-- Raised errors carry a table so they can be told apart from Lua faults.
local function fail(pos, reason)
  error({ mailboat_json = true, pos = pos, reason = reason }, 0)
end

-- Encode a code point as UTF-8 (the code point is already validated).
local function utf8_encode(cp)
  if cp < 0x80 then
    return char(cp)
  elseif cp < 0x800 then
    return char(0xC0 | (cp >> 6), 0x80 | (cp & 0x3F))
  elseif cp < 0x10000 then
    return char(0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
  else
    return char(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F),
                0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
  end
end

-- Validate one raw UTF-8 sequence starting at i (byte b0 >= 0x80).
-- Returns the index after it. Rejects overlongs, surrogates and > U+10FFFF
-- (the well-formed table of Unicode 15, section 3.9, table 3-7).
local function check_utf8(s, i, b0)
  local function cont(j, lo, hi)
    local b = byte(s, j)
    if b == nil or b < lo or b > hi then fail(j, "invalid UTF-8") end
  end
  if b0 >= 0xC2 and b0 <= 0xDF then
    cont(i + 1, 0x80, 0xBF)
    return i + 2
  elseif b0 == 0xE0 then
    cont(i + 1, 0xA0, 0xBF); cont(i + 2, 0x80, 0xBF)
    return i + 3
  elseif (b0 >= 0xE1 and b0 <= 0xEC) or b0 == 0xEE or b0 == 0xEF then
    cont(i + 1, 0x80, 0xBF); cont(i + 2, 0x80, 0xBF)
    return i + 3
  elseif b0 == 0xED then
    cont(i + 1, 0x80, 0x9F); cont(i + 2, 0x80, 0xBF)   -- excludes surrogates
    return i + 3
  elseif b0 == 0xF0 then
    cont(i + 1, 0x90, 0xBF); cont(i + 2, 0x80, 0xBF); cont(i + 3, 0x80, 0xBF)
    return i + 4
  elseif b0 >= 0xF1 and b0 <= 0xF3 then
    cont(i + 1, 0x80, 0xBF); cont(i + 2, 0x80, 0xBF); cont(i + 3, 0x80, 0xBF)
    return i + 4
  elseif b0 == 0xF4 then
    cont(i + 1, 0x80, 0x8F); cont(i + 2, 0x80, 0xBF); cont(i + 3, 0x80, 0xBF)
    return i + 4
  end
  fail(i, "invalid UTF-8")
end

local ESCAPES = {
  [0x22] = '"', [0x5C] = "\\", [0x2F] = "/",
  [0x62] = "\b", [0x66] = "\f", [0x6E] = "\n", [0x72] = "\r", [0x74] = "\t",
}

local function read_hex4(s, i)
  local h = sub(s, i, i + 3)
  if #h ~= 4 or not find(h, "^%x%x%x%x$") then fail(i, "bad \\u escape") end
  return tonumber(h, 16)
end

-- s:byte(i) is the opening quote. Returns the decoded string and the index
-- after the closing quote.
local function parse_string(s, i)
  local parts, n = {}, 0
  local j = i + 1
  local run_start = j
  while true do
    local b = byte(s, j)
    if b == nil then fail(i, "unterminated string") end
    if b == 0x22 then
      n = n + 1; parts[n] = sub(s, run_start, j - 1)
      return table.concat(parts), j + 1
    elseif b == 0x5C then
      n = n + 1; parts[n] = sub(s, run_start, j - 1)
      local e = byte(s, j + 1)
      if e == 0x75 then
        local cp = read_hex4(s, j + 2)
        local nxt = j + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          if byte(s, nxt) ~= 0x5C or byte(s, nxt + 1) ~= 0x75 then
            fail(j, "lone high surrogate")
          end
          local lo = read_hex4(s, nxt + 2)
          if lo < 0xDC00 or lo > 0xDFFF then fail(nxt, "high surrogate not followed by low") end
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
          nxt = nxt + 6
        elseif cp >= 0xDC00 and cp <= 0xDFFF then
          fail(j, "lone low surrogate")
        end
        n = n + 1; parts[n] = utf8_encode(cp)
        j = nxt
      else
        local rep = e and ESCAPES[e]
        if rep == nil then fail(j, "bad escape") end
        n = n + 1; parts[n] = rep
        j = j + 2
      end
      run_start = j
    elseif b < 0x20 then
      fail(j, "control character in string")
    elseif b < 0x80 then
      j = j + 1
    else
      j = check_utf8(s, j, b)
    end
  end
end

local function skip_ws(s, i)
  -- RFC 8259 whitespace only: space, tab, LF, CR.
  local _, e = find(s, "^[ \t\n\r]*", i)
  return e + 1
end

local function parse_number(s, i)
  -- -? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?
  local j = i
  if byte(s, j) == 0x2D then j = j + 1 end
  local b = byte(s, j)
  if b == 0x30 then
    j = j + 1
    local d = byte(s, j)
    if d and d >= 0x30 and d <= 0x39 then fail(i, "leading zero") end
  elseif b and b >= 0x31 and b <= 0x39 then
    local _, e = find(s, "^[0-9]+", j); j = e + 1
  else
    fail(i, "bad number")
  end
  if byte(s, j) == 0x2E then
    local _, e = find(s, "^[0-9]+", j + 1)
    if not e then fail(j, "bad fraction") end
    j = e + 1
  end
  b = byte(s, j)
  if b == 0x65 or b == 0x45 then
    local _, e = find(s, "^[+-]?[0-9]+", j + 1)
    if not e then fail(j, "bad exponent") end
    j = e + 1
  end
  local v = tonumber(sub(s, i, j - 1))
  if v == nil or v ~= v or v == math.huge or v == -math.huge then fail(i, "number out of range") end
  return v, j
end

local parse_value

local function parse_object(s, i, depth, max_depth, spans)
  if depth > max_depth then fail(i, "too deep") end
  local obj = setmetatable({}, M.OBJECT)
  local j = skip_ws(s, i + 1)
  if byte(s, j) == 0x7D then return obj, j + 1 end
  while true do
    if byte(s, j) ~= 0x22 then fail(j, "expected string key") end
    local key_pos = j
    local key
    key, j = parse_string(s, j)
    if obj[key] ~= nil then fail(key_pos, "duplicate key") end
    j = skip_ws(s, j)
    if byte(s, j) ~= 0x3A then fail(j, "expected ':'") end
    local v
    local vstart = skip_ws(s, j + 1)
    v, j = parse_value(s, vstart, depth, max_depth)
    if spans and depth == 1 then
      -- where this top-level value sits in the original bytes (0-based offset)
      spans[key] = { offset = vstart - 1, length = j - vstart }
    end
    obj[key] = v
    j = skip_ws(s, j)
    local b = byte(s, j)
    if b == 0x7D then return obj, j + 1 end
    if b ~= 0x2C then fail(j, "expected ',' or '}'") end
    j = skip_ws(s, j + 1)
  end
end

local function parse_array(s, i, depth, max_depth)
  if depth > max_depth then fail(i, "too deep") end
  local arr = setmetatable({ n = 0 }, M.ARRAY)
  local j = skip_ws(s, i + 1)
  if byte(s, j) == 0x5D then return arr, j + 1 end
  while true do
    local v
    v, j = parse_value(s, j, depth, max_depth)
    arr.n = arr.n + 1
    arr[arr.n] = v
    j = skip_ws(s, j)
    local b = byte(s, j)
    if b == 0x5D then return arr, j + 1 end
    if b ~= 0x2C then fail(j, "expected ',' or ']'") end
    j = skip_ws(s, j + 1)
  end
end

parse_value = function(s, i, depth, max_depth, spans)
  local b = byte(s, i)
  if b == 0x7B then return parse_object(s, i, depth + 1, max_depth, spans) end
  if b == 0x5B then return parse_array(s, i, depth + 1, max_depth) end
  if b == 0x22 then return parse_string(s, i) end
  if b == 0x2D or (b and b >= 0x30 and b <= 0x39) then return parse_number(s, i) end
  if sub(s, i, i + 3) == "true" then return true, i + 4 end
  if sub(s, i, i + 4) == "false" then return false, i + 5 end
  if sub(s, i, i + 3) == "null" then return M.null, i + 4 end
  if b == nil then fail(i, "unexpected end of input") end
  fail(i, "unexpected character")
end

function M.decode(s, opts)
  opts = opts or {}
  local max_depth = opts.max_depth or DEFAULT_MAX_DEPTH
  local max_bytes = opts.max_bytes or DEFAULT_MAX_BYTES
  if type(s) ~= "string" then return nil, "offset 0: not a string" end
  if #s > max_bytes then return nil, "offset 0: body too large" end
  local ok, value, j = pcall(function()
    local v, k = parse_value(s, skip_ws(s, 1), 0, max_depth, opts.spans)
    return v, skip_ws(s, k)
  end)
  if not ok then
    if type(value) == "table" and value.mailboat_json then
      return nil, string.format("offset %d: %s", value.pos - 1, value.reason)
    end
    return nil, "offset 0: internal error: " .. tostring(value)
  end
  if j <= #s then return nil, string.format("offset %d: trailing data", j - 1) end
  return value
end

return M
