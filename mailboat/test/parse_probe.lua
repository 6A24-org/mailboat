-- SPDX-License-Identifier: GPL-2.0-or-later
-- Copyright (C) 2026 6A24 Technologies
-- parse_probe.lua -- TEST ONLY. An HAProxy Lua service that decodes the
-- request body with mailboat_json and answers with a canonical rendering
-- (or "ERR <reason>"), so tests/test_mailboat.py can compare the
-- decoder against Python's json module from outside HAProxy.
--
-- Canonical form (mirrored in the Python test):
--   null  -> z        true/false -> t / f
--   number -> n<%.17g>
--   string -> s<hex of UTF-8 bytes>;
--   array -> [ items joined by , ]
--   object -> { key:value joined by , } with keys sorted bytewise,
--             each key rendered as a string

local json = require("mailboat_json")

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local canon
canon = function(v)
  local k = json.kind(v)
  if k == "null" then return "z" end
  if k == "boolean" then return v and "t" or "f" end
  if k == "number" then return "n" .. string.format("%.17g", v) end
  if k == "string" then return "s" .. hex(v) .. ";" end
  if k == "array" then
    local out = {}
    for i = 1, v.n do out[i] = canon(v[i]) end
    return "[" .. table.concat(out, ",") .. "]"
  end
  if k == "object" then
    local keys = {}
    for key in pairs(v) do keys[#keys + 1] = key end
    table.sort(keys)
    local out = {}
    for i, key in ipairs(keys) do out[i] = canon(key) .. ":" .. canon(v[key]) end
    return "{" .. table.concat(out, ",") .. "}"
  end
  return "?"
end

core.register_service("parse_probe", "http", function(applet)
  local body = applet:receive()
  local depth = tonumber(applet.headers["x-max-depth"] and applet.headers["x-max-depth"][0])
  local value, err = json.decode(body, { max_depth = depth })
  local out
  if value == nil then out = "ERR " .. err else out = "OK " .. canon(value) end
  applet:set_status(200)
  applet:add_header("content-type", "text/plain")
  applet:add_header("content-length", tostring(#out))
  applet:start_response()
  applet:send(out)
end)

-- c_probe: decode, then validate as a mailboat v1 message, and render the
-- routing fields on one line so the Python test can compare them exactly.
local mc = require("mailboat_c")

core.register_service("c_probe", "http", function(applet)
  local body = applet:receive()
  local value, err = json.decode(body)
  local out
  if value == nil then
    out = "ERR json " .. err
  else
    local msg
    msg, err = mc.validate(value, { local_scope = "mesh:node1:example.org" })
    if msg == nil then
      out = "ERR " .. err
    else
      local cells = {}
      for i, cell in ipairs(msg.cells) do
        cells[i] = cell.ok and cell.canonical or ("!" .. cell.raw)
      end
      out = string.format("OK from=%s to=%s kind=%s prio=%s class=%d aa=%s route=%s scope=%s cells=%s rb=%s",
        msg.from, table.concat(msg.to, ","), msg.kind, msg.priority, msg.priority_class,
        msg.action_asked and "1" or "0", msg.scope_route, msg.scope and msg.scope.text or "-",
        table.concat(cells, "|"), mc.header_safe(table.concat(msg.readback, ";")))
    end
  end
  applet:set_status(200)
  applet:add_header("content-type", "text/plain")
  applet:add_header("content-length", tostring(#out))
  applet:start_response()
  applet:send(out)
end)
