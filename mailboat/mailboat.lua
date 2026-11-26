-- SPDX-License-Identifier: GPL-2.0-or-later
-- Copyright (C) 2026 6A24 Technologies
-- mailboat.lua -- HAProxy Lua action: route a JSON message on named fields,
-- never on its free text.
--
-- Load with:
--   global
--     tune.lua.bool-sample-conversion normal
--     lua-prepend-path /path/to/mailboat/?.lua
--     lua-load /path/to/mailboat/mailboat.lua
--   frontend ...
--     option http-buffer-request
--     http-request lua.mailboat
--
-- The action decodes the request body with a strict JSON decoder
-- (mailboat_json), validates it as a mailboat v1 message (mailboat_c), and
-- sets transaction variables for ACLs to route on. It never rewrites the
-- body: the backend receives exactly the bytes the sender sent.
--
-- Variables set (all txn scope):
--   mb_ok          bool    true if the message is valid
--   mb_status      int     HTTP status to answer with when mb_ok is false
--   mb_reply       string  a JSON reply body to send when mb_ok is false
--   mb_cell        string  the proxy's own 6A24 status for the reply header
--   mb_from        string  sender name (self-asserted; see README.md)
--   mb_to          string  recipients, comma-joined (names cannot hold a comma)
--   mb_to_count    int
--   mb_kind        string  "chat" or "send"
--   mb_route       string  "local" or "federation"
--   mb_prio        string  "iu", "i", "u", "x" or "none"
--   mb_prio_class  int     for http-request set-priority-class
--   mb_action_asked bool
--   mb_readback    string  what was read generously, header-safe
--   mb_body_offset int     kind json only: where the body value starts in the
--   mb_body_length int     request body (0-based) and how many bytes it spans
--
-- Settings, read once at load from the environment:
--   MAILBOAT_LOCAL_SCOPE  this system's c:x scope (default: none, so any
--                         scoped message routes to federation)
--   MAILBOAT_MAX_BYTES    body cap (default 65536; must fit tune.bufsize)

local json = require("mailboat_json")
local mc = require("mailboat_c")

local LOCAL_SCOPE = os.getenv("MAILBOAT_LOCAL_SCOPE")
local MAX_BYTES = tonumber(os.getenv("MAILBOAT_MAX_BYTES") or "") or 65536

if LOCAL_SCOPE and LOCAL_SCOPE ~= "" then
  local ok, err = mc.parse_scope(LOCAL_SCOPE)
  if not ok then error("MAILBOAT_LOCAL_SCOPE is not a valid scope: " .. err) end
else
  LOCAL_SCOPE = nil
end

-- Header-safe text: see mailboat_c.header_safe. HAProxy 3.2 also encodes
-- control characters when a sample is written into a header (observed
-- 2026-11-25), so this is defence in depth for front ends that use the
-- variables some other way.
local header_safe = mc.header_safe

local ESC = { ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\f"] = "\\f",
              ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t" }

local function json_string(s)
  return '"' .. s:gsub('[%c"\\]', function(c)
    return ESC[c] or string.format("\\u%04x", c:byte())
  end) .. '"'
end

-- A small JSON object of string fields, in a fixed order.
local function json_object(fields)
  local out = {}
  for _, kv in ipairs(fields) do
    out[#out + 1] = json_string(kv[1]) .. ":" .. json_string(kv[2])
  end
  return "{" .. table.concat(out, ",") .. "}"
end

-- The proxy's own cell is written from the PROXY's side (spec 7.3: party is
-- counted from the writer). These are the replies mailboat itself makes.
local CELL_UNREADABLE = "c:unfamiliar c:p=other-pending-out"   -- fix and send again
local CELL_REFUSED = "c:p=self-cancel-flight c:cause=operator"  -- route not configured
local CELL_ACCEPTED = "c:p=self-done-flight"                    -- passed to the backend

local function refuse(txn, status, cell, reason)
  txn:set_var("txn.mb_ok", false)
  txn:set_var("txn.mb_status", status)
  txn:set_var("txn.mb_cell", cell)
  txn:set_var("txn.mb_reply", json_object({
    { "outcome", "refused" }, { "reason", reason }, { "c", cell },
  }))
end

local function mailboat(txn)
  -- A body larger than HAProxy's buffer arrives truncated; never route on a
  -- partial body.
  local len = txn.f:req_body_len() or 0
  local size = txn.f:req_body_size() or 0
  if size ~= len or len > MAX_BYTES then
    return refuse(txn, 413, CELL_UNREADABLE, "body too large")
  end
  local body = txn.f:req_body() or ""

  local spans = {}
  local value, err = json.decode(body, { max_bytes = MAX_BYTES, spans = spans })
  if value == nil then
    return refuse(txn, 400, CELL_UNREADABLE, "json " .. err)
  end
  local msg
  msg, err = mc.validate(value, { local_scope = LOCAL_SCOPE })
  if msg == nil then
    return refuse(txn, 400, CELL_UNREADABLE, err)
  end

  if msg.scope_route == "federation" then
    -- v0: federation is refused until it is configured on purpose
    -- (routing beyond this system is opened on purpose, never by default).
    txn:set_var("txn.mb_route", "federation")
    return refuse(txn, 403, CELL_REFUSED, "federation route not configured")
  end

  txn:set_var("txn.mb_ok", true)
  txn:set_var("txn.mb_cell", CELL_ACCEPTED)
  txn:set_var("txn.mb_from", msg.from)
  txn:set_var("txn.mb_to", table.concat(msg.to, ","))
  txn:set_var("txn.mb_to_count", #msg.to)
  txn:set_var("txn.mb_kind", msg.kind)
  txn:set_var("txn.mb_route", msg.scope_route)
  txn:set_var("txn.mb_prio", msg.priority)
  txn:set_var("txn.mb_prio_class", msg.priority_class)
  txn:set_var("txn.mb_action_asked", msg.action_asked)
  txn:set_var("txn.mb_readback", header_safe(table.concat(msg.readback, "; ")))
  if msg.kind == "json" then
    -- The nested message is forwarded as its exact original bytes: the
    -- backend takes this slice of the request body. Nothing is re-encoded.
    txn:set_var("txn.mb_body_offset", spans.body.offset)
    txn:set_var("txn.mb_body_length", spans.body.length)
  end
end

core.register_action("mailboat", { "http-req" }, mailboat, 0)
