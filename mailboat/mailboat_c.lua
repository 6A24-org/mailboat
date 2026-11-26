-- SPDX-License-Identifier: GPL-2.0-or-later
-- Copyright (C) 2026 6A24 Technologies
-- mailboat_c.lua -- validate a mailboat v1 message (the `c:` schema) and
-- extract its routing fields. Pure Lua: no HAProxy calls, so it can be
-- tested on its own and reused by other front ends.
--
-- The message shape (also described in README.md):
--
--   { "v": 1, "from": "<name>", "to": ["<name>", ...], "kind": "chat"|"send",
--     "text": "<body, never parsed for routing>", "why": "<optional>",
--     "c": { "<tag key>": <value>, ... } }
--
-- Two layers, two standards:
--
--   * The ENVELOPE (v, from, to, kind, text, why) is mailboat's own schema.
--     It is checked strictly, and an unknown top-level key is refused,
--     because anything a router ignores is something a backend might not.
--
--   * The `c` object carries 6A24 tags (spec section 7). Those follow the
--     protocol's own rules: unknown keys are kept, not refused (7.2 rule 6),
--     and closed-list values are READ GENEROUSLY (7.2 rule 8): a value one
--     edit from exactly one valid value is read as that value, and the
--     reading is reported in `readback` so the reply can say so plainly.
--     A cell that cannot be read is kept, reported, and never refused.
--
-- Usage:
--   local mc = require("mailboat_c")
--   local msg, err = mc.validate(decoded_json, { local_scope = "mesh:node1:example.org" })
--
-- On success, msg holds the routing fields (see the end of validate()).

local json = require("mailboat_json")

local M = {}

M.MAX_RECIPIENTS = 16
M.MAX_CELLS = 16
M.NAME_PATTERN = "^[A-Za-z0-9][A-Za-z0-9_-]*$"
M.NAME_MAX = 64

local ENVELOPE_KEYS = { v = true, from = true, to = true, kind = true, text = true, why = true, c = true }
local KINDS = { chat = true, send = true }

-- Closed lists for the status token (spec 7.3), with retired values mapped.
local PARTY = { self = "self", other = "other", shared = "shared",
                int = "self", ext = "other", joint = "shared" }
local STATUS = { pending = "pending", working = "working", hold = "hold", done = "done",
                 cancel = "cancel", wait = "pending" }
local ACTION = { read = "read", ack = "ack", flight = "flight", out = "out",
                 comp = "flight", prog = "flight" }
local PRIORITY = { iu = "iu", ui = "iu", i = "i", u = "u", x = "x",
                   ["1"] = "iu", ["2"] = "i", ["3"] = "u", ["4"] = "x" }
-- Lower number = served first (HAProxy priority classes order ascending).
M.PRIORITY_CLASS = { iu = -3, i = -2, u = -1, x = 1, none = 0 }

-- Optimal string alignment distance, capped: is it at most 1?
local function within_one(a, b)
  if a == b then return true end
  local la, lb = #a, #b
  if math.abs(la - lb) > 1 then return false end
  if la == lb then
    local diffs = {}
    for i = 1, la do
      if a:sub(i, i) ~= b:sub(i, i) then
        diffs[#diffs + 1] = i
        if #diffs > 2 then return false end
      end
    end
    if #diffs == 1 then return true end
    -- one adjacent transposition
    local i, j = diffs[1], diffs[2]
    return j == i + 1 and a:sub(i, i) == b:sub(j, j) and a:sub(j, j) == b:sub(i, i)
  end
  -- one insertion or deletion
  local long, short = a, b
  if la < lb then long, short = b, a end
  local i, j, skipped = 1, 1, false
  while i <= #long do
    if long:sub(i, i) ~= (short:sub(j, j)) then
      if skipped then return false end
      skipped = true
      i = i + 1
    else
      i = i + 1; j = j + 1
    end
  end
  return true
end

-- Read one segment against a closed list. Returns canonical, note-or-nil.
-- nil canonical means "could not read" (close to none, or to more than one).
local function read_closed(word, list, what)
  if list[word] then return list[word], nil end
  local hit, hits = nil, 0
  local seen = {}
  for candidate, canonical in pairs(list) do
    if within_one(word, candidate) and not seen[canonical] then
      seen[canonical] = true
      hits = hits + 1
      hit = canonical
    end
  end
  if hits == 1 then
    return hit, string.format("%s '%s' read as '%s'", what, word, hit)
  end
  if hits > 1 then
    return nil, string.format("%s '%s' is close to more than one value", what, word)
  end
  return nil, string.format("%s '%s' is not a known value", what, word)
end

-- Parse one status-cell value: party-status-action[=priority][?]
-- Returns a cell table; cell.ok is false when it could not be read, and
-- cell.notes always says what was read generously or not at all.
function M.parse_cell(raw)
  local cell = { raw = raw, notes = {}, ok = false }
  local s = raw:lower()
  if s:sub(-1) == "?" then
    cell.question = true
    s = s:sub(1, -2)
  end
  local body, prio = s:match("^([^=]*)=(.*)$")
  if body == nil then body = s end
  local p, st, a = body:match("^([^-]+)-([^-]+)-([^-]+)$")
  if p == nil then
    cell.notes[#cell.notes + 1] = string.format("cell '%s' is not party-status-action", raw)
    return cell
  end
  local note
  local ok = true
  cell.party, note = read_closed(p, PARTY, "party")
  if note then cell.notes[#cell.notes + 1] = note end
  ok = ok and cell.party ~= nil
  cell.status, note = read_closed(st, STATUS, "status")
  if note then cell.notes[#cell.notes + 1] = note end
  ok = ok and cell.status ~= nil
  cell.action, note = read_closed(a, ACTION, "action")
  if note then cell.notes[#cell.notes + 1] = note end
  ok = ok and cell.action ~= nil
  if prio ~= nil then
    -- Priority letters come in either order; never guessed, only matched.
    cell.priority = PRIORITY[prio]
    if cell.priority == nil then
      cell.notes[#cell.notes + 1] = string.format("priority '=%s' is not known; ignored", prio)
    end
  end
  cell.ok = ok
  if ok then
    cell.canonical = cell.party .. "-" .. cell.status .. "-" .. cell.action ..
      (cell.priority and ("=" .. cell.priority) or "") .. (cell.question and "?" or "")
  end
  return cell
end

-- Parse a c:x scope (spec section 8). Returns {system, name, org} or nil, err.
function M.parse_scope(raw)
  local s = raw:lower():gsub(";", ":")
  if s == "" or s:sub(1, 1) == ":" or s:sub(-1) == ":" or s:find("::", 1, true) then
    return nil, "scope has an empty part"
  end
  local parts = {}
  for part in s:gmatch("[^:]+") do parts[#parts + 1] = part end
  if #parts > 3 then return nil, "scope has more than three parts" end
  local scope = {}
  if parts[#parts]:find(".", 1, true) then
    scope.org = table.remove(parts)
  end
  for _, part in ipairs(parts) do
    if part:find(".", 1, true) then return nil, "only the organisation may contain a dot" end
  end
  if #parts > 2 then return nil, "scope has too many parts before the organisation" end
  scope.system, scope.name = parts[1], parts[2]
  scope.text = table.concat({ scope.system or "", scope.name or "", scope.org or "" }, ":")
  return scope
end

-- Make any text safe for a header value and a log line: '%' is encoded
-- first so the result is unambiguous, then everything outside printable
-- ASCII (CR, LF, other controls, non-ASCII) is percent-encoded. The readback
-- echoes words from the sender's cells, and a JSON string can carry an
-- escaped CR LF, so without this a cell could inject a response header.
function M.header_safe(s)
  s = s:gsub("%%", "%%25")
  return (s:gsub("[^\32-\126]", function(c) return string.format("%%%02X", c:byte()) end))
end

local function check_name(v, what)
  if type(v) ~= "string" then return nil, what .. " must be a string" end
  if #v == 0 or #v > M.NAME_MAX or not v:find(M.NAME_PATTERN) then
    return nil, what .. " is not a valid name"
  end
  return v
end

-- Validate a decoded message. Returns msg or nil, err.
function M.validate(value, opts)
  opts = opts or {}
  if json.kind(value) ~= "object" then return nil, "message must be a JSON object" end
  for k in pairs(value) do
    if not ENVELOPE_KEYS[k] then return nil, "unknown top-level key '" .. k .. "'" end
  end
  if value.v ~= 1 or math.type(value.v) ~= "integer" then return nil, "v must be the integer 1" end

  local from, err = check_name(value.from, "from")
  if not from then return nil, err end

  if json.kind(value.to) ~= "array" or value.to.n == 0 then
    return nil, "to must be a non-empty array"
  end
  if value.to.n > M.MAX_RECIPIENTS then return nil, "too many recipients" end
  local to, seen = {}, {}
  for i = 1, value.to.n do
    local name
    name, err = check_name(value.to[i], "to[" .. (i - 1) .. "]")
    if not name then return nil, err end
    if seen[name] then return nil, "recipient '" .. name .. "' listed twice" end
    seen[name] = true
    to[i] = name
  end

  if type(value.kind) ~= "string" or not KINDS[value.kind:lower()] then
    return nil, "kind must be 'chat' or 'send'"
  end
  if type(value.text) ~= "string" then return nil, "text must be a string" end
  if value.why ~= nil and type(value.why) ~= "string" then return nil, "why must be a string" end

  local msg = {
    from = from, to = to, kind = value.kind:lower(),
    cells = {}, readback = {}, tags = {},
    priority = "none", action_asked = false,
    scope = nil, scope_route = "local",
  }

  local c = value.c
  if c ~= nil then
    if json.kind(c) ~= "object" then return nil, "c must be an object" end
    -- Keys are matched WHOLE and compared lower-cased (spec 7.2 rule 1, 4.1).
    local lowered = {}
    for k, v in pairs(c) do
      local lk = k:lower()
      if lowered[lk] then return nil, "c has the key '" .. lk .. "' twice in different case" end
      lowered[lk] = v
    end
    -- c:progress= is the long form of c:p= (spec 7.3); both at once is ambiguous.
    if lowered.progress ~= nil then
      if lowered.p ~= nil then return nil, "c has both 'p' and 'progress'" end
      lowered.p, lowered.progress = lowered.progress, nil
    end
    for k, v in pairs(lowered) do msg.tags[k] = v end

    local p = lowered.p
    if p ~= nil then
      local list
      if type(p) == "string" then
        list = { n = 1, p }
      elseif json.kind(p) == "array" then
        list = p
      else
        return nil, "c.p must be a string or an array of strings"
      end
      if list.n > M.MAX_CELLS then return nil, "too many status cells" end
      local best = nil
      for i = 1, list.n do
        if type(list[i]) ~= "string" then return nil, "c.p entries must be strings" end
        local cell = M.parse_cell(list[i])
        msg.cells[i] = cell
        for _, note in ipairs(cell.notes) do msg.readback[#msg.readback + 1] = note end
        if cell.ok and cell.priority then
          if best == nil or M.PRIORITY_CLASS[cell.priority] < M.PRIORITY_CLASS[best] then
            best = cell.priority
          end
        end
      end
      msg.priority = best or "none"
    end

    local aa = lowered["action-asked"]
    if aa ~= nil and aa ~= true then return nil, "c.action-asked is a flag: true or absent" end
    msg.action_asked = aa == true

    local x = lowered.x
    if x ~= nil then
      if type(x) ~= "string" then return nil, "c.x must be a string" end
      local scope
      scope, err = M.parse_scope(x)
      if not scope then return nil, "c.x: " .. err end
      msg.scope = scope
    end
  end

  -- Routing decision for the scope: a scope matching this system exactly,
  -- or no scope, is local; anything else goes to federation.
  if msg.scope and opts.local_scope then
    local here = assert(M.parse_scope(opts.local_scope))
    if msg.scope.text ~= here.text then msg.scope_route = "federation" end
  end
  msg.priority_class = M.PRIORITY_CLASS[msg.priority]
  return msg
end

return M
