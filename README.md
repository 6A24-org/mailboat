# mailboat

An HAProxy Lua module that routes JSON messages on **named fields**, never on free text.

Mailboat is for load balancing and routing the traffic of **AI agents**. When agents send each other work, or call the services they depend on, mailboat lets HAProxy route each message by who sent it, who it is for, how urgent it is, and which system it belongs to. It does that with the balancing, queueing and health checking HAProxy already does well, while refusing anything ambiguous or malformed before it reaches a backend. Made the agents' only route to their backends, it also gives them a narrow, controlled path to just the services you choose.

Mailboat reads a JSON request body with a strict decoder, validates it against a message schema, and exposes the routing fields as HAProxy transaction variables. Your ACLs route on those variables. The body is forwarded to the backend unchanged, byte for byte.

This version ships one schema: **6A24 messages** (the `c:` tags of the [6A24 Protocol 1.0](https://6a24.org/protocol)). The engine is schema-independent, and other schemas can be added beside it.

**Status:** working version. Tested on HAProxy 3.2.25; older versions are not yet tested (see Tests).

## Why a strict decoder

A proxy that reads a body differently from the backend can be steered. Example: a body that names the same key twice. HAProxy's `json_query` converter returns the **first** value. Python's `json` module and many servers keep the **last**. So a request can be routed as one thing and executed as another. Mailboat's decoder **refuses** anything two parsers could read differently, rather than choosing a reading:

- duplicate keys, compared after unescaping (`"a"` and `"a"` are the same key)
- invalid UTF-8, overlong encodings, encoded surrogates, and lone or mis-paired `\u` surrogates
- control characters in strings
- anything RFC 8259 does not allow: comments, trailing commas, NaN and Infinity, leading zeros, a byte-order mark, trailing data

It also caps nesting depth and body size. A body larger than HAProxy's buffer arrives truncated, so mailboat refuses it rather than routing on part of a message.

## Files

| file | what it is |
|---|---|
| `mailboat/mailboat_json.lua` | the strict JSON decoder (no dependencies) |
| `mailboat/mailboat_c.lua` | the 6A24 message schema: validation and routing fields (pure Lua) |
| `mailboat/mailboat.lua` | the HAProxy action, `lua.mailboat` |
| `mailboat/haproxy-mailboat.cfg` | a complete, runnable configuration |
| `mailboat/test/parse_probe.lua` | test-only services used by the test suite |
| `tests/test_mailboat.py` | the test suite |

## The message

```json
{
  "v": 1,
  "from": "sender-name",
  "to": ["recipient-a", "recipient-b"],
  "kind": "chat",
  "text": "the body, carried verbatim and never parsed for routing",
  "why": "optional",
  "c": { "x": "system:name:example.org", "p": ["self-pending-flight=iu"], "action-asked": true }
}
```

- **The envelope** (`v`, `from`, `to`, `kind`, `text`, `why`, `c`) is checked strictly, and an unknown top-level key is refused.
- **The `c` object** follows the 6A24 Protocol's own reading rules:
  - Unknown tag keys are kept, not refused.
  - Keys are matched whole and case-insensitively.
  - A status value that is one edit from exactly one valid value is **read as that value**, and the reading is reported back (`status 'pnding' read as 'pending'`).
  - A value close to two values, or to none, is kept and reported, and never refused.
  - Retired values are mapped on input.
- **Scope** (`c.x`): a message scoped exactly to this system routes locally. Any other scope routes to federation, which this version refuses with 403 until it is configured deliberately.
- **Priority** comes from the status cells (`=iu`, `=i`, `=u`, `=x`, or box numbers 1 to 4) and becomes HAProxy's request priority class. Priority orders the queue; it never bypasses a check.

## Carrying other JSON protocols: never strip, slice

The envelope can carry any JSON agent protocol: put the foreign message (an agent-to-agent message, an MCP request) inside it, route on the envelope, and forward the inner message.

**Do not do this by deleting the mailboat keys and re-serialising the body.** Re-encoding changes bytes: key order, whitespace, number formatting, escape choices. The backend would then receive a message the sender never sent, and two parsers would read it differently again, which is the very problem the strict decoder exists to close. Mailboat's guarantee is that **the bytes the sender wrote are the bytes the backend receives**.

The safe way, planned and not yet built: carry the foreign message as **one nested value** (for example `"payload": {...}`). The decoder records where that value starts and ends in the original body, and mailboat forwards **exactly that slice**, untouched. The other option is to carry the envelope in headers, with the untouched inner message as the body.

## Replies carry the proxy's own status

Every reply to a message carries a `6a24-status` header, written from the proxy's side:

| outcome | HTTP | `6a24-status` |
|---|---|---|
| passed to the backend | the backend's | `c:p=self-done-flight` |
| unreadable or invalid | 400 | `c:unfamiliar c:p=other-pending-out` (fix it and send again) |
| too large | 413 | `c:unfamiliar c:p=other-pending-out` |
| scope not routed here | 403 | `c:p=self-cancel-flight c:cause=operator` |

Refusals come with a small JSON body: `{"outcome":"refused","reason":"...","c":"..."}`. When a value was read generously, a `6a24-readback` header says what was understood.

## Running it

HAProxy with Lua. Tested on **3.2.25 with Lua 5.4.8** only; earlier versions are untested. It runs as an ordinary user process:

```sh
MAILBOAT_DIR=/path/to/mailboat \
MAILBOAT_SOCK=/run/user/$UID/mailboat.sock \
MAILBOAT_BACKEND=unix@/run/user/$UID/backend.sock \
MAILBOAT_LOCAL_SCOPE=system:name:example.org \
haproxy -f /path/to/mailboat/haproxy-mailboat.cfg
```

**Exposure is narrow by default.** The configuration binds a unix socket with mode 0600, and refuses any request carrying an `Origin` header, so a web page cannot reach it. `from` is self-asserted, so **a non-local listener needs sender authentication first**. That is a design change, not a configuration change.

**The backend owns health and stop.** Mailboat health-checks `GET /health` on the backend. While the backend answers anything but 200, mailboat refuses every message with 503 and forwards nothing. This is how a backend closes the front door.

## Tests

```sh
python3 tests/test_mailboat.py        # needs only Python 3 and HAProxy on PATH
MAILBOAT_HAPROXY=/path/to/haproxy python3 tests/test_mailboat.py
```

There are 175 checks, run **inside HAProxy**:
- the decoder against Python's `json`, including the inputs Python accepts and mailboat must refuse;
- the schema;
- end to end against a recording backend. These check that the body arrives byte for byte, that sender-supplied routing headers are stripped, that a CR LF in a value cannot inject a header, that refusals never reach the backend, and that an unhealthy backend closes the door.

Every check family was mutation-tested: the code was broken deliberately and the suite had to catch it.

**Known gap:** the configuration's last-resort rule (`deny 500` for a message the action did not accept) has no input that reaches it, so no test exercises it. The request priority class is set but its effect on queueing is not measured.

**Observed:** HAProxy 3.2 itself percent-encodes control characters when a sample is written into a header. Mailboat encodes them as well, for front ends that use its variables some other way.

## Licence

GNU General Public License, version 2 or (at your option) any later version. See `LICENSE`.

Copyright (C) 2026 6A24 Technologies. Written by Andromeda Turnbull and Cairn.
