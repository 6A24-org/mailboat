#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 6A24 Technologies
"""Tests for mailboat: the strict JSON decoder, the message schema, and end to end.

Dependency-free: Python 3 and HAProxy only. Everything is exercised INSIDE
HAProxy itself: the test starts a private
HAProxy on a unix socket in a temporary directory, loads a test-only Lua
service (mailboat/test/parse_probe.lua) that decodes each POSTed
body, and compares the result with Python's json module.

Two kinds of vector:
  * VALID   -- must decode, and must agree with Python's reading exactly.
  * INVALID -- must be REFUSED, with the reason given. Several of these are
               bodies Python ACCEPTS (duplicate keys, lone surrogates,
               1e400): those are the parser differentials mailboat exists
               to close, so agreeing with Python there would be the bug.

Positive control: before the vectors run, the test checks that the probe
refuses a plainly broken body AND accepts a plainly good one, so an always-OK
or always-ERR probe cannot pass.

Run: python3 tests/test_mailboat.py
HAProxy is found on PATH; override with MAILBOAT_HAPROXY=/path/to/haproxy.
"""
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
LB = pathlib.Path(os.environ.get("MAILBOAT_LB", HERE.parent / "mailboat"))  # override for mutation tests
HAPROXY = os.environ.get(
    "MAILBOAT_HAPROXY",
    shutil.which("haproxy") or "haproxy",
)

FAILURES = []


def check(label, ok, detail=""):
    if not ok:
        FAILURES.append("%s\n    %s" % (label, detail))


# --- canonical form, mirrored from parse_probe.lua ---------------------------------
def canon(v):
    if v is None:
        return "z"
    if v is True:
        return "t"
    if v is False:
        return "f"
    if isinstance(v, (int, float)):
        return "n" + format(float(v), ".17g")
    if isinstance(v, str):
        return "s" + v.encode("utf-8").hex() + ";"
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-8"))
        return "{" + ",".join(canon(k) + ":" + canon(v[k]) for k in keys) + "}"
    raise TypeError(v)


# --- a private HAProxy --------------------------------------------------------------
CONFIG = """\
global
  tune.lua.bool-sample-conversion normal
  lua-prepend-path {lb}/?.lua
  lua-load {lb}/test/parse_probe.lua
defaults
  mode http
  timeout client 5s
  timeout server 5s
  timeout connect 5s
frontend fe
  bind unix@{sock} mode 600
  http-request use-service lua.c_probe if {{ path /c }}
  http-request use-service lua.parse_probe
"""


def post(sock_path, body, headers=None, path="/"):
    hdrs = {"Host": "probe", "Content-Length": str(len(body)), "Connection": "close"}
    hdrs.update(headers or {})
    req = ("POST %s HTTP/1.1\r\n" % path).encode() + b"".join(
        ("%s: %s\r\n" % kv).encode() for kv in hdrs.items()
    ) + b"\r\n" + body
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(req)
    chunks = []
    while True:
        c = s.recv(65536)
        if not c:
            break
        chunks.append(c)
    s.close()
    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0]
    if b" 200 " not in status + b" ":
        return "HTTP " + status.decode("latin-1")
    return payload.decode("utf-8")


# --- vectors ------------------------------------------------------------------------
VALID = [
    b'{}', b'[]', b'0', b'-0', b'-0.0', b'1.5e3', b'1E-2', b'true', b'false', b'null',
    b'"plain"', b'"\\u00e9"', b'"\\ud83d\\ude00"', '"café \U0001F600"'.encode(),
    b'"\\"\\\\\\/\\b\\f\\n\\r\\t"', b' \t\r\n{"a" : [1, 2.5, "x", null, true]} \n',
    b'{"v":1,"from":"alice","to":["bob"],"kind":"chat",'
    b'"text":"the body","c":{"x":"mesh:node1:example.org","p":["self-done-read"]}}',
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}',
    b'[[[[[[[[[[1]]]]]]]]]]',
    b'{"a":{"a":{"a":1}}}',            # the same key at different levels is fine
    b'{"a":1,"A":2}',                    # keys are case-sensitive
    b'9007199254740993', b'123456789012345678901234567890',
    '"ࠀ￿"'.encode(),           # 3-byte boundaries
    '"\U00010000\U0010ffff"'.encode(),   # 4-byte boundaries
]

# (body, reason substring). Comments say where Python's json would accept.
INVALID = [
    (b'{"method":"tools/call","method":"initialize"}', "duplicate key"),     # Python: last wins
    (b'{"m":1,"\\u006d":2}', "duplicate key"),                                # escaped duplicate
    (b'{"a":{"b":1,"b":2}}', "duplicate key"),                                # nested
    (b'[{"x":1,"x":1}]', "duplicate key"),                                    # identical values too
    (b'"\\ud800"', "lone high surrogate"),                                    # Python accepts
    (b'"\\udc00"', "lone low surrogate"),                                     # Python accepts
    (b'"\\ud800\\u0041"', "not followed by low"),
    (b'"\xed\xa0\x80"', "invalid UTF-8"),                                     # encoded surrogate
    (b'"\xc0\xaf"', "invalid UTF-8"),                                         # overlong
    (b'"\xe0\x80\xaf"', "invalid UTF-8"),                                     # overlong
    (b'"\xf4\x90\x80\x80"', "invalid UTF-8"),                                 # > U+10FFFF
    (b'"\xff"', "invalid UTF-8"),
    (b'"\xe2\x82"', "invalid UTF-8"),                                         # truncated
    (b'"a\x01b"', "control character"),
    (b'"tab\there"', "control character"),
    (b'"\\x41"', "bad escape"), (b'"\\u12G4"', "bad \\u escape"),
    (b'"open', "unterminated string"),
    (b'1e400', "out of range"),                                               # Python: inf
    (b'NaN', "unexpected character"), (b'Infinity', "unexpected character"),
    (b'01', "leading zero"), (b'-', "bad number"), (b'1.', "bad fraction"),
    (b'1e', "bad exponent"), (b'.5', "unexpected character"), (b'+1', "unexpected character"),
    (b'[1,]', "unexpected character"), (b'{"a":1,}', "expected string key"),
    (b"{'a':1}", "expected string key"), (b'{a:1}', "expected string key"),
    (b'{"a" 1}', "expected ':'"), (b'[1 2]', "expected ',' or ']'"),
    (b'{"a":1 "b":2}', "expected ',' or '}'"),
    (b'{"a":1}/*c*/', "trailing data"), (b'{} {}', "trailing data"), (b'tru', "unexpected character"),
    (b'truex', "trailing data"),
    (b'\xef\xbb\xbf{}', "unexpected character"),                              # BOM
    (b'\x0c{}', "unexpected character"),                                      # form feed is not JSON whitespace
    (b'', "unexpected end of input"), (b'   ', "unexpected end of input"),
    (b'[' * 40 + b']' * 40, "too deep"),
    (b'{"a":' * 40 + b'1' + b'}' * 40, "too deep"),
    (b'"' + b'a' * 70000 + b'"', "body too large"),
]


# --- the c: envelope (mailboat_c.lua) -----------------------------------------------
def msg(**over):
    m = {"v": 1, "from": "alice", "to": ["bob"], "kind": "chat", "text": "hello"}
    for k, v in over.items():
        if v is DROP:
            m.pop(k, None)
        else:
            m[k] = v
    return json.dumps(m).encode()


DROP = object()
BASE = "OK from=alice to=bob kind=chat "

# (body, expected line, or prefix ending in "*")
C_VECTORS = [
    # the README's example message
    (msg(**{"from": "alice", "to": ["bob"],
            "c": {"x": "mesh:node1:example.org", "p": ["self-done-read", "self-pending-flight=iu"],
                  "action-asked": True}}),
     BASE + "prio=iu class=-3 aa=1 route=local scope=mesh:node1:example.org "
            "cells=self-done-read|self-pending-flight=iu rb="),
    # no c at all: local, no priority
    (msg(), BASE + "prio=none class=0 aa=0 route=local scope=- cells= rb="),
    # spec section 11 cells
    (msg(c={"p": ["self-working-flight=i", "other-pending-flight"]}),
     BASE + "prio=i class=-2 aa=0 route=local scope=- cells=self-working-flight=i|other-pending-flight rb="),
    # p as a single string; priority letters in either order; box numbers
    (msg(c={"p": "self-working-flight=ui"}), BASE + "prio=iu class=-3 *"),
    (msg(c={"p": ["self-done-out=4", "self-done-read=3"]}), BASE + "prio=u class=-1 *"),
    # the long key, and case-insensitive keys and registered values
    (msg(c={"progress": "Self-Done-Read"}), BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-done-read rb="),
    (msg(c={"P": "self-done-read"}, kind="CHAT"), BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-done-read rb="),
    # a question binds to the cell
    (msg(c={"p": "other-done-out?"}), BASE + "prio=none class=0 aa=0 route=local scope=- cells=other-done-out? rb="),
    # values outside the lists (here the old int/wait/comp forms) are kept and reported, never refused
    (msg(c={"p": "int-wait-comp"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=!int-wait-comp "
            "rb=party 'int' is not a known value;status 'wait' is not a known value;action 'comp' is not a known value"),
    # READ GENEROUSLY: one edit from exactly one value, reported in the readback
    (msg(c={"p": "self-pnding-flight"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-pending-flight rb=status 'pnding' read as 'pending'"),
    (msg(c={"p": "slef-done-read"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-done-read rb=party 'slef' read as 'self'"),
    (msg(c={"p": "self-done-fligt"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-done-flight rb=action 'fligt' read as 'flight'"),
    # ...but never refused: an unreadable cell is kept and reported
    (msg(c={"p": "self-banana-read"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=!self-banana-read rb=status 'banana' is not a known value"),
    (msg(c={"p": "just-two"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=!just-two rb=cell 'just-two' is not party-status-action"),
    # the readback is header-safe: '%' first, then CR LF and other controls
    (msg(c={"p": "self-x\r\nX-Evil: 1-read"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=!self-x\r\nX-Evil: 1-read "
            "rb=cell 'self-x%0D%0AX-Evil: 1-read' is not party-status-action"),
    (msg(c={"p": "self-100%-read"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=!self-100%-read rb=status '100%25' is not a known value"),
    # an unreadable cell contributes no priority, even with a valid suffix
    (msg(c={"p": ["self-banana-read=iu", "self-done-read=x"]}), BASE + "prio=x class=1 *"),
    (msg(c={"p": "self-done-read=zz"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells=self-done-read rb=priority '=zz' is not known; ignored"),
    # unknown c keys are kept, never refused (spec 7.2 rule 6); keys match WHOLE
    (msg(c={"place": "the-garden-room", "pending": "x", "pp": "self-done-read"}),
     BASE + "prio=none class=0 aa=0 route=local scope=- cells= rb="),
    # scope: exact match is local; anything else is federation
    (msg(c={"x": "MESH;node1;Example.ORG"}), BASE + "prio=none class=0 aa=0 route=local scope=mesh:node1:example.org *"),
    (msg(c={"x": "mesh:node2:example.org"}), BASE + "prio=none class=0 aa=0 route=federation scope=mesh:node2:example.org *"),
    (msg(c={"x": "mesh"}), BASE + "prio=none class=0 aa=0 route=federation scope=mesh:: *"),
    (msg(c={"x": "example.org"}), BASE + "prio=none class=0 aa=0 route=federation scope=::example.org *"),
    # multicast and send
    (msg(to=["mallory", "carol"], kind="send"),
     "OK from=alice to=mallory,carol kind=send prio=none *"),
    # REFUSED: the envelope is mailboat's own and is strict
    (msg(extra=1), "ERR unknown top-level key 'extra'"),
    (msg(v=2), "ERR v must be the integer 1"),
    (b'{"v":1.0,"from":"a","to":["b"],"kind":"chat","text":""}', "ERR v must be the integer 1"),
    (msg(v=DROP), "ERR v must be the integer 1"),
    (msg(**{"from": "bad name"}), "ERR from is not a valid name"),
    (msg(**{"from": "-leading"}), "ERR from is not a valid name"),
    (msg(**{"from": "x" * 65}), "ERR from is not a valid name"),
    (msg(to=[]), "ERR to must be a non-empty array"),
    (msg(to="bob"), "ERR to must be a non-empty array"),
    (msg(to=["a,b"]), "ERR to[0] is not a valid name"),
    (msg(to=["A", "A"]), "ERR recipient 'A' listed twice"),
    (msg(to=["d%d" % i for i in range(17)]), "ERR too many recipients"),
    (msg(kind="wake"), "ERR kind must be 'chat' or 'send'"),
    (msg(text=DROP), "ERR text must be a string"),
    (msg(why=3), "ERR why must be a string"),
    (msg(c=[]), "ERR c must be an object"),
    (msg(c={"p": 3}), "ERR c.p must be a string or an array of strings"),
    (msg(c={"p": ["self-done-read", None]}), "ERR c.p entries must be strings"),
    (msg(c={"p": ["self-done-read"] * 17}), "ERR too many status cells"),
    (msg(c={"p": "self-done-read", "progress": "self-done-read"}), "ERR c has both 'p' and 'progress'"),
    (msg(c={"p": "self-done-read", "P": "self-done-read"}), "ERR c has the key 'p' twice in different case"),
    (msg(c={"action-asked": "yes"}), "ERR c.action-asked is a flag: true or absent"),
    (msg(c={"x": "mesh::example.org"}), "ERR c.x: scope has an empty part"),
    (msg(c={"x": "mesh:no.de:example.org"}), "ERR c.x: only the organisation may contain a dot"),
    (msg(c={"x": "a:b:c:d"}), "ERR c.x: scope has more than three parts"),
    (msg(c={"x": "a:b:c"}), "ERR c.x: scope has too many parts before the organisation"),
    # not an object at all: a JSON-RPC style batch, or a bare value
    (b'[{"v":1}]', "ERR message must be a JSON object"),
    (b'"hello"', "ERR message must be a JSON object"),
    # the JSON layer still refuses first
    (b'{"v":1,"v":1}', "ERR json offset 7: duplicate key"),
]


def run_c(sock):
    for body, want in C_VECTORS:
        got = post(sock, body, path="/c")
        if want.endswith("*"):
            ok = got.startswith(want[:-1])
        else:
            ok = got == want
        check("c %r" % body[:70], ok, "got  %r\n    want %r" % (got, want))


# --- end to end: the real config, a recording backend -------------------------------
import http.server
import socketserver
import threading

RECEIVED = []


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _answer(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", "echo")
        self.end_headers()
        self.wfile.write(body)

    stop = False   # set True to act like a backend that wants traffic stopped

    def do_GET(self):
        if self.path == "/health":
            if Echo.stop:
                return self._answer(503, b'{"status":"stop"}')
            return self._answer(200, b'{"status":"ok"}')
        self._answer(404, b"{}")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        RECEIVED.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        self._answer(200, b'{"outcome":"delivered"}')


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def request(sock_path, method, path, body=b"", headers=None):
    """Raw HTTP/1.1 over a unix socket. Returns (status, headers, body)."""
    hdrs = {"Host": "mailboat", "Content-Length": str(len(body)), "Connection": "close",
            "Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode() + b"".join(
        ("%s: %s\r\n" % kv).encode() for kv in hdrs.items()) + b"\r\n" + body
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(req)
    chunks = []
    while True:
        c = s.recv(65536)
        if not c:
            break
        chunks.append(c)
    s.close()
    head, _, payload = b"".join(chunks).partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    got = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        got.setdefault(k.strip().lower(), []).append(v.strip())
    return status, got, payload


def wait_for(cond, seconds=8.0):
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


E2E_COUNT = 0


def e2e_check(label, ok, detail=""):
    global E2E_COUNT
    E2E_COUNT += 1
    check("e2e: " + label, ok, detail)


def run_e2e(tmp):
    front = os.path.join(tmp, "mailboat.sock")
    back = os.path.join(tmp, "backend.sock")
    server = UnixServer(back, Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, MAILBOAT_DIR=str(LB), MAILBOAT_SOCK=front,
               MAILBOAT_BACKEND="unix@" + back, MAILBOAT_LOCAL_SCOPE="mesh:node1:example.org")
    proc = subprocess.Popen([HAPROXY, "-db", "-f", str(LB / "haproxy-mailboat.cfg")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        if not wait_for(lambda: os.path.exists(front) or proc.poll() is not None):
            e2e_check("haproxy starts", False, "socket never appeared")
            return
        if proc.poll() is not None:
            e2e_check("haproxy starts", False, proc.stdout.read().decode(errors="replace"))
            return
        e2e_check("front socket is 0600", (os.stat(front).st_mode & 0o777) == 0o600,
                  oct(os.stat(front).st_mode))
        # Wait for the first health check to mark the backend up.
        wait_for(lambda: request(front, "POST", "/v1/msg", msg())[0] == 200)
        RECEIVED.clear()

        # 1. A valid message reaches the backend BYTE FOR BYTE, with the routing
        #    headers set by mailboat, never by the sender.
        exact = ('{ "v":1, "from":"alice", "to":["bob","carol"],\n'
                 '  "kind":"send", "text":"caf\u00e9 \\u0041 > quoted\\n<<<END>>>",\n'
                 '  "c":{"p":["self-pnding-flight=iu"], "x":"mesh:node1:example.org"} }').encode("utf-8")
        st, hd, body = request(front, "POST", "/v1/msg", exact,
                               {"X-Mailboat-From": "mallory", "X-Mailboat-Priority": "iu"})
        e2e_check("valid: 200 from the backend", st == 200 and body == b'{"outcome":"delivered"}',
                  "%r %r" % (st, body))
        e2e_check("valid: proxy cell on the reply", hd.get("6a24-status") == ["c:p=self-done-flight"],
                  repr(hd.get("6a24-status")))
        e2e_check("valid: readback on the reply",
                  hd.get("6a24-readback") == ["status 'pnding' read as 'pending'"], repr(hd.get("6a24-readback")))
        e2e_check("valid: backend reached once", len(RECEIVED) == 1, repr(len(RECEIVED)))
        if RECEIVED:
            path, bh, bbody = RECEIVED[0]
            e2e_check("valid: body forwarded byte for byte", bbody == exact, repr(bbody[:80]))
            e2e_check("valid: from set by mailboat, not the sender",
                      bh.get("x-mailboat-from") == "alice", repr(bh.get("x-mailboat-from")))
            e2e_check("valid: to", bh.get("x-mailboat-to") == "bob,carol", repr(bh.get("x-mailboat-to")))
            e2e_check("valid: kind", bh.get("x-mailboat-kind") == "send", repr(bh.get("x-mailboat-kind")))
            e2e_check("valid: priority", bh.get("x-mailboat-priority") == "iu", repr(bh.get("x-mailboat-priority")))

        # 2. Refusals answer from the proxy and never reach the backend.
        def refused(label, body, want_status, want_cell, reason_part, headers=None, path="/v1/msg", method="POST"):
            RECEIVED.clear()
            st, hd, rbody = request(front, method, path, body, headers)
            e2e_check(label + ": status %d" % want_status, st == want_status, "got %r %r" % (st, rbody[:120]))
            e2e_check(label + ": backend not reached", not RECEIVED, repr(RECEIVED[:1]))
            if want_cell is not None:
                e2e_check(label + ": proxy cell", hd.get("6a24-status") == [want_cell], repr(hd.get("6a24-status")))
                try:
                    reply = json.loads(rbody)
                except ValueError:
                    reply = {}
                e2e_check(label + ": JSON reply", reply.get("outcome") == "refused" and reason_part in reply.get("reason", ""),
                          repr(rbody[:160]))

        unread = "c:unfamiliar c:p=other-pending-out"
        refused("broken JSON", b'{"v":1,', 400, unread, "json")
        refused("duplicate key (parser differential)",
                b'{"v":1,"from":"a","to":["b"],"kind":"chat","text":"","text":"x"}', 400, unread, "duplicate key")
        refused("bad envelope", msg(kind="wake"), 400, unread, "kind")
        refused("federation", msg(c={"x": "mesh:node2:example.org"}), 403,
                "c:p=self-cancel-flight c:cause=operator", "federation route not configured")
        refused("body over the buffer", msg(text="a" * 20000), 413, unread, "too large")
        refused("browser Origin", msg(), 403, None, "", headers={"Origin": "https://example.org"})
        refused("GET on the message path", b"", 405, None, "", method="GET")
        refused("unknown path", msg(), 404, None, "", path="/v1/other")

        # 3. A cell carrying CR LF cannot inject a header, in either direction.
        RECEIVED.clear()
        st, hd, _ = request(front, "POST", "/v1/msg", msg(c={"p": "self-x\r\nX-Evil: 1-read"}))
        e2e_check("CRLF cell: still delivered", st == 200, repr(st))
        e2e_check("CRLF cell: no injected reply header", "x-evil" not in hd, repr(sorted(hd)))
        rb = (hd.get("6a24-readback") or [""])[0]
        e2e_check("CRLF cell: readback percent-encoded", "%0D%0A" in rb and "\r" not in rb, repr(rb))
        if RECEIVED:
            e2e_check("CRLF cell: no injected backend header", "x-evil" not in RECEIVED[0][1], repr(sorted(RECEIVED[0][1])))

        # 3b. A sender cannot plant the readback header mailboat sets only sometimes.
        RECEIVED.clear()
        st, hd, _ = request(front, "POST", "/v1/msg", msg(), {"X-Mailboat-Readback": "planted"})
        e2e_check("planted readback: delivered", st == 200, repr(st))
        if RECEIVED:
            e2e_check("planted readback: stripped", "x-mailboat-readback" not in RECEIVED[0][1],
                      repr(RECEIVED[0][1].get("x-mailboat-readback")))

        # 4. Health passes through to the backend.
        st, hd, body = request(front, "GET", "/health")
        e2e_check("health passes through", st == 200 and body == b'{"status":"ok"}', "%r %r" % (st, body))

        # 4b. Stop: the backend is alive but reports unhealthy. Mailboat must
        #     close its front door and stop forwarding.
        Echo.stop = True
        RECEIVED.clear()
        closed = wait_for(lambda: request(front, "POST", "/v1/msg", msg())[0] == 503, 10)
        e2e_check("stop via health: 503", closed)
        RECEIVED.clear()
        st, _, _ = request(front, "POST", "/v1/msg", msg())
        e2e_check("stop via health: backend not reached", st == 503 and not RECEIVED, "%r %r" % (st, len(RECEIVED)))
        Echo.stop = False
        e2e_check("stop lifted: door reopens",
                  wait_for(lambda: request(front, "POST", "/v1/msg", msg())[0] == 200, 10))

        # 5. Backend down: health checks fail and mailboat closes its door (fail closed).
        server.shutdown()
        server.server_close()
        os.unlink(back)
        closed = wait_for(lambda: request(front, "POST", "/v1/msg", msg())[0] == 503, 10)
        e2e_check("backend down: 503 (fail closed)", closed)
    finally:
        proc.terminate()
        proc.wait(5)
        try:
            server.server_close()
        except Exception:
            pass


def main():
    if not os.access(HAPROXY, os.X_OK):
        print("SKIP: no HAProxy at %s (set MAILBOAT_HAPROXY)" % HAPROXY)
        return 2
    with tempfile.TemporaryDirectory(prefix="mailboat-test-") as tmp:
        sock = os.path.join(tmp, "probe.sock")
        cfg = os.path.join(tmp, "probe.cfg")
        with open(cfg, "w") as f:
            f.write(CONFIG.format(lb=LB, sock=sock))
        proc = subprocess.Popen([HAPROXY, "-db", "-f", cfg],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for _ in range(50):
                if os.path.exists(sock):
                    break
                if proc.poll() is not None:
                    print(proc.stdout.read().decode(errors="replace"))
                    print("FAIL: HAProxy exited at startup")
                    return 1
                time.sleep(0.1)
            else:
                print("FAIL: HAProxy socket never appeared")
                return 1
            run(sock)
            run_c(sock)
        finally:
            proc.terminate()
            proc.wait(5)
        run_e2e(tmp)

    total = len(VALID) + len(INVALID) + len(C_VECTORS) + 4 + E2E_COUNT
    if FAILURES:
        print("FAILED %d of %d checks:" % (len(FAILURES), total))
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("ok: %d checks (%d valid, %d invalid, %d envelope, 4 controls, %d end-to-end)"
          % (total, len(VALID), len(INVALID), len(C_VECTORS), E2E_COUNT))
    return 0


def run(sock):
    # Positive controls: the probe must be able to say both OK and ERR.
    good = post(sock, b'{"a":1}')
    check("control: good body accepted", good == "OK {s61;:n1}", repr(good))
    bad = post(sock, b'{"a":')
    check("control: broken body refused", bad.startswith("ERR "), repr(bad))
    # The depth cap is a real parameter, not a constant that happens to pass.
    shallow = post(sock, b'[[1]]', {"X-Max-Depth": "1"})
    check("control: depth cap honoured", "too deep" in shallow, repr(shallow))
    deep_ok = post(sock, b'[[1]]', {"X-Max-Depth": "2"})
    check("control: depth cap not off by one", deep_ok.startswith("OK "), repr(deep_ok))

    for body in VALID:
        want = "OK " + canon(json.loads(body))
        got = post(sock, body)
        check("valid %r" % body[:60], got == want, "got %r want %r" % (got[:120], want[:120]))

    for body, reason in INVALID:
        got = post(sock, body)
        check("invalid %r" % body[:60], got.startswith("ERR ") and reason in got,
              "got %r, want ERR containing %r" % (got[:120], reason))


if __name__ == "__main__":
    sys.exit(main())
