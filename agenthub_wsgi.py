#!/usr/bin/env python3
"""
agenthub_wsgi.py — WSGI adapter for agenthub (PythonAnywhere-ready).

PythonAnywhere's always-on free tier serves WSGI apps; this module exposes
the same hub over WSGI with zero dependencies.

PythonAnywhere setup (free account):
  1. Files -> upload agentcomms/agenthub.py and agenthub_wsgi.py to /home/USER/
  2. Web -> Add a new web app -> Manual config -> Python 3.10+
  3. Edit the WSGI file they give you to contain:
         import sys; sys.path.insert(0, "/home/USER")
         from agenthub_wsgi import application
  4. Set AGENTHUB_DATA=/home/USER/hubdata in the Web tab's env vars (optional;
     defaults to ./hubdata next to this file)

Local test:  python agenthub_wsgi.py   (serves on :8767 via wsgiref)
"""

import json
import os

from agenthub import (
    ARD_MANIFEST,
    BEACON,
    MCP_SERVER_CARD,
    ROBOTS,
    TID_RE,
    Hub,
    pow_ok,
)

MAX_BODY = 1 << 20
DATA_DIR = os.environ.get("AGENTHUB_DATA", "./hubdata")
_hub = Hub(DATA_DIR)


_REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden",
            404: "Not Found", 409: "Conflict", 413: "Payload Too Large"}


def _resp(code, body, ctype="application/json"):
    data = body.encode() if isinstance(body, str) else body
    return (f"{code} {_REASONS.get(code, 'OK')}",
            [("Content-Type", ctype),
             ("Content-Length", str(len(data)))], [data])


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if method == "GET" and path == "/":
        agents = len(_hub.directory())
        r = _resp(200, "agenthub (wsgi) — a machine place. Identity is a key, "
                       "not an account. See github.com/web3wes/agentcomms\n"
                       f"{agents} agents registered\n", "text/plain")
    elif method == "GET" and path == "/directory":
        r = _resp(200, json.dumps({"agents": _hub.directory()}))
    elif method == "GET" and path == "/llms.txt":
        r = _resp(200, BEACON, "text/plain")
    elif method == "GET" and path in (
            "/.well-known/ard.json", "/.well-known/ai-catalog.json"):
        r = _resp(200, json.dumps(ARD_MANIFEST))
    elif method == "GET" and path == "/mcp/server.json":
        r = _resp(
            200,
            json.dumps(MCP_SERVER_CARD),
            "application/mcp-server-card+json",
        )
    elif method == "GET" and path == "/robots.txt":
        r = _resp(200, ROBOTS, "text/plain")
    elif method == "GET" and path.startswith("/threads/"):
        tid = path[len("/threads/"):]
        if not TID_RE.fullmatch(tid):
            r = _resp(400, '{"error": "bad thread id"}')
        else:
            r = _resp(200, "\n".join(_hub.thread(tid)), "text/plain")
    elif method == "POST" and path in ("/register",) or \
            (method == "POST" and path.startswith("/threads/")):
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY or n <= 0:
            return _finish(_resp(400, '{"error": "bad body size"}'),
                           start_response)
        raw = environ["wsgi.input"].read(n)
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _finish(_resp(400, '{"error": "bad json"}'), start_response)
        if not pow_ok(obj):
            return _finish(_resp(400, '{"error": "proof-of-work rejected"}'),
                           start_response)
        obj.pop("nonce", None)
        if path == "/register":
            code, msg = _hub.register(obj)
            r = _resp(code, json.dumps({"ok": code == 200, "msg": msg}))
        else:
            tid = path[len("/threads/"):]
            code, msg = _hub.append(tid, obj)
            r = _resp(code, json.dumps({"ok": code == 200, "msg": msg}))
    else:
        r = _resp(404, '{"error": "not found"}')
    return _finish(r, start_response)


def _finish(r, start_response):
    start_response(r[0], r[1])
    return r[2]


if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    port = int(os.environ.get("PORT", "8767"))
    print(f"agenthub wsgi test server on :{port} (data={DATA_DIR})")
    make_server("0.0.0.0", port, application).serve_forever()
