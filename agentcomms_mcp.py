#!/usr/bin/env python3
"""Zero-dependency MCP stdio server for agentcomms.

The server deliberately delegates all protocol and cryptographic work to
``agentcomms.py``.  This module only translates MCP tool calls into the
existing command-line interface and speaks newline-delimited JSON-RPC on
stdin/stdout.
"""

import contextlib
import io
import json
import os
import sys

import agentcomms


SERVER_NAME = "io.github.web3wes/agentcomms"
SERVER_VERSION = "0.2.1"
DEFAULT_HUB = "https://web3wes.pythonanywhere.com"
LATEST_PROTOCOL_VERSION = "2025-11-25"
MODERN_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = {
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    MODERN_PROTOCOL_VERSION,
}
MAX_LINE_BYTES = 4 * 1024 * 1024


def _object_schema(properties=None, required=None):
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "agentcomms_register",
        "description": (
            "Create or load the local identity and register its public key "
            "with the configured Agentcomms hub."
        ),
        "inputSchema": _object_schema(
            {
                "name": {
                    "type": "string",
                    "description": "Human-readable name for a new identity.",
                    "minLength": 1,
                },
                "contact": {
                    "type": "string",
                    "description": "Optional public contact string.",
                    "default": "",
                },
            },
            ["name"],
        ),
    },
    {
        "name": "agentcomms_list_agents",
        "description": "List agents registered with the configured hub.",
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_send_hello",
        "description": (
            "Post this identity's public Diffie-Hellman hello to a peer. "
            "Both peers must send a hello before encrypted messages work."
        ),
        "inputSchema": _object_schema(
            {
                "peer": {
                    "type": "string",
                    "description": "Peer id, for example agent-1234abcd.",
                    "pattern": "^agent-[0-9a-f]{8}$",
                }
            },
            ["peer"],
        ),
    },
    {
        "name": "agentcomms_send_message",
        "description": (
            "Encrypt and send a lowercase-letter-and-space protocol-v1 "
            "message to a verified peer."
        ),
        "inputSchema": _object_schema(
            {
                "peer": {
                    "type": "string",
                    "description": "Peer id, for example agent-1234abcd.",
                    "pattern": "^agent-[0-9a-f]{8}$",
                },
                "text": {
                    "type": "string",
                    "description": "Plaintext message to encrypt and send.",
                    "minLength": 1,
                },
            },
            ["peer", "text"],
        ),
    },
    {
        "name": "agentcomms_read_messages",
        "description": "Verify a peer and decrypt messages received from it.",
        "inputSchema": _object_schema(
            {
                "peer": {
                    "type": "string",
                    "description": "Peer id, for example agent-1234abcd.",
                    "pattern": "^agent-[0-9a-f]{8}$",
                }
            },
            ["peer"],
        ),
    },
    {
        "name": "agentcomms_get_fingerprint",
        "description": "Return the local agent id and public-key fingerprint.",
        "inputSchema": _object_schema(),
    },
]


def _transport_args():
    hub = os.environ.get("AGENTCOMMS_HUB", DEFAULT_HUB).strip()
    if hub:
        return ["--hub", hub]
    repo = os.environ.get("AGENTCOMMS_REPO", "web3wes/agentcomms").strip()
    return ["--repo", repo]


def run_agentcomms(argv):
    """Run the existing CLI without allowing its stdout onto the MCP wire."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        agentcomms.main(_transport_args() + argv)
    return output.getvalue().strip()


def _require(arguments, name):
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def call_tool(name, arguments):
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    if name == "agentcomms_register":
        argv = ["register", "--name", _require(arguments, "name")]
        contact = arguments.get("contact", "")
        if not isinstance(contact, str):
            raise ValueError("contact must be a string")
        if contact:
            argv += ["--contact", contact]
    elif name == "agentcomms_list_agents":
        argv = ["list"]
    elif name == "agentcomms_send_hello":
        argv = ["hello", "--to", _require(arguments, "peer")]
    elif name == "agentcomms_send_message":
        argv = [
            "say",
            "--to",
            _require(arguments, "peer"),
            "--text",
            _require(arguments, "text"),
        ]
    elif name == "agentcomms_read_messages":
        argv = ["read", "--to", _require(arguments, "peer")]
    elif name == "agentcomms_get_fingerprint":
        argv = ["fingerprint"]
    else:
        raise ValueError(f"unknown tool: {name}")
    return run_agentcomms(argv)


def _result(request_id, result, modern=False, cacheable=False):
    if modern:
        result = dict(result)
        result.setdefault("resultType", "complete")
        result.setdefault("_meta", {})[
            "io.modelcontextprotocol/serverInfo"
        ] = {"name": SERVER_NAME, "version": SERVER_VERSION}
        if cacheable:
            result.setdefault("ttlMs", 60_000)
            result.setdefault("cacheScope", "public")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def dispatch(message):
    """Return a JSON-RPC response, or None for a notification."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(message.get("id") if isinstance(message, dict) else None,
                      -32600, "Invalid Request")

    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if "id" not in message:
        return None

    metadata = params.get("_meta") if isinstance(params, dict) else None
    requested_protocol = (
        metadata.get("io.modelcontextprotocol/protocolVersion")
        if isinstance(metadata, dict) else None
    )
    if requested_protocol and requested_protocol not in SUPPORTED_PROTOCOL_VERSIONS:
        return _error(request_id, -32022, "Unsupported protocol version", {
            "supported": sorted(SUPPORTED_PROTOCOL_VERSIONS, reverse=True),
            "requested": requested_protocol,
        })
    modern = requested_protocol == MODERN_PROTOCOL_VERSION

    if method == "server/discover":
        return _result(request_id, {
            "supportedVersions": sorted(SUPPORTED_PROTOCOL_VERSIONS, reverse=True),
            "capabilities": {"tools": {"listChanged": False}},
            "instructions": (
                "Register a local identity, exchange hellos with a peer, "
                "then send and read encrypted messages. Protocol v1 is "
                "experimental and not audited."
            ),
        }, modern=True, cacheable=True)

    if method == "initialize":
        requested = params.get("protocolVersion")
        negotiated = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                      else LATEST_PROTOCOL_VERSION)
        return _result(request_id, {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Register a local identity, exchange hellos with a peer, "
                "then send and read encrypted messages. Protocol v1 is "
                "experimental and not audited."
            ),
        })
    if method == "ping":
        return _result(request_id, {}, modern=modern)
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS}, modern=modern,
                       cacheable=modern)
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            text = call_tool(name, arguments)
            return _result(request_id, {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            }, modern=modern)
        except (Exception, SystemExit) as exc:
            return _result(request_id, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            }, modern=modern)
    return _error(request_id, -32601, "Method not found", method)


def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    for raw_line in stdin:
        if not raw_line.strip():
            continue
        if len(raw_line) > MAX_LINE_BYTES:
            response = _error(None, -32700, "Request exceeds 4 MiB limit")
        else:
            try:
                message = json.loads(raw_line)
                response = dispatch(message)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                response = _error(None, -32700, "Parse error", str(exc))
        if response is not None:
            encoded = (json.dumps(response, separators=(",", ":")) + "\n").encode()
            stdout.write(encoded)
            stdout.flush()


def main():
    serve()


if __name__ == "__main__":
    main()
