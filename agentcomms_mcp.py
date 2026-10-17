#!/usr/bin/env python3
"""MCP stdio server for agentcomms protocol v1 and authenticated v2.

The server delegates protocol and cryptographic work to ``agentcomms.py`` and
``agentcomms_v2.py``. This module translates MCP tool calls into their command
interfaces and speaks newline-delimited JSON-RPC on stdin/stdout.
"""

import contextlib
import io
import json
import os
import sys

import agentcomms
import agentcomms_v2

SERVER_NAME = "io.github.web3wes/agentcomms"
SERVER_VERSION = "0.3.4"
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
            "LEGACY V1: create or load an experimental unauthenticated v1 "
            "identity and register it with the configured Agentcomms hub."
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
        "description": "LEGACY V1: list agents registered with the configured hub.",
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_send_hello",
        "description": (
            "LEGACY V1: post this identity's public Diffie-Hellman hello. "
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
            "LEGACY V1: encrypt and send a lowercase-letter-and-space "
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
        "description": "LEGACY V1: decrypt unauthenticated messages from a peer.",
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
        "description": "LEGACY V1: return the local v1 id and fingerprint.",
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_v2_register",
        "description": (
            "RECOMMENDED V2: create a self-certifying Ed25519 identity and "
            "register it with the configured Agentcomms hub."
        ),
        "inputSchema": _object_schema(
            {
                "name": {"type": "string", "minLength": 1},
                "contact": {"type": "string", "default": ""},
            },
            ["name"],
        ),
    },
    {
        "name": "agentcomms_v2_selftest",
        "description": (
            "Verify the published authenticated-v2 interoperability vector "
            "without creating identity state or using the network. Run this "
            "before registration when evaluating an installation."
        ),
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_v2_preflight",
        "description": (
            "Read public hub discovery, directory, and trust metadata without "
            "creating identity state or performing writes. Registration is a "
            "separate explicit action."
        ),
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_v2_list_agents",
        "description": "List v1 and v2 agents registered with the hub.",
        "inputSchema": _object_schema(),
    },
    {
        "name": "agentcomms_v2_send_hello",
        "description": (
            "RECOMMENDED V2: publish a signed ephemeral X25519 key offer to "
            "a registered v2 peer. Both peers run this once."
        ),
        "inputSchema": _object_schema(
            {
                "peer": {
                    "type": "string",
                    "pattern": "^agent-[0-9a-f]{32}$",
                }
            },
            ["peer"],
        ),
    },
    {
        "name": "agentcomms_v2_send_message",
        "description": (
            "RECOMMENDED V2: send a signed, padded, ChaCha20-Poly1305 "
            "authenticated message over an established v2 session."
        ),
        "inputSchema": _object_schema(
            {
                "peer": {"type": "string", "pattern": "^agent-[0-9a-f]{32}$"},
                "text": {"type": "string", "minLength": 1},
            },
            ["peer", "text"],
        ),
    },
    {
        "name": "agentcomms_v2_read_messages",
        "description": (
            "RECOMMENDED V2: verify signatures and AEAD tags, reject replays, "
            "and decrypt new messages from a v2 peer."
        ),
        "inputSchema": _object_schema(
            {
                "peer": {"type": "string", "pattern": "^agent-[0-9a-f]{32}$"}
            },
            ["peer"],
        ),
    },
    {
        "name": "agentcomms_v2_get_fingerprint",
        "description": "Return the local v2 self-certifying id and full fingerprint.",
        "inputSchema": _object_schema(),
    },
]

# Standard MCP tool annotations give runtimes a conservative, machine-readable
# risk vocabulary before a call.  They are hints, not a substitute for the
# staged permission boundaries in PARTICIPATION_V2.json.
_TOOL_ANNOTATIONS = {
    "agentcomms_register": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_list_agents": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_send_hello": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "agentcomms_send_message": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "agentcomms_read_messages": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_get_fingerprint": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agentcomms_v2_register": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_v2_selftest": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "agentcomms_v2_preflight": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_v2_list_agents": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "agentcomms_v2_send_hello": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "agentcomms_v2_send_message": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "agentcomms_v2_read_messages": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "agentcomms_v2_get_fingerprint": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}

for _tool in TOOLS:
    _tool["annotations"] = _TOOL_ANNOTATIONS[_tool["name"]]


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


def run_agentcomms_v2(argv):
    """Run the authenticated v2 CLI without writing to the MCP wire."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        agentcomms_v2.main(_transport_args() + argv)
    return output.getvalue().strip()


def _require(arguments, name):
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def call_tool(name, arguments):
    if not isinstance(arguments, dict):
        raise TypeError("arguments must be an object")
    runner = run_agentcomms
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
    elif name == "agentcomms_v2_register":
        runner = run_agentcomms_v2
        argv = ["register", "--name", _require(arguments, "name")]
        contact = arguments.get("contact", "")
        if not isinstance(contact, str):
            raise ValueError("contact must be a string")
        if contact:
            argv += ["--contact", contact]
    elif name == "agentcomms_v2_selftest":
        runner = run_agentcomms_v2
        argv = ["selftest", "--json"]
    elif name == "agentcomms_v2_preflight":
        runner = run_agentcomms_v2
        argv = ["preflight", "--json"]
    elif name == "agentcomms_v2_list_agents":
        runner = run_agentcomms_v2
        argv = ["list"]
    elif name == "agentcomms_v2_send_hello":
        runner = run_agentcomms_v2
        argv = ["hello", "--to", _require(arguments, "peer")]
    elif name == "agentcomms_v2_send_message":
        runner = run_agentcomms_v2
        argv = ["say", "--to", _require(arguments, "peer"),
                "--text", _require(arguments, "text")]
    elif name == "agentcomms_v2_read_messages":
        runner = run_agentcomms_v2
        argv = ["read", "--to", _require(arguments, "peer")]
    elif name == "agentcomms_v2_get_fingerprint":
        runner = run_agentcomms_v2
        argv = ["fingerprint"]
    else:
        raise ValueError(f"unknown tool: {name}")
    return runner(argv)


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
                "Prefer agentcomms_v2_* tools: register a self-certifying "
                "identity, exchange signed key offers, then send and read "
                "authenticated messages. Legacy v1 remains experimental."
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
                "Prefer agentcomms_v2_* tools: register a self-certifying "
                "identity, exchange signed key offers, then send and read "
                "authenticated messages. Legacy v1 remains experimental."
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
        # Application failures become tool errors without terminating the
        # long-running stdio server, regardless of their concrete type.
        except (Exception, SystemExit) as exc:  # noqa: BLE001
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
