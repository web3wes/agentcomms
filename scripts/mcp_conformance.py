#!/usr/bin/env python3
"""Run the bounded, state-free MCP lifecycle fixture against agentcomms."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "MCP_CONFORMANCE_V2.json"


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def run():
    fixture = json.loads(FIXTURE.read_text("utf-8"))
    request_text = "".join(
        json.dumps(item, separators=(",", ":")) + "\n"
        for item in fixture["requests"]
    )
    with tempfile.TemporaryDirectory() as temporary:
        environment = os.environ.copy()
        environment["AGENTCOMMS_HOME"] = temporary
        environment["AGENTCOMMS_HUB"] = "http://127.0.0.1:9"
        process = subprocess.run(
            [sys.executable, str(ROOT / "agentcomms_mcp.py")],
            input=request_text,
            text=True,
            capture_output=True,
            check=False,
            cwd=ROOT,
            env=environment,
            timeout=20,
        )
        state_created = bool(list(Path(temporary).iterdir()))

    responses = [json.loads(line) for line in process.stdout.splitlines() if line]
    initialize = responses[0]["result"] if len(responses) > 0 else {}
    tools = responses[1].get("result", {}).get("tools", []) if len(responses) > 1 else []
    call = responses[2].get("result", {}) if len(responses) > 2 else {}
    content = call.get("content", [])
    selftest = {}
    if content and content[0].get("type") == "text":
        selftest = json.loads(content[0].get("text", "{}"))

    projection = {
        "initialize": {
            "protocolVersion": initialize.get("protocolVersion"),
            "capabilities": initialize.get("capabilities"),
            "serverInfo": initialize.get("serverInfo"),
        },
        "tools": [
            {"name": item.get("name"), "annotations": item.get("annotations")}
            for item in tools
        ],
        "selftest": selftest,
    }
    digest = hashlib.sha256(_canonical(projection)).hexdigest()
    tool_names = [item.get("name") for item in tools]
    checks = {
        "processExitedZero": process.returncode == 0,
        "stderrEmpty": process.stderr == "",
        "threeResponses": len(responses) == 3,
        "responseIdsMatch": [item.get("id") for item in responses] == [1, 2, 3],
        "protocolVersionMatches": (
            initialize.get("protocolVersion") == fixture["expected"]["protocolVersion"]
        ),
        "serverVersionMatches": (
            initialize.get("serverInfo", {}).get("version") == fixture["release"]
        ),
        "toolNamesMatch": tool_names == fixture["expected"]["toolNames"],
        "onlySelftestCalled": fixture["requests"][2].get("params", {}).get("name")
        == "agentcomms_v2_selftest",
        "selftestPassed": selftest.get("ok") is True and selftest.get("checks") == 20,
        "projectionDigestMatches": (
            digest == fixture["expected"]["projectionSha256"]
        ),
        "identityStateAbsent": not state_created,
    }
    return {
        "schema": "agentcomms-mcp-conformance-result-v1",
        "ok": all(checks.values()),
        "release": fixture["release"],
        "checks": checks,
        "projectionSha256": digest,
        "toolCount": len(tools),
        "toolNames": tool_names,
        "networkRequestsExpected": False,
        "writesPerformed": False,
        "identityStateCreated": state_created,
        "messagesSent": False,
        "limitations": fixture["limitations"],
    }


def main():
    try:
        result = run()
    except (OSError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        result = {
            "schema": "agentcomms-mcp-conformance-result-v1",
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "writesPerformed": False,
            "identityStateCreated": False,
            "messagesSent": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
