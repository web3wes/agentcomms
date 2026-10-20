#!/usr/bin/env python3
"""Read-only, standard-library preflight for agentcomms discovery evidence."""

import argparse
import json
import sys
import urllib.parse
import urllib.request

EXPECTED_RELEASE = "0.3.5"
EXPECTED_WHEEL_SHA256 = (
    "c6ba325daa27a750bd64ad746e4c521803ab3db0ee1e756017105af1425ed918"
)
EXPECTED_SESSION = "61821bb89d208bc5e557a5f4fa6de55b"
PATHS = (
    "/directory",
    "/.well-known/ard.json",
    "/.well-known/agentcomms-trust.json",
    "/.well-known/agentcomms-conformance.json",
)


def _get_json(hub, path, timeout):
    url = hub.rstrip("/") + path
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "agentcomms-preflight/1"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.load(response)


def run(hub, timeout=15):
    parsed = urllib.parse.urlparse(hub)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("hub must be an absolute HTTP(S) URL")

    responses = {}
    requests = []
    for path in PATHS:
        status, body = _get_json(hub, path, timeout)
        requests.append({"method": "GET", "path": path, "status": status})
        responses[path] = body

    directory = responses["/directory"]
    ard = responses["/.well-known/ard.json"]
    trust = responses["/.well-known/agentcomms-trust.json"]
    conformance = responses["/.well-known/agentcomms-conformance.json"]
    artifacts = trust.get("artifacts", [])
    wheel = next((x for x in artifacts if x.get("filename", "").endswith(".whl")), {})
    entries = ard.get("entries", [])

    checks = {
        "allRequestsSucceeded": all(item["status"] == 200 for item in requests),
        "directoryIsList": isinstance(directory.get("agents"), list),
        "ardEntryPresent": any(
            item.get("identifier")
            == "urn:air:web3wes.pythonanywhere.com:mcp:agentcomms"
            for item in entries
        ),
        "trustReleaseMatches": trust.get("version") == EXPECTED_RELEASE,
        "wheelDigestMatches": wheel.get("sha256") == EXPECTED_WHEEL_SHA256,
        "conformanceProtocolMatches": conformance.get("protocol") == "agentcomms-v2",
        "conformanceSessionMatches": (
            conformance.get("expected", {}).get("session") == EXPECTED_SESSION
        ),
        "conformanceSelftestCountMatches": (
            conformance.get("referenceSelftest", {}).get("expectedChecks") == 20
        ),
    }
    return {
        "schema": "agentcomms-no-install-preflight-v1",
        "ok": all(checks.values()),
        "mode": "read-only",
        "hub": hub.rstrip("/"),
        "requests": requests,
        "checks": checks,
        "directoryAgentCount": len(directory.get("agents", [])),
        "writesPerformed": False,
        "messagesSent": False,
        "identityStateCreated": False,
        "secretsRead": False,
        "filesystemWrites": False,
        "limitations": [
            "validates discovery structure and published expected values only",
            "does not install or import agentcomms",
            "does not execute cryptographic primitives or establish security",
            "does not establish independent participation",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub", default="https://web3wes.pythonanywhere.com")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args(argv)
    try:
        result = run(args.hub, args.timeout)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {
            "schema": "agentcomms-no-install-preflight-v1",
            "ok": False,
            "mode": "read-only",
            "error": f"{type(exc).__name__}: {exc}",
            "writesPerformed": False,
            "messagesSent": False,
            "identityStateCreated": False,
            "secretsRead": False,
            "filesystemWrites": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
