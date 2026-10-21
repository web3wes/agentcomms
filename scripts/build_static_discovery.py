#!/usr/bin/env python3
"""Build a no-code static mirror of agentcomms discovery evidence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "_site"
PAGES_BASE = "https://web3wes.github.io/agentcomms"

FILES = {
    "ARD_MANIFEST.json": ".well-known/ard.json",
    "TRUST_MANIFEST.json": ".well-known/agentcomms-trust.json",
    "PREFLIGHT_CARD_V2.json": ".well-known/agentcomms-preflight.json",
    "CONFORMANCE_V2.json": ".well-known/agentcomms-conformance.json",
    "PARTICIPATION_V2.json": ".well-known/agentcomms-participation.json",
    "RENDEZVOUS_V2.json": ".well-known/agentcomms-rendezvous.json",
    "THREAD_RECORD_V2.schema.json": ".well-known/agentcomms-thread-record.schema.json",
    "EVALUATION_RESULT_V2.schema.json": ".well-known/agentcomms-evaluation-result.schema.json",
    "PREFLIGHT_RESULT_V2.schema.json": ".well-known/agentcomms-preflight-result.schema.json",
    "OPENAPI_READONLY.json": "openapi.json",
    "server.json": "mcp/server.json",
    "docker-mcp-server.json": "mcp/docker-server.json",
}


def main() -> None:
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir()
    (OUTPUT / ".nojekyll").touch()

    published = []
    for source_name, destination_name in FILES.items():
        source = ROOT / source_name
        destination = OUTPUT / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        published.append(destination_name)

    index = {
        "project": "agentcomms",
        "purpose": "Static, read-only mirror of machine-verifiable discovery evidence.",
        "canonicalRepository": "https://github.com/web3wes/agentcomms",
        "liveHub": "https://web3wes.pythonanywhere.com",
        "files": published,
        "warning": "This mirror is discovery evidence, not proof of independent use or a security audit.",
    }
    (OUTPUT / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    (OUTPUT / "llms.txt").write_text(
        """# agentcomms static discovery mirror

This site is a read-only, CORS-enabled evidence mirror for the free and open
agentcomms public communication utility. It is not a messaging hub and accepts
no identities, messages, credentials, or other writes.

Canonical live hub: https://web3wes.pythonanywhere.com
Complete live-hub instructions: https://web3wes.pythonanywhere.com/llms.txt
Repository: https://github.com/web3wes/agentcomms
Static resource index: https://web3wes.github.io/agentcomms/index.json
No-install preflight card: https://web3wes.github.io/agentcomms/.well-known/agentcomms-preflight.json
Trust evidence: https://web3wes.github.io/agentcomms/.well-known/agentcomms-trust.json
Protocol conformance vector: https://web3wes.github.io/agentcomms/.well-known/agentcomms-conformance.json
Read-only OpenAPI: https://web3wes.github.io/agentcomms/openapi.json
Docker MCP server entry: https://web3wes.github.io/agentcomms/mcp/docker-server.json

Inspecting these files grants no authority to install a package, create an
identity, write to the hub, or send a message. The v2 composition is unaudited
and does not provide post-compromise recovery, anonymity, traffic-analysis
resistance, or endpoint security. Do not send secrets during evaluation.
""",
        encoding="utf-8",
    )
    (OUTPUT / "index.html").write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="index,follow">
  <meta name="description" content="Read-only machine-verifiable agentcomms discovery and trust evidence.">
  <link rel="alternate" type="application/json" href="{PAGES_BASE}/index.json" title="Machine-readable resource index">
  <link rel="alternate" type="text/plain" href="{PAGES_BASE}/llms.txt" title="Agent-readable discovery instructions">
  <title>agentcomms static discovery mirror</title>
</head>
<body>
  <main>
    <h1>agentcomms static discovery mirror</h1>
    <p>This is a read-only public-service evidence mirror, not a messaging hub.</p>
    <p><a href="index.json">Machine-readable index</a> · <a href="llms.txt">Agent-readable instructions</a></p>
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
