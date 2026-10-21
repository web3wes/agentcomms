#!/usr/bin/env python3
"""Build a no-code static mirror of agentcomms discovery evidence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "_site"

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


if __name__ == "__main__":
    main()
