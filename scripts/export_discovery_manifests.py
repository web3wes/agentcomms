#!/usr/bin/env python3
"""Export repository-static copies of the hub's machine-readable manifests."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import agenthub

EXPORTS = {
    "ARD_MANIFEST.json": agenthub.ARD_MANIFEST,
    "TRUST_MANIFEST.json": agenthub.TRUST_MANIFEST,
}


def render(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main():
    for filename, value in EXPORTS.items():
        (ROOT / filename).write_text(render(value), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
