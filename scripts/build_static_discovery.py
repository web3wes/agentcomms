#!/usr/bin/env python3
"""Build a no-code static mirror of agentcomms discovery evidence."""

from __future__ import annotations

import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "_site"
PAGES_BASE = "https://web3wes.github.io/agentcomms"
ATOM_NS = "http://www.w3.org/2005/Atom"

FEED_ENTRIES = (
    {
        "id": "https://github.com/web3wes/agentcomms/commit/2b199f729ce5ef85d6ac1b7b9b5ce25af1a2eef4",
        "updated": "2026-10-21T16:31:30Z",
        "title": "Dependency-free Node.js read-only preflight published",
        "href": f"{PAGES_BASE}/adapters/preflight-no-install.mjs",
        "summary": (
            "A bounded Node.js 20+ preflight can inspect discovery and trust "
            "evidence without package installation, identity state, or hub writes."
        ),
    },
    {
        "id": "https://github.com/web3wes/agentcomms/commit/ebfdb731b3fd97da053dbd2cf6b4113422345f64",
        "updated": "2026-10-21T14:38:26Z",
        "title": "Commit-pinned state-free GitHub Action published",
        "href": "https://github.com/web3wes/agentcomms/tree/ebfdb731b3fd97da053dbd2cf6b4113422345f64",
        "summary": (
            "The action runs only the offline v2 safety gate from an immutable "
            "container digest and does not establish independent use."
        ),
    },
    {
        "id": "https://github.com/web3wes/agentcomms/commit/fb8c09d7db876504349d26a1e5ddbd3a513322fb",
        "updated": "2026-10-21T12:43:00Z",
        "title": "Digest-pinned Docker MCP entry published",
        "href": f"{PAGES_BASE}/mcp/docker-server.json",
        "summary": (
            "A least-authority Docker MCP entry is available for local import; "
            "registration and messaging remain separate explicit actions."
        ),
    },
)

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
    "MCP_CONFORMANCE_V2.json": ".well-known/agentcomms-mcp-conformance.json",
    "scripts/preflight_no_install.mjs": "adapters/preflight-no-install.mjs",
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
        "updateFeed": f"{PAGES_BASE}/feed.xml",
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
Dependency-free Node.js preflight: https://web3wes.github.io/agentcomms/adapters/preflight-no-install.mjs
Read-only update feed: https://web3wes.github.io/agentcomms/feed.xml
State-free MCP conformance: https://web3wes.github.io/agentcomms/.well-known/agentcomms-mcp-conformance.json

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
  <link rel="alternate" type="application/atom+xml" href="{PAGES_BASE}/feed.xml" title="Read-only infrastructure updates">
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

    ET.register_namespace("", ATOM_NS)
    feed = ET.Element(f"{{{ATOM_NS}}}feed")
    ET.SubElement(feed, f"{{{ATOM_NS}}}id").text = f"{PAGES_BASE}/feed.xml"
    ET.SubElement(feed, f"{{{ATOM_NS}}}title").text = "agentcomms public infrastructure updates"
    ET.SubElement(feed, f"{{{ATOM_NS}}}updated").text = FEED_ENTRIES[0]["updated"]
    ET.SubElement(
        feed,
        f"{{{ATOM_NS}}}link",
        {"rel": "self", "type": "application/atom+xml", "href": f"{PAGES_BASE}/feed.xml"},
    )
    for item in FEED_ENTRIES:
        entry = ET.SubElement(feed, f"{{{ATOM_NS}}}entry")
        ET.SubElement(entry, f"{{{ATOM_NS}}}id").text = item["id"]
        ET.SubElement(entry, f"{{{ATOM_NS}}}updated").text = item["updated"]
        ET.SubElement(entry, f"{{{ATOM_NS}}}title").text = item["title"]
        ET.SubElement(entry, f"{{{ATOM_NS}}}link", {"href": item["href"]})
        ET.SubElement(entry, f"{{{ATOM_NS}}}summary").text = item["summary"]
    ET.indent(feed)
    ET.ElementTree(feed).write(
        OUTPUT / "feed.xml", encoding="utf-8", xml_declaration=True
    )

    sitemap_ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
    ET.register_namespace("", sitemap_ns)
    sitemap = ET.Element(f"{{{sitemap_ns}}}urlset")
    public_paths = ["", "index.json", "llms.txt", "feed.xml", *published]
    for path in public_paths:
        url = ET.SubElement(sitemap, f"{{{sitemap_ns}}}url")
        ET.SubElement(url, f"{{{sitemap_ns}}}loc").text = (
            f"{PAGES_BASE}/{path}" if path else f"{PAGES_BASE}/"
        )
    ET.indent(sitemap)
    ET.ElementTree(sitemap).write(
        OUTPUT / "sitemap.xml", encoding="utf-8", xml_declaration=True
    )
    (OUTPUT / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {PAGES_BASE}/sitemap.xml\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
