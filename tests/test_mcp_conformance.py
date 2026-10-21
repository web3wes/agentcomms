"""Verify the bounded MCP lifecycle fixture remains state-free and exact."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class McpConformanceTests(unittest.TestCase):
    def test_fixture_calls_only_the_offline_selftest(self):
        fixture = json.loads((ROOT / "MCP_CONFORMANCE_V2.json").read_text("utf-8"))
        self.assertEqual(3, len(fixture["requests"]))
        self.assertEqual(
            "agentcomms_v2_selftest", fixture["requests"][2]["params"]["name"]
        )
        self.assertTrue(all(value is False for value in fixture["authority"].values()))
        self.assertEqual(64, len(fixture["expected"]["projectionSha256"]))

    def test_runner_matches_the_published_projection(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "mcp_conformance.py")],
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(report["ok"])
        self.assertFalse(report["writesPerformed"])
        self.assertFalse(report["identityStateCreated"])
        self.assertFalse(report["messagesSent"])


if __name__ == "__main__":
    unittest.main()
