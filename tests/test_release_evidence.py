"""Verify deterministic release evidence and package transparency metadata."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_package_manifest import build_manifest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseEvidenceTests(unittest.TestCase):
    def test_selftest_stdout_matches_published_digest(self):
        evidence = json.loads((ROOT / "SELFTEST_V2.json").read_text("utf-8"))
        result = subprocess.run(
            [sys.executable, str(ROOT / "agentcomms_v2.py"), "selftest", "--json"],
            capture_output=True,
            check=False,
        )
        normalized = result.stdout.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.assertEqual(evidence["expectedExitCode"], result.returncode)
        self.assertEqual(evidence["expectedStderrUtf8"].encode(), result.stderr)
        self.assertEqual(evidence["expectedStdoutUtf8"].encode(), normalized)
        self.assertEqual(
            evidence["expectedStdoutSha256"], hashlib.sha256(normalized).hexdigest()
        )
        self.assertFalse(evidence["safety"]["networkRequests"])
        self.assertFalse(evidence["safety"]["filesystemWrites"])

    def test_preflight_schema_forbids_writes(self):
        schema = json.loads(
            (ROOT / "PREFLIGHT_RESULT_V2.schema.json").read_text("utf-8")
        )
        properties = schema["properties"]
        self.assertEqual(False, properties["writesPerformed"]["const"])
        self.assertEqual(False, properties["identityStateCreated"]["const"])
        self.assertEqual("GET", properties["requests"]["items"]["properties"]["method"]["const"])
        self.assertEqual(3, properties["requests"]["maxItems"])

    def test_wheel_manifest_lists_files_hooks_native_code_and_hosts(self):
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("demo.py", "VALUE = 1\n")
                archive.writestr(
                    "demo-1.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
                    "Requires-Dist: cryptography>=49,<51\n\n",
                )
                archive.writestr(
                    "demo-1.0.dist-info/entry_points.txt",
                    "[console_scripts]\ndemo = demo:main\n",
                )
            manifest = build_manifest(wheel)

        self.assertEqual("agentcomms-package-manifest-v1", manifest["schema"])
        self.assertEqual(3, len(manifest["files"]))
        self.assertTrue(manifest["distribution"]["purePython"])
        self.assertEqual([], manifest["nativeBinaries"])
        self.assertEqual([], manifest["installBehavior"]["installTimeCodeHooks"])
        self.assertEqual(
            [{"name": "demo", "target": "demo:main"}],
            manifest["installBehavior"]["consoleScripts"],
        )
        self.assertEqual(
            ["web3wes.pythonanywhere.com"],
            manifest["declaredNetwork"]["defaultPackageCodeOutboundHosts"],
        )
        self.assertIn("--hub", manifest["declaredNetwork"]["operatorConfiguredOutboundHosts"])


if __name__ == "__main__":
    unittest.main()
