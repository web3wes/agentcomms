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
    def test_release_catalog_is_closed_world_and_does_not_grant_authority(self):
        catalog = json.loads((ROOT / "RELEASE_EVIDENCE_V2.json").read_text("utf-8"))
        self.assertEqual("0.3.5", catalog["release"])
        self.assertEqual(5, len(catalog["evidence"]))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in catalog["evidence"]))
        self.assertTrue(all(value is False for value in catalog["authority"].values()))
        self.assertTrue(
            any("not a security audit" in item for item in catalog["limitations"])
        )

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

    def test_release_workflow_attaches_the_attested_distributions(self):
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        release_job = workflow.split("  publish-release-evidence:", 1)[1]
        self.assertIn("name: python-dist", release_job)
        self.assertIn("path: dist/", release_job)
        self.assertIn('gh release upload "$GITHUB_REF_NAME" dist/* evidence/*', release_job)

    def test_runtime_container_base_image_is_digest_pinned(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        first_line = dockerfile.splitlines()[0]
        self.assertRegex(first_line, r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$")

    def test_beacon_health_check_does_not_pipe_downloads_to_an_interpreter(self):
        workflow = (
            ROOT / ".github" / "workflows" / "beacon.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("curl -fsS", workflow)
        self.assertIn("urllib.request.urlopen", workflow)

    def test_ci_dependency_inputs_are_hash_locked(self):
        for name in (
            "requirements-runtime.lock",
            "requirements-release.lock",
            "requirements-security.lock",
        ):
            lock = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("--hash=sha256:", lock, name)
            self.assertNotIn("# WARNING:", lock, name)

        publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        security = (ROOT / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--require-hashes", publish)
        self.assertIn("requirements-release.lock", publish)
        self.assertIn("--require-hashes", security)
        self.assertIn("requirements-security.lock", security)

    def test_clusterfuzzlite_uses_pinned_actions_and_image(self):
        workflow = (ROOT / ".github" / "workflows" / "fuzzing.yml").read_text(
            encoding="utf-8"
        )
        dockerfile = (ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("google/clusterfuzzlite/actions/build_fuzzers@v1", workflow)
        self.assertNotIn("google/clusterfuzzlite/actions/run_fuzzers@v1", workflow)
        self.assertRegex(dockerfile.splitlines()[0], r"@sha256:[0-9a-f]{64}$")
        self.assertNotIn("pip install --disable-pip-version-check --no-deps .", dockerfile)
        self.assertIn("keep-unaffected-fuzz-targets: true", workflow)

        build_script = (ROOT / ".clusterfuzzlite" / "build.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--hidden-import agentcomms_v2", build_script)


if __name__ == "__main__":
    unittest.main()
