import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify_wheel_manifest import verify


class VerifyWheelManifestTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        wheel = root / "sample-1.0-py3-none-any.whl"
        files = {"sample.py": b"VALUE = 1\n", "sample.dist-info/WHEEL": b"Wheel-Version: 1.0\n"}
        with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        wheel_bytes = wheel.read_bytes()
        manifest = {
            "distribution": {
                "filename": wheel.name,
                "size": len(wheel_bytes),
                "sha256": hashlib.sha256(wheel_bytes).hexdigest(),
            },
            "files": [
                {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in files.items()
            ],
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return temp, wheel, manifest_path

    def test_verifies_without_extracting(self):
        temp, wheel, manifest = self.fixture()
        self.addCleanup(temp.cleanup)
        result = verify(wheel, manifest)
        self.assertTrue(result["verified"])
        self.assertEqual(result["filesChecked"], 2)
        self.assertFalse(result["authorityUsed"]["packageInstall"])
        self.assertEqual(sorted(Path(temp.name).iterdir()), [manifest, wheel])

    def test_rejects_modified_wheel(self):
        temp, wheel, manifest = self.fixture()
        self.addCleanup(temp.cleanup)
        with wheel.open("ab") as stream:
            stream.write(b"tampered")
        result = verify(wheel, manifest)
        self.assertFalse(result["verified"])
        self.assertIn("wheel SHA-256 does not match manifest", result["errors"])


if __name__ == "__main__":
    unittest.main()
