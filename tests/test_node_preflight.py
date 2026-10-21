"""Exercise the dependency-free Node.js preflight adapter."""

import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scripts import preflight_no_install

ROOT = Path(__file__).resolve().parents[1]


class _Handler(BaseHTTPRequestHandler):
    methods = []
    documents = {
        "/directory": {"agents": []},
        "/.well-known/ard.json": {
            "entries": [{
                "identifier": "urn:air:web3wes.pythonanywhere.com:mcp:agentcomms"
            }]
        },
        "/.well-known/agentcomms-trust.json": {
            "version": "0.3.5",
            "artifacts": [{
                "filename": "agentcomms_secure-0.3.5-py3-none-any.whl",
                "sha256": preflight_no_install.EXPECTED_WHEEL_SHA256,
            }],
        },
        "/.well-known/agentcomms-conformance.json": {
            "protocol": "agentcomms-v2",
            "referenceSelftest": {"expectedChecks": 20},
            "expected": {"session": preflight_no_install.EXPECTED_SESSION},
        },
    }

    def do_GET(self):
        self.methods.append(self.command)
        body = json.dumps(self.documents[self.path]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
class NodePreflightTests(unittest.TestCase):
    def setUp(self):
        _Handler.methods = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_uses_only_gets_and_creates_no_state(self):
        hub = f"http://127.0.0.1:{self.server.server_port}"
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    "node",
                    str(ROOT / "scripts" / "preflight_no_install.mjs"),
                    "--hub",
                    hub,
                    "--timeout",
                    "4",
                ],
                cwd=temporary,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual([], list(Path(temporary).iterdir()))

        report = json.loads(result.stdout)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(report["ok"])
        self.assertEqual(["GET"] * 4, _Handler.methods)
        for field in (
            "writesPerformed",
            "messagesSent",
            "identityStateCreated",
            "secretsRead",
            "filesystemWrites",
        ):
            self.assertFalse(report[field])

    def test_rejects_non_http_hub_before_network(self):
        result = subprocess.run(
            [
                "node",
                str(ROOT / "scripts" / "preflight_no_install.mjs"),
                "--hub",
                "file:///tmp/hub",
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(1, result.returncode)
        self.assertFalse(json.loads(result.stdout)["ok"])
        self.assertEqual([], _Handler.methods)


if __name__ == "__main__":
    unittest.main()
