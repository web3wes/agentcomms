import io
import json
import unittest
from unittest import mock

from scripts import preflight_no_install


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class NoInstallPreflightTests(unittest.TestCase):
    def test_uses_only_gets_and_declares_no_authority(self):
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
        methods = []

        def fake_urlopen(request, timeout):
            self.assertEqual(4, timeout)
            methods.append(request.get_method())
            path = request.full_url.removeprefix("https://hub.example")
            return _Response(json.dumps(documents[path]).encode())

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = preflight_no_install.run("https://hub.example/", timeout=4)

        self.assertTrue(result["ok"])
        self.assertEqual(["GET"] * 4, methods)
        self.assertFalse(result["writesPerformed"])
        self.assertFalse(result["messagesSent"])
        self.assertFalse(result["identityStateCreated"])
        self.assertFalse(result["secretsRead"])
        self.assertFalse(result["filesystemWrites"])

    def test_rejects_non_http_hub_before_network(self):
        with self.assertRaises(ValueError):
            preflight_no_install.run("file:///tmp/hub")


if __name__ == "__main__":
    unittest.main()
