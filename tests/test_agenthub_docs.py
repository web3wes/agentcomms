"""Guard the machine-readable onboarding packet against security overclaims."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import agenthub
import agenthub_wsgi


class BeaconDocumentationTests(unittest.TestCase):
    def test_beacon_has_independent_agent_route_and_protocol(self):
        self.assertIn("agent-69263305", agenthub.BEACON)
        self.assertIn("PROTOCOL.md", agenthub.BEACON)
        self.assertIn("PROTOCOL_V2.md", agenthub.BEACON)
        self.assertIn("agentcomms-v2", agenthub.BEACON)
        self.assertIn("agentcomms-v2 selftest", agenthub.BEACON)
        self.assertIn("/.well-known/ard.json", agenthub.BEACON)

    def test_agent_native_discovery_manifest_is_searchable_and_executable(self):
        manifest = agenthub.ARD_MANIFEST
        self.assertEqual(1, len(manifest["entries"]))
        entry = manifest["entries"][0]
        self.assertEqual(
            "urn:air:web3wes.pythonanywhere.com:mcp:agentcomms",
            entry["identifier"],
        )
        self.assertEqual("application/mcp-server-card+json", entry["type"])
        self.assertEqual(4, len(entry["representativeQueries"]))
        self.assertIn("AgentMessaging", entry["capabilities"])
        self.assertEqual(
            "io.github.web3wes/agentcomms",
            agenthub.MCP_SERVER_CARD["name"],
        )
        self.assertEqual("0.3.1", agenthub.MCP_SERVER_CARD["version"])
        self.assertIn("Agentmap:", agenthub.ROBOTS)

    def test_beacon_discloses_v2_security_limits(self):
        self.assertIn("not been independently audited", agenthub.BEACON)
        self.assertIn("no post-compromise recovery", agenthub.BEACON)
        self.assertIn("traffic-analysis", agenthub.BEACON)

    def test_beacon_discloses_v1_security_limits(self):
        self.assertIn("no forward secrecy", agenthub.BEACON)
        self.assertIn("not authenticated", agenthub.BEACON)
        self.assertIn("Do not send serious secrets", agenthub.BEACON)
        self.assertNotIn("ephemeral Diffie-Hellman", agenthub.BEACON)

    def test_wsgi_serves_agent_discovery_documents(self):
        cases = {
            "/.well-known/ard.json": "application/json",
            "/.well-known/ai-catalog.json": "application/json",
            "/mcp/server.json": "application/mcp-server-card+json",
            "/robots.txt": "text/plain",
        }
        for path, expected_type in cases.items():
            captured = {}

            def start_response(status, headers, captured=captured):
                captured["status"] = status
                captured["headers"] = dict(headers)

            body = b"".join(agenthub_wsgi.application({
                "REQUEST_METHOD": "GET",
                "PATH_INFO": path,
            }, start_response))
            self.assertEqual("200 OK", captured["status"])
            self.assertEqual(expected_type, captured["headers"]["Content-Type"])
            self.assertTrue(body)

    def test_wsgi_accepts_v2_thread_ids(self):
        captured = {}
        v2_id_a = "agent-" + "a" * 32
        v2_id_b = "agent-" + "b" * 32

        def start_response(status, headers):
            captured["status"] = status

        body = b"".join(agenthub_wsgi.application({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": f"/threads/{v2_id_a}__{v2_id_b}",
        }, start_response))
        self.assertEqual("200 OK", captured["status"])
        self.assertEqual(b"", body)

    def test_repository_docs_do_not_overstate_identity_or_ciphertext(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        hub_source = (root / "agenthub.py").read_text(encoding="utf-8")
        self.assertNotIn("squatting is structurally impossible", readme)
        self.assertIn("collision-based pre-registration is possible", readme)
        self.assertNotIn("all payloads are end-to-end encrypted", hub_source)
        self.assertIn("does not\nauthenticate that ciphertext", hub_source)

    def test_hub_accepts_self_certifying_v2_identity_and_long_thread_ids(self):
        import base64
        import hashlib

        import agentcomms_v2 as v2

        with TemporaryDirectory() as temp:
            hub = agenthub.Hub(temp)
            pub = bytes(range(32))
            fp = hashlib.sha256(pub).hexdigest()
            entry = {
                "id": "agent-" + fp[:32],
                "name": "v2 test",
                "fingerprint": fp,
                "pub": base64.b64encode(pub).decode(),
                "protocol": "v2",
                "contact": "test",
            }
            self.assertEqual((200, "registered"), hub.register(entry))
            peer_pub = bytes(reversed(range(32)))
            peer_fp = hashlib.sha256(peer_pub).hexdigest()
            peer = {
                "id": "agent-" + peer_fp[:32],
                "name": "v2 peer",
                "fingerprint": peer_fp,
                "pub": base64.b64encode(peer_pub).decode(),
                "protocol": "v2",
                "contact": "test",
            }
            self.assertEqual((200, "registered"), hub.register(peer))
            tid = "__".join(sorted([entry["id"], peer["id"]]))
            hello = {"type": "hello", "from": entry["id"],
                     "pub": entry["pub"], "ts": v2.now()}
            self.assertEqual((200, "appended"), hub.append(tid, hello))
            forged = dict(hello, pub=peer["pub"])
            self.assertEqual(403, hub.append(tid, forged)[0])


if __name__ == "__main__":
    unittest.main()
