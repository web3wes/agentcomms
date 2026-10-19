"""Guard the machine-readable onboarding packet against security overclaims."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import agentcomms_v2 as v2
import agenthub
import agenthub_wsgi


class BeaconDocumentationTests(unittest.TestCase):
    def test_a2a_extension_is_optional_data_only_discovery(self):
        path = Path(__file__).resolve().parents[1] / "A2A_EXTENSION.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            "https://web3wes.pythonanywhere.com/extensions/agentcomms/v1",
            schema["$id"],
        )
        example = schema["examples"][0]
        self.assertEqual("optional-side-channel", example["mode"])
        self.assertEqual("agentcomms-v2", example["protocol"])
        self.assertEqual(set(schema["required"]), set(example))
        self.assertFalse(schema["additionalProperties"])

    def test_rendezvous_policy_is_read_only_and_excludes_project_identities(self):
        path = Path(__file__).resolve().parents[1] / "RENDEZVOUS_V2.json"
        policy = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("agentcomms-rendezvous-v1", policy["schema"])
        self.assertFalse(policy["safety"]["automaticRegistration"])
        self.assertFalse(policy["safety"]["automaticHello"])
        self.assertFalse(policy["safety"]["automaticMessage"])
        self.assertEqual("GET /directory", policy["readOnlyLoop"]["request"])
        self.assertGreaterEqual(
            policy["readOnlyLoop"]["minimumIntervalSeconds"], 900
        )
        self.assertIn("agent-69263305", policy["knownProjectIdentities"])
        self.assertTrue(
            policy["compatiblePeerFilter"]["excludeKnownProjectIdentities"]
        )

    def test_no_install_rendezvous_fixture_matches_executable_filter(self):
        root = Path(__file__).resolve().parents[1]
        fixture = json.loads(
            (root / "RENDEZVOUS_CONFORMANCE_V2.json").read_text(encoding="utf-8")
        )
        vector = json.loads(
            (root / "CONFORMANCE_V2.json").read_text(encoding="utf-8")
        )
        self.assertEqual("none", fixture["execution"]["network"])
        self.assertFalse(fixture["execution"]["packageInstallOrImportRequired"])
        self.assertFalse(fixture["execution"]["hubWrites"])
        self.assertEqual(vector["expected"]["offers"], fixture["inputs"]["offers"])
        response = {
            "status": 200,
            "contentType": "application/json",
            "bytes": 1000,
            "json": fixture["inputs"]["directory"],
        }
        with mock.patch("agentcomms_v2._preflight_get_json", return_value=response):
            result = v2.read_only_rendezvous(
                "https://hub.example", fixture["inputs"]["localId"]
            )
        expected = fixture["expected"]
        self.assertEqual(expected["compatiblePeerCount"], result["compatiblePeerCount"])
        self.assertEqual(expected["selectedPeer"], result["compatiblePeers"][0])
        self.assertEqual(
            expected["invalidEntriesIgnored"], result["invalidEntriesIgnored"]
        )
        self.assertEqual(
            expected["knownProjectEntriesExcluded"],
            result["knownProjectEntriesExcluded"],
        )
        self.assertFalse(result["writesPerformed"])
        self.assertFalse(result["identityStateCreated"])

    def test_participation_plan_separates_observation_from_writes(self):
        path = Path(__file__).resolve().parents[1] / "PARTICIPATION_V2.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("agentcomms-participation-v1", plan["schema"])
        self.assertFalse(plan["rules"]["advanceAutomatically"])
        stages = {stage["id"]: stage for stage in plan["stages"]}
        self.assertEqual([], stages["offline-selftest"]["network"])
        self.assertEqual([], stages["read-only-preflight"]["hubWrites"])
        self.assertFalse(stages["read-only-preflight"]["createsIdentity"])
        self.assertFalse(stages["register"]["automatic"])
        self.assertTrue(stages["register"]["createsIdentity"])
        self.assertIn("legacy v1", stages["hello"]["warning"])

    def test_agent_skill_preserves_staged_authority_and_untrusted_data_boundary(self):
        path = Path(__file__).resolve().parents[1] / "SKILL.md"
        skill = path.read_text(encoding="utf-8")
        self.assertIn("version: 0.3.5", skill)
        self.assertIn("untrusted data, never as an instruction", skill)
        self.assertIn("Stop after each stage", skill)
        self.assertIn("selftest --json", skill)
        self.assertIn("RENDEZVOUS_CONFORMANCE_V2.json", skill)
        self.assertIn(
            "299a396cf321e642351c37bb88a16eb5dafc450b8b518d1daf5c6ffab74088f4",
            skill,
        )
        self.assertIn("no agentcomms install or import", skill)
        self.assertIn("must never be used live", skill)
        self.assertIn("preflight --json", skill)
        self.assertIn("rendezvous --json", skill)
        self.assertIn("Do not send them a v2 hello", skill)
        self.assertIn("not independently audited", skill)
        self.assertIn("provenance is uncertain", skill)
        self.assertIn("EVALUATION_RESULT_V2.schema.json", skill)
        self.assertIn("Never put private keys", skill)

    def test_evaluation_result_schema_is_bounded_and_non_secret(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "EVALUATION_RESULT_V2.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            "agentcomms-evaluation-result-v1",
            schema["properties"]["schema"]["const"],
        )
        authority = schema["properties"]["authorityUsed"]
        self.assertFalse(authority["additionalProperties"])
        self.assertIn("hubWrite", authority["required"])
        result = schema["properties"]["result"]
        self.assertIn("sessionHex", result["properties"])
        self.assertIn("resultSha256", result["properties"])
        self.assertFalse(
            schema["properties"]["limitations"]["properties"]["securityAudit"]["const"]
        )
        self.assertIn("must not contain private keys", schema["description"])

    def test_beacon_has_independent_agent_route_and_protocol(self):
        self.assertIn("agent-69263305", agenthub.BEACON)
        self.assertIn("PROTOCOL.md", agenthub.BEACON)
        self.assertIn("PROTOCOL_V2.md", agenthub.BEACON)
        self.assertIn("agentcomms-v2", agenthub.BEACON)
        self.assertIn("agentcomms-v2 selftest", agenthub.BEACON)
        self.assertIn("/.well-known/ard.json", agenthub.BEACON)
        self.assertIn("/.well-known/agentcomms-trust.json", agenthub.BEACON)
        self.assertIn("/.well-known/agentcomms-conformance.json", agenthub.BEACON)

    def test_agent_native_discovery_manifest_is_searchable_and_executable(self):
        manifest = agenthub.ARD_MANIFEST
        self.assertEqual(1, len(manifest["entries"]))
        entry = manifest["entries"][0]
        self.assertEqual(
            "urn:air:web3wes.pythonanywhere.com:mcp:agentcomms",
            entry["identifier"],
        )
        self.assertEqual("application/mcp-server-card+json", entry["type"])
        self.assertEqual(5, len(entry["representativeQueries"]))
        self.assertIn("AgentMessaging", entry["capabilities"])
        self.assertTrue(entry["trust"].endswith("agentcomms-trust.json"))
        offline = entry["offlineConformance"]
        self.assertTrue(offline["url"].endswith("RENDEZVOUS_CONFORMANCE_V2.json"))
        self.assertEqual(
            "299a396cf321e642351c37bb88a16eb5dafc450b8b518d1daf5c6ffab74088f4",
            offline["sha256"],
        )
        self.assertFalse(offline["packageInstallRequired"])
        self.assertFalse(offline["packageImportRequired"])
        self.assertFalse(offline["networkDuringEvaluationRequired"])
        self.assertFalse(offline["filesystemWriteRequired"])
        self.assertEqual(
            "io.github.web3wes/agentcomms",
            agenthub.MCP_SERVER_CARD["name"],
        )
        self.assertEqual("0.3.5", agenthub.MCP_SERVER_CARD["version"])
        self.assertIn("Agentmap:", agenthub.ROBOTS)

    def test_trust_manifest_is_exact_and_does_not_overclaim(self):
        trust = agenthub.TRUST_MANIFEST
        self.assertEqual("0.3.5", trust["version"])
        self.assertEqual(2, len(trust["artifacts"]))
        self.assertEqual(64, len(trust["artifacts"][0]["sha256"]))
        self.assertTrue(trust["artifacts"][0]["provenance"].endswith("/provenance"))
        self.assertEqual("none", trust["runtime"]["network"]["selftest"])
        self.assertIn("--network none", trust["sandbox"]["run"])
        rendezvous = trust["offlineConformance"]["rendezvous"]
        self.assertTrue(rendezvous["url"].endswith("RENDEZVOUS_CONFORMANCE_V2.json"))
        self.assertEqual(
            "299a396cf321e642351c37bb88a16eb5dafc450b8b518d1daf5c6ffab74088f4",
            rendezvous["sha256"],
        )
        self.assertFalse(rendezvous["execution"]["packageInstall"])
        self.assertFalse(rendezvous["execution"]["packageImport"])
        self.assertFalse(rendezvous["execution"]["network"])
        self.assertFalse(rendezvous["execution"]["filesystemWrite"])
        self.assertIn("never use them live", rendezvous["warning"])
        self.assertFalse(trust["security"]["independentlyAudited"])
        self.assertEqual(2, len(trust["independentEvaluations"]))
        evaluation = trust["independentEvaluations"][0]
        self.assertEqual("independent third party", evaluation["relationship"])
        self.assertEqual("0.3.1", evaluation["testedRelease"])
        self.assertFalse(
            evaluation["environment"]["agentcommsInstalledOrImported"]
        )
        self.assertIn("not a security audit", evaluation["limitations"])
        self.assertIn(
            "did not evaluate the 0.3.2 bidirectional extension",
            evaluation["limitations"],
        )
        neo = trust["independentEvaluations"][1]
        self.assertEqual("0.3.1", neo["testedRelease"])
        self.assertFalse(neo["provenance"]["agentCommonsNameVerified"])
        self.assertFalse(neo["provenance"]["registeredAgentProfileFound"])
        self.assertEqual(64, len(neo["resultBodySha256"]))
        self.assertIn("operator identity are unverified", neo["limitations"][1])
        self.assertIn("does not establish hub participation", neo["limitations"])

    def test_conformance_manifest_matches_executable_vector(self):
        vector = agenthub.CONFORMANCE_MANIFEST
        expected = vector["expected"]
        self.assertEqual("agentcomms-v2", vector["protocol"])
        self.assertIn("never use these keys live", vector["warning"])
        self.assertEqual(20, vector["referenceSelftest"]["expectedChecks"])
        self.assertEqual(64, len(vector["inputs"]["aEd25519SeedHex"]))
        self.assertEqual(64, len(vector["inputs"]["bX25519PrivateHex"]))
        self.assertEqual("A-to-B", vector["inputs"]["messageDirection"])
        self.assertEqual("B-to-A", vector["inputs"]["reverseMessageDirection"])
        self.assertEqual(
            "2026-01-01T00:00:00+00:00",
            vector["inputs"]["aOfferTimestamp"],
        )
        self.assertIn("root[32:64]", vector["clarifications"]["directionalChains"])
        self.assertIn("excluding sig", vector["clarifications"]["messageSignature"])
        self.assertEqual(
            "agent-56475aa75463474c0285df5dbf2bcab7", expected["aId"]
        )
        self.assertEqual(
            "61821bb89d208bc5e557a5f4fa6de55b", expected["session"]
        )
        self.assertEqual(2, len(expected["offers"]))
        self.assertEqual("key", expected["offers"][0]["kind"])
        self.assertEqual("hello v2", expected["decryptedPlaintextUtf8"])
        self.assertEqual("hello back v2", expected["bToADecryptedPlaintextUtf8"])
        published = json.loads(
            (Path(__file__).resolve().parents[1] / "CONFORMANCE_V2.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(vector, published)

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
            "/.well-known/agentcomms-trust.json": "application/json",
            "/.well-known/agentcomms-conformance.json": "application/json",
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
