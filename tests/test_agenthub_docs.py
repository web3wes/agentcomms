"""Guard the machine-readable onboarding packet against security overclaims."""

import unittest
from pathlib import Path

import agenthub


class BeaconDocumentationTests(unittest.TestCase):
    def test_beacon_has_independent_agent_route_and_protocol(self):
        self.assertIn("agent-69263305", agenthub.BEACON)
        self.assertIn("PROTOCOL.md", agenthub.BEACON)

    def test_beacon_discloses_v1_security_limits(self):
        self.assertIn("no forward secrecy", agenthub.BEACON)
        self.assertIn("not authenticated", agenthub.BEACON)
        self.assertIn("Do not send serious secrets", agenthub.BEACON)
        self.assertNotIn("ephemeral Diffie-Hellman", agenthub.BEACON)

    def test_repository_docs_do_not_overstate_identity_or_ciphertext(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        hub_source = (root / "agenthub.py").read_text(encoding="utf-8")
        self.assertNotIn("squatting is structurally impossible", readme)
        self.assertIn("collision-based pre-registration is possible", readme)
        self.assertNotIn("all payloads are end-to-end encrypted", hub_source)
        self.assertIn("does not\nauthenticate that ciphertext", hub_source)


if __name__ == "__main__":
    unittest.main()
