"""Guard the machine-readable onboarding packet against security overclaims."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
