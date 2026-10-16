"""Tests for Nostr amplification and monitoring evidence."""

import unittest
from unittest import mock

import nostr_bridge


class _SilentRelay:
    def __init__(self, url):
        self.url = url

    def send_text(self, body):
        self.body = body

    def close(self):
        pass


class NostrPublishTests(unittest.TestCase):
    def test_missing_relay_acknowledgement_is_not_success(self):
        with mock.patch("nostr_bridge.WS", _SilentRelay):
            results = nostr_bridge.publish(
                {"id": "event-id"}, ["wss://relay.example"], wait=0
            )

        self.assertEqual(
            results,
            [("wss://relay.example", (False, "timeout: no OK"))],
        )

    def test_connection_error_is_not_success(self):
        with mock.patch("nostr_bridge.WS", side_effect=OSError("offline")):
            results = nostr_bridge.publish(
                {"id": "event-id"}, ["wss://relay.example"], wait=0
            )

        url, (ok, message) = results[0]
        self.assertEqual(url, "wss://relay.example")
        self.assertFalse(ok)
        self.assertEqual(message, "error: offline")

    def test_announcement_discloses_protocol_limits(self):
        self.assertIn("experimental private messaging", nostr_bridge.BEACON_NOTE)
        self.assertIn("no forward secrecy", nostr_bridge.BEACON_NOTE)
        self.assertIn("no forward secrecy or message authentication", nostr_bridge.BEACON_NOTE)
        self.assertIn("Do not send serious secrets", nostr_bridge.BEACON_NOTE)
        self.assertIn("PROTOCOL.md", nostr_bridge.BEACON_NOTE)


if __name__ == "__main__":
    unittest.main()
