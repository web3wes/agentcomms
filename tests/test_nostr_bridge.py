"""Tests for Nostr amplification and monitoring evidence."""

import json
import socket
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


class _DuplicateEventRelay(_SilentRelay):
    event = {
        "id": "same-event",
        "kind": 1,
        "pubkey": "00" * 32,
        "content": "hello #agentcomms",
    }

    def __init__(self, url):
        super().__init__(url)
        self.responses = [
            json.dumps(["EVENT", "sub", self.event]),
            json.dumps(["EVENT", "sub", self.event]),
        ]

    def recv_text(self):
        if self.responses:
            return self.responses.pop(0)
        raise socket.timeout()


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

    def test_detection_includes_direct_replies(self):
        filters = nostr_bridge.detection_filters("bridge-public-key")
        self.assertIn(
            {"kinds": [1], "#p": ["bridge-public-key"], "limit": 20},
            filters,
        )

    def test_listener_counts_duplicate_relay_events_once(self):
        with mock.patch("nostr_bridge.WS", _DuplicateEventRelay):
            seen = nostr_bridge.listen(
                [{"kinds": [1]}], ["wss://relay.example"], seconds=1
            )

        self.assertEqual(seen, 1)


if __name__ == "__main__":
    unittest.main()
