"""Protocol-v2 authenticated messaging tests."""

import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import agentcomms_v2 as v2


class MemoryRepo:
    def __init__(self, entries):
        self.entries = copy.deepcopy(entries)
        self.threads = {}

    def pull(self):
        pass

    def directory(self):
        return {"agents": copy.deepcopy(self.entries)}

    def lookup(self, agent_id):
        for entry in self.entries:
            if entry["id"] == agent_id:
                return copy.deepcopy(entry)
        return None

    def thread(self, tid):
        return copy.deepcopy(self.threads.get(tid, []))

    def append(self, tid, line, msg=None):
        self.threads.setdefault(tid, []).append(copy.deepcopy(line))


class ProtocolV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_home = v2.HOME
        root = Path(self.temp.name)
        self.a_home = root / "a"
        self.b_home = root / "b"
        v2.HOME = self.a_home
        self.a = v2.generate_identity("A")
        v2.HOME = self.b_home
        self.b = v2.generate_identity("B")
        self.repo = MemoryRepo([
            v2.directory_entry(self.a, "test"),
            v2.directory_entry(self.b, "test"),
        ])

    def tearDown(self):
        v2.HOME = self.old_home
        self.temp.cleanup()

    def establish(self):
        v2.HOME = self.a_home
        v2.ensure_hello_and_offer(self.repo, self.a, self.b["id"])
        v2.HOME = self.b_home
        v2.ensure_hello_and_offer(self.repo, self.b, self.a["id"])
        v2.HOME = self.a_home
        a_state = v2.establish_session(self.repo, self.a, self.b["id"])
        v2.HOME = self.b_home
        b_state = v2.establish_session(self.repo, self.b, self.a["id"])
        return a_state, b_state

    def test_interoperability_selftest_is_state_free(self):
        untouched_home = Path(self.temp.name) / "selftest-home"
        env = os.environ.copy()
        env["AGENTCOMMS_HOME"] = str(untouched_home)
        completed = subprocess.run(
            [sys.executable, str(Path(v2.__file__)), "selftest", "--json"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(20, result["checks"])
        self.assertEqual("61821bb89d208bc5e557a5f4fa6de55b", result["session"])
        self.assertEqual("hello back v2", result["reverse_plaintext"])
        self.assertFalse(untouched_home.exists())

    @mock.patch("agentcomms_v2._preflight_get_json")
    def test_preflight_is_read_only_and_reports_stale_trust(self, get_json):
        get_json.side_effect = [
            {
                "status": 200,
                "contentType": "application/json",
                "bytes": 20,
                "json": {"agents": [{"id": "agent-example"}]},
            },
            {
                "status": 200,
                "contentType": "application/json",
                "bytes": 20,
                "json": {"version": "0.3.1"},
            },
            {
                "status": 200,
                "contentType": "application/json",
                "bytes": 20,
                "json": {"name": "agentcomms"},
            },
        ]
        untouched_home = Path(self.temp.name) / "preflight-home"
        v2.HOME = untouched_home
        result = v2.read_only_preflight("https://hub.example")
        self.assertTrue(result["ok"])
        self.assertEqual("read-only", result["mode"])
        self.assertFalse(result["writesPerformed"])
        self.assertFalse(result["identityStateCreated"])
        self.assertEqual(1, result["directoryAgentCount"])
        self.assertFalse(result["trustMatchesExpectedRelease"])
        self.assertTrue(result["warnings"])
        self.assertFalse(untouched_home.exists())
        self.assertEqual(3, get_json.call_count)

    @mock.patch("agentcomms_v2._preflight_get_json")
    def test_rendezvous_filters_and_validates_without_identity_state(self, get_json):
        project = {"id": "agent-69263305", "protocol": "v1"}
        invalid = dict(v2.directory_entry(self.b, "untrusted"))
        invalid["fingerprint"] = "0" * 64
        get_json.return_value = {
            "status": 200,
            "contentType": "application/json",
            "bytes": 500,
            "json": {
                "agents": [
                    project,
                    v2.directory_entry(self.a, "local"),
                    invalid,
                    v2.directory_entry(self.b, "candidate"),
                ]
            },
        }
        untouched_home = Path(self.temp.name) / "rendezvous-home"
        v2.HOME = untouched_home
        result = v2.read_only_rendezvous("https://hub.example", self.a["id"])
        self.assertTrue(result["ok"])
        self.assertEqual(1, result["compatiblePeerCount"])
        self.assertEqual(self.b["id"], result["compatiblePeers"][0]["id"])
        self.assertEqual(1, result["invalidEntriesIgnored"])
        self.assertEqual(1, result["knownProjectEntriesExcluded"])
        self.assertFalse(result["writesPerformed"])
        self.assertFalse(result["identityStateCreated"])
        self.assertFalse(untouched_home.exists())
        get_json.assert_called_once_with("https://hub.example/directory")

    def test_identity_is_self_certifying_and_uses_128_bit_id(self):
        self.assertEqual(38, len(self.a["id"]))
        self.assertEqual(64, len(self.a["fingerprint"]))
        self.assertTrue(self.a["fingerprint"].startswith(self.a["id"][6:]))
        v2.validate_identity(self.a)
        v2.validate_directory_entry(self.repo.lookup(self.a["id"]), self.a["id"])

    def test_base64url_parser_is_strict_and_canonical(self):
        self.assertEqual(b"hello", v2.unb64u(v2.b64u(b"hello")))
        for malformed in ("a", "ab=", "ab+", "ab/", "ab whitespace"):
            with self.subTest(malformed=malformed), self.assertRaises(v2.SecurityError):
                v2.unb64u(malformed)

    def test_signed_ephemeral_handshake_agrees_and_erases_private_keys(self):
        a_state, b_state = self.establish()
        self.assertEqual(a_state["session"], b_state["session"])
        self.assertNotIn("pending", a_state)
        self.assertNotIn("pending", b_state)
        self.assertEqual(a_state["send_chain"], b_state["recv_chain"])
        self.assertEqual(a_state["recv_chain"], b_state["send_chain"])

    def test_authenticated_unicode_round_trip_ratchet_and_replay_rejection(self):
        self.establish()
        v2.HOME = self.a_home
        self.assertEqual(0, v2.send_message(
            self.repo, self.a, self.b["id"], "Hello, B — café 🔐"
        ))
        a_after = v2.load_state(self.b["id"])
        self.assertEqual(1, a_after["send_seq"])

        v2.HOME = self.b_home
        messages = v2.read_messages(self.repo, self.b, self.a["id"])
        self.assertEqual(["Hello, B — café 🔐"], [m["text"] for m in messages])
        self.assertEqual([], v2.read_messages(self.repo, self.b, self.a["id"]))

        tid = "__".join(sorted([self.a["id"], self.b["id"]]))
        self.repo.threads[tid].append(copy.deepcopy(self.repo.threads[tid][-1]))
        self.assertEqual([], v2.read_messages(self.repo, self.b, self.a["id"]))

    def test_ciphertext_or_signature_tampering_is_rejected(self):
        self.establish()
        v2.HOME = self.a_home
        v2.send_message(self.repo, self.a, self.b["id"], "authenticated")
        tid = "__".join(sorted([self.a["id"], self.b["id"]]))
        outer = self.repo.threads[tid][-1]
        envelope = v2.decode_envelope(outer["cipher"])
        envelope["cipher"] = ("A" if envelope["cipher"][0] != "A" else "B") + envelope["cipher"][1:]
        outer["cipher"] = v2.ENVELOPE_PREFIX + v2.b64u(v2.canonical(envelope))

        v2.HOME = self.b_home
        with self.assertRaisesRegex(v2.SecurityError, "signature"):
            v2.read_messages(self.repo, self.b, self.a["id"])

    def test_padding_hides_exact_short_plaintext_length(self):
        self.establish()
        v2.HOME = self.a_home
        v2.send_message(self.repo, self.a, self.b["id"], "x")
        tid = "__".join(sorted([self.a["id"], self.b["id"]]))
        first = v2.decode_envelope(self.repo.threads[tid][-1]["cipher"])
        first_size = len(v2.unb64u(first["cipher"]))
        v2.send_message(self.repo, self.a, self.b["id"], "x" * 100)
        second = v2.decode_envelope(self.repo.threads[tid][-1]["cipher"])
        self.assertEqual(first_size, len(v2.unb64u(second["cipher"])))

    def test_published_interoperability_vector(self):
        a_sign = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        b_sign = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        a_id = "agent-56475aa75463474c0285df5dbf2bcab7"
        b_id = "agent-24f6ed6acbfe1009c030d7ca567c33ca"
        self.assertEqual(a_id, v2.agent_id(v2.raw_public(a_sign.public_key())))
        self.assertEqual(b_id, v2.agent_id(v2.raw_public(b_sign.public_key())))

        a_x = x25519.X25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
        b_x = x25519.X25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
        a_body = {
            "v": 2, "kind": "key", "from": a_id, "to": b_id,
            "offer": "AAECAwQFBgcICQoLDA0ODw",
            "eph": "eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo",
            "ts": "2026-01-01T00:00:00+00:00",
        }
        b_body = {
            "v": 2, "kind": "key", "from": b_id, "to": a_id,
            "offer": "EBESExQVFhcYGRobHB0eHw",
            "eph": "Z13VdO13iTELPS52gfN5C0ZsdzsVIf7PNld5WDcepS8",
            "ts": "2026-01-01T00:00:01+00:00",
        }
        a_offer = {**a_body, "sig": v2.b64u(a_sign.sign(v2.canonical(a_body)))}
        b_offer = {**b_body, "sig": v2.b64u(b_sign.sign(v2.canonical(b_body)))}
        self.assertEqual(
            "cXA8Hwhe1ZnYi99Cwh-u0yfuyPTbVN5a9fSaNuzofS8JXX8fFKcgqwmeMDOEMXXyy1P1rABW0sjZRUbiprOJAw",
            a_offer["sig"],
        )
        self.assertEqual(
            "MLO-l2ERsYPMB__v_LyiqxkIZDi0V__5QCpYlxnVsr8hDAiz4mkmICw1sv4c_wDT_mGQ7i1Hk1KZiPl9NzX3AQ",
            b_offer["sig"],
        )
        transcript = v2.canonical(sorted([a_offer, b_offer], key=lambda offer: offer["from"]))
        tid = "__".join(sorted([a_id, b_id]))
        shared = a_x.exchange(b_x.public_key())
        self.assertEqual(
            "d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e",
            shared.hex(),
        )
        session = hashlib.sha256(b"agentcomms-v2/session\0" + transcript).hexdigest()[:32]
        self.assertEqual("61821bb89d208bc5e557a5f4fa6de55b", session)
        root = HKDF(
            algorithm=hashes.SHA256(), length=64,
            salt=hashlib.sha256(transcript).digest(),
            info=b"agentcomms-v2/root\0" + tid.encode("ascii"),
        ).derive(shared)
        self.assertEqual(
            "e66c517c0e885f0a5e8529e9793c72a54dfe66a389c20e69c59e594a7a9fd576"
            "c7079e0c701f53a3abd2b27b19773b5cf3720f237d5bd483cf70134bd61a5800",
            root.hex(),
        )
        a_chain = root[32:]
        message_key = hmac.new(
            a_chain, b"agentcomms-v2/message", hashlib.sha256
        ).digest()
        nonce = hmac.new(
            message_key, b"agentcomms-v2/nonce", hashlib.sha256
        ).digest()[:12]
        header = {
            "v": 2, "kind": "msg", "from": a_id, "to": b_id,
            "session": session, "seq": 0,
            "ts": "2026-01-01T00:00:02+00:00",
        }
        plaintext = b"hello v2"
        padded = len(plaintext).to_bytes(4, "big") + plaintext
        padded += bytes(256 - len(padded))
        cipher = ChaCha20Poly1305(message_key).encrypt(
            nonce, padded, v2.canonical(header)
        )
        self.assertEqual(
            "cGaiiBSoaEy-O3vU__Ov3x8Trj9BhQYA1SbFMMeef80KTb__dvAMSjQnZNpxQ87B7sW-c2Qvl-bGefXsoYFvShPKyTEwevRJnlwg-K1GAxp2-0RWUwnKMQAj-XBZ8v-74gmVxKvUIZk7LQpaGxubGqFYu7xiPv9WbDL1wsXJyqcKRbtskWIh-7iLx0DSDD_CClt80pgpnhVYXKn00J3Yrh1smOPapN3pIXewjezuWXUps0oU1kRu95-MTUZwSR_kWPNZuENgdcc3h9VWJJSvW5PvFdnqJpTe5MicwLQ11iwB0lka6O0taBQ0UhuVAbzsZa1ik_ZTfZiJicbuw6Bn7LZyZwAkSt55sz2Fu9U-CkM",
            v2.b64u(cipher),
        )
        body = {**header, "cipher": v2.b64u(cipher)}
        self.assertEqual(
            "-TQi5XuWWMRvyxr9Uu61Aa3XTyW71AU3YkVd5jgG2p5KpPUohMCiPtBK7M4GN6wjyoUjI7Rl0xscNmWXFz0gDQ",
            v2.b64u(a_sign.sign(v2.canonical(body))),
        )


if __name__ == "__main__":
    unittest.main()
