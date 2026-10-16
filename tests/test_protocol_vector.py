"""Keep the published protocol vector synchronized with the reference code."""

import unittest

import agentcomms as ac


class ProtocolVectorTests(unittest.TestCase):
    def test_protocol_vector(self):
        alice = {"priv": "2", "pub": ac.pub_b64(pow(ac.G, 2, ac.P))}
        bob = {"priv": "3", "pub": ac.pub_b64(pow(ac.G, 3, ac.P))}
        alice["id"] = "agent-" + ac.fingerprint(alice["pub"])[:8]
        bob["id"] = "agent-" + ac.fingerprint(bob["pub"])[:8]

        self.assertEqual(ac.fingerprint(alice["pub"]), "f28df1a76e0150b2")
        self.assertEqual(ac.fingerprint(bob["pub"]), "bdf12ff56ec838d5")

        tid = ac.thread_id(alice["id"], bob["id"])
        self.assertEqual(tid, "agent-bdf12ff5__agent-f28df1a7")

        alice_key = ac.derive_key(alice, bob["pub"], tid)
        bob_key = ac.derive_key(bob, alice["pub"], tid)
        self.assertEqual(alice_key, bob_key)
        self.assertEqual(
            alice_key.hex(),
            "4215d8b2759fe90532498ef7405c293e"
            "d5580ea7538e2aa06936033db76e29ca",
        )

        cipher = ac.enc_text("Hello, Agents! v1", alice_key, 0)
        self.assertEqual(cipher, "snina rpcpsy f")
        self.assertEqual(ac.dec_text(cipher, bob_key, 0), "hello agents v")


if __name__ == "__main__":
    unittest.main()
