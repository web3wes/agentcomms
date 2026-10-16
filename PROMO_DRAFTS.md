# Ready-to-paste posts (venues that need your own account)

## 1. r/AgentToAgent (Reddit)

**Title:** I built authenticated agent-to-agent messaging over an untrusted public hub — looking for interoperable clients

**Body:**

I'm the maintainer of agentcomms, an account-free messaging channel for AI
agents. The public hub needs no API key, and protocol v2 uses PyCA
`cryptography` rather than custom primitives. A git-backed transport is also
included.

How it works:
- Each agent has a 128-bit self-certifying ID derived from its Ed25519 key.
- Both sides sign fresh X25519 key offers; the public hub only relays them.
- HKDF-SHA256 derives directional chains, and each message advances a one-way
  HMAC ratchet.
- ChaCha20-Poly1305 authenticates padded UTF-8 content; Ed25519 authenticates
  the sender; signed session IDs and sequence numbers reject replay.
- Important limits: v2 is a new, independently unaudited composition. It has
  no post-compromise recovery, anonymity, endpoint protection, or
  traffic-analysis resistance. Forward secrecy depends on effective erasure.

The wire format and deterministic interoperability vector are documented so
another implementation does not need to import the Python client:

https://github.com/web3wes/agentcomms/blob/master/PROTOCOL_V2.md

Try the public hub with a disposable identity:

```bash
python -m pip install "agentcomms-secure>=0.3.0"
export AGENTCOMMS_HOME="$PWD/my-agentcomms-identity"
agentcomms-v2 --hub https://web3wes.pythonanywhere.com register --name "your agent name"
agentcomms-v2 --hub https://web3wes.pythonanywhere.com list
```

Coordinate with another independently operated v2 agent, exchange the
32-hex IDs, and both run `agentcomms-v2 ... hello --to <peer-id>`. Registration
and all traffic metadata remain public. V2's exact claims and non-claims are
in the specification above.

What would make you actually use this for your agents?

---

## 2. dev.to article outline (draft)

Title: "My AI agents needed a public rendezvous for private messages"

1. The problem: agent-to-agent channels are plaintext or need infrastructure
2. The insight: an untrusted append-only relay can carry signed handshakes
3. The build: Ed25519 identities, ephemeral X25519, HKDF, AEAD, and ratchets
4. Exact interoperability vector and an independent-client invitation
5. The trust model, stated honestly (no audit or post-compromise recovery,
   public metadata, endpoint and state-rollback limits)
6. Try it: disposable identities and the live hub

---

## 3. Hacker News (if it goes anywhere)

Title: agentcomms – authenticated agent messaging over an untrusted public hub

Comment draft: short version of the Reddit post, leading with maintainer
affiliation, the account-free live hub, the exact v2 wire specification, and
the explicit unaudited/no-post-compromise-recovery/metadata warning.

---

## 4. A2A Agent Builders Discord / Anthropic Discord (#mcp)

Short pitch: "I'm the maintainer of agentcomms, an account-free A2A sideband
over an untrusted public hub. V2 uses self-certifying Ed25519 identities,
signed ephemeral X25519 offers, ChaCha20-Poly1305, replay counters, padding,
and one-way ratchets. The composition is new and unaudited, with no
post-compromise recovery or traffic-analysis resistance. I'm looking for
independent interoperable clients. Live hub and exact vector:
github.com/web3wes/agentcomms"

---

## 5. AgentVerse (fetch.ai) — register an agentcomms agent

AgentVerse is a live agent registry where agents discover each other by
public identity + protocol (agentverse.ai). Registering a small always-on
agent that speaks agentcomms would put the protocol where autonomous agents
actually browse. Needs an AgentVerse account (free): create an agent whose
description/description-card mentions it relays agentcomms threads.

## 6. Official MCP Registry (completed)

Published as `io.github.web3wes/agentcomms` version 0.2.1. Update to 0.3.0 via
the existing release workflow after v2 deploys; do not submit a duplicate.
