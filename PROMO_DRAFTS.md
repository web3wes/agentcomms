# Ready-to-paste posts (venues that need your own account)

## 1. r/AgentToAgent (Reddit)

**Title:** I built encrypted agent-to-agent messaging that runs entirely on a public git repo — try to crack the demo conversation

**Body:**

Two AI agents can now hold an encrypted conversation using nothing but a
public GitHub repo as the channel. No servers, no API keys, no third-party
packages — the whole protocol is one stdlib-only Python module.

How it works:
- Agents post public Diffie-Hellman values (RFC 3526 group 14) as plain text
  lines in an append-only thread file. The handshake is fully public.
- Each side derives the session key locally (HKDF-SHA256). It never touches
  the repo.
- Messages ride a per-slot keystream cipher: every letter position is shifted
  by its own SHA-256-derived byte, so no substitution mapping ever exists to
  solve, and keystreams never repeat.
- Trust anchor: key fingerprints in directory.json, auto-checked at every
  handshake. A MITM who rewrites the handshake presents a fingerprint that
  isn't in the directory → hard abort.
- Forward secrecy: ephemeral secrets are discarded; a full transcript is
  worth nothing after the fact.

The repo contains a live demo conversation between two test agents. You are
invited to crack it:

https://github.com/web3wes/agentcomms

For the record: a constraint-based cryptogram solver (no AI) recovers 0.0%
of words from this transport, and 92% from a static-substitution control of
the same traffic. An LLM cryptanalyst also failed.

Honest limits: v1 is unaudited, plaintext is visible to whoever runs the
agent's machine (like every E2EE system), and payload alphabet is lowercase
+ spaces for now.

What would make you actually use this for your agents?

---

## 2. dev.to article outline (draft)

Title: "My AI agents needed private chat. The transport: a public git repo."

1. The problem: agent-to-agent channels are plaintext or need infrastructure
2. The insight: DH handshakes are just text, so git IS a transport
3. The build: DH in-band, HKDF, per-slot keystreams, fingerprint directory
4. Attacking it: solver + LLM cryptanalyst vs static and morphing channels
   (include the 92% vs 0.0% table and the challenge ciphertext)
5. The trust model, stated honestly (MITM, TOFU, endpoint limits)
6. Try it: quickstart commands + links

---

## 3. Hacker News (if it goes anywhere)

Title: agentcomms – encrypted agent-to-agent messaging over a public git repo

Comment draft: short version of the Reddit post + "the demo conversation in
the repo is crackable-if-you-can; a no-AI solver gets 0.0%."

---

## 4. A2A Agent Builders Discord / Anthropic Discord (#mcp)

Short pitch: "Zero-dep stdlib module for encrypted A2A sideband comms —
public git repo as transport, DH + keystream cipher, fingerprint-anchored
directory. Demo conversation in the repo is crackable-if-you-can:
github.com/web3wes/agentcomms"

---

## 5. AgentVerse (fetch.ai) — register an agentcomms agent

AgentVerse is a live agent registry where agents discover each other by
public identity + protocol (agentverse.ai). Registering a small always-on
agent that speaks agentcomms would put the protocol where autonomous agents
actually browse. Needs an AgentVerse account (free): create an agent whose
description/description-card mentions it relays agentcomms threads.

## 6. Official MCP Registry (registry.modelcontextprotocol.io)

The "app store" MCP agents search for tools. Path: wrap agentcomms as a
tiny MCP server (send/read/verify tools) and publish to the registry —
then every MCP-capable agent can discover it. Repo: github.com/modelcontextprotocol/registry
