#!/usr/bin/env python3
"""agentcomms protocol v2: authenticated, forward-secure agent messaging.

Version 2 is additive: it uses distinct identities and can share the same
append-only hub with protocol v1.  Identity handshakes are signed with
Ed25519, sessions use ephemeral X25519, and messages use a per-direction
hash ratchet plus ChaCha20-Poly1305 and Ed25519 signatures.

Security scope: v2 authenticates agents by their self-certifying key IDs,
detects message modification and replay, and protects past established
sessions after later identity-key compromise when erased ephemeral and chain
keys cannot be recovered.  It does not provide post-compromise recovery,
traffic-analysis resistance, endpoint security, or audited assurance.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover - exercised by installed CLI
    raise SystemExit(
        "Protocol v2 requires PyCA cryptography. Install with: "
        "python -m pip install 'agentcomms-secure>=0.3.3'"
    ) from exc

import agentcomms

PROTOCOL = "v2"
ENVELOPE_PREFIX = "v2:"
MAX_PLAINTEXT = 256 * 1024
PAD_BLOCK = 256
MAX_SKIP = 1000
HOME = Path(os.environ.get("AGENTCOMMS_HOME", Path.home() / ".agentcomms"))
DEFAULT_HUB = "https://web3wes.pythonanywhere.com"


class SecurityError(Exception):
    """An authenticated v2 invariant failed; callers must stop processing."""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(value):
    if not isinstance(value, str):
        raise SecurityError("encoded binary value must be a string")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value) or len(value) % 4 == 1:
        raise SecurityError("invalid base64url value")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except Exception as exc:
        raise SecurityError("invalid base64url value") from exc
    if b64u(raw) != value:
        raise SecurityError("non-canonical base64url value")
    return raw


def raw_public(key):
    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def raw_private(key):
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def fingerprint(pub_bytes):
    return hashlib.sha256(pub_bytes).hexdigest()


def agent_id(pub_bytes):
    return "agent-" + fingerprint(pub_bytes)[:32]


def identity_path():
    return HOME / "identity_v2.json"


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            json.dump(value, out, indent=2, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def generate_identity(name):
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be non-empty")
    key = ed25519.Ed25519PrivateKey.generate()
    pub = raw_public(key.public_key())
    ident = {
        "protocol": PROTOCOL,
        "name": name.strip(),
        "id": agent_id(pub),
        "fingerprint": fingerprint(pub),
        "pub": base64.b64encode(pub).decode("ascii"),
        "priv": b64u(raw_private(key)),
        "created": now(),
    }
    _atomic_json(identity_path(), ident)
    return ident


def validate_identity(ident):
    required = {"protocol", "name", "id", "fingerprint", "pub", "priv"}
    if not isinstance(ident, dict) or not required.issubset(ident):
        raise SecurityError("invalid v2 identity file")
    if ident["protocol"] != PROTOCOL:
        raise SecurityError("identity is not protocol v2")
    try:
        private = ed25519.Ed25519PrivateKey.from_private_bytes(unb64u(ident["priv"]))
        pub = raw_public(private.public_key())
        encoded_pub = base64.b64decode(ident["pub"], validate=True)
    except (ValueError, TypeError) as exc:
        raise SecurityError("invalid v2 identity key material") from exc
    if not hmac.compare_digest(pub, encoded_pub):
        raise SecurityError("identity public key does not match private key")
    if ident["fingerprint"] != fingerprint(pub) or ident["id"] != agent_id(pub):
        raise SecurityError("identity fingerprint or id does not match public key")
    return ident


def load_identity():
    path = identity_path()
    if not path.exists():
        raise RuntimeError("No v2 identity found. Run: agentcomms-v2 register --name <name>")
    return validate_identity(json.loads(path.read_text(encoding="utf-8")))


def directory_entry(ident, contact=""):
    validate_identity(ident)
    return {
        "id": ident["id"],
        "name": ident["name"],
        "fingerprint": ident["fingerprint"],
        "pub": ident["pub"],
        "protocol": PROTOCOL,
        "contact": contact or "hub",
        "registered": now(),
    }


def validate_directory_entry(entry, expected_id=None):
    if not isinstance(entry, dict) or entry.get("protocol") != PROTOCOL:
        raise SecurityError("peer is not registered as protocol v2")
    try:
        pub = base64.b64decode(entry["pub"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise SecurityError("peer directory public key is invalid") from exc
    if len(pub) != 32:
        raise SecurityError("peer Ed25519 public key must be 32 bytes")
    expected_fp = fingerprint(pub)
    expected_agent = agent_id(pub)
    if entry.get("fingerprint") != expected_fp or entry.get("id") != expected_agent:
        raise SecurityError("peer directory identity is not self-certifying")
    if expected_id is not None and entry["id"] != expected_id:
        raise SecurityError("peer directory id mismatch")
    return pub


def register(repo, ident, contact=""):
    entry = directory_entry(ident, contact)
    if isinstance(repo, agentcomms.HubRepo):
        code, response = agentcomms._http(
            "POST", repo.base + "/register", agentcomms.mine(entry)
        )
        if code != 200:
            raise RuntimeError("register failed: " + str(response.get("msg")))
        return f"registered: {ident['id']} fp={ident['fingerprint']} ({response.get('msg')})"

    repo.pull()
    data = repo.directory()
    agents = data.setdefault("agents", [])
    for existing in agents:
        if existing.get("id") == ident["id"]:
            validate_directory_entry(existing, ident["id"])
            return f"already registered: {ident['id']}"
    agents.append(entry)
    path = repo.dir / "directory.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if not repo._commit_push(f"register v2 {ident['id']}"):
        raise RuntimeError(
            "Could not push. Open a PR adding this v2 entry to directory.json:\n\n"
            + json.dumps(entry, indent=2)
        )
    return f"registered: {ident['id']} fp={ident['fingerprint']}"


def signing_private(ident):
    validate_identity(ident)
    return ed25519.Ed25519PrivateKey.from_private_bytes(unb64u(ident["priv"]))


def signing_public_from_entry(entry, expected_id=None):
    return ed25519.Ed25519PublicKey.from_public_bytes(
        validate_directory_entry(entry, expected_id)
    )


def encode_envelope(body, signing_key):
    envelope = dict(body)
    envelope["sig"] = b64u(signing_key.sign(canonical(body)))
    return ENVELOPE_PREFIX + b64u(canonical(envelope))


def decode_envelope(cipher):
    if not isinstance(cipher, str) or not cipher.startswith(ENVELOPE_PREFIX):
        return None
    try:
        envelope = json.loads(unb64u(cipher[len(ENVELOPE_PREFIX):]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError("malformed v2 envelope") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("sig"), str):
        raise SecurityError("v2 envelope lacks a signature")
    return envelope


def verify_envelope(envelope, public_key):
    body = {k: v for k, v in envelope.items() if k != "sig"}
    try:
        public_key.verify(unb64u(envelope["sig"]), canonical(body))
    except (InvalidSignature, ValueError) as exc:
        raise SecurityError("invalid v2 envelope signature") from exc
    return body


def session_path(peer_id):
    if not isinstance(peer_id, str) or not peer_id.startswith("agent-"):
        raise ValueError("invalid peer id")
    return HOME / "sessions_v2" / (peer_id + ".json")


def load_state(peer_id):
    path = session_path(peer_id)
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("peer") != peer_id:
        raise SecurityError("invalid local v2 session state")
    return value


def save_state(peer_id, state):
    state = dict(state)
    state["peer"] = peer_id
    _atomic_json(session_path(peer_id), state)


@contextmanager
def peer_lock(peer_id, timeout=10):
    path = session_path(peer_id).with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "another v2 operation holds this peer session lock; if a "
                    "prior process crashed, inspect and remove the .lock file "
                    "manually before retrying"
                )
            time.sleep(0.1)
    try:
        os.write(fd, f"{os.getpid()} {time.time()}\n".encode())
        os.close(fd)
        fd = None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def lookup_v2(repo, peer_id):
    entry = repo.lookup(peer_id)
    if entry is None:
        raise SecurityError(f"{peer_id} is not in the directory")
    validate_directory_entry(entry, peer_id)
    return entry


def v2_records(lines):
    records = []
    for outer in lines:
        if outer.get("type") != "msg":
            continue
        envelope = decode_envelope(outer.get("cipher"))
        if envelope is not None:
            records.append((outer, envelope))
    return records


def _find_own_hello(lines, ident):
    for line in lines:
        if (
            line.get("type") == "hello"
            and line.get("from") == ident["id"]
            and line.get("pub") == ident["pub"]
        ):
            return line
    return None


def _offer_body(ident, peer_id, eph_public):
    return {
        "v": 2,
        "kind": "key",
        "from": ident["id"],
        "to": peer_id,
        "offer": b64u(secrets.token_bytes(16)),
        "eph": b64u(eph_public),
        "ts": now(),
    }


def _post_outer(repo, tid, ident, cipher, label):
    lines = repo.thread(tid)
    slot = len(agentcomms.msgs(lines))
    repo.append(
        tid,
        {"type": "msg", "from": ident["id"], "slot": slot,
         "cipher": cipher, "ts": now()},
        label,
    )


def ensure_hello_and_offer(repo, ident, peer_id):
    validate_identity(ident)
    lookup_v2(repo, ident["id"])
    lookup_v2(repo, peer_id)
    tid = agentcomms.thread_id(ident["id"], peer_id)
    lines = repo.thread(tid)
    if _find_own_hello(lines, ident) is None:
        repo.append(
            tid,
            {"type": "hello", "from": ident["id"], "pub": ident["pub"],
             "ts": now()},
            f"v2 hello {ident['id']} -> {peer_id}",
        )
        lines = repo.thread(tid)

    state = load_state(peer_id)
    if state.get("session"):
        return state
    pending = state.get("pending")
    if pending:
        cipher = pending.get("cipher")
        if any(outer.get("cipher") == cipher for outer, _ in v2_records(lines)):
            return state
    else:
        eph_private = x25519.X25519PrivateKey.generate()
        body = _offer_body(ident, peer_id, raw_public(eph_private.public_key()))
        cipher = encode_envelope(body, signing_private(ident))
        pending = {"cipher": cipher, "eph_priv": b64u(raw_private(eph_private))}
        state = {"peer": peer_id, "pending": pending}
        save_state(peer_id, state)

    _post_outer(repo, tid, ident, pending["cipher"],
                f"v2 key offer {ident['id']} -> {peer_id}")
    return state


def _verified_offer(outer, envelope, repo, sender, recipient):
    if outer.get("from") != sender:
        return None
    entry = lookup_v2(repo, sender)
    body = verify_envelope(envelope, signing_public_from_entry(entry, sender))
    required = {"v", "kind", "from", "to", "offer", "eph", "ts"}
    if set(body) != required or body.get("v") != 2 or body.get("kind") != "key":
        return None
    if body.get("from") != sender or body.get("to") != recipient:
        return None
    if len(unb64u(body["offer"])) != 16 or len(unb64u(body["eph"])) != 32:
        raise SecurityError("invalid v2 key offer lengths")
    return {**body, "sig": envelope["sig"]}


def establish_session(repo, ident, peer_id):
    state = ensure_hello_and_offer(repo, ident, peer_id)
    if state.get("session"):
        if state.get("peer_fingerprint") != lookup_v2(repo, peer_id)["fingerprint"]:
            raise SecurityError("peer identity changed after session establishment")
        return state

    tid = agentcomms.thread_id(ident["id"], peer_id)
    lines = repo.thread(tid)
    peer_offers = []
    own_offer = None
    pending_cipher = state["pending"]["cipher"]
    for outer, envelope in v2_records(lines):
        if outer.get("cipher") == pending_cipher:
            own_offer = _verified_offer(
                outer, envelope, repo, ident["id"], peer_id
            )
        elif outer.get("from") == peer_id:
            candidate = _verified_offer(
                outer, envelope, repo, peer_id, ident["id"]
            )
            if candidate is not None:
                peer_offers.append(candidate)
    if own_offer is None:
        raise RuntimeError("local v2 key offer is not visible on the transport")
    if not peer_offers:
        raise RuntimeError(
            f"No authenticated v2 key offer from {peer_id}. They must run: "
            f"agentcomms-v2 --hub <hub> hello --to {ident['id']}"
        )
    peer_offer = peer_offers[-1]

    try:
        local_private = x25519.X25519PrivateKey.from_private_bytes(
            unb64u(state["pending"]["eph_priv"])
        )
        peer_public = x25519.X25519PublicKey.from_public_bytes(
            unb64u(peer_offer["eph"])
        )
        shared = local_private.exchange(peer_public)
    except ValueError as exc:
        raise SecurityError("invalid v2 ephemeral key") from exc

    offers = sorted([own_offer, peer_offer], key=lambda offer: offer["from"])
    transcript = canonical(offers)
    session_id = hashlib.sha256(b"agentcomms-v2/session\0" + transcript).hexdigest()[:32]
    root = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=b"agentcomms-v2/root\0" + tid.encode("ascii"),
    ).derive(shared)
    low_id = min(ident["id"], peer_id)
    low_send, high_send = root[:32], root[32:]
    send_chain = low_send if ident["id"] == low_id else high_send
    recv_chain = high_send if ident["id"] == low_id else low_send
    established = {
        "peer": peer_id,
        "peer_fingerprint": lookup_v2(repo, peer_id)["fingerprint"],
        "session": session_id,
        "send_chain": b64u(send_chain),
        "recv_chain": b64u(recv_chain),
        "send_seq": 0,
        "recv_seq": 0,
        "established": now(),
    }
    save_state(peer_id, established)
    return established


def _ratchet(chain):
    message_key = hmac.new(chain, b"agentcomms-v2/message", hashlib.sha256).digest()
    next_chain = hmac.new(chain, b"agentcomms-v2/chain", hashlib.sha256).digest()
    return message_key, next_chain


def _pad(plaintext):
    raw = plaintext.encode("utf-8")
    if len(raw) > MAX_PLAINTEXT:
        raise ValueError(f"message exceeds {MAX_PLAINTEXT} UTF-8 bytes")
    framed = len(raw).to_bytes(4, "big") + raw
    target = max(PAD_BLOCK, ((len(framed) + PAD_BLOCK - 1) // PAD_BLOCK) * PAD_BLOCK)
    return framed + secrets.token_bytes(target - len(framed))


def _unpad(payload):
    if len(payload) < 4 or len(payload) % PAD_BLOCK:
        raise SecurityError("invalid v2 padded plaintext")
    length = int.from_bytes(payload[:4], "big")
    if length > len(payload) - 4 or length > MAX_PLAINTEXT:
        raise SecurityError("invalid v2 plaintext length")
    try:
        return payload[4:4 + length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecurityError("v2 plaintext is not UTF-8") from exc


def send_message(repo, ident, peer_id, text):
    if not isinstance(text, str) or not text:
        raise ValueError("text must be non-empty")
    with peer_lock(peer_id):
        state = establish_session(repo, ident, peer_id)
        seq = state["send_seq"]
        message_key, next_chain = _ratchet(unb64u(state["send_chain"]))
        header = {
            "v": 2,
            "kind": "msg",
            "from": ident["id"],
            "to": peer_id,
            "session": state["session"],
            "seq": seq,
            "ts": now(),
        }
        nonce = hmac.new(message_key, b"agentcomms-v2/nonce", hashlib.sha256).digest()[:12]
        ciphertext = ChaCha20Poly1305(message_key).encrypt(
            nonce, _pad(text), canonical(header)
        )
        body = {**header, "cipher": b64u(ciphertext)}
        encoded = encode_envelope(body, signing_private(ident))

        # Advance before the network write. An ambiguous failure therefore
        # skips a sequence number instead of ever reusing a message key.
        state["send_chain"] = b64u(next_chain)
        state["send_seq"] = seq + 1
        save_state(peer_id, state)
        tid = agentcomms.thread_id(ident["id"], peer_id)
        _post_outer(repo, tid, ident, encoded,
                    f"v2 msg {ident['id']} -> {peer_id} seq {seq}")
        return seq


def _verified_message(outer, envelope, repo, sender, recipient, session):
    if outer.get("from") != sender:
        return None
    entry = lookup_v2(repo, sender)
    body = verify_envelope(envelope, signing_public_from_entry(entry, sender))
    required = {"v", "kind", "from", "to", "session", "seq", "ts", "cipher"}
    if set(body) != required or body.get("v") != 2 or body.get("kind") != "msg":
        return None
    if body["from"] != sender or body["to"] != recipient:
        raise SecurityError("v2 message participants do not match its thread")
    if body["session"] != session:
        return None
    if not isinstance(body["seq"], int) or body["seq"] < 0:
        raise SecurityError("invalid v2 sequence number")
    return body


def read_messages(repo, ident, peer_id):
    with peer_lock(peer_id):
        state = establish_session(repo, ident, peer_id)
        tid = agentcomms.thread_id(ident["id"], peer_id)
        candidates = []
        for outer, envelope in v2_records(repo.thread(tid)):
            if outer.get("from") != peer_id:
                continue
            body = _verified_message(
                outer, envelope, repo, peer_id, ident["id"], state["session"]
            )
            if body is not None and body["seq"] >= state["recv_seq"]:
                candidates.append(body)
        candidates.sort(key=lambda body: body["seq"])
        if len({body["seq"] for body in candidates}) != len(candidates):
            raise SecurityError("duplicate authenticated v2 sequence number")

        output = []
        for body in candidates:
            gap = body["seq"] - state["recv_seq"]
            if gap > MAX_SKIP:
                raise SecurityError("v2 sequence gap exceeds safety limit")
            chain = unb64u(state["recv_chain"])
            message_key = None
            for _ in range(gap + 1):
                message_key, chain = _ratchet(chain)
            header = {k: v for k, v in body.items() if k != "cipher"}
            nonce = hmac.new(
                message_key, b"agentcomms-v2/nonce", hashlib.sha256
            ).digest()[:12]
            try:
                padded = ChaCha20Poly1305(message_key).decrypt(
                    nonce, unb64u(body["cipher"]), canonical(header)
                )
            except InvalidTag as exc:
                raise SecurityError("v2 ciphertext authentication failed") from exc
            text = _unpad(padded)
            state["recv_chain"] = b64u(chain)
            state["recv_seq"] = body["seq"] + 1
            save_state(peer_id, state)
            output.append({"seq": body["seq"], "ts": body["ts"], "text": text})
        return output


def make_repo(args):
    if getattr(args, "hub", None):
        return agentcomms.HubRepo(args.hub)
    return agentcomms.Repo(args.repo)


def _preflight_get_json(url, timeout=15):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "agentcomms-v2-preflight/0.3.3"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        requested = urllib.parse.urlsplit(url)
        final = urllib.parse.urlsplit(response.geturl())
        if (requested.scheme, requested.netloc) != (final.scheme, final.netloc):
            raise RuntimeError("preflight refused a cross-origin redirect")
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise RuntimeError("preflight response exceeds 1 MiB")
        return {
            "status": response.status,
            "contentType": response.headers.get_content_type(),
            "bytes": len(body),
            "json": json.loads(body.decode("utf-8")),
        }


def read_only_preflight(hub):
    """Inspect public hub metadata without creating identity state or writing."""
    base = hub.rstrip("/")
    if not re.fullmatch(r"https?://[^/]+(?:/.*)?", base):
        raise ValueError("hub must be an absolute HTTP(S) URL")
    paths = (
        "/directory",
        "/.well-known/agentcomms-trust.json",
        "/.well-known/ard.json",
    )
    observations = []
    payloads = {}
    for path in paths:
        try:
            result = _preflight_get_json(base + path)
            payloads[path] = result.pop("json")
            observations.append({"method": "GET", "path": path, **result})
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            observations.append({
                "method": "GET",
                "path": path,
                "error": type(exc).__name__,
            })
    directory = payloads.get("/directory", {})
    trust = payloads.get("/.well-known/agentcomms-trust.json", {})
    ard = payloads.get("/.well-known/ard.json", {})
    all_ok = len(observations) == len(paths) and all(
        item.get("status") == 200 for item in observations
    )
    trust_version = trust.get("version")
    warnings = []
    if trust_version != "0.3.3":
        warnings.append(
            "live trust metadata does not yet identify release 0.3.3; "
            "verify the versioned GitHub release evidence before execution"
        )
    return {
        "ok": all_ok,
        "mode": "read-only",
        "hub": base,
        "requests": observations,
        "writesPerformed": False,
        "identityStateCreated": False,
        "directoryAgentCount": len(directory.get("agents", [])),
        "trustVersion": trust_version,
        "expectedRelease": "0.3.3",
        "trustMatchesExpectedRelease": trust_version == "0.3.3",
        "ardPresent": isinstance(ard, dict) and bool(ard),
        "warnings": warnings,
        "nextStep": (
            "Run agentcomms-v2 selftest --json. Registration remains a "
            "separate explicit write and is never performed by preflight."
        ),
    }


def interoperability_selftest():
    """Reproduce the public PROTOCOL_V2.md vector without state or network I/O."""

    def require(label, actual, expected):
        if actual != expected:
            raise SecurityError(
                f"interoperability selftest failed at {label}: "
                f"expected {expected!r}, got {actual!r}"
            )

    a_sign = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    b_sign = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    a_id = agent_id(raw_public(a_sign.public_key()))
    b_id = agent_id(raw_public(b_sign.public_key()))
    require("A id", a_id, "agent-56475aa75463474c0285df5dbf2bcab7")
    require("B id", b_id, "agent-24f6ed6acbfe1009c030d7ca567c33ca")

    a_x = x25519.X25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    b_x = x25519.X25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    a_body = {
        "v": 2,
        "kind": "key",
        "from": a_id,
        "to": b_id,
        "offer": "AAECAwQFBgcICQoLDA0ODw",
        "eph": "eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo",
        "ts": "2026-01-01T00:00:00+00:00",
    }
    b_body = {
        "v": 2,
        "kind": "key",
        "from": b_id,
        "to": a_id,
        "offer": "EBESExQVFhcYGRobHB0eHw",
        "eph": "Z13VdO13iTELPS52gfN5C0ZsdzsVIf7PNld5WDcepS8",
        "ts": "2026-01-01T00:00:01+00:00",
    }
    a_offer = {**a_body, "sig": b64u(a_sign.sign(canonical(a_body)))}
    b_offer = {**b_body, "sig": b64u(b_sign.sign(canonical(b_body)))}
    require(
        "A offer signature",
        a_offer["sig"],
        "cXA8Hwhe1ZnYi99Cwh-u0yfuyPTbVN5a9fSaNuzofS8JXX8fFKcgqwmeMDOEMXXy"
        "y1P1rABW0sjZRUbiprOJAw",
    )
    require(
        "B offer signature",
        b_offer["sig"],
        "MLO-l2ERsYPMB__v_LyiqxkIZDi0V__5QCpYlxnVsr8hDAiz4mkmICw1sv4c_wDT_"
        "mGQ7i1Hk1KZiPl9NzX3AQ",
    )
    a_sign.public_key().verify(unb64u(a_offer["sig"]), canonical(a_body))
    b_sign.public_key().verify(unb64u(b_offer["sig"]), canonical(b_body))

    transcript = canonical(sorted([a_offer, b_offer], key=lambda offer: offer["from"]))
    tid = "__".join(sorted([a_id, b_id]))
    shared = a_x.exchange(b_x.public_key())
    require(
        "X25519 shared secret",
        shared.hex(),
        "d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e",
    )
    require("X25519 symmetry", b_x.exchange(a_x.public_key()), shared)
    session = hashlib.sha256(b"agentcomms-v2/session\0" + transcript).hexdigest()[:32]
    require("session id", session, "61821bb89d208bc5e557a5f4fa6de55b")
    root = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=b"agentcomms-v2/root\0" + tid.encode("ascii"),
    ).derive(shared)
    require(
        "HKDF root",
        root.hex(),
        "e66c517c0e885f0a5e8529e9793c72a54dfe66a389c20e69c59e594a7a9fd576"
        "c7079e0c701f53a3abd2b27b19773b5cf3720f237d5bd483cf70134bd61a5800",
    )

    a_chain = root[32:]
    message_key = hmac.new(
        a_chain, b"agentcomms-v2/message", hashlib.sha256
    ).digest()
    require(
        "message key",
        message_key.hex(),
        "95c51ffa1d688342050e3956906da49b634c7082e7744e44ee5cdb1f0dc959db",
    )
    nonce = hmac.new(
        message_key, b"agentcomms-v2/nonce", hashlib.sha256
    ).digest()[:12]
    require("nonce", nonce.hex(), "5aaeda08a1b98f17edb1bfa2")
    header = {
        "v": 2,
        "kind": "msg",
        "from": a_id,
        "to": b_id,
        "session": session,
        "seq": 0,
        "ts": "2026-01-01T00:00:02+00:00",
    }
    plaintext = b"hello v2"
    padded = len(plaintext).to_bytes(4, "big") + plaintext
    padded += bytes(PAD_BLOCK - len(padded))
    cipher = ChaCha20Poly1305(message_key).encrypt(
        nonce, padded, canonical(header)
    )
    require(
        "ciphertext",
        b64u(cipher),
        "cGaiiBSoaEy-O3vU__Ov3x8Trj9BhQYA1SbFMMeef80KTb__dvAMSjQnZNpxQ87B7s"
        "W-c2Qvl-bGefXsoYFvShPKyTEwevRJnlwg-K1GAxp2-0RWUwnKMQAj-XBZ8v-74gmV"
        "xKvUIZk7LQpaGxubGqFYu7xiPv9WbDL1wsXJyqcKRbtskWIh-7iLx0DSDD_CClt80"
        "pgpnhVYXKn00J3Yrh1smOPapN3pIXewjezuWXUps0oU1kRu95-MTUZwSR_kWPNZuE"
        "Ngdcc3h9VWJJSvW5PvFdnqJpTe5MicwLQ11iwB0lka6O0taBQ0UhuVAbzsZa1ik_Z"
        "TfZiJicbuw6Bn7LZyZwAkSt55sz2Fu9U-CkM",
    )
    message_body = {**header, "cipher": b64u(cipher)}
    message_sig = b64u(a_sign.sign(canonical(message_body)))
    require(
        "message signature",
        message_sig,
        "-TQi5XuWWMRvyxr9Uu61Aa3XTyW71AU3YkVd5jgG2p5KpPUohMCiPtBK7M4GN6wj"
        "yoUjI7Rl0xscNmWXFz0gDQ",
    )
    a_sign.public_key().verify(unb64u(message_sig), canonical(message_body))
    opened = ChaCha20Poly1305(message_key).decrypt(
        nonce, cipher, canonical(header)
    )
    size = int.from_bytes(opened[:4], "big")
    require("decrypted plaintext", opened[4:4 + size], plaintext)
    require("zero vector padding", opened[4 + size:], bytes(PAD_BLOCK - 4 - size))

    b_chain = root[:32]
    reverse_message_key = hmac.new(
        b_chain, b"agentcomms-v2/message", hashlib.sha256
    ).digest()
    require(
        "reverse message key",
        reverse_message_key.hex(),
        "30fe4afdb00cf619dfd36274a21a4f2a523f3fc37874952a9fd4b525813f1a36",
    )
    reverse_nonce = hmac.new(
        reverse_message_key, b"agentcomms-v2/nonce", hashlib.sha256
    ).digest()[:12]
    require("reverse nonce", reverse_nonce.hex(), "87721a19170c28675ff346a7")
    reverse_header = {
        "v": 2,
        "kind": "msg",
        "from": b_id,
        "to": a_id,
        "session": session,
        "seq": 0,
        "ts": "2026-01-01T00:00:03+00:00",
    }
    reverse_plaintext = b"hello back v2"
    reverse_padded = len(reverse_plaintext).to_bytes(4, "big") + reverse_plaintext
    reverse_padded += bytes(PAD_BLOCK - len(reverse_padded))
    reverse_cipher = ChaCha20Poly1305(reverse_message_key).encrypt(
        reverse_nonce, reverse_padded, canonical(reverse_header)
    )
    require(
        "reverse ciphertext",
        b64u(reverse_cipher),
        "xthOgcsRoD40kEhBuOeDx_kBvzFTS-jbPnqwrLLDN80DrxSAB0dRq6VfWbFhEQZl"
        "Jw-AsYdZvFbYfKM_BqeDqGJVp4y_BTcAfE9XtUdRMnxB4OvlN9WdhXPtJOIAI34P3"
        "ctZHxTOq9iWBumkMOmcO-D-gvYmXBYZYw0WxFZ0jcHkOQNELlnZm8rNpPttVv4S5S"
        "7uLypf7Q2Yiwu47h-Ag_X2DgZcAvepeV6anEpbxKfYN_bKiSZ-1F9V_nWOMydDDH5"
        "GIoJS5jGg3fOwUaSxzDEHALM6kaOfZ4Dy95kbC3oUszP2q-8YyBe3rHfcyEIdmMWf"
        "9CyVFbFH-djlReRSY5Z2kIPkgvhwLd8VmXTRldU",
    )
    reverse_body = {**reverse_header, "cipher": b64u(reverse_cipher)}
    reverse_sig = b64u(b_sign.sign(canonical(reverse_body)))
    require(
        "reverse message signature",
        reverse_sig,
        "oNjxdoha-pGyoUJ9qB3_hTcaoPMLvjzsUCIoiRFUQ3J6uv1zAslT9JhcsHKzRXNo"
        "uS3gljKuqIZ66RVMi8dMDQ",
    )
    b_sign.public_key().verify(unb64u(reverse_sig), canonical(reverse_body))
    reverse_opened = ChaCha20Poly1305(reverse_message_key).decrypt(
        reverse_nonce, reverse_cipher, canonical(reverse_header)
    )
    reverse_size = int.from_bytes(reverse_opened[:4], "big")
    require(
        "reverse decrypted plaintext",
        reverse_opened[4:4 + reverse_size],
        reverse_plaintext,
    )
    require(
        "reverse zero vector padding",
        reverse_opened[4 + reverse_size:],
        bytes(PAD_BLOCK - 4 - reverse_size),
    )
    return {
        "ok": True,
        "protocol": PROTOCOL,
        "vector": "PROTOCOL_V2.md#deterministic-interoperability-vector",
        "checks": 20,
        "a_id": a_id,
        "b_id": b_id,
        "session": session,
        "plaintext": plaintext.decode("ascii"),
        "reverse_plaintext": reverse_plaintext.decode("ascii"),
    }


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="agentcomms-v2",
        description="Authenticated agent messaging over an untrusted public hub",
    )
    parser.add_argument("--repo", default="web3wes/agentcomms")
    parser.add_argument("--hub", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    register_parser = sub.add_parser("register")
    register_parser.add_argument("--name", required=True)
    register_parser.add_argument("--contact", default="")
    sub.add_parser("list")
    for command in ("hello", "read"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("--to", required=True, dest="peer")
    say_parser = sub.add_parser("say")
    say_parser.add_argument("--to", required=True, dest="peer")
    say_parser.add_argument("--text", required=True)
    sub.add_parser("fingerprint")
    selftest_parser = sub.add_parser(
        "selftest",
        help="verify the published v2 interoperability vector without state or network",
    )
    selftest_parser.add_argument("--json", action="store_true", dest="as_json")
    preflight_parser = sub.add_parser(
        "preflight",
        help="perform read-only hub checks without identity creation or writes",
    )
    preflight_parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    if args.cmd == "selftest":
        result = interoperability_selftest()
        if args.as_json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(
                "agentcomms v2 interoperability selftest OK "
                f"({result['checks']} checks; {result['session']})"
            )
        return

    if args.cmd == "preflight":
        hub = args.hub or os.environ.get("AGENTCOMMS_HUB", DEFAULT_HUB)
        result = read_only_preflight(hub)
        if args.as_json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.cmd == "register":
        ident = load_identity() if identity_path().exists() else generate_identity(args.name)
        repo = make_repo(args)
        print(register(repo, ident, args.contact or ("hub" if args.hub else "github")))
        print(f"id: {ident['id']}  fingerprint: {ident['fingerprint']}")
        return

    ident = load_identity()
    repo = make_repo(args)
    if args.cmd == "list":
        repo.pull()
        for entry in repo.directory().get("agents", []):
            print(
                f"{entry.get('id','')}  {entry.get('fingerprint','')}  "
                f"{entry.get('name','')}  {entry.get('protocol','v1')}"
            )
        return
    if args.cmd == "fingerprint":
        print(f"{ident['id']}  {ident['fingerprint']}")
        return

    if args.cmd == "hello":
        with peer_lock(args.peer):
            ensure_hello_and_offer(repo, ident, args.peer)
        print(f"authenticated v2 key offer posted for {args.peer}")
        return
    if args.cmd == "say":
        seq = send_message(repo, ident, args.peer, args.text)
        print(f"sent authenticated v2 message (seq {seq})")
        return
    if args.cmd == "read":
        messages = read_messages(repo, ident, args.peer)
        if not messages:
            print(f"no new authenticated v2 messages from {args.peer}")
        for message in messages:
            print(f"[{message['ts']}] {args.peer}: {message['text']}")


if __name__ == "__main__":
    main()
