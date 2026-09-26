
"""
Stevens Chain v0.5.2 public-testnet networking layer.

Adds on top of v0.3:
- persistent Ed25519 node identities
- signed peer envelopes with timestamp/replay protection
- peer scoring + temporary bans
- per-IP request rate limiting
- orphan-block pool
- headers-first synchronization
- reorg transaction salvage back into mempool
- testnet faucet with address/IP cooldowns
- read-only block explorer endpoints

Experimental TESTNET software only. Do not use real funds.
"""

from __future__ import annotations
import stevens_chain_v0_3 as _v3_limits

import base64
import copy
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.request
import urllib.error
import ipaddress
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature

import stevens_chain_v0_2 as ledger
from stevens_chain_v0_3 import (
    NetworkChain, cumulative_work, chain_is_better, expected_difficulty,
    validate_block_timestamp,
    NETWORK_ID as DEVNET_ID, json_size, MAX_BLOCK_BYTES,
    MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS
)

TESTNET_VERSION = "0.5.2"
NETWORK_ID = "stevens-testnet-v0.5.2"

MAX_ORPHANS = 256
ORPHAN_TTL_SECONDS = 30 * 60
# Count bounds alone are insufficient because each orphan may approach the
# consensus block-size limit. Keep orphan memory bounded independently.
MAX_ORPHAN_BYTES = 16 * 1024 * 1024
MAX_HEADERS_PER_RESPONSE = 2000
MAX_UTXOS_PER_RESPONSE = 256
MAX_UTXO_RESPONSE_DATA_BYTES = 2 * 1024 * 1024
MAX_PEER_JSON_BYTES = 8 * 1024 * 1024

# Outbound peer adaptive-challenge policy.
#
# Sentinel itself may issue harder challenges, but an untrusted remote peer
# must not be able to force this node into unbounded proof-of-work. Refuse
# challenges above this client-side ceiling and bound both attempts and time.
PEER_CHALLENGE_MAX_BITS = 20
PEER_CHALLENGE_MAX_TRIES = 4_000_000
PEER_CHALLENGE_MAX_SECONDS = 3.0
PEER_CHALLENGE_MAX_NONCE_CHARS = 4096
MAX_CHAIN_SYNC_BYTES = 64 * 1024 * 1024  # legacy one-shot /chain compatibility only
# r4 paginated full-chain synchronization. Each response remains bounded by
# MAX_PEER_JSON_BYTES even when the complete valid chain is much larger than
# the legacy 64 MiB one-shot cap.
MAX_CHAIN_PAGE_BLOCKS = 128
MAX_CHAIN_PAGE_DATA_BYTES = 4 * 1024 * 1024
MAX_CHAIN_PAGE_RESPONSE_BYTES = MAX_PEER_JSON_BYTES
MAX_LEGACY_CHAIN_RESPONSE_DATA_BYTES = 32 * 1024 * 1024

REQUESTS_PER_MINUTE = 180
BURST_REQUESTS = 60
RATE_LIMIT_IDLE_TTL_SECONDS = 15 * 60
PUBLIC_EGRESS_BYTES_PER_TOKEN = 512 * 1024
MAX_RATE_LIMIT_KEYS = 20_000

PEER_BAN_THRESHOLD = -100
PEER_BAN_SECONDS = 15 * 60
MAX_PEERS = 64
MAX_SYNC_CANDIDATES = 8
MAX_SYNC_HEADER_PREFLIGHT = 10_000

# Optional fail-closed bootstrap policy for public testnet operation.
# A bootstrap entry pins a URL to a cryptographic node identity and an
# operator-controlled diversity label. The label is trusted only because it
# comes from the local operator policy, never from remote peer input.
MAX_BOOTSTRAP_POLICY_BYTES = 64 * 1024
MAX_BOOTSTRAP_PEERS = 16
MAX_OPERATOR_GROUP_CHARS = 64
DEFAULT_BOOTSTRAP_MIN_GROUPS = 2

ENVELOPE_MAX_SKEW_SECONDS = 120
SEEN_NONCE_TTL_SECONDS = 10 * 60
MAX_SEEN_NONCES = 50_000
PEER_NONCE_HEX_CHARS = 32

FAUCET_AMOUNT = 5 * ledger.UNIT
FAUCET_ADDRESS_COOLDOWN = 6 * 60 * 60
FAUCET_IP_COOLDOWN = 60 * 60

ADMIN_ENDPOINTS = {"/peers/add", "/sync", "/mine", "/validate"}
MIN_ADMIN_TOKEN_CHARS = 32
NODE_IDENTITY_MAX_BYTES = 64 * 1024


def canonical(obj) -> bytes:
    return ledger.canonical_json(obj)


def host_is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return str(host).strip().lower() == "localhost"


def raw_pub(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def node_id_from_pubkey_hex(pubkey_hex: str) -> str:
    try:
        pubraw = bytes.fromhex(str(pubkey_hex))
    except ValueError as e:
        raise ValueError("invalid peer public key encoding") from e
    if len(pubraw) != 32:
        raise ValueError("invalid peer public key length")
    return hashlib.sha256(b"StevensNodeId" + pubraw).hexdigest()[:32]


class NodeIdentity:
    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key

    @classmethod
    def load_or_create(cls, path: str | Path):
        path = Path(path)
        if path.exists():
            try:
                size = path.stat().st_size
                if size <= 0 or size > NODE_IDENTITY_MAX_BYTES:
                    raise ValueError("node identity file size invalid")
                doc = json.loads(path.read_text(encoding="utf-8"))
                if doc.get("format") != "StevensNodeIdentity" or int(doc.get("version", 0)) != 1:
                    raise ValueError("invalid node identity format/version")
                raw = bytes.fromhex(str(doc["private_key"]))
                if len(raw) != 32:
                    raise ValueError("invalid node private key length")
                ident = cls(Ed25519PrivateKey.from_private_bytes(raw))
                declared = doc.get("public_key")
                if declared is not None and str(declared) != ident.public_key_hex:
                    raise ValueError("node identity public/private key mismatch")
                return ident
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                # Never silently regenerate on malformed existing state: that
                # would mutate the node identity after corruption/power loss.
                raise ValueError("invalid or damaged node identity file") from e
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        doc = {
            "format": "StevensNodeIdentity",
            "version": 1,
            "private_key": raw.hex(),
            "public_key": raw_pub(priv.public_key()).hex(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
        fd = None
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(json.dumps(doc, indent=2))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            # Best-effort parent-directory durability on POSIX.
            try:
                dfd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            if fd is not None:
                os.close(fd)
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        return cls(priv)

    @property
    def public_key_hex(self) -> str:
        return raw_pub(self.private_key.public_key()).hex()

    @property
    def node_id(self) -> str:
        return hashlib.sha256(
            b"StevensNodeId" + bytes.fromhex(self.public_key_hex)
        ).hexdigest()[:32]

    def sign_envelope(self, kind: str, payload: dict) -> dict:
        body = {
            "network_id": NETWORK_ID,
            "kind": kind,
            "timestamp": int(time.time()),
            "nonce": secrets.token_hex(16),
            "sender_node_id": self.node_id,
            "sender_pubkey": self.public_key_hex,
            "payload": payload,
        }
        sig = self.private_key.sign(canonical(body))
        return {**body, "signature": sig.hex()}


def verify_envelope(env: dict, seen_nonces: dict) -> tuple[str, dict]:
    required = [
        "network_id", "kind", "timestamp", "nonce", "sender_node_id",
        "sender_pubkey", "payload", "signature"
    ]
    for k in required:
        if k not in env:
            raise ValueError(f"missing envelope field {k}")
    if env["network_id"] != NETWORK_ID:
        raise ValueError("wrong network")
    now = int(time.time())
    ts = int(env["timestamp"])
    if abs(now - ts) > ENVELOPE_MAX_SKEW_SECONDS:
        raise ValueError("stale/future peer message")
    nonce = str(env["nonce"])
    if len(nonce) != PEER_NONCE_HEX_CHARS:
        raise ValueError("invalid peer nonce length")
    try:
        bytes.fromhex(nonce)
    except ValueError as e:
        raise ValueError("invalid peer nonce encoding") from e

    # Prune replay state in insertion/time order. TestnetNode uses OrderedDict,
    # which avoids an O(n) full-table scan on every valid peer message.
    cutoff = now - SEEN_NONCE_TTL_SECONDS
    while seen_nonces:
        first = next(iter(seen_nonces))
        if seen_nonces[first] >= cutoff:
            break
        del seen_nonces[first]
    if nonce in seen_nonces:
        raise ValueError("replayed peer message")
    # Never evict an unexpired nonce merely to make room: doing so would turn
    # memory pressure into a replay bypass. Fail closed until entries expire.
    if len(seen_nonces) >= MAX_SEEN_NONCES:
        raise ValueError("peer replay cache capacity exceeded")

    try:
        pubraw = bytes.fromhex(env["sender_pubkey"])
    except ValueError as e:
        raise ValueError("invalid peer public key encoding") from e
    if len(pubraw) != 32:
        raise ValueError("invalid peer public key length")
    node_id = hashlib.sha256(b"StevensNodeId" + pubraw).hexdigest()[:32]
    if node_id != env["sender_node_id"]:
        raise ValueError("node id/public key mismatch")

    body = {k: env[k] for k in required if k != "signature"}
    try:
        sig = bytes.fromhex(env["signature"])
    except ValueError as e:
        raise ValueError("invalid peer signature encoding") from e
    if len(sig) != 64:
        raise ValueError("invalid peer signature length")
    try:
        Ed25519PublicKey.from_public_bytes(pubraw).verify(sig, canonical(body))
    except InvalidSignature as e:
        raise ValueError("invalid peer signature") from e

    seen_nonces[nonce] = now
    return node_id, env["payload"]


@dataclass
class PeerRecord:
    url: str
    node_id: str | None = None
    pubkey: str | None = None
    score: int = 0
    banned_until: int = 0
    last_seen: int = 0
    failures: int = 0
    bootstrap: bool = False
    operator_group: str | None = None

    def banned(self) -> bool:
        return int(time.time()) < self.banned_until


class PeerBook:
    def __init__(self, max_peers=MAX_PEERS):
        self.records: dict[str, PeerRecord] = {}
        self.max_peers = int(max_peers)
        self.lock = threading.RLock()

    def add(self, url: str, node_id=None, pubkey=None, *,
            bootstrap=False, operator_group=None):
        url = url.rstrip("/")
        with self.lock:
            rec = self.records.get(url)
            if rec is None:
                if len(self.records) >= self.max_peers:
                    raise ValueError("peer table capacity exceeded")
                if node_id:
                    for existing in self.records.values():
                        if existing.node_id and existing.node_id == node_id:
                            raise ValueError("duplicate peer node identity")
                rec = PeerRecord(url=url)
                self.records[url] = rec
            elif node_id and rec.node_id and rec.node_id != node_id:
                raise ValueError("peer URL changed node identity")
            if node_id:
                rec.node_id = node_id
            if pubkey:
                rec.pubkey = pubkey
            if bootstrap:
                if not operator_group:
                    raise ValueError("bootstrap peer requires operator group")
                if rec.operator_group and rec.operator_group != operator_group:
                    raise ValueError("bootstrap operator group changed")
                rec.bootstrap = True
                rec.operator_group = str(operator_group)
            return rec

    def score(self, url: str, delta: int):
        with self.lock:
            rec = self.add(url)
            delta = int(delta)
            rec.score += delta
            rec.last_seen = int(time.time())
            # Only adverse scoring may create or extend a ban. A successful
            # interaction must not re-ban a recovering peer merely because
            # its historical score remains below the ban threshold.
            if delta < 0 and rec.score <= PEER_BAN_THRESHOLD:
                rec.banned_until = int(time.time()) + PEER_BAN_SECONDS

    def note_failure(self, url: str):
        with self.lock:
            rec = self.records.get(url.rstrip("/"))
            if rec is None:
                # Failed, never-admitted endpoints are not peers and must not
                # create durable peer-table state.
                return
            rec.failures += 1
            self.score(url, -10)

    def note_success(self, url: str):
        """Bounded recovery for a known peer after a valid health exchange."""
        with self.lock:
            rec = self.records.get(url.rstrip("/"))
            if rec is None:
                return
            # Routine health checks may rehabilitate negative reputation, but
            # must never inflate a healthy peer above neutral.
            if rec.score < 0:
                rec.score = min(0, rec.score + 1)
            if rec.failures > 0:
                rec.failures -= 1
            rec.last_seen = int(time.time())
            # Do not clear or shorten an active ban here. Normal callers only
            # reach peers returned by active(), so rehabilitation begins after
            # the timed ban has expired.

    def active(self):
        with self.lock:
            return sorted(
                (r for r in self.records.values() if not r.banned()),
                key=lambda r: (-r.score, r.failures, r.url),
            )

    def as_json(self):
        with self.lock:
            return [
                {
                    "url": r.url, "node_id": r.node_id, "score": r.score,
                    "banned_until": r.banned_until, "last_seen": r.last_seen,
                    "failures": r.failures, "bootstrap": r.bootstrap,
                    "operator_group": r.operator_group,
                }
                for r in self.records.values()
            ]


class TokenBucketLimiter:
    def __init__(self, per_minute=REQUESTS_PER_MINUTE, burst=BURST_REQUESTS,
                 max_keys=MAX_RATE_LIMIT_KEYS,
                 idle_ttl=RATE_LIMIT_IDLE_TTL_SECONDS):
        self.rate = per_minute / 60.0
        self.capacity = float(burst)
        self.max_keys = int(max_keys)
        self.idle_ttl = float(idle_ttl)
        self.state = OrderedDict()
        self.lock = threading.Lock()

    def _prune_idle_locked(self, now: float) -> None:
        # OrderedDict keeps the least recently touched entry first.
        cutoff = now - self.idle_ttl
        while self.state:
            first = next(iter(self.state))
            _, last = self.state[first]
            if last >= cutoff:
                break
            self.state.popitem(last=False)

    def allow(self, key: str) -> bool:
        return self.allow_cost(key, 1.0)

    def allow_cost(self, key: str, cost: float) -> bool:
        cost = float(cost)
        if cost <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            self._prune_idle_locked(now)
            current = self.state.pop(key, None)
            if current is None:
                # Do not evict live entries or hand a new identity
                # a fresh burst when the active-key cap is full.
                if len(self.state) >= self.max_keys:
                    return False
                tokens, last = self.capacity, now
            else:
                tokens, last = current
                tokens = min(
                    self.capacity,
                    tokens + (now - last) * self.rate,
                )
            if tokens < cost:
                self.state[key] = (tokens, now)
                return False
            self.state[key] = (tokens - cost, now)
            return True

class TestnetChain(NetworkChain):
    """
    v0.5.2 chain wrapper.
    The transaction/block format remains inherited from v0.2/v0.3.
    """
    def __init__(self, data_dir=None):
        super().__init__(data_dir)
        self.orphans: dict[str, tuple[dict, int]] = {}
        self.orphan_bytes = 0

    def _drop_orphan(self, h: str) -> None:
        old = self.orphans.pop(h, None)
        if old is not None:
            self.orphan_bytes = max(0, self.orphan_bytes - json_size(old[0]))


    def _drop_orphan_subtree(self, root_hash: str) -> None:
        """Drop an orphan and every retained descendant of that orphan."""
        children = {}

        for h, (block, _) in self.orphans.items():
            parent = block.get("previous_hash")
            children.setdefault(parent, []).append(h)

        pending = [root_hash]
        seen = set()

        while pending:
            h = pending.pop()

            if h in seen:
                continue

            seen.add(h)
            pending.extend(children.get(h, ()))

            self._drop_orphan(h)

    def _prevalidate_orphan(self, block: dict) -> int:
        # An orphan cannot receive full stateful UTXO validation until its
        # parent is known. It can still be required to have one canonical
        # intrinsic representation before entering the orphan pool.
        self._limits_check_block(block)

        ledger._require_exact_keys(
            block,
            {
                "version",
                "chain",
                "height",
                "previous_hash",
                "timestamp",
                "merkle_root",
                "difficulty_bits",
                "nonce",
                "transactions",
                "hash",
            },
            "orphan block",
        )

        version = ledger._require_consensus_int(
            block["version"],
            "orphan block version",
        )

        height = ledger._require_consensus_int(
            block["height"],
            "orphan block height",
        )

        ledger._require_consensus_int(
            block["timestamp"],
            "orphan block timestamp",
        )

        bits = ledger._require_consensus_int(
            block["difficulty_bits"],
            "orphan block difficulty_bits",
        )

        ledger._require_consensus_int(
            block["nonce"],
            "orphan block nonce",
        )

        if (
            version != 2
            or block["chain"] != ledger.CHAIN_NAME
        ):
            raise ValueError(
                "bad orphan chain/version"
            )

        if height <= 0:
            raise ValueError(
                "orphan must be a non-genesis block"
            )

        if not (
            MIN_DIFFICULTY_BITS
            <= bits
            <= MAX_DIFFICULTY_BITS
        ):
            raise ValueError(
                "orphan difficulty outside allowed range"
            )

        txs = block["transactions"]

        if not isinstance(txs, list) or not txs:
            raise ValueError(
                "orphan block missing transaction list"
            )

        for pos, tx in enumerate(txs):
            if not isinstance(tx, dict):
                raise ValueError(
                    "invalid orphan transaction object"
                )

            kind = tx.get("kind")

            if pos == 0 and kind != "coinbase":
                raise ValueError(
                    "orphan first transaction must be coinbase"
                )

            if pos > 0 and kind == "coinbase":
                raise ValueError(
                    "orphan contains multiple coinbase transactions"
                )

            if kind == "coinbase":
                ledger._require_exact_keys(
                    tx,
                    {
                        "version",
                        "chain",
                        "kind",
                        "height",
                        "inputs",
                        "fee",
                        "outputs",
                        "txid",
                    },
                    "orphan coinbase transaction",
                )

                tx_version = ledger._require_consensus_int(
                    tx["version"],
                    "orphan coinbase version",
                )

                tx_height = ledger._require_consensus_int(
                    tx["height"],
                    "orphan coinbase height",
                )

                tx_fee = ledger._require_consensus_int(
                    tx["fee"],
                    "orphan coinbase fee",
                )

                if (
                    tx_version != 2
                    or tx["chain"] != ledger.CHAIN_NAME
                ):
                    raise ValueError(
                        "bad orphan coinbase chain/version"
                    )

                if tx_height != height:
                    raise ValueError(
                        "orphan coinbase height mismatch"
                    )

                if tx_fee != 0:
                    raise ValueError(
                        "orphan coinbase fee must be zero"
                    )

                if tx["inputs"] != []:
                    raise ValueError(
                        "orphan coinbase inputs must be empty"
                    )

                if (
                    not isinstance(tx["outputs"], list)
                    or not tx["outputs"]
                ):
                    raise ValueError(
                        "orphan coinbase outputs invalid"
                    )

                for output in tx["outputs"]:
                    ledger.validate_output_shape(
                        output
                    )

            elif kind == "payment":
                ledger._require_exact_keys(
                    tx,
                    {
                        "version",
                        "chain",
                        "kind",
                        "fee",
                        "inputs",
                        "outputs",
                        "txid",
                    },
                    "orphan payment transaction",
                )

                tx_version = ledger._require_consensus_int(
                    tx["version"],
                    "orphan payment version",
                )

                tx_fee = ledger._require_consensus_int(
                    tx["fee"],
                    "orphan payment fee",
                )

                if (
                    tx_version != 2
                    or tx["chain"] != ledger.CHAIN_NAME
                ):
                    raise ValueError(
                        "bad orphan payment chain/version"
                    )

                if tx_fee < 0:
                    raise ValueError(
                        "negative orphan payment fee"
                    )

                if (
                    not isinstance(tx["inputs"], list)
                    or not tx["inputs"]
                ):
                    raise ValueError(
                        "orphan payment inputs invalid"
                    )

                if (
                    not isinstance(tx["outputs"], list)
                    or not tx["outputs"]
                ):
                    raise ValueError(
                        "orphan payment outputs invalid"
                    )

                for inp in tx["inputs"]:
                    ledger._require_exact_keys(
                        inp,
                        {
                            "txid",
                            "index",
                            "signature",
                        },
                        "orphan payment input",
                    )

                    ledger._require_consensus_int(
                        inp["index"],
                        "orphan payment input index",
                    )

                    if not isinstance(
                        inp["txid"],
                        str,
                    ):
                        raise ValueError(
                            "invalid orphan input txid"
                        )

                    if not isinstance(
                        inp["signature"],
                        str,
                    ):
                        raise ValueError(
                            "invalid orphan input signature"
                        )

                    try:
                        ref = bytes.fromhex(
                            inp["txid"]
                        )
                        sig = bytes.fromhex(
                            inp["signature"]
                        )
                    except ValueError as e:
                        raise ValueError(
                            "invalid orphan payment input encoding"
                        ) from e

                    if len(ref) != 32:
                        raise ValueError(
                            "invalid orphan input txid length"
                        )

                    if len(sig) != 64:
                        raise ValueError(
                            "invalid orphan signature length"
                        )

                for output in tx["outputs"]:
                    ledger.validate_output_shape(
                        output
                    )

            else:
                raise ValueError(
                    "unsupported orphan transaction kind"
                )

            txid = tx.get("txid")

            if not isinstance(txid, str):
                raise ValueError(
                    "invalid orphan transaction txid"
                )

            try:
                raw_txid = bytes.fromhex(
                    txid
                )
            except ValueError as e:
                raise ValueError(
                    "invalid orphan transaction txid"
                ) from e

            if len(raw_txid) != 32:
                raise ValueError(
                    "invalid orphan transaction txid length"
                )

            if not ledger.check_txid(tx):
                raise ValueError(
                    "orphan transaction txid mismatch"
                )

        txids = [
            tx["txid"]
            for tx in txs
        ]

        if len(txids) != len(set(txids)):
            raise ValueError(
                "duplicate transaction id in block"
            )

        expected_merkle = ledger.merkle_root(
            txids
        )

        if block["merkle_root"] != expected_merkle:
            raise ValueError(
                "orphan merkle root mismatch"
            )

        want_hash = ledger.block_hash(
            block
        )

        if block["hash"] != want_hash:
            raise ValueError(
                "bad orphan block hash"
            )

        if not ledger.pow_valid(
            want_hash,
            bits,
        ):
            raise ValueError(
                "invalid orphan proof of work"
            )

        return json_size(block)

    def add_orphan(self, block: dict):
        entry_bytes = self._prevalidate_orphan(block)

        # Expired orphan state must not remain authoritative for parent
        # relationship checks. Expiring an orphan also expires its retained
        # descendant subtree so stale parentless descendants are not left
        # consuming orphan-pool resources.
        now = int(time.time())
        for h, (_, ts) in list(self.orphans.items()):
            if now - ts > ORPHAN_TTL_SECONDS:
                self._drop_orphan_subtree(h)

        # Intrinsic orphan validation, including hash and proof of work,
        # has completed above. If the claimed parent is already known
        # either canonically or as a still-live orphan, enforce its only
        # valid child height before consuming another orphan slot.
        parent_hash = block["previous_hash"]
        parent_height = None

        for known_height, known_block in enumerate(self.blocks):
            if known_block.get("hash") == parent_hash:
                parent_height = known_height
                break

        if parent_height is None:
            orphan_parent = self.orphans.get(parent_hash)

            if orphan_parent is not None:
                parent_block, _ = orphan_parent
                parent_height = parent_block["height"]

        if (
            parent_height is not None
            and block["height"] != parent_height + 1
        ):
            raise ValueError(
                "block extending known parent has wrong height"
            )

        h = block["hash"]
        # Replacing the same hash must not leak byte-accounting state.
        if h in self.orphans:
            self._drop_orphan(h)


        # A child may arrive before its parent. Once this parent becomes
        # known, remove any already-retained direct child whose claimed
        # height is impossible for this parent.
        expected_child_height = block["height"] + 1

        for child_hash, (child_block, _) in list(self.orphans.items()):
            if (
                child_block.get("previous_hash") == h
                and child_block["height"] != expected_child_height
            ):
                self._drop_orphan_subtree(child_hash)

        # Bound both entry count and total retained bytes. Evict oldest
        # non-authoritative orphan state until the new valid candidate fits.
        while self.orphans and (
            len(self.orphans) >= MAX_ORPHANS or
            self.orphan_bytes + entry_bytes > MAX_ORPHAN_BYTES
        ):
            oldest = min(self.orphans.items(), key=lambda kv: kv[1][1])[0]
            self._drop_orphan_subtree(oldest)
        if entry_bytes > MAX_ORPHAN_BYTES:
            raise ValueError("orphan exceeds total orphan memory budget")
        self.orphans[h] = (block, now)
        self.orphan_bytes += entry_bytes

    def process_orphans(self):
        changed = True
        accepted = []
        while changed:
            changed = False
            for h, (block, ts) in list(self.orphans.items()):
                if (
                    self.blocks and
                    block.get("previous_hash") == self.blocks[-1]["hash"] and
                    int(block.get("height", -1)) == len(self.blocks)
                ):
                    try:
                        self.append_external_block(block)
                        accepted.append(h)
                        self._drop_orphan(h)
                        changed = True
                        break
                    except ValueError:
                        self._drop_orphan_subtree(h)
        return accepted

    def append_or_orphan(self, block: dict) -> str:
        # This is a direct untrusted-network ingress boundary. Reject
        # malformed whole-block objects before any .get() access.
        if not isinstance(block, dict):
            raise ValueError("invalid block object")

        # An exact block already present in the canonical chain is known data,
        # not an orphan. Use its claimed height for O(1) lookup. A same-hash
        # but altered representation is deliberately NOT accepted here; it
        # falls through to hardened orphan prevalidation instead.
        replay_height = block.get("height")

        if (
            isinstance(replay_height, int)
            and not isinstance(replay_height, bool)
            and 0 <= replay_height < len(self.blocks)
            and self.blocks[replay_height].get("hash") == block.get("hash")
            and self.blocks[replay_height] == block
        ):
            return "accepted"

        # A block whose parent is our current canonical tip is not an
        # orphan. Its only valid child height is the next canonical height.
        # Reject a canonical integer height mismatch rather than retaining
        # impossible known-parent data in the orphan pool.
        claimed_height = block.get("height")
        if (
            self.blocks
            and block.get("previous_hash") == self.blocks[-1]["hash"]
            and isinstance(claimed_height, int)
            and not isinstance(claimed_height, bool)
            and claimed_height != len(self.blocks)
        ):
            raise ValueError(
                "block extending current tip has wrong height"
            )

        if (
            self.blocks and
            block.get("previous_hash") == self.blocks[-1]["hash"] and
            int(block.get("height", -1)) == len(self.blocks)
        ):
            self.append_external_block(block)

            # A child may have arrived before this parent became canonical.
            # Now that the parent height is authoritative, remove any retained
            # direct child whose claimed height is impossible before normal
            # orphan processing attempts valid next-height descendants.
            parent_hash = block["hash"]
            expected_child_height = block["height"] + 1

            for child_hash, (child_block, _) in list(self.orphans.items()):
                if (
                    child_block.get("previous_hash") == parent_hash
                    and child_block["height"] != expected_child_height
                ):
                    self._drop_orphan_subtree(child_hash)

            self.process_orphans()
            return "accepted"
        self.add_orphan(block)
        return "orphaned"

    def headers(self, start_height=0, limit=MAX_HEADERS_PER_RESPONSE):
        start_height = max(0, int(start_height))
        limit = min(MAX_HEADERS_PER_RESPONSE, max(1, int(limit)))
        rows = []
        for b in self.blocks[start_height:start_height+limit]:
            rows.append({
                "height": b["height"],
                "hash": b["hash"],
                "previous_hash": b["previous_hash"],
                "timestamp": b["timestamp"],
                "merkle_root": b["merkle_root"],
                "difficulty_bits": b["difficulty_bits"],
                "nonce": b["nonce"],
                "version": b["version"],
                "chain": b["chain"],
            })
        return rows

    def chain_page(self, start_height=0, limit=MAX_CHAIN_PAGE_BLOCKS,
                   max_data_bytes=MAX_CHAIN_PAGE_DATA_BYTES):
        """Return a contiguous, size-bounded page of full blocks.

        The page limit is intentionally dual: number of blocks and encoded
        payload bytes. This prevents a peer from forcing giant single-response
        allocations while still allowing a chain whose total size exceeds the
        legacy one-shot /chain limit to synchronize page-by-page.
        """
        start = max(0, int(start_height))
        limit = min(MAX_CHAIN_PAGE_BLOCKS, max(1, int(limit)))
        budget = max(MAX_BLOCK_BYTES + 4096, int(max_data_bytes))
        rows = []
        used = 0
        for b in self.blocks[start:start + limit]:
            n = json_size(b)
            # A consensus-valid block must fit MAX_BLOCK_BYTES. Keep the
            # endpoint fail-closed if in-memory state is unexpectedly larger.
            if n > MAX_BLOCK_BYTES:
                raise ValueError("stored block exceeds consensus block-size limit")
            if rows and used + n > budget:
                break
            rows.append(b)
            used += n
            if used >= budget:
                break
        next_start = start + len(rows)
        return {
            "start": start,
            "next_start": next_start,
            "done": next_start >= len(self.blocks),
            "blocks": rows,
        }

    def try_adopt_chain(self, candidate_blocks: list[dict]) -> bool:
        """Adopt a better chain and deterministically rebuild the mempool.

        Transactions disconnected by the reorg are eligible for resurrection,
        but only if they remain valid against the winning chain. Duplicate
        candidates are collapsed by txid and previously-confirmed disconnected
        payments are considered before old unconfirmed mempool entries. This
        makes conflicting-spend handling deterministic and prevents a losing
        double-spend from surviving when the winning chain already consumes the
        same input.
        """
        if not candidate_blocks:
            return False
        if self.blocks and candidate_blocks[0]["hash"] != self.blocks[0]["hash"]:
            raise ValueError("different genesis")

        tester = NetworkChain()
        tester.blocks = json.loads(json.dumps(candidate_blocks))
        tester.validate_chain(rebuild=True)

        if not chain_is_better(candidate_blocks, self.blocks):
            return False

        old_blocks = json.loads(json.dumps(self.blocks))
        old_mp = list(self.mempool)
        candidate_txids = {
            tx["txid"] for b in candidate_blocks for tx in b.get("transactions", [])
        }

        # Preserve the old-chain order for formerly confirmed payments. That
        # order is deterministic for a given disconnected branch.
        disconnected = []
        new_hashes = {b["hash"] for b in candidate_blocks}
        for b in old_blocks:
            if b["hash"] in new_hashes:
                continue
            for tx in b.get("transactions", []):
                if tx.get("kind") == "payment" and tx.get("txid") not in candidate_txids:
                    disconnected.append(tx)

        self.blocks = json.loads(json.dumps(candidate_blocks))
        self.validate_chain(rebuild=True)
        self.mempool = []

        seen = set(candidate_txids)
        # Old mempool order is not globally authoritative. Sort it by txid so
        # two nodes rebuilding the same candidate set do not choose conflicting
        # unconfirmed spends based solely on arrival order.
        old_unconfirmed = sorted(old_mp, key=lambda tx: str(tx.get("txid", "")))
        for tx in disconnected + old_unconfirmed:
            txid = tx.get("txid")
            if not txid or txid in seen:
                continue
            seen.add(txid)
            try:
                ledger.Blockchain.submit_tx(self, tx, save=False)
            except Exception:
                # Invalid/conflicting transactions are intentionally dropped.
                pass

        try:
            self.save()
        except Exception:
            # The SQLite save is transactional. Restore the old in-memory view
            # as well so a failed durable reorg never leaves process state ahead
            # of disk.
            self.blocks = old_blocks
            self.validate_chain(rebuild=True)
            self.mempool = old_mp
            raise
        return True



class Faucet:
    """Crash-recoverable testnet faucet claim ledger.

    r4 uses a durable prepared->submitted state machine. The claim intent is
    committed before the chain mempool write. On restart, any prepared intent
    is replayed or reconciled with the persisted chain state before new claims
    are accepted. This closes the old crash window where a faucet transaction
    could persist while the cooldown record did not.
    """
    ACTIVE_STATES = ("prepared", "submitted")

    def __init__(self, chain: TestnetChain, wallet: ledger.Wallet, data_dir: str | Path):
        self.chain = chain
        self.wallet = wallet
        self.db = Path(data_dir) / "faucet.sqlite3"
        self.lock = threading.RLock()
        self._init_db()
        self._recover_prepared_claims()

    def _connect(self):
        con = sqlite3.connect(self.db, timeout=10)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=10000")
        return con

    def _init_db(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS claims(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    txid TEXT,
                    state TEXT NOT NULL DEFAULT 'submitted',
                    tx_json TEXT,
                    updated_at INTEGER NOT NULL DEFAULT 0
                )
            """)
            cols = {r[1] for r in con.execute("PRAGMA table_info(claims)")}
            if "state" not in cols:
                con.execute("ALTER TABLE claims ADD COLUMN state TEXT NOT NULL DEFAULT 'submitted'")
            if "tx_json" not in cols:
                con.execute("ALTER TABLE claims ADD COLUMN tx_json TEXT")
            if "updated_at" not in cols:
                con.execute("ALTER TABLE claims ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0")
            con.execute("UPDATE claims SET state='submitted' WHERE state IS NULL OR state='' ")
            con.execute("CREATE INDEX IF NOT EXISTS claims_addr_ts ON claims(address,timestamp)")
            con.execute("CREATE INDEX IF NOT EXISTS claims_ip_ts ON claims(ip,timestamp)")
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS claims_txid_unique ON claims(txid) WHERE txid IS NOT NULL")

    @staticmethod
    def _last_claim_in(con, field: str, value: str):
        if field not in {"address", "ip"}:
            raise ValueError("invalid faucet claim lookup field")
        row = con.execute(
            f"SELECT timestamp FROM claims WHERE {field}=? "
            "AND state IN ('prepared','submitted') "
            "ORDER BY timestamp DESC,id DESC LIMIT 1", (value,)
        ).fetchone()
        return int(row[0]) if row else None

    def _last_claim(self, field: str, value: str):
        with self._connect() as con:
            return self._last_claim_in(con, field, value)

    def _tx_present(self, txid: str) -> bool:
        if any(tx.get("txid") == txid for tx in self.chain.mempool):
            return True
        return any(
            tx.get("txid") == txid
            for block in self.chain.blocks
            for tx in block.get("transactions", [])
        )

    def _set_claim_state(self, txid: str, state: str) -> None:
        if state not in {"submitted", "failed"}:
            raise ValueError("invalid faucet claim state")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute(
                "UPDATE claims SET state=?,updated_at=? WHERE txid=? AND state='prepared'",
                (state, int(time.time()), txid),
            )
            if cur.rowcount not in (0, 1):
                raise ValueError("ambiguous faucet claim state")

    def _recover_prepared_claims(self) -> None:
        # Caller/node startup loads and validates chain persistence before the
        # faucet is constructed, so reconciliation can safely inspect mempool
        # and confirmed blocks here.
        with self.lock:
            with self._connect() as con:
                rows = con.execute(
                    "SELECT txid,tx_json FROM claims WHERE state='prepared' ORDER BY id"
                ).fetchall()
            for txid, tx_json in rows:
                try:
                    if not txid or not tx_json:
                        raise ValueError("prepared claim missing transaction")
                    tx = json.loads(tx_json)
                    if tx.get("txid") != txid:
                        raise ValueError("prepared claim txid mismatch")
                    if not self._tx_present(txid):
                        self.chain.submit_tx(tx)
                    self._set_claim_state(txid, "submitted")
                except Exception:
                    # A prepared transaction can become invalid if the faucet
                    # wallet was independently spent while this node was down.
                    # Mark it failed so it does not permanently consume a
                    # cooldown slot; no duplicate payout is created.
                    self._set_claim_state(txid, "failed")

    def claim(self, recipient: ledger.PublicIdentity, ip: str):
        now = int(time.time())
        with self.lock:
            # Serialize check+reservation across processes sharing this faucet
            # database. A durable reservation exists before the chain write.
            with self._connect() as con:
                con.execute("BEGIN IMMEDIATE")
                last_addr = self._last_claim_in(con, "address", recipient.address)
                last_ip = self._last_claim_in(con, "ip", ip)
                if last_addr and now-last_addr < FAUCET_ADDRESS_COOLDOWN:
                    raise ValueError("address faucet cooldown active")
                if last_ip and now-last_ip < FAUCET_IP_COOLDOWN:
                    raise ValueError("IP faucet cooldown active")

                tx = ledger.create_simple_payment(
                    self.chain, self.wallet, recipient,
                    FAUCET_AMOUNT, 0, "Stevens Testnet Faucet"
                )
                tx_json = json.dumps(tx, separators=(",", ":"), sort_keys=True)
                con.execute(
                    "INSERT INTO claims(address,ip,timestamp,txid,state,tx_json,updated_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (recipient.address, ip, now, tx["txid"], "prepared", tx_json, now),
                )

            # The chain persistence transaction is separate, so the prepared
            # row is our durable recovery intent across this crash boundary.
            try:
                self.chain.submit_tx(tx)
            except Exception:
                self._set_claim_state(tx["txid"], "failed")
                raise
            self._set_claim_state(tx["txid"], "submitted")
            return tx


def validate_peer_url(url: str) -> str:
    """Strictly parse a configured peer URL before the node makes requests."""
    u = urlparse(str(url).strip())
    if u.scheme not in {"http", "https"}:
        raise ValueError("peer URL must use http or https")
    if not u.hostname:
        raise ValueError("peer URL must include a hostname")
    if u.username or u.password:
        raise ValueError("peer URL credentials are not allowed")
    if u.query or u.fragment:
        raise ValueError("peer URL query/fragment is not allowed")
    if u.path not in {"", "/"}:
        raise ValueError("peer URL must not contain a path")
    # Normalize and strip the trailing slash. Private/loopback peers remain
    # permitted when deliberately configured by the operator; the public
    # /peers/add endpoint is protected as an admin operation.
    return str(url).strip().rstrip("/")


@dataclass(frozen=True)
class BootstrapPeerSpec:
    url: str
    node_id: str
    operator_group: str


def _validate_bootstrap_node_id(value: str) -> str:
    value = str(value).strip().lower()
    if len(value) != 32:
        raise ValueError("bootstrap node_id must be 32 hex characters")
    try:
        int(value, 16)
    except ValueError as e:
        raise ValueError("bootstrap node_id must be hexadecimal") from e
    return value


def _validate_operator_group(value: str) -> str:
    value = str(value).strip()
    if not (1 <= len(value) <= MAX_OPERATOR_GROUP_CHARS):
        raise ValueError("invalid bootstrap operator group length")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in value):
        raise ValueError("bootstrap operator group contains unsafe characters")
    return value


def load_bootstrap_policy(path: str | Path):
    """Load a local, operator-authored bootstrap identity/diversity policy."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as e:
        raise ValueError("unable to read bootstrap policy") from e
    if size <= 0 or size > MAX_BOOTSTRAP_POLICY_BYTES:
        raise ValueError("bootstrap policy size is invalid or exceeds safety limit")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError("invalid bootstrap policy JSON") from e
    if doc.get("format") != "StevensBootstrapPolicy":
        raise ValueError("invalid bootstrap policy format")
    if int(doc.get("version", 0)) != 1:
        raise ValueError("unsupported bootstrap policy version")
    if doc.get("network_id") != NETWORK_ID:
        raise ValueError("bootstrap policy network mismatch")
    raw = doc.get("peers")
    if not isinstance(raw, list) or not raw or len(raw) > MAX_BOOTSTRAP_PEERS:
        raise ValueError("bootstrap policy peer count is invalid")
    specs = []
    seen_urls = set()
    seen_ids = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("invalid bootstrap peer entry")
        url = validate_peer_url(item.get("url", ""))
        node_id = _validate_bootstrap_node_id(item.get("node_id", ""))
        group = _validate_operator_group(item.get("operator_group", ""))
        if url in seen_urls:
            raise ValueError("duplicate bootstrap URL")
        if node_id in seen_ids:
            raise ValueError("duplicate bootstrap node identity")
        seen_urls.add(url); seen_ids.add(node_id)
        specs.append(BootstrapPeerSpec(url, node_id, group))
    groups = {x.operator_group for x in specs}
    minimum = int(doc.get("minimum_operator_groups", DEFAULT_BOOTSTRAP_MIN_GROUPS))
    if minimum < 1 or minimum > len(groups):
        raise ValueError("bootstrap minimum_operator_groups is not satisfiable")
    require_quorum = bool(doc.get("require_quorum", True))
    return {
        "specs": specs,
        "minimum_operator_groups": minimum,
        "require_quorum": require_quorum,
    }


def _read_bounded_peer_json(response, max_bytes):
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            declared_n = int(declared)
        except (TypeError, ValueError):
            raise ValueError("invalid peer Content-Length")
        if declared_n < 0:
            raise ValueError("invalid peer Content-Length")
        if declared_n > int(max_bytes):
            raise ValueError("peer response exceeds size limit")

    raw = response.read(int(max_bytes) + 1)
    if len(raw) > int(max_bytes):
        raise ValueError("peer response exceeds size limit")
    return json.loads(raw)


def _peer_challenge_solution(challenge, observed_source_ip):
    if not isinstance(challenge, dict):
        raise ValueError("invalid peer adaptive challenge")

    if challenge.get("algorithm") != "sha256-leading-zero-bits-v1":
        raise ValueError("unsupported peer challenge algorithm")

    if challenge.get("token_format") != "hmac-stateless-v1":
        raise ValueError("unsupported peer challenge token format")

    nonce = challenge.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("invalid peer challenge nonce")
    if len(nonce) > PEER_CHALLENGE_MAX_NONCE_CHARS:
        raise ValueError("peer challenge nonce exceeds size limit")

    bits = challenge.get("difficulty_bits")
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise ValueError("invalid peer challenge difficulty")
    if bits < 4 or bits > PEER_CHALLENGE_MAX_BITS:
        raise ValueError("peer challenge difficulty exceeds client policy")

    try:
        source_ip = str(ipaddress.ip_address(str(observed_source_ip)))
    except ValueError:
        raise ValueError("invalid peer challenge observed source IP")

    expires_at = challenge.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        raise ValueError("invalid peer challenge expiry")
    if expires_at < int(time.time()) - 5:
        raise ValueError("peer adaptive challenge already expired")

    prefix = f"{nonce}:{source_ip}:".encode()
    target = 1 << (256 - bits)
    deadline = time.monotonic() + PEER_CHALLENGE_MAX_SECONDS

    for i in range(PEER_CHALLENGE_MAX_TRIES):
        digest = hashlib.sha256(prefix + str(i).encode()).digest()
        if int.from_bytes(digest, "big") < target:
            return str(i)

        if (i & 4095) == 4095 and time.monotonic() >= deadline:
            break

    raise ValueError("peer adaptive challenge solve limit exceeded")


def http_json(url, method="GET", obj=None, timeout=3,
              max_bytes=MAX_PEER_JSON_BYTES):
    data = None
    base_headers = {}

    if obj is not None:
        data = json.dumps(obj).encode()
        base_headers["Content-Type"] = "application/json"

    def request_once(extra_headers=None):
        headers = dict(base_headers)
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _read_bounded_peer_json(r, max_bytes)

    try:
        return request_once()

    except urllib.error.HTTPError as e:
        if int(getattr(e, "code", 0)) != 428:
            raise

        try:
            response = _read_bounded_peer_json(e, max_bytes)
        finally:
            try:
                e.close()
            except Exception:
                pass

        if not isinstance(response, dict):
            raise ValueError("invalid peer adaptive challenge response")

        if response.get("error") != "adaptive challenge required":
            raise ValueError("unexpected peer HTTP 428 response")

        challenge = response.get("challenge")
        observed_source_ip = response.get("observed_source_ip")

        solution = _peer_challenge_solution(
            challenge,
            observed_source_ip,
        )

        # Exactly one retry. A second 428 or any other failure propagates
        # normally and is handled by the existing peer-reputation logic.
        return request_once({
            "X-Stevens-Challenge-Nonce": str(challenge["nonce"]),
            "X-Stevens-Challenge-Solution": solution,
        })


def validate_peer_header_chain(headers: list[dict], genesis_hash: str) -> int:
    """Validate a complete 0..tip header sequence and return actual work."""
    if not isinstance(headers, list) or not headers:
        raise ValueError("peer returned no headers")
    if len(headers) > MAX_SYNC_HEADER_PREFLIGHT:
        raise ValueError("peer header preflight exceeds safety limit")
    if headers[0].get("hash") != genesis_hash:
        raise ValueError("peer headers use different genesis")
    now = int(time.time())
    for height, hdr in enumerate(headers):
        if int(hdr.get("height", -1)) != height:
            raise ValueError("peer header height mismatch")
        if hdr.get("chain") != ledger.CHAIN_NAME or int(hdr.get("version", 0)) != 2:
            raise ValueError("peer header chain/version mismatch")
        if height == 0:
            if hdr.get("previous_hash") != "00" * 32:
                raise ValueError("peer genesis previous hash mismatch")
        elif hdr.get("previous_hash") != headers[height - 1].get("hash"):
            raise ValueError("peer header linkage mismatch")
        want_hash = ledger.block_hash(hdr)
        if hdr.get("hash") != want_hash:
            raise ValueError("peer header hash mismatch")
        bits = int(hdr.get("difficulty_bits", -1))
        if bits != expected_difficulty(headers[:height], height):
            raise ValueError("peer header difficulty mismatch")
        if not ledger.pow_valid(want_hash, bits):
            raise ValueError("peer header proof of work invalid")
        validate_block_timestamp(headers, height, now=now)
    return cumulative_work(headers)


class TestnetNode:
    def __init__(self, chain: TestnetChain, identity: NodeIdentity, self_url: str):
        self.chain = chain
        self.identity = identity
        self.self_url = self_url.rstrip("/")
        self.peers = PeerBook()
        self.seen_nonces = OrderedDict()
        self.lock = threading.RLock()
        self.bootstrap_policy_enabled = False
        self.bootstrap_min_groups = 0
        self.bootstrap_require_quorum = False

        # Dynamic peer cache lives beside this node's SQLite chain state.
        self.peer_store_path = (
            self.chain.v03_data_dir / "peers.json"
            if getattr(self.chain, "v03_data_dir", None) else None
        )
        self.persisted_peer_candidates = {}
        self._load_persisted_peers()

    def _save_persisted_peers(self):
        path = self.peer_store_path
        if path is None:
            return

        with self.peers.lock:
            active = {}

            for rec in self.peers.records.values():
                if (
                    not rec.bootstrap
                    and rec.node_id
                    and rec.pubkey
                ):
                    active[rec.url] = {
                        "url": rec.url,
                        "node_id": rec.node_id,
                        "pubkey": rec.pubkey,
                    }

            merged = dict(active)

            for url in sorted(
                self.persisted_peer_candidates
            ):
                if url in merged:
                    continue

                if len(merged) >= self.peers.max_peers:
                    break

                item = self.persisted_peer_candidates[url]

                merged[url] = {
                    "url": item["url"],
                    "node_id": item["node_id"],
                    "pubkey": item["pubkey"],
                }

            peers = [
                merged[url]
                for url in sorted(merged)
            ]

            self.persisted_peer_candidates = {
                item["url"]: dict(item)
                for item in peers
            }

            doc = {
                "format": "StevensPeerStore",
                "version": 1,
                "network_id": NETWORK_ID,
                "peers": peers,
            }

            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            tmp = path.with_name(
                path.name + ".tmp"
            )

            tmp.write_text(
                json.dumps(doc, indent=2) + "\n",
                encoding="utf-8",
            )

            tmp.replace(path)

    def _load_persisted_peers(self):
        path = self.peer_store_path
        self.persisted_peer_candidates = {}

        if path is None or not path.exists():
            return

        try:
            size = path.stat().st_size

            if size <= 0 or size > 262144:
                raise ValueError(
                    "persisted peer store size invalid"
                )

            doc = json.loads(
                path.read_text(encoding="utf-8")
            )

            if (
                doc.get("format")
                != "StevensPeerStore"
                or int(doc.get("version", 0)) != 1
                or doc.get("network_id")
                != NETWORK_ID
            ):
                raise ValueError(
                    "persisted peer store metadata invalid"
                )

            entries = doc.get("peers", [])

            if not isinstance(entries, list):
                raise ValueError(
                    "persisted peer list invalid"
                )

            if len(entries) > self.peers.max_peers:
                raise ValueError(
                    "persisted peer count exceeds limit"
                )

            candidates = {}
            seen_node_ids = set()

            for item in entries:
                if not isinstance(item, dict):
                    continue

                try:
                    url = validate_peer_url(
                        str(item.get("url") or "")
                    )
                except Exception:
                    continue

                node_id = str(
                    item.get("node_id") or ""
                ).lower()

                pubkey = str(
                    item.get("pubkey") or ""
                ).lower()

                if (
                    not url
                    or url == self.self_url
                    or len(node_id) != 32
                    or any(
                        c not in "0123456789abcdef"
                        for c in node_id
                    )
                    or len(pubkey) != 64
                    or any(
                        c not in "0123456789abcdef"
                        for c in pubkey
                    )
                ):
                    continue

                try:
                    derived = node_id_from_pubkey_hex(
                        pubkey
                    )
                except Exception:
                    continue

                if derived != node_id:
                    continue

                if (
                    url in candidates
                    or node_id in seen_node_ids
                ):
                    continue

                candidates[url] = {
                    "url": url,
                    "node_id": node_id,
                    "pubkey": pubkey,
                }

                seen_node_ids.add(node_id)

            self.persisted_peer_candidates = (
                candidates
            )

        except Exception:
            self.persisted_peer_candidates = {}

    def configure_bootstrap_policy(self, policy: dict):
        self.bootstrap_policy_enabled = True
        self.bootstrap_min_groups = int(policy["minimum_operator_groups"])
        self.bootstrap_require_quorum = bool(policy.get("require_quorum", True))

    def bootstrap_health(self):
        groups = {
            r.operator_group for r in self.peers.active()
            if r.bootstrap and r.operator_group
        }
        peers = sum(1 for r in self.peers.active() if r.bootstrap)
        return {
            "enabled": self.bootstrap_policy_enabled,
            "active_bootstrap_peers": peers,
            "active_operator_groups": len(groups),
            "minimum_operator_groups": self.bootstrap_min_groups,
            "require_quorum": self.bootstrap_require_quorum,
            "quorum_met": (not self.bootstrap_policy_enabled or
                           len(groups) >= self.bootstrap_min_groups),
        }

    def add_peer(self, url: str, *, expected_node_id=None,
                 bootstrap=False, operator_group=None, persist=True):
        url = validate_peer_url(url)
        if not url or url == self.self_url:
            return None
        if bootstrap and not expected_node_id:
            raise ValueError("bootstrap peer requires pinned node identity")
        try:
            hello = http_json(url + "/hello", timeout=2)
            if hello.get("network_id") != NETWORK_ID:
                raise ValueError("peer is on different network")
            hello_node_id = str(hello.get("node_id") or "").lower()
            hello_pubkey = str(hello.get("node_pubkey") or "")
            if node_id_from_pubkey_hex(hello_pubkey) != hello_node_id:
                raise ValueError("peer hello node id/public key mismatch")
            if expected_node_id and hello_node_id != str(expected_node_id).lower():
                raise ValueError("bootstrap peer identity pin mismatch")
            rec = self.peers.add(
                url, hello_node_id, hello_pubkey,
                bootstrap=bootstrap, operator_group=operator_group
            )
            self.peers.score(url, +2)
            if persist and not bootstrap:
                self._save_persisted_peers()
            return rec
        except Exception:
            self.peers.note_failure(url)
            raise

    def add_bootstrap_peer(self, spec: BootstrapPeerSpec):
        return self.add_peer(
            spec.url, expected_node_id=spec.node_id, bootstrap=True,
            operator_group=spec.operator_group
        )

    @staticmethod
    def _candidate_sort_key(item):
        # Candidate tuples carry (peer, status snapshot, verified work,
        # verified header snapshot). Keep sorting independent of tuple growth.
        rec, verified_work = item[0], item[2]
        return (-rec.score, rec.failures, -int(verified_work), rec.url)

    def _diversity_order_candidates(self, candidates):
        ordered = sorted(candidates, key=self._candidate_sort_key)
        if not self.bootstrap_policy_enabled:
            return ordered
        groups = {}
        dynamic = []
        for item in ordered:
            rec = item[0]
            if rec.bootstrap and rec.operator_group:
                groups.setdefault(rec.operator_group, []).append(item)
            else:
                dynamic.append(item)
        # First take one best verified candidate from each independently
        # configured operator group. Only after that can extra aliases from
        # the same operator compete for remaining slots.
        representatives = [items[0] for items in groups.values() if items]
        representatives.sort(key=self._candidate_sort_key)
        remainder = []
        for items in groups.values():
            remainder.extend(items[1:])
        remainder.sort(key=self._candidate_sort_key)
        return representatives + dynamic + remainder

    def signed_post(self, peer_url: str, path: str, kind: str, payload: dict, timeout=2):
        env = self.identity.sign_envelope(kind, payload)
        try:
            result = http_json(peer_url + path, "POST", {"envelope": env}, timeout=timeout)
            self.peers.score(peer_url, +1)
            return result
        except Exception:
            self.peers.note_failure(peer_url)
            raise

    def broadcast(self, path: str, kind: str, payload: dict):
        for rec in self.peers.active():
            try:
                self.signed_post(rec.url, path, kind, payload, timeout=1.5)
            except Exception:
                pass

    def _fetch_paginated_chain(self, rec, st, headers, verified_work,
                               common_height: int = 0, local_blocks=None):
        """Fetch only the divergent/new suffix in bounded full-block pages.

        `headers` has already been fully verified. Blocks at or below
        common_height are therefore reused from the local chain instead of
        being retransmitted on every routine sync.
        """
        remote_height = int(st["height"])
        remote_tip = str(st["tip"])
        common_height = int(common_height)
        if local_blocks is None:
            local_blocks = self.chain.blocks
        if common_height < 0 or common_height >= len(local_blocks):
            raise ValueError("invalid sync common ancestor")
        if common_height > remote_height:
            raise ValueError("common ancestor exceeds remote height")
        # Build from the immutable local snapshot captured before remote I/O.
        # Live mining/reorg activity must not silently change the reused prefix.
        candidate = json.loads(json.dumps(local_blocks[:common_height + 1]))
        start = common_height + 1
        while start <= remote_height:
            page = http_json(
                rec.url + f"/chain-page?start={start}&limit={MAX_CHAIN_PAGE_BLOCKS}",
                timeout=5, max_bytes=MAX_CHAIN_PAGE_RESPONSE_BYTES,
            )
            if page.get("network_id") != NETWORK_ID:
                raise ValueError("peer chain-page network mismatch")
            if int(page.get("height", -1)) != remote_height:
                raise ValueError("peer chain-page height changed during sync")
            if str(page.get("tip", "")) != remote_tip:
                raise ValueError("peer chain-page tip changed during sync")
            if int(page.get("cumulative_work", -1)) != int(verified_work):
                raise ValueError("peer chain-page work changed during sync")
            if int(page.get("start", -1)) != start:
                raise ValueError("peer chain-page start mismatch")
            blocks = page.get("blocks")
            if not isinstance(blocks, list) or not blocks:
                raise ValueError("peer returned empty/invalid chain page")
            if len(blocks) > MAX_CHAIN_PAGE_BLOCKS:
                raise ValueError("peer chain page exceeds block-count limit")
            if start + len(blocks) > remote_height + 1:
                raise ValueError("peer chain page exceeds advertised height")

            page_bytes = 0
            for offset, block in enumerate(blocks):
                height = start + offset
                if not isinstance(block, dict) or int(block.get("height", -1)) != height:
                    raise ValueError("peer chain-page block height mismatch")
                self.chain._limits_check_block(block)
                page_bytes += json_size(block)
                hdr = headers[height]
                # The verified header preflight commits to every consensus
                # header field. Full blocks must reproduce that exact header
                # hash before they are retained in the candidate list.
                if block.get("hash") != hdr.get("hash"):
                    raise ValueError("peer full block does not match verified header hash")
                if ledger.block_hash(block) != hdr.get("hash"):
                    raise ValueError("peer full block header content mismatch")
                if block.get("merkle_root") != ledger.merkle_root(
                    [tx["txid"] for tx in block.get("transactions", [])]
                ):
                    raise ValueError("peer full block merkle root mismatch")
            if page_bytes > MAX_CHAIN_PAGE_DATA_BYTES + MAX_BLOCK_BYTES:
                raise ValueError("peer chain page exceeds decoded data budget")

            expected_next = start + len(blocks)
            if int(page.get("next_start", -1)) != expected_next:
                raise ValueError("peer chain-page continuation mismatch")
            done = bool(page.get("done", False))
            if done != (expected_next == remote_height + 1):
                raise ValueError("peer chain-page completion flag mismatch")

            candidate.extend(blocks)
            start = expected_next

        if len(candidate) != remote_height + 1:
            raise ValueError("peer paginated chain length mismatch")
        if candidate[-1].get("hash") != remote_tip:
            raise ValueError("peer paginated chain tip mismatch")
        if cumulative_work(candidate) != int(verified_work):
            raise ValueError("peer paginated chain work mismatch")
        return candidate

    def headers_first_sync(self):
        """
        Ask peers for headers first, but do not let one self-reported
        "best" peer monopolize sync. Candidate status/work is advisory only;
        each fetched full chain is independently validated before adoption,
        and a bad candidate is penalized before trying the next peer.
        """
        candidates = []
        # Capture one immutable local view before any untrusted network I/O.
        # HTTP mutation endpoints use this same node lock. Remote fetches stay
        # outside the lock so a slow peer cannot freeze local transaction/mining
        # service, while final adoption is serialized again below.
        with self.lock:
            local_blocks = json.loads(json.dumps(self.chain.blocks))
        local_work = cumulative_work(local_blocks)
        for rec in self.peers.active():
            try:
                st = http_json(rec.url + "/status", timeout=2)
                if st.get("network_id") != NETWORK_ID:
                    self.peers.score(rec.url, -50)
                    continue
                if rec.node_id and st.get("node_id") and st.get("node_id") != rec.node_id:
                    self.peers.score(rec.url, -100)
                    continue
                remote_work = int(st["cumulative_work"])
                # A valid same-or-weaker status proves this known peer is
                # reachable and speaking the expected network protocol. Give
                # bounded recovery credit without allowing routine health
                # checks to inflate reputation above neutral. Better-chain
                # candidates earn their existing +10 only after full
                # validation and adoption.
                if remote_work == local_work:
                    self.peers.note_success(rec.url)
                # Strict fork choice requires strictly greater cumulative
                # work. Equal-work forks can never be adopted, so do not
                # spend header/full-block bandwidth fetching them.
                if remote_work > local_work:
                    try:
                        remote_height = int(st["height"])
                        remote_tip = str(st["tip"])
                    except (KeyError, TypeError, ValueError):
                        raise ValueError("peer status missing height/tip")
                    if remote_height < 0 or remote_height + 1 > MAX_SYNC_HEADER_PREFLIGHT:
                        raise ValueError("peer height exceeds header preflight safety limit")

                    # Fetch the complete advertised header sequence in bounded
                    # pages. This turns self-reported work into verifiable PoW
                    # before a peer becomes a full-chain candidate.
                    headers = []
                    start = 0
                    while start <= remote_height:
                        want = min(MAX_HEADERS_PER_RESPONSE, remote_height + 1 - start)
                        hdr = http_json(
                            rec.url + f"/headers?start={start}&limit={want}",
                            timeout=3,
                        )
                        if hdr.get("network_id") != NETWORK_ID:
                            raise ValueError("peer header network mismatch")
                        page = hdr.get("headers", [])
                        if len(page) != want:
                            raise ValueError("peer returned incomplete header page")
                        headers.extend(page)
                        start += len(page)

                    genesis_hash = local_blocks[0]["hash"] if local_blocks else headers[0]["hash"]
                    verified_work = validate_peer_header_chain(headers, genesis_hash)
                    if headers[-1]["hash"] != remote_tip:
                        raise ValueError("peer status tip/header tip mismatch")
                    if verified_work != remote_work:
                        raise ValueError("peer status work/header work mismatch")
                    # Bind the exact verified header snapshot to this peer
                    # candidate. Never reuse a loop-local `headers` value from
                    # another peer during the later full-block fetch.
                    candidates.append((rec, st, verified_work, tuple(headers)))
            except Exception:
                self.peers.note_failure(rec.url)

        if not candidates:
            return False, None

        if self.bootstrap_policy_enabled and self.bootstrap_require_quorum:
            verified_groups = {
                item[0].operator_group for item in candidates
                if item[0].bootstrap and item[0].operator_group
            }
            if len(verified_groups) < self.bootstrap_min_groups:
                # Fail closed: when the operator explicitly requires a
                # bootstrap quorum, unpinned dynamic peers cannot substitute
                # for missing independent bootstrap operators.
                return False, None

        # Prefer one verified candidate from each independently configured
        # bootstrap operator group before allowing a single group to consume
        # multiple sync-candidate slots. Claimed work remains advisory until
        # the candidate chain validates locally.
        candidates = self._diversity_order_candidates(candidates)
        for rec, st, verified_work, candidate_headers in candidates[:MAX_SYNC_CANDIDATES]:
            try:
                headers = candidate_headers
                # Find the highest verified common ancestor. Header hashes
                # make this deterministic and prevent an untrusted peer from
                # choosing what local prefix gets reused.
                common_height = 0
                max_common = min(len(local_blocks), len(headers)) - 1
                for h in range(max_common + 1):
                    if local_blocks[h].get("hash") != headers[h].get("hash"):
                        break
                    common_height = h
                blocks = self._fetch_paginated_chain(
                    rec, st, headers, verified_work, common_height=common_height,
                    local_blocks=local_blocks,
                )
                # Re-enter the same mutation lock used by /tx, /block, /mine
                # and /faucet. try_adopt_chain re-evaluates whether this fully
                # validated candidate is still better than the *current* chain,
                # so mining/reorg activity that happened during remote I/O is
                # handled safely instead of racing the candidate install.
                with self.lock:
                    adopted = self.chain.try_adopt_chain(blocks)
                if adopted:
                    self.peers.score(rec.url, +10)
                    return True, rec.url
                # Valid but not better is not malicious; mildly de-prioritize
                # the stale candidate and continue.
                self.peers.score(rec.url, -1)
            except Exception:
                self.peers.note_failure(rec.url)
                continue
        return False, None


class Handler(BaseHTTPRequestHandler):
    # Bound idle client connections so slow/incomplete HTTP requests cannot
    # occupy a server thread indefinitely.
    CLIENT_SOCKET_TIMEOUT_SECONDS = 15

    def setup(self):
        super().setup()
        self.connection.settimeout(self.CLIENT_SOCKET_TIMEOUT_SECONDS)

    node: TestnetNode = None
    limiter = TokenBucketLimiter()
    faucet: Faucet | None = None
    admin_token: str | None = None

    def _ip(self):
        return self.client_address[0]

    def _bound_host_is_loopback(self) -> bool:
        try:
            host = str(self.server.server_address[0])
            return ipaddress.ip_address(host).is_loopback
        except Exception:
            return False

    def _client_is_loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self._ip()).is_loopback
        except Exception:
            return False

    def _admin_authorized(self) -> bool:
        token = self.admin_token
        if token:
            auth = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not auth.startswith(prefix):
                return False
            supplied = auth[len(prefix):].strip()
            return secrets.compare_digest(supplied, token)
        # With no token configured, admin operations are available only when
        # the node itself is bound to loopback and the caller is loopback.
        # This avoids reverse-proxy source-address confusion on public binds.
        return self._bound_host_is_loopback() and self._client_is_loopback()

    def _send(self, code, obj, ctype="application/json"):
        if ctype == "application/json":
            data = json.dumps(obj, indent=2).encode()
        else:
            data = obj.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Stevens-Network", NETWORK_ID)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0:
            return {}
        if n > 2 * 1024 * 1024:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n))

    def _rate_check(self):
        if not self.limiter.allow(self._ip()):
            self._send(429, {"error": "rate limit exceeded"})
            return False
        return True


    def _egress_rate_check(self, estimated_bytes: int) -> bool:
        n = max(0, int(estimated_bytes))
        quantum = PUBLIC_EGRESS_BYTES_PER_TOKEN
        total_cost = max(
            1,
            (n + quantum - 1) // quantum,
        )
        # Permit one bounded response from a completely full
        # bucket even if its estimated size exceeds the nominal
        # capacity expressed in egress quanta.
        total_cost = min(
            int(self.limiter.capacity),
            total_cost,
        )
        # do_GET/do_POST already consumed the first token.
        extra_cost = max(0, total_cost - 1)
        if extra_cost and not self.limiter.allow_cost(
            self._ip(),
            extra_cost,
        ):
            self._send(429, {
                "error": "egress rate limit exceeded",
                "estimated_bytes": n,
                "required_tokens": total_cost,
            })
            return False
        return True
    def _verified_payload(self, expected_kind: str):
        body = self._read_json()
        env = body.get("envelope")
        if not env:
            raise ValueError("signed peer envelope required")
        node_id, payload = verify_envelope(env, self.node.seen_nonces)
        if env["kind"] != expected_kind:
            raise ValueError("wrong envelope kind")
        return node_id, payload

    def log_message(self, fmt, *args):
        print("[testnet]", fmt % args)

    def do_GET(self):
        if not self._rate_check():
            return
        u = urlparse(self.path)
        n = self.node

        if u.path == "/hello":
            payload = {
                "network_id": NETWORK_ID,
                "version": TESTNET_VERSION,
                "node_id": n.identity.node_id,
                "node_pubkey": n.identity.public_key_hex,
            }
            build_identity = getattr(type(self), "build_identity", None)
            if isinstance(build_identity, dict):
                payload["build_identity"] = build_identity
            return self._send(200, payload)

        if u.path == "/status":
            with n.lock:
                st = n.chain.public_status()
                st.update({
                    "network_id": NETWORK_ID,
                    "testnet_version": TESTNET_VERSION,
                    "node_id": n.identity.node_id,
                    "orphan_count": len(n.chain.orphans),
                    "peers": len(n.peers.active()),
                    "bootstrap": n.bootstrap_health(),
                })
            return self._send(200, st)

        if u.path == "/peers":
            return self._send(200, {"peers": n.peers.as_json()})

        if u.path == "/headers":
            q = parse_qs(u.query)
            start = int(q.get("start", [0])[0])
            limit = int(q.get("limit", [200])[0])
            with n.lock:
                payload = {
                    "network_id": NETWORK_ID,
                    "headers": copy.deepcopy(n.chain.headers(start, limit)),
                    "cumulative_work": n.chain.canonical_cumulative_work(),
                }
            return self._send(200, payload)

        if u.path == "/chain-page":
            q = parse_qs(u.query)
            start = int(q.get("start", [0])[0])
            limit = int(q.get("limit", [MAX_CHAIN_PAGE_BLOCKS])[0])
            requested_blocks = min(
                MAX_CHAIN_PAGE_BLOCKS,
                max(1, int(limit)),
            )
            estimated_bytes = min(
                MAX_CHAIN_PAGE_DATA_BYTES,
                requested_blocks * MAX_BLOCK_BYTES,
            )
            if not self._egress_rate_check(estimated_bytes):
                return
            with n.lock:
                page = copy.deepcopy(
                    n.chain.chain_page(start, limit)
                )
                page.update({
                    "network_id": NETWORK_ID,
                    "height": len(n.chain.blocks) - 1,
                    "tip": n.chain.blocks[-1]["hash"] if n.chain.blocks else "",
                    "cumulative_work": n.chain.canonical_cumulative_work(),
                })
            return self._send(200, page)

        if u.path == "/chain":
            # Legacy/read-only compatibility endpoint. New synchronization
            # uses /chain-page. Refuse giant legacy responses before building
            # one monolithic JSON object, so this compatibility route cannot
            # reintroduce the memory-pressure problem on the serving node.
            # Capture only O(1) canonical metadata before weighted egress
            # admission. Do not deep-copy the historical chain for a request
            # that the egress limiter will reject anyway.
            with n.lock:
                approx = n.chain.canonical_chain_json_bytes()
                chain_height = len(n.chain.blocks) - 1
                chain_tip = (
                    n.chain.blocks[-1]["hash"]
                    if n.chain.blocks
                    else ""
                )

            if approx > MAX_LEGACY_CHAIN_RESPONSE_DATA_BYTES:
                return self._send(413, {
                    "error": "legacy full-chain response exceeds safety limit; use /chain-page",
                    "height": chain_height,
                    "approx_chain_bytes": approx,
                })

            estimated_bytes = min(
                MAX_LEGACY_CHAIN_RESPONSE_DATA_BYTES,
                max(
                    1,
                    approx + max(4096, approx // 20),
                ),
            )
            if not self._egress_rate_check(estimated_bytes):
                return

            # The chain may advance while egress admission runs. Reacquire the
            # mutation lock and require the exact admitted canonical snapshot
            # to still be current before doing the expensive deep copy.
            snapshot_changed = False
            with n.lock:
                current_height = len(n.chain.blocks) - 1
                current_tip = (
                    n.chain.blocks[-1]["hash"]
                    if n.chain.blocks
                    else ""
                )
                current_approx = n.chain.canonical_chain_json_bytes()

                if (
                    current_height != chain_height
                    or
                    current_tip != chain_tip
                    or
                    current_approx != approx
                ):
                    snapshot_changed = True
                    chain_payload = None
                else:
                    chain_payload = {
                        "network_id": NETWORK_ID,
                        "cumulative_work": n.chain.canonical_cumulative_work(),
                        "blocks": copy.deepcopy(n.chain.blocks),
                    }

            if snapshot_changed:
                return self._send(409, {
                    "error": "canonical chain changed during legacy snapshot; retry",
                    "height": current_height,
                    "tip": current_tip,
                })

            return self._send(200, chain_payload)

        if u.path == "/mempool":
            with n.lock:
                mempool_snapshot = copy.deepcopy(n.chain.mempool)
                estimated_txs = len(mempool_snapshot)

            estimated_bytes = min(
                _v3_limits.MAX_MEMPOOL_BYTES,
                estimated_txs * _v3_limits.MAX_TX_BYTES,
            )
            if not self._egress_rate_check(estimated_bytes):
                return
            return self._send(200, {
                "transactions": mempool_snapshot,
            })

        if u.path == "/utxos":
            q = parse_qs(u.query)
            address = q.get("address", [None])[0]
            if not address:
                return self._send(400, {"error": "address required"})

            start = max(0, int(q.get("start", [0])[0]))
            requested_limit = min(
                MAX_UTXOS_PER_RESPONSE,
                max(1, int(q.get("limit", [MAX_UTXOS_PER_RESPONSE])[0])),
            )

            with n.lock:
                (
                    page_rows,
                    balance_units,
                    total_utxos,
                ) = n.chain.utxo_page_for_address(
                    address,
                    start,
                    requested_limit,
                    include_mempool=True,
                )

                rows = []
                used = 0

                for (txid, index), out in page_rows:
                    row = {
                        "txid": txid,
                        "index": index,
                        "output": copy.deepcopy(out),
                    }

                    row_bytes = json_size(row)

                    if row_bytes > MAX_UTXO_RESPONSE_DATA_BYTES:
                        raise ValueError(
                            "single UTXO exceeds response data budget"
                        )

                    if (
                        rows
                        and used + row_bytes
                        > MAX_UTXO_RESPONSE_DATA_BYTES
                    ):
                        break

                    rows.append(row)
                    used += row_bytes

                next_start = start + len(rows)
                done = next_start >= total_utxos

            payload = {
                "address": address,
                "balance_units": balance_units,
                "utxos": rows,
                "start": start,
                "next_start": next_start,
                "done": done,
                "total_utxos": total_utxos,
            }

            estimated_bytes = len(
                json.dumps(payload, indent=2).encode("utf-8")
            )

            if not self._egress_rate_check(estimated_bytes):
                return

            return self._send(200, payload)

        if u.path == "/explorer":
            with n.lock:
                blocks = list(reversed(n.chain.blocks[-30:]))
                mempool_n = len(n.chain.mempool)
            rows = "\n".join(
                f"<tr><td>{b['height']}</td><td><code>{b['hash'][:20]}…</code></td>"
                f"<td>{b['difficulty_bits']}</td><td>{len(b['transactions'])}</td>"
                f"<td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b['timestamp']))}</td></tr>"
                for b in blocks
            )
            html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Stevens Testnet Explorer</title>
<style>
body{{font-family:system-ui;margin:2rem;background:#0c1424;color:#e9f0ff}}
a{{color:#8cc8ff}} table{{border-collapse:collapse;width:100%;background:#121f35}}
td,th{{padding:.65rem;border-bottom:1px solid #263b5c;text-align:left}}
code{{color:#b8e1ff}} .card{{padding:1rem;background:#121f35;border-radius:12px;margin-bottom:1rem}}
</style></head><body>
<h1>Stevens Chain v0.5.2 Testnet Explorer</h1>
<div class="card">Height: {n.chain.public_status()['height']} &nbsp; | &nbsp;
Mempool: {mempool_n} &nbsp; | &nbsp; Peers: {len(n.peers.active())}</div>
<table><tr><th>Height</th><th>Hash</th><th>Difficulty</th><th>Txs</th><th>Time</th></tr>
{rows}</table></body></html>"""
            return self._send(200, html, "text/html; charset=utf-8")

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._rate_check():
            return
        n = self.node
        u = urlparse(self.path)
        if u.path in ADMIN_ENDPOINTS and not self._admin_authorized():
            return self._send(403, {"error": "admin authorization required"})
        try:
            if u.path == "/peers/add":
                body = self._read_json()
                rec = n.add_peer(body["peer"])
                return self._send(200, {"added": rec.url, "node_id": rec.node_id})

            if u.path == "/sync":
                adopted, source = n.headers_first_sync()
                return self._send(200, {"adopted": adopted, "source": source})

            if u.path == "/tx":
                sender, payload = self._verified_payload("tx")
                tx = payload["transaction"]
                with n.lock:
                    try:
                        txid = n.chain.submit_tx(tx)
                        accepted = True
                    except ValueError as e:
                        if "already in mempool" in str(e):
                            txid = tx.get("txid")
                            accepted = False
                        else:
                            raise
                if accepted:
                    threading.Thread(
                        target=n.broadcast,
                        args=("/tx", "tx", {"transaction": tx}),
                        daemon=True
                    ).start()
                return self._send(200, {"accepted": accepted, "txid": txid})

            if u.path == "/block":
                sender, payload = self._verified_payload("block")
                block = payload["block"]
                with n.lock:
                    before_height = len(n.chain.blocks)
                    state = n.chain.append_or_orphan(block)
                    chain_advanced = len(n.chain.blocks) > before_height
                if state == "accepted" and chain_advanced:
                    threading.Thread(
                        target=n.broadcast,
                        args=("/block", "block", {"block": block}),
                        daemon=True
                    ).start()
                return self._send(200, {
                    "state": state,
                    "tip": n.chain.blocks[-1]["hash"],
                    "orphans": len(n.chain.orphans),
                })

            if u.path == "/mine":
                body = self._read_json()
                miner = ledger.PublicIdentity.from_dict(body["miner"])
                with n.lock:
                    block = n.chain.mine_mempool(miner)
                threading.Thread(
                    target=n.broadcast,
                    args=("/block", "block", {"block": block}),
                    daemon=True
                ).start()
                return self._send(200, {
                    "height": block["height"],
                    "hash": block["hash"],
                    "difficulty_bits": block["difficulty_bits"],
                })

            if u.path == "/faucet":
                if self.faucet is None:
                    raise ValueError("faucet disabled")
                body = self._read_json()
                recipient = ledger.PublicIdentity.from_dict(body["recipient"])
                with n.lock:
                    tx = self.faucet.claim(recipient, self._ip())
                threading.Thread(
                    target=n.broadcast,
                    args=("/tx", "tx", {"transaction": tx}),
                    daemon=True
                ).start()
                return self._send(200, {
                    "txid": tx["txid"],
                    "amount_units": FAUCET_AMOUNT,
                    "amount": ledger.fmt_amount(FAUCET_AMOUNT),
                })

            if u.path == "/validate":
                with n.lock:
                    n.chain.validate_chain(rebuild=False)
                return self._send(200, {"valid": True})

            return self._send(404, {"error": "not found"})

        except Exception as e:
            return self._send(400, {"error": str(e)})


def serve(data_dir: str, genesis_file: str, host: str, port: int,
          peers=None, faucet_wallet_file=None, faucet_password=None,
          public_url=None, admin_token_file=None):
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True)

    doc = json.load(open(genesis_file))
    if doc.get("network") != NETWORK_ID:
        raise ValueError(
            f"genesis network mismatch: got {doc.get('network')!r}, expected {NETWORK_ID!r}"
        )
    canonical_genesis = doc["block"]

    chain = TestnetChain(data)
    chain.load()
    if not chain.blocks:
        chain.initialize_from_genesis_block(canonical_genesis)
    elif chain.blocks[0]["hash"] != canonical_genesis["hash"]:
        raise ValueError("existing data directory belongs to a different genesis/testnet")

    identity = NodeIdentity.load_or_create(data / "node_identity.json")
    self_url = (public_url or f"http://{host}:{port}").rstrip("/")
    node = TestnetNode(chain, identity, self_url)

    for p in peers or []:
        try:
            node.add_peer(p)
        except Exception:
            pass

    Handler.node = node
    Handler.faucet = None
    Handler.admin_token = None
    if admin_token_file:
        token = Path(admin_token_file).read_text().strip()
        if len(token) < MIN_ADMIN_TOKEN_CHARS:
            raise ValueError(f"admin token must be at least {MIN_ADMIN_TOKEN_CHARS} characters")
        Handler.admin_token = token
    if faucet_wallet_file:
        if not faucet_password:
            raise ValueError("faucet password required when faucet wallet is enabled")
        fw = ledger.Wallet.load(faucet_wallet_file, faucet_password)
        Handler.faucet = Faucet(chain, fw, data)

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Stevens Chain v0.5.2 testnet node: {self_url}", flush=True)
    print(f"node_id={identity.node_id}", flush=True)
    print(f"height={len(chain.blocks)-1} tip={chain.blocks[-1]['hash']}", flush=True)
    if Handler.admin_token:
        print("admin API: bearer-token protected", flush=True)
    elif host_is_loopback(host):
        print("admin API: loopback-only (no bearer token configured)", flush=True)
    else:
        print("admin API: disabled for remote callers (configure --admin-token-file to enable)", flush=True)
    print("TESTNET ONLY — no real funds.", flush=True)
    server.serve_forever()
