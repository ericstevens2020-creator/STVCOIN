"""
Stevens Sentinel v0.9 — Committed Keyring Journal + Multi-Node Receipt Trust

Purpose
-------
Address the v0.8 multi-node / recovery findings without sharing one receipt-signing
secret across hosts.

v0.9 introduces:
- a stable per-node Ed25519 receipt-issuer identity;
- short-lived/rotatable Ed25519 receipt-signing keys certified by that identity;
- issuer ID + signing certificate embedded in each v3 receipt;
- explicit trusted-issuer public-key registry;
- cross-node verification using public keys only;
- a signed, append-only committed keyring journal;
- recovery from the highest valid committed revision;
- automatic repair of a stale/corrupt primary signing-key file from the journal;
- legacy v2 receipt verification retained temporarily for rolling upgrades.

Important security properties
-----------------------------
- Nodes do NOT share receipt private keys.
- Rotating a node's receipt-signing key does not require peers to receive that
  private key or a new trust-registry entry. The new signing key carries a
  certificate signed by the node's already-trusted stable issuer identity.
- Receipt signing-key rotation does not invalidate already-issued v3 receipts;
  each receipt carries the certified public signing key needed to verify it.
- The local CHALLENGE / QUARANTINE / ISOLATE decision remains authoritative.

No blockchain consensus rule changes. No hack-back.
TESTNET / DEFENSIVE SECURITY ONLY.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from stevens_sentinel_v0_2 import canonical
from stevens_sentinel_v0_4 import _b64e, _b64d
from stevens_sentinel_v0_8 import (
    StevensSentinel as SafeKeyringSentinel,
    KeyringSafetyPolicy,
)
from stevens_sentinel_v0_7 import ReceiptPolicy
from stevens_sentinel_v0_6 import ReliabilityPolicy
from stevens_sentinel_v0_5 import FairnessPolicy
from stevens_sentinel_v0_4 import ResourcePolicy
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "0.9"


@dataclass(frozen=True)
class ClusterReceiptPolicy:
    allow_legacy_v2_receipts: bool = True
    auto_repair_primary_from_journal: bool = True
    trust_registry_enabled: bool = True
    require_explicit_peer_trust: bool = True

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelClusterReceiptPolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ClusterReceiptPolicy":
        if d.get("format") != "StevensSentinelClusterReceiptPolicy":
            raise ValueError("not a Stevens Sentinel cluster receipt policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported cluster receipt policy version")
        defaults = cls()
        return cls(**{
            k: d.get(k, getattr(defaults, k))
            for k in defaults.__dict__
        })

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be boolean")


class StevensSentinel(SafeKeyringSentinel):
    def __init__(self, data_dir, config,
                 swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None,
                 fairness_policy: FairnessPolicy | None = None,
                 reliability_policy: ReliabilityPolicy | None = None,
                 receipt_policy: ReceiptPolicy | None = None,
                 keyring_safety_policy: KeyringSafetyPolicy | None = None,
                 cluster_receipt_policy: ClusterReceiptPolicy | None = None):
        self._v09_state_lock = threading.RLock()

        super().__init__(
            data_dir, config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
            fairness_policy=fairness_policy,
            reliability_policy=reliability_policy,
            receipt_policy=receipt_policy,
            keyring_safety_policy=keyring_safety_policy,
        )

        self.cluster_receipt_policy_path = (
            self.data_dir / "sentinel_cluster_receipt_policy.json"
        )
        self.receipt_issuer_identity_path = (
            self.data_dir / "sentinel_receipt_issuer_identity.json"
        )
        self.receipt_trust_registry_path = (
            self.data_dir / "sentinel_receipt_trust_registry.json"
        )
        self.asym_keyring_path = (
            self.data_dir / "sentinel_receipt_asym_keyring.json"
        )
        self.asym_journal_dir = (
            self.data_dir / "sentinel_receipt_keyring_commits"
        )
        self.asym_rotation_lock_path = (
            self.data_dir / "sentinel_v09_asym_rotation.lock"
        )

        self.cluster_receipt_policy = (
            cluster_receipt_policy or self._load_or_create_cluster_receipt_policy()
        )
        self.cluster_receipt_policy.validate()

        self._issuer_identity = self._load_or_create_issuer_identity()
        self._trust_registry = self._load_or_create_trust_registry()
        self._asym_keyring = self._load_or_create_committed_asym_keyring()
        self._asym_keyring_mtime_ns = self._asym_keyring_stat_mtime()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        # Serialize the full v0.9 state bootstrap.
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "sentinel_v09_startup.lock"
        lock_file = lock_path.open("a+b")
        locked = False
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                locked = True
            except (ImportError, OSError) as exc:
                raise RuntimeError(
                    "cross-process v0.9 startup locking unavailable"
                ) from exc

            base = SafeKeyringSentinel.load_or_create(
                data_dir, public_base_url
            )
            return cls(
                base.data_dir,
                base.config,
                swarm_policy=base.swarm_policy,
                resource_policy=base.resource_policy,
                fairness_policy=base.fairness_policy,
                reliability_policy=base.reliability_policy,
                receipt_policy=base.receipt_policy,
                keyring_safety_policy=base.keyring_safety_policy,
            )
        finally:
            if locked:
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
            lock_file.close()

    # ------------------------------------------------------------------
    # Small crypto helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _private_raw(key: Ed25519PrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def _public_raw(key: Ed25519PublicKey) -> bytes:
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _issuer_id_from_public(raw_public: bytes) -> str:
        return hashlib.sha256(
            b"Stevens-Sentinel-v0.9/issuer|" + raw_public
        ).hexdigest()[:32]

    @staticmethod
    def _signing_kid_from_public(raw_public: bytes) -> str:
        return hashlib.sha256(
            b"Stevens-Sentinel-v0.9/signing-kid|" + raw_public
        ).hexdigest()[:24]

    # ------------------------------------------------------------------
    # Cluster policy
    # ------------------------------------------------------------------
    def _load_or_create_cluster_receipt_policy(self) -> ClusterReceiptPolicy:
        if self.cluster_receipt_policy_path.exists():
            p = ClusterReceiptPolicy.from_dict(
                json.loads(self.cluster_receipt_policy_path.read_text())
            )
        else:
            p = ClusterReceiptPolicy()
            self._write_json_atomic(
                self.cluster_receipt_policy_path,
                p.to_dict(),
            )
        return p

    def _persist_cluster_receipt_policy(self) -> None:
        self.cluster_receipt_policy.validate()
        self._write_json_atomic(
            self.cluster_receipt_policy_path,
            self.cluster_receipt_policy.to_dict(),
        )

    # ------------------------------------------------------------------
    # Stable issuer identity
    # ------------------------------------------------------------------
    def _load_or_create_issuer_identity(self) -> dict:
        if self.receipt_issuer_identity_path.exists():
            raw = json.loads(self.receipt_issuer_identity_path.read_text())
            return self._validate_issuer_identity(raw)

        priv = Ed25519PrivateKey.generate()
        priv_raw = self._private_raw(priv)
        pub_raw = self._public_raw(priv.public_key())
        identity = {
            "format": "StevensSentinelReceiptIssuerIdentity",
            "version": 1,
            "issuer_id": self._issuer_id_from_public(pub_raw),
            "private_key": _b64e(priv_raw),
            "public_key": _b64e(pub_raw),
            "created_at": int(time.time()),
        }
        self._write_json_atomic(
            self.receipt_issuer_identity_path,
            identity,
        )
        return self._validate_issuer_identity(identity)

    def _validate_issuer_identity(self, raw: dict) -> dict:
        if raw.get("format") != "StevensSentinelReceiptIssuerIdentity":
            raise ValueError("bad receipt issuer identity format")
        if int(raw.get("version", 0)) != 1:
            raise ValueError("unsupported receipt issuer identity version")

        priv_raw = _b64d(str(raw.get("private_key", "")))
        pub_raw = _b64d(str(raw.get("public_key", "")))
        if len(priv_raw) != 32 or len(pub_raw) != 32:
            raise ValueError("issuer Ed25519 key length invalid")

        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        derived_pub = self._public_raw(priv.public_key())
        if derived_pub != pub_raw:
            raise ValueError("issuer public/private key mismatch")

        issuer_id = self._issuer_id_from_public(pub_raw)
        if issuer_id != str(raw.get("issuer_id", "")):
            raise ValueError("issuer id mismatch")

        return {
            "format": "StevensSentinelReceiptIssuerIdentity",
            "version": 1,
            "issuer_id": issuer_id,
            "private_key": _b64e(priv_raw),
            "public_key": _b64e(pub_raw),
            "created_at": int(raw.get("created_at", 0) or time.time()),
        }

    def _issuer_private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            _b64d(self._issuer_identity["private_key"])
        )

    def issuer_id(self) -> str:
        return self._issuer_identity["issuer_id"]

    def export_receipt_issuer_bundle(self) -> dict:
        return {
            "format": "StevensSentinelReceiptIssuerBundle",
            "version": 1,
            "issuer_id": self._issuer_identity["issuer_id"],
            "public_key": self._issuer_identity["public_key"],
            "created_at": int(self._issuer_identity["created_at"]),
        }

    # ------------------------------------------------------------------
    # Explicit trusted-issuer registry
    # ------------------------------------------------------------------
    def _empty_trust_registry(self) -> dict:
        return {
            "format": "StevensSentinelReceiptTrustRegistry",
            "version": 1,
            "revision": 0,
            "issuers": {},
        }

    def _load_or_create_trust_registry(self) -> dict:
        if self.receipt_trust_registry_path.exists():
            reg = json.loads(self.receipt_trust_registry_path.read_text())
            reg = self._validate_trust_registry(reg)
        else:
            reg = self._empty_trust_registry()

        # Always trust self locally without requiring operator import.
        own = self.export_receipt_issuer_bundle()
        reg["issuers"][own["issuer_id"]] = {
            "public_key": own["public_key"],
            "trusted_at": int(time.time()),
            "label": "self",
            "revoked": False,
        }
        self._write_json_atomic(self.receipt_trust_registry_path, reg)
        return self._validate_trust_registry(reg)

    def _validate_trust_registry(self, reg: dict) -> dict:
        if reg.get("format") != "StevensSentinelReceiptTrustRegistry":
            raise ValueError("bad receipt trust registry format")
        if int(reg.get("version", 0)) != 1:
            raise ValueError("unsupported receipt trust registry version")
        issuers = reg.get("issuers", {})
        if not isinstance(issuers, dict):
            raise ValueError("trust registry issuers must be object")

        clean = {}
        for issuer_id, entry in issuers.items():
            pub_raw = _b64d(str(entry.get("public_key", "")))
            if len(pub_raw) != 32:
                raise ValueError("trusted issuer public key invalid")
            derived = self._issuer_id_from_public(pub_raw)
            if derived != issuer_id:
                raise ValueError("trusted issuer id/public-key mismatch")
            clean[issuer_id] = {
                "public_key": _b64e(pub_raw),
                "trusted_at": int(entry.get("trusted_at", 0) or time.time()),
                "label": str(entry.get("label", "")),
                "revoked": bool(entry.get("revoked", False)),
            }
        return {
            "format": "StevensSentinelReceiptTrustRegistry",
            "version": 1,
            "revision": max(0, int(reg.get("revision", 0))),
            "issuers": clean,
        }

    def _reload_trust_registry(self) -> None:
        self._trust_registry = self._validate_trust_registry(
            json.loads(self.receipt_trust_registry_path.read_text())
        )

    def trust_receipt_issuer(self, bundle: dict, label: str = "") -> dict:
        if bundle.get("format") != "StevensSentinelReceiptIssuerBundle":
            raise ValueError("bad issuer bundle format")
        if int(bundle.get("version", 0)) != 1:
            raise ValueError("unsupported issuer bundle version")

        pub_raw = _b64d(str(bundle.get("public_key", "")))
        if len(pub_raw) != 32:
            raise ValueError("issuer public key invalid")
        issuer_id = self._issuer_id_from_public(pub_raw)
        if issuer_id != str(bundle.get("issuer_id", "")):
            raise ValueError("issuer bundle id mismatch")

        with self._v09_state_lock:
            self._reload_trust_registry()
            reg = self._trust_registry
            reg["issuers"][issuer_id] = {
                "public_key": _b64e(pub_raw),
                "trusted_at": int(time.time()),
                "label": label or issuer_id,
                "revoked": False,
            }
            reg["revision"] = int(reg.get("revision", 0)) + 1
            reg = self._validate_trust_registry(reg)
            self._write_json_atomic(self.receipt_trust_registry_path, reg)
            self._trust_registry = reg
        return self.cluster_trust_status()

    def revoke_receipt_issuer(self, issuer_id: str) -> dict:
        with self._v09_state_lock:
            self._reload_trust_registry()
            if issuer_id == self.issuer_id():
                raise ValueError("cannot revoke local issuer through peer registry")
            if issuer_id not in self._trust_registry["issuers"]:
                raise KeyError("issuer is not trusted")
            self._trust_registry["issuers"][issuer_id]["revoked"] = True
            self._trust_registry["revision"] += 1
            self._write_json_atomic(
                self.receipt_trust_registry_path,
                self._trust_registry,
            )
        return self.cluster_trust_status()

    def _trusted_issuer_public(self, issuer_id: str) -> bytes | None:
        if not self.cluster_receipt_policy.trust_registry_enabled:
            return None
        try:
            self._reload_trust_registry()
        except Exception:
            return None
        entry = self._trust_registry["issuers"].get(issuer_id)
        if not entry or entry.get("revoked"):
            return None
        try:
            pub = _b64d(entry["public_key"])
            return pub if len(pub) == 32 else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Signed committed asymmetric keyring journal
    # ------------------------------------------------------------------
    def _new_asym_signing_key(self, revision: int, now: int) -> dict:
        priv = Ed25519PrivateKey.generate()
        priv_raw = self._private_raw(priv)
        pub_raw = self._public_raw(priv.public_key())
        return {
            "kid": self._signing_kid_from_public(pub_raw),
            "private_key": _b64e(priv_raw),
            "public_key": _b64e(pub_raw),
            "created_at": int(now),
            "revision": int(revision),
        }

    def _validate_asym_keyring(self, kr: dict) -> dict:
        if kr.get("format") != "StevensSentinelAsymmetricReceiptKeyring":
            raise ValueError("bad asymmetric receipt keyring format")
        if int(kr.get("version", 0)) != 1:
            raise ValueError("unsupported asymmetric receipt keyring version")
        if str(kr.get("issuer_id", "")) != self.issuer_id():
            raise ValueError("asymmetric keyring issuer mismatch")

        current = kr.get("current")
        if not isinstance(current, dict):
            raise ValueError("asymmetric keyring has no current key")

        priv_raw = _b64d(str(current.get("private_key", "")))
        pub_raw = _b64d(str(current.get("public_key", "")))
        if len(priv_raw) != 32 or len(pub_raw) != 32:
            raise ValueError("asymmetric signing key length invalid")

        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        if self._public_raw(priv.public_key()) != pub_raw:
            raise ValueError("asymmetric signing public/private mismatch")

        kid = self._signing_kid_from_public(pub_raw)
        if kid != str(current.get("kid", "")):
            raise ValueError("asymmetric signing kid mismatch")

        revision = max(0, int(kr.get("revision", 0)))
        if int(current.get("revision", -1)) != revision:
            raise ValueError("asymmetric current key revision mismatch")

        return {
            "format": "StevensSentinelAsymmetricReceiptKeyring",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "revision": revision,
            "current": {
                "kid": kid,
                "private_key": _b64e(priv_raw),
                "public_key": _b64e(pub_raw),
                "created_at": int(current.get("created_at", 0) or time.time()),
                "revision": revision,
            },
        }

    def _certificate_for_key(self, current: dict) -> dict:
        cert = {
            "format": "StevensSentinelReceiptSigningCertificate",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "kid": current["kid"],
            "public_key": current["public_key"],
            "created_at": int(current["created_at"]),
            "revision": int(current["revision"]),
        }
        signature = self._issuer_private_key().sign(canonical(cert))
        return {
            "certificate": cert,
            "issuer_signature": _b64e(signature),
        }

    def _commit_filename(self, revision: int) -> Path:
        return self.asym_journal_dir / f"rev-{revision:012d}.json"

    def _commit_body(self, kr: dict, previous_commit_hash: str) -> dict:
        return {
            "format": "StevensSentinelReceiptKeyringCommit",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "revision": int(kr["revision"]),
            "previous_commit_hash": previous_commit_hash,
            "created_at": int(time.time()),
            "keyring": kr,
        }

    def _make_commit(self, kr: dict, previous_commit_hash: str) -> dict:
        body = self._commit_body(kr, previous_commit_hash)
        signature = self._issuer_private_key().sign(canonical(body))
        signed = {
            "body": body,
            "signature": _b64e(signature),
        }
        commit_hash = hashlib.sha256(
            b"Stevens-Sentinel-v0.9/commit|" + canonical(signed)
        ).hexdigest()
        return {
            **signed,
            "commit_hash": commit_hash,
        }

    def _validate_commit(self, commit: dict,
                         expected_previous_hash: str | None = None) -> dict:
        body = commit.get("body")
        if not isinstance(body, dict):
            raise ValueError("keyring commit body missing")
        if body.get("format") != "StevensSentinelReceiptKeyringCommit":
            raise ValueError("bad keyring commit format")
        if int(body.get("version", 0)) != 1:
            raise ValueError("unsupported keyring commit version")
        if str(body.get("issuer_id", "")) != self.issuer_id():
            raise ValueError("keyring commit issuer mismatch")

        signature = _b64d(str(commit.get("signature", "")))
        root_pub = Ed25519PublicKey.from_public_bytes(
            _b64d(self._issuer_identity["public_key"])
        )
        root_pub.verify(signature, canonical(body))

        signed = {"body": body, "signature": commit["signature"]}
        expected_hash = hashlib.sha256(
            b"Stevens-Sentinel-v0.9/commit|" + canonical(signed)
        ).hexdigest()
        if expected_hash != str(commit.get("commit_hash", "")):
            raise ValueError("keyring commit hash mismatch")

        if (
            expected_previous_hash is not None
            and str(body.get("previous_commit_hash", ""))
            != expected_previous_hash
        ):
            raise ValueError("keyring commit chain link mismatch")

        kr = self._validate_asym_keyring(body["keyring"])
        if int(body.get("revision", -1)) != int(kr["revision"]):
            raise ValueError("keyring commit revision mismatch")
        return {
            "commit_hash": expected_hash,
            "keyring": kr,
            "body": body,
        }

    def _load_valid_commit_chain(self) -> list[dict]:
        self.asym_journal_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(self.asym_journal_dir.glob("rev-*.json"))
        if not files:
            return []

        validated = []
        prev_hash = "0" * 64
        expected_revision = 0

        for path in files:
            commit = json.loads(path.read_text())
            v = self._validate_commit(
                commit,
                expected_previous_hash=prev_hash,
            )
            revision = int(v["keyring"]["revision"])
            if revision != expected_revision:
                raise ValueError(
                    f"non-contiguous keyring journal revision {revision}, "
                    f"expected {expected_revision}"
                )
            validated.append(v)
            prev_hash = v["commit_hash"]
            expected_revision += 1
        return validated

    def _write_commit_atomic(self, commit: dict, revision: int) -> None:
        path = self._commit_filename(revision)
        if path.exists():
            # Immutable journal: an existing revision must match byte-for-byte
            # in semantic content.
            existing = json.loads(path.read_text())
            if existing != commit:
                raise ValueError("attempt to overwrite immutable keyring commit")
            return
        self._write_json_atomic(path, commit)

    def _asym_keyring_stat_mtime(self) -> int:
        try:
            return int(self.asym_keyring_path.stat().st_mtime_ns)
        except FileNotFoundError:
            return 0

    def _load_or_create_committed_asym_keyring(self) -> dict:
        self.asym_journal_dir.mkdir(parents=True, exist_ok=True)
        chain = self._load_valid_commit_chain()

        if not chain:
            now = int(time.time())
            kr = {
                "format": "StevensSentinelAsymmetricReceiptKeyring",
                "version": 1,
                "issuer_id": self.issuer_id(),
                "revision": 0,
                "current": self._new_asym_signing_key(0, now),
            }
            kr = self._validate_asym_keyring(kr)
            commit = self._make_commit(kr, "0" * 64)
            self._write_commit_atomic(commit, 0)
            self._write_json_atomic(self.asym_keyring_path, kr)
            return kr

        highest = chain[-1]["keyring"]

        primary = None
        primary_error = None
        try:
            primary = self._validate_asym_keyring(
                json.loads(self.asym_keyring_path.read_text())
            )
        except Exception as exc:
            primary_error = exc

        if primary is None:
            if not self.cluster_receipt_policy.auto_repair_primary_from_journal:
                raise ValueError(
                    f"primary asymmetric keyring invalid: {primary_error}"
                )
            self._write_json_atomic(self.asym_keyring_path, highest)
            return highest

        if int(primary["revision"]) < int(highest["revision"]):
            if not self.cluster_receipt_policy.auto_repair_primary_from_journal:
                raise ValueError("primary asymmetric keyring is behind committed journal")
            self._write_json_atomic(self.asym_keyring_path, highest)
            return highest

        if int(primary["revision"]) > int(highest["revision"]):
            raise ValueError(
                "primary asymmetric keyring revision exceeds committed journal"
            )

        if primary != highest:
            raise ValueError(
                "primary asymmetric keyring differs from committed revision"
            )
        return primary

    def _reload_asym_keyring_if_changed(self, force: bool = False) -> None:
        mtime = self._asym_keyring_stat_mtime()
        if not force and mtime == getattr(self, "_asym_keyring_mtime_ns", 0):
            return
        with self._v09_state_lock:
            latest = self._load_or_create_committed_asym_keyring()
            self._asym_keyring = latest
            self._asym_keyring_mtime_ns = self._asym_keyring_stat_mtime()

    def _asym_rotation_lock(self):
        class _Lock:
            def __init__(inner, sentinel):
                inner.s = sentinel
                inner.f = None
                inner.locked = False

            def __enter__(inner):
                inner.f = inner.s.asym_rotation_lock_path.open("a+b")
                try:
                    import fcntl
                    fcntl.flock(inner.f.fileno(), fcntl.LOCK_EX)
                    inner.locked = True
                except (ImportError, OSError) as exc:
                    inner.f.close()
                    raise RuntimeError(
                        "cross-process v0.9 signing-key locking unavailable"
                    ) from exc
                return inner

            def __exit__(inner, exc_type, exc, tb):
                if inner.f is not None:
                    if inner.locked:
                        try:
                            import fcntl
                            fcntl.flock(inner.f.fileno(), fcntl.LOCK_UN)
                        except Exception:
                            pass
                    inner.f.close()
                return False
        return _Lock(self)

    def rotate_receipt_key(self, now: int | None = None) -> dict:
        """
        v3 receipt signing-key rotation.

        Old v3 receipts remain independently verifiable because they carry the
        certified signing public key used at issue time. No previous private
        signing key is required for receipt verification.
        """
        now = int(now or time.time())

        with self._asym_rotation_lock():
            chain = self._load_valid_commit_chain()
            if not chain:
                current = self._load_or_create_committed_asym_keyring()
                chain = self._load_valid_commit_chain()
            else:
                current = chain[-1]["keyring"]

            new_revision = int(current["revision"]) + 1
            new_kr = {
                "format": "StevensSentinelAsymmetricReceiptKeyring",
                "version": 1,
                "issuer_id": self.issuer_id(),
                "revision": new_revision,
                "current": self._new_asym_signing_key(
                    new_revision, now
                ),
            }
            new_kr = self._validate_asym_keyring(new_kr)
            previous_hash = chain[-1]["commit_hash"]
            commit = self._make_commit(new_kr, previous_hash)

            # Commit is published BEFORE primary. If the process dies after this
            # point, startup recovers the highest valid signed commit.
            self._write_commit_atomic(commit, new_revision)
            self._write_json_atomic(self.asym_keyring_path, new_kr)

            self._asym_keyring = new_kr
            self._asym_keyring_mtime_ns = self._asym_keyring_stat_mtime()

        status = self.receipt_status(now=now)
        status["rotation_applied"] = True
        status["rotation_blocked_reason"] = None
        return status

    @classmethod
    def recover_asymmetric_keyring_from_journal_path(cls, data_dir) -> dict:
        """
        Explicit recovery entry point. It intentionally constructs a normal
        v0.9 Sentinel so the journal, issuer identity, and signatures are
        validated before the highest committed revision is restored.
        """
        s = cls.load_or_create(data_dir)
        s._reload_asym_keyring_if_changed(force=True)
        return {
            "restored": True,
            "issuer_id": s.issuer_id(),
            "revision": int(s._asym_keyring["revision"]),
            "current_kid": s._asym_keyring["current"]["kid"],
            "commit_count": len(s._load_valid_commit_chain()),
        }

    # ------------------------------------------------------------------
    # v3 receipt binding / issue / verify
    # ------------------------------------------------------------------
    def _binding_material_v3(self, source_ip: str,
                             client_binding: str | None,
                             mode: str) -> bytes | None:
        # Reuse the explicit v0.7 binding policy semantics.
        return self._binding_material(
            source_ip,
            client_binding,
            mode,
        )

    def _binding_hash_v3(self, source_ip: str,
                         client_binding: str | None,
                         mode: str,
                         nonce: str) -> str | None:
        material = self._binding_material_v3(
            source_ip, client_binding, mode
        )
        if material is None:
            return None
        return hashlib.sha256(
            b"Stevens-Sentinel-v0.9/binding|"
            + nonce.encode()
            + b"|"
            + material
        ).hexdigest()

    def issue_proof_receipt(self, source_ip: str,
                            client_binding: str | None = None,
                            now: int | None = None) -> str:
        self._reload_asym_keyring_if_changed()

        if not self._binding_mode_allowed():
            raise ValueError(
                "experimental receipt binding mode is disabled by keyring safety policy"
            )

        now = int(now or time.time())
        ttl = int(self.reliability_policy.proof_receipt_ttl_seconds)
        mode = self.receipt_policy.binding_mode
        nonce = os.urandom(12).hex()

        current = self._asym_keyring["current"]
        binding_hash = self._binding_hash_v3(
            source_ip,
            client_binding,
            mode,
            nonce,
        )
        if binding_hash is None:
            raise ValueError("receipt binding material missing or invalid")

        cert = self._certificate_for_key(current)
        payload = {
            "v": 3,
            "issuer": self.issuer_id(),
            "kid": current["kid"],
            "iat": now,
            "exp": now + ttl,
            "scope": "global-swarm-proof",
            "bm": mode,
            "nonce": nonce,
            "bind": binding_hash,
            "cert": cert["certificate"],
            "cert_sig": cert["issuer_signature"],
        }
        body = canonical(payload)

        signing_priv = Ed25519PrivateKey.from_private_bytes(
            _b64d(current["private_key"])
        )
        signature = signing_priv.sign(body)
        return _b64e(body) + "." + _b64e(signature)

    def _verify_v3_receipt(self, receipt: str,
                           source_ip: str,
                           client_binding: str | None,
                           now: int) -> bool:
        try:
            body64, sig64 = str(receipt).split(".", 1)
            body = _b64d(body64)
            signature = _b64d(sig64)
            if _b64e(body) != body64 or _b64e(signature) != sig64:
                return False

            payload = json.loads(body)
            if int(payload.get("v", 0)) != 3:
                return False
            if payload.get("scope") != "global-swarm-proof":
                return False

            issuer_id = str(payload.get("issuer", ""))
            trusted_root = self._trusted_issuer_public(issuer_id)
            if trusted_root is None:
                return False

            cert = payload.get("cert")
            if not isinstance(cert, dict):
                return False
            if cert.get("format") != "StevensSentinelReceiptSigningCertificate":
                return False
            if int(cert.get("version", 0)) != 1:
                return False
            if str(cert.get("issuer_id", "")) != issuer_id:
                return False
            if str(cert.get("kid", "")) != str(payload.get("kid", "")):
                return False

            signing_pub_raw = _b64d(str(cert.get("public_key", "")))
            if len(signing_pub_raw) != 32:
                return False
            if (
                self._signing_kid_from_public(signing_pub_raw)
                != str(cert.get("kid", ""))
            ):
                return False

            cert_sig = _b64d(str(payload.get("cert_sig", "")))
            Ed25519PublicKey.from_public_bytes(
                trusted_root
            ).verify(cert_sig, canonical(cert))

            Ed25519PublicKey.from_public_bytes(
                signing_pub_raw
            ).verify(signature, body)

            skew = int(
                self.reliability_policy.proof_receipt_clock_skew_seconds
            )
            if int(payload.get("iat", 0)) > now + skew:
                return False
            if int(payload.get("exp", 0)) < now - skew:
                return False

            mode = str(payload.get("bm", ""))
            if mode != self.receipt_policy.binding_mode:
                return False
            if mode != "exact-ip" and not self._binding_mode_allowed():
                return False

            nonce = str(payload.get("nonce", ""))
            expected_bind = self._binding_hash_v3(
                source_ip,
                client_binding,
                mode,
                nonce,
            )
            if expected_bind is None:
                return False
            if expected_bind != str(payload.get("bind", "")):
                return False
            return True
        except Exception:
            return False

    def verify_proof_receipt(self, receipt: str | None,
                             source_ip: str,
                             client_binding: str | None = None,
                             now: int | None = None) -> bool:
        if not receipt:
            return False
        now = int(now or time.time())

        # Detect receipt version cheaply from the signed body.
        try:
            body64 = str(receipt).split(".", 1)[0]
            body = _b64d(body64)
            payload = json.loads(body)
            version = int(payload.get("v", 0))
        except Exception:
            return False

        if version == 3:
            return self._verify_v3_receipt(
                str(receipt),
                source_ip,
                client_binding,
                now,
            )

        if (
            version == 2
            and self.cluster_receipt_policy.allow_legacy_v2_receipts
        ):
            return super().verify_proof_receipt(
                receipt,
                source_ip,
                client_binding=client_binding,
                now=now,
            )
        return False

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def cluster_trust_status(self) -> dict:
        try:
            self._reload_trust_registry()
        except Exception:
            pass
        issuers = []
        for issuer_id, entry in sorted(
            self._trust_registry.get("issuers", {}).items()
        ):
            issuers.append({
                "issuer_id": issuer_id,
                "label": entry.get("label", ""),
                "revoked": bool(entry.get("revoked", False)),
                "self": issuer_id == self.issuer_id(),
            })
        return {
            "sentinel_version": VERSION,
            "local_issuer_id": self.issuer_id(),
            "registry_revision": int(
                self._trust_registry.get("revision", 0)
            ),
            "trusted_issuer_count": sum(
                1 for x in issuers if not x["revoked"]
            ),
            "issuers": issuers,
            "shared_private_receipt_secret_across_nodes": False,
            "peer_trust_is_explicit": bool(
                self.cluster_receipt_policy.require_explicit_peer_trust
            ),
        }

    def receipt_status(self, now: int | None = None) -> dict:
        self._reload_asym_keyring_if_changed()
        chain = self._load_valid_commit_chain()
        status = {
            "sentinel_version": VERSION,
            "receipt_format": "ed25519-certified-v3",
            "issuer_id": self.issuer_id(),
            "current_kid": self._asym_keyring["current"]["kid"],
            "keyring_revision": int(self._asym_keyring["revision"]),
            "committed_revision": int(chain[-1]["keyring"]["revision"]),
            "commit_count": len(chain),
            "journal_mode": "signed-append-only",
            "recovery_source": "highest-valid-committed-revision",
            "binding_mode": self.receipt_policy.binding_mode,
            "experimental_bindings_enabled": bool(
                self.keyring_safety_policy.allow_experimental_binding_modes
            ),
            "signing_key_rotation_invalidates_old_v3_receipts": False,
            "issuer_identity_is_stable": True,
            "shared_private_receipt_secret_across_nodes": False,
        }
        return status

    def cluster_receipt_status(self) -> dict:
        status = self.receipt_status()
        status["trust"] = self.cluster_trust_status()
        status["legacy_v2_verification_enabled"] = bool(
            self.cluster_receipt_policy.allow_legacy_v2_receipts
        )
        return status

    def reliability_status(self) -> dict:
        status = super().reliability_status()
        status["sentinel_version"] = VERSION
        status["proof_receipt_mode"] = "ed25519-certified-v3"
        status["committed_keyring_journal"] = True
        status["multi_node_public_key_trust"] = True
        status["shared_receipt_private_key_across_nodes"] = False
        return status

    def resource_status(self) -> dict:
        status = super().resource_status()
        status["sentinel_version"] = VERSION
        status["cluster_receipt"] = self.cluster_receipt_status()
        return status

    def review_bundle(self, event_limit: int = 500,
                      subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["cluster_receipt_defense"] = {
            "asymmetric_per_node_issuer": True,
            "shared_private_receipt_secret": False,
            "embedded_signing_key_certificate": True,
            "explicit_peer_root_trust": True,
            "committed_keyring_journal": True,
            "highest_valid_revision_recovery": True,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = (
            "adaptive-swarm-resource-fairness-audit-asymmetric-cluster-receipts"
        )
        summary["cluster_receipt_status"] = self.cluster_receipt_status()
        return summary
