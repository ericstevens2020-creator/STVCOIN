"""Stevens Sentinel v1.1 — strong-attack fixes.

Defensive/testnet code. No blockchain consensus changes.

v1.1 closes the six concrete trust/control-plane findings reproduced against v1.0:
- missing established anti-rollback anchor now fails closed;
- legacy v3 receipts are disabled by default and v1 revocation dominates migration mode;
- highest-seen peer issuer policy is stored in the signed trust journal;
- signed revocation bundles are deduplicated by durable operation id;
- recovery private shares are no longer stored together in node state;
- trust-journal mutations are serialized across processes.

Recovery design:
The node stores only recovery PUBLIC keys. Production callers should provide an
external recovery_signer callback backed by independent HSM/KMS/off-host authorities.
For local TESTNET development only, allow_local_dev_recovery=True provisions three
separate one-share authority files outside the node data directory. That mode is
explicitly not independent physical custody.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from stevens_sentinel_v0_2 import canonical
from stevens_sentinel_v0_4 import _b64e, _b64d
from stevens_sentinel_v0_9 import StevensSentinel as ClusterSentinel
from stevens_sentinel_v1_0 import StevensSentinel as V1Sentinel

VERSION = "1.1"


MAX_EVENT_DETAILS_BYTES = 64 * 1024
MAX_EVENT_ROWS = 20_000
EVENT_PRUNE_TARGET_ROWS = 18_000
EVENT_RETENTION_CHECK_EVERY = 256
MAX_EVENT_DETAILS_TOTAL_BYTES = 32 * 1024 * 1024
EVENT_PRUNE_TARGET_DETAILS_BYTES = 24 * 1024 * 1024


class StevensSentinel(V1Sentinel):
    """v1.1 hardening layer over the v1.0 Sentinel trust model."""

    def record(self, severity: str, category: str, source_ip: str | None = None,
               source_node_id: str | None = None, details: dict | None = None,
               affect_score: bool = True) -> str:
        details = details or {}
        raw = json.dumps(details, sort_keys=True).encode("utf-8")
        if len(raw) > MAX_EVENT_DETAILS_BYTES:
            details = {
                "details_truncated": True,
                "original_details_bytes": len(raw),
                "original_details_sha256": hashlib.sha256(raw).hexdigest(),
            }
        event_hash = super().record(severity, category, source_ip, source_node_id, details, affect_score)
        if getattr(self, "_v11_event_retention_ready", False):
            run_retention = False
            with self._event_chain_lock:
                self._v11_event_records_since_retention_check += 1
                if self._v11_event_records_since_retention_check >= EVENT_RETENTION_CHECK_EVERY:
                    self._v11_event_records_since_retention_check = 0
                    run_retention = True
            if run_retention:
                try:
                    retention_result = self._run_event_retention()
                except Exception:
                    with self._event_chain_lock:
                        self._v11_event_records_since_retention_check = max(
                            self._v11_event_records_since_retention_check,
                            EVENT_RETENTION_CHECK_EVERY,
                        )
                    raise
                if retention_result is None:
                    with self._event_chain_lock:
                        self._v11_event_records_since_retention_check = max(
                            self._v11_event_records_since_retention_check,
                            EVENT_RETENTION_CHECK_EVERY,
                        )
        return event_hash

    def _event_retention_lock(self):
        class _Lock:
            def __init__(inner, sentinel):
                inner.s = sentinel
                inner.f = None
                inner.locked = False

            def __enter__(inner):
                inner.f = inner.s.v11_event_retention_lock_path.open("a+b")
                try:
                    import fcntl
                    fcntl.flock(inner.f.fileno(), fcntl.LOCK_EX)
                    inner.locked = True
                except (ImportError, OSError) as exc:
                    inner.f.close()
                    raise RuntimeError("cross-process event retention locking unavailable") from exc
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

    def _event_retention_snapshot(self):
        with self._connect() as con:
            rows = con.execute("""
                SELECT id,event_hash,previous_hash,LENGTH(details_json)
                FROM events ORDER BY id ASC
            """).fetchall()
        return {
            "rows": rows,
            "row_count": len(rows),
            "detail_bytes": sum(int(r[3] or 0) for r in rows),
        }

    def _event_retention_plan(self, snapshot):
        rows = list(snapshot["rows"])
        row_count = int(snapshot["row_count"])
        detail_bytes = int(snapshot["detail_bytes"])
        if row_count <= MAX_EVENT_ROWS and detail_bytes <= MAX_EVENT_DETAILS_TOTAL_BYTES:
            return None
        if len(rows) < 2:
            raise RuntimeError("event retention cannot prune the final event")
        delete_count = max(0, row_count - EVENT_PRUNE_TARGET_ROWS)
        delete_count = min(delete_count, len(rows) - 1)
        retained_bytes = detail_bytes - sum(int(r[3] or 0) for r in rows[:delete_count])
        while retained_bytes > EVENT_PRUNE_TARGET_DETAILS_BYTES and delete_count < len(rows) - 1:
            retained_bytes -= int(rows[delete_count][3] or 0)
            delete_count += 1
        if delete_count <= 0 or retained_bytes > EVENT_PRUNE_TARGET_DETAILS_BYTES:
            raise RuntimeError("event retention targets cannot be satisfied safely")
        boundary = rows[delete_count - 1]
        first_retained = rows[delete_count]
        return {
            "delete_count": delete_count,
            "pruned_through_id": int(boundary[0]),
            "pruned_through_hash": str(boundary[1]),
            "first_retained_id": int(first_retained[0]),
            "first_retained_previous_hash": str(first_retained[2]),
            "retained_rows": len(rows) - delete_count,
            "retained_detail_bytes": int(retained_bytes),
        }

    def _apply_event_retention_anchor(self, anchor):
        body = anchor["body"]
        previous_id = int(body["previous_pruned_through_id"])
        previous_hash = str(body["previous_pruned_through_hash"])
        pruned_id = int(body["pruned_through_id"])
        pruned_hash = str(body["pruned_through_hash"])
        tip_id = int(body["tip_id_at_checkpoint"])
        tip_hash = str(body["tip_hash_at_checkpoint"])

        with self._event_chain_lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                first = con.execute(
                    "SELECT id,previous_hash FROM events ORDER BY id ASC LIMIT 1"
                ).fetchone()
                tip = con.execute(
                    "SELECT event_hash FROM events WHERE id=?", (tip_id,)
                ).fetchone()
                if first is None or tip is None or not hmac.compare_digest(str(tip[0]), tip_hash):
                    raise RuntimeError("event retention checkpoint tip unavailable or changed")

                first_id = int(first[0])
                first_prev = str(first[1])
                if first_id == pruned_id + 1 and hmac.compare_digest(first_prev, pruned_hash):
                    con.rollback()
                    return 0

                if first_id != previous_id + 1 or not hmac.compare_digest(first_prev, previous_hash):
                    raise RuntimeError("event retention previous boundary mismatch")

                boundary = con.execute(
                    "SELECT event_hash FROM events WHERE id=?", (pruned_id,)
                ).fetchone()
                retained = con.execute(
                    "SELECT id,previous_hash FROM events WHERE id>? ORDER BY id ASC LIMIT 1",
                    (pruned_id,),
                ).fetchone()
                if boundary is None or not hmac.compare_digest(str(boundary[0]), pruned_hash):
                    raise RuntimeError("event retention prune boundary changed")
                if retained is None or int(retained[0]) != pruned_id + 1:
                    raise RuntimeError("event retention first retained event missing")
                if not hmac.compare_digest(str(retained[1]), pruned_hash):
                    raise RuntimeError("event retention first retained link mismatch")

                cur = con.execute("DELETE FROM events WHERE id<=?", (pruned_id,))
                expected_deleted = pruned_id - previous_id
                if int(cur.rowcount) != expected_deleted:
                    raise RuntimeError("event retention delete count mismatch")
                con.commit()
                return int(cur.rowcount)
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

    def _run_event_retention(self):
        with self._event_retention_lock():
            anchor = self._read_event_retention_anchor()
            if anchor is not None:
                self._apply_event_retention_anchor(anchor)
                if not self.verify_log_chain():
                    raise RuntimeError("event log invalid after retention checkpoint recovery")

            snapshot = self._event_retention_snapshot()
            plan = self._event_retention_plan(snapshot)
            if plan is None:
                return 0

            if not self.verify_log_chain():
                raise RuntimeError("event log invalid before retention")

            rows = snapshot["rows"]
            if not rows:
                raise RuntimeError("event retention snapshot unexpectedly empty")

            if anchor is None:
                previous_id = 0
                previous_hash = "0" * 64
            else:
                previous_id = int(anchor["body"]["pruned_through_id"])
                previous_hash = str(anchor["body"]["pruned_through_hash"])

            if int(rows[0][0]) != previous_id + 1:
                raise RuntimeError("event retention snapshot start mismatch")
            if not hmac.compare_digest(str(rows[0][2]), previous_hash):
                raise RuntimeError("event retention snapshot predecessor mismatch")
            if int(plan["first_retained_id"]) != int(plan["pruned_through_id"]) + 1:
                raise RuntimeError("event retention plan is not contiguous")
            if not hmac.compare_digest(
                str(plan["first_retained_previous_hash"]),
                str(plan["pruned_through_hash"]),
            ):
                raise RuntimeError("event retention plan link mismatch")

            tip_id = int(rows[-1][0])
            tip_hash = str(rows[-1][1])
            body = self._event_retention_anchor_body(
                previous_id,
                previous_hash,
                int(plan["pruned_through_id"]),
                str(plan["pruned_through_hash"]),
                tip_id,
                tip_hash,
            )

            try:
                signed = self._write_event_retention_anchor(body)
            except Exception:
                return None

            return self._apply_event_retention_anchor(signed)

    def _event_retention_anchor_body(self, previous_id, previous_hash, pruned_id, pruned_hash, tip_id, tip_hash):
        return {
            "format": "StevensSentinelV11EventRetentionAnchor",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "trust_admin_public_key": self._v1_admin["public_key"],
            "previous_pruned_through_id": int(previous_id),
            "previous_pruned_through_hash": str(previous_hash),
            "pruned_through_id": int(pruned_id),
            "pruned_through_hash": str(pruned_hash),
            "tip_id_at_checkpoint": int(tip_id),
            "tip_hash_at_checkpoint": str(tip_hash),
            "updated_at": int(time.time()),
        }

    def _read_event_retention_anchor(self):
        path = self.v11_event_retention_anchor_path
        if not path.exists():
            return None
        signed = json.loads(path.read_text())
        body = signed.get("body")
        if not isinstance(body, dict) or body.get("format") != "StevensSentinelV11EventRetentionAnchor":
            raise ValueError("invalid event retention anchor")
        if int(body.get("version", 0)) != 1:
            raise ValueError("unsupported event retention anchor version")
        if str(body.get("issuer_id", "")) != self.issuer_id():
            raise ValueError("event retention anchor issuer mismatch")
        pub = str(body.get("trust_admin_public_key", ""))
        if pub != self._v1_admin["public_key"]:
            raise ValueError("event retention anchor authority mismatch")
        previous_id = int(body.get("previous_pruned_through_id", -1))
        pruned_id = int(body.get("pruned_through_id", -1))
        previous_hash = str(body.get("previous_pruned_through_hash", ""))
        pruned_hash = str(body.get("pruned_through_hash", ""))
        tip_id = int(body.get("tip_id_at_checkpoint", -1))
        tip_hash = str(body.get("tip_hash_at_checkpoint", ""))
        if previous_id < 0 or pruned_id <= previous_id or tip_id <= pruned_id:
            raise ValueError("invalid event retention anchor range")
        for value in (previous_hash, pruned_hash, tip_hash):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("invalid event retention anchor hash")
        Ed25519PublicKey.from_public_bytes(_b64d(pub)).verify(_b64d(signed["signature"]), canonical(body))
        return signed

    def _write_event_retention_anchor(self, body):
        self.v11_event_retention_anchor_path.parent.mkdir(parents=True, exist_ok=True)
        signed = {"body": body, "signature": self._admin_sign(body)}
        self._write_json_atomic(self.v11_event_retention_anchor_path, signed)
        return signed

    def verify_log_chain(self) -> bool:
        if not getattr(self, "_v11_event_retention_ready", False):
            return super().verify_log_chain()
        try:
            anchor = self._read_event_retention_anchor()
            with self._connect() as con:
                rows = con.execute("""
                    SELECT id,timestamp,severity,category,source_ip,source_node_id,
                           details_json,previous_hash,event_hash
                    FROM events ORDER BY id ASC
                """).fetchall()
            zero = "0" * 64
            if not rows:
                return anchor is None
            if anchor is None:
                if int(rows[0][0]) != 1 or not hmac.compare_digest(str(rows[0][7]), zero):
                    return False
                prev = zero
                expected_id = 1
                tip_id = None
                tip_hash = None
                found_tip = True
            else:
                body = anchor["body"]
                previous_id = int(body["previous_pruned_through_id"])
                previous_hash = str(body["previous_pruned_through_hash"])
                pruned_id = int(body["pruned_through_id"])
                pruned_hash = str(body["pruned_through_hash"])
                tip_id = int(body["tip_id_at_checkpoint"])
                tip_hash = str(body["tip_hash_at_checkpoint"])
                first_id = int(rows[0][0])
                first_prev = str(rows[0][7])
                if first_id == pruned_id + 1 and hmac.compare_digest(first_prev, pruned_hash):
                    prev = pruned_hash
                elif first_id == previous_id + 1 and hmac.compare_digest(first_prev, previous_hash):
                    prev = previous_hash
                else:
                    return False
                expected_id = first_id
                found_tip = False
            for r in rows:
                if int(r[0]) != expected_id:
                    return False
                if not hmac.compare_digest(str(r[7]), prev):
                    return False
                event_body = {
                    "timestamp": r[1],
                    "severity": r[2],
                    "category": r[3],
                    "source_ip": r[4],
                    "source_node_id": r[5],
                    "details": json.loads(r[6]),
                    "previous_hash": r[7],
                }
                expected = hashlib.sha256(prev.encode() + canonical(event_body)).hexdigest()
                if not hmac.compare_digest(expected, str(r[8])):
                    return False
                if tip_id is not None and int(r[0]) == tip_id:
                    if not hmac.compare_digest(str(r[8]), tip_hash):
                        return False
                    found_tip = True
                prev = str(r[8])
                expected_id += 1
            return found_tip
        except Exception:
            return False

    def __init__(
        self,
        data_dir,
        config,
        swarm_policy=None,
        resource_policy=None,
        fairness_policy=None,
        reliability_policy=None,
        receipt_policy=None,
        keyring_safety_policy=None,
        cluster_receipt_policy=None,
        v1_trust_policy=None,
        external_anchor_path=None,
        *,
        recovery_signer: Optional[Callable[[dict], list[dict]]] = None,
        recovery_public_keys: Optional[list[dict]] = None,
        allow_local_dev_recovery: bool = False,
        local_dev_recovery_root: Optional[Path] = None,
        trust_admin_signer: Optional[Callable[[dict], str]] = None,
        trust_admin_public_key: Optional[str] = None,
        allow_local_dev_admin: Optional[bool] = None,
        local_dev_admin_root: Optional[Path] = None,
    ):
        data_dir = Path(data_dir)
        self.v11_event_retention_anchor_path = data_dir.parent / f".{data_dir.name}.sentinel_v11_event_retention_anchor.json"
        self.v11_event_retention_lock_path = data_dir / "sentinel_v11_event_retention.lock"
        self._v11_event_records_since_retention_check = 0
        self._v11_event_retention_ready = False
        # These facts are captured before v1.0 initialization mutates anything.
        self._v11_admin_preexisting = (
            data_dir.parent / f".{data_dir.name}.sentinel_v1_trust_admin_identity.json"
        ).exists()
        self._v11_anchor_path_hint = Path(
            external_anchor_path
            or (data_dir.parent / f".{data_dir.name}.sentinel_v1_anchor.json")
        )
        self._v11_recovery_signer = recovery_signer
        self._v11_recovery_public_keys_bootstrap = recovery_public_keys
        self._v11_allow_local_dev_recovery = bool(allow_local_dev_recovery)
        self._v11_local_dev_recovery_root = Path(
            local_dev_recovery_root
            or (data_dir.parent / ".stevens_v11_local_dev_recovery")
        )
        self._v11_local_authority_dirs: list[Path] = []
        self._v11_trust_admin_signer = trust_admin_signer
        self._v11_trust_admin_public_key_bootstrap = trust_admin_public_key
        self._v11_allow_local_dev_admin = (
            bool(allow_local_dev_recovery) if allow_local_dev_admin is None else bool(allow_local_dev_admin)
        )
        self._v11_local_dev_admin_root = Path(
            local_dev_admin_root or (data_dir.parent / '.stevens_v11_local_dev_admin')
        )

        super().__init__(
            data_dir,
            config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
            fairness_policy=fairness_policy,
            reliability_policy=reliability_policy,
            receipt_policy=receipt_policy,
            keyring_safety_policy=keyring_safety_policy,
            cluster_receipt_policy=cluster_receipt_policy,
            v1_trust_policy=v1_trust_policy,
            external_anchor_path=external_anchor_path,
        )

        self.v11_trust_mutation_lock_path = self.data_dir / "sentinel_v11_trust_mutation.lock"
        self.v11_anchor_lock_path = self.data_dir / "sentinel_v11_anchor.lock"
        self.v11_current_certificate_path = self.data_dir / "sentinel_v11_current_signing_certificate.json"
        self.v11_legacy_migration_path = self.data_dir / "sentinel_v11_legacy_migration.json"
        self.v11_recovery_refs_path = self.data_dir / "sentinel_v11_recovery_authority_refs.json"

        # Ignore the v1.0 peer-policy JSON as an authority. Rebuild from signed journal.
        self._refresh_peer_policies_from_journal()
        self._ensure_legacy_migration_file()
        self._verify_or_initialize_external_anchor()
        self._v11_event_retention_ready = True
        if not self.verify_log_chain():
            raise ValueError("Sentinel event log or retention anchor verification failed")
        self._run_event_retention()

    @classmethod
    def load_or_create(
        cls,
        data_dir,
        public_base_url="http://127.0.0.1",
        external_anchor_path=None,
        *,
        recovery_signer=None,
        recovery_public_keys=None,
        allow_local_dev_recovery=False,
        local_dev_recovery_root=None,
        trust_admin_signer=None,
        trust_admin_public_key=None,
        allow_local_dev_admin=None,
        local_dev_admin_root=None,
    ):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "sentinel_v11_startup.lock"
        lock_file = lock_path.open("a+b")
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError) as exc:
                raise RuntimeError("cross-process v1.1 startup locking unavailable") from exc

            # Build/load the v0.9 base without invoking v1.0's classmethod (which
            # cannot pass v1.1 recovery-custody parameters through).
            base = ClusterSentinel.load_or_create(data_dir, public_base_url)
            return cls(
                base.data_dir,
                base.config,
                swarm_policy=base.swarm_policy,
                resource_policy=base.resource_policy,
                fairness_policy=base.fairness_policy,
                reliability_policy=base.reliability_policy,
                receipt_policy=base.receipt_policy,
                keyring_safety_policy=base.keyring_safety_policy,
                cluster_receipt_policy=base.cluster_receipt_policy,
                external_anchor_path=external_anchor_path,
                recovery_signer=recovery_signer,
                recovery_public_keys=recovery_public_keys,
                allow_local_dev_recovery=allow_local_dev_recovery,
                local_dev_recovery_root=local_dev_recovery_root,
                trust_admin_signer=trust_admin_signer,
                trust_admin_public_key=trust_admin_public_key,
                allow_local_dev_admin=allow_local_dev_admin,
                local_dev_admin_root=local_dev_admin_root,
            )
        finally:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_file.close()

    # ------------------------------------------------------------------
    # Recovery custody: public-only node state + external signer interface
    # ------------------------------------------------------------------
    def _load_or_create_recovery_keys(self):
        """Load/store recovery PUBLIC keys only.

        v1.0 private-key sets are migrated out of the node's recovery file. In
        explicit local-dev mode, each private share is written to a separate
        authority directory outside the node data directory.
        """
        path = self.v1_recovery_keys_path
        if path.exists():
            raw = json.loads(path.read_text())
            # v1.1 public-only format
            if raw.get("format") == "StevensSentinelV11RecoveryPublicKeys":
                return self._validate_v11_recovery_public(raw)
            # v1.0 migration: move private shares out of this single file.
            if raw.get("format") == "StevensSentinelV1RecoveryKeys":
                if not self._v11_allow_local_dev_recovery and self._v11_recovery_signer is None:
                    raise RuntimeError(
                        "v1.0 recovery private keys require explicit v1.1 migration. "
                        "Provide an external recovery_signer, or enable local TESTNET migration explicitly."
                    )
                pubs = []
                if self._v11_allow_local_dev_recovery:
                    self._v11_local_authority_dirs = self._migrate_v1_private_recovery_to_dev_authorities(raw)
                for e in raw.get("keys", []):
                    pubs.append({"slot": int(e["slot"]), "public_key": e["public_key"]})
                public_doc = {
                    "format": "StevensSentinelV11RecoveryPublicKeys",
                    "version": 1,
                    "threshold": 2,
                    "keys": pubs,
                    "created_at": int(raw.get("created_at", time.time())),
                    "private_material_in_node_state": False,
                }
                self._write_json_atomic(path, public_doc)
                return self._validate_v11_recovery_public(public_doc)
            raise ValueError("unknown recovery-key format")

        # Fresh v1.1 node.
        if self._v11_recovery_public_keys_bootstrap is not None:
            public_doc = {
                "format": "StevensSentinelV11RecoveryPublicKeys",
                "version": 1,
                "threshold": 2,
                "keys": self._v11_recovery_public_keys_bootstrap,
                "created_at": int(time.time()),
                "private_material_in_node_state": False,
            }
            self._write_json_atomic(path, public_doc)
            return self._validate_v11_recovery_public(public_doc)

        if not self._v11_allow_local_dev_recovery:
            raise RuntimeError(
                "v1.1 secure default requires externally provisioned recovery public keys/signers. "
                "For local TESTNET only, pass allow_local_dev_recovery=True."
            )

        pubs = self._provision_local_dev_recovery_authorities()
        public_doc = {
            "format": "StevensSentinelV11RecoveryPublicKeys",
            "version": 1,
            "threshold": 2,
            "keys": pubs,
            "created_at": int(time.time()),
            "private_material_in_node_state": False,
        }
        self._write_json_atomic(path, public_doc)
        return self._validate_v11_recovery_public(public_doc)

    def _validate_v11_recovery_public(self, raw):
        if raw.get("format") != "StevensSentinelV11RecoveryPublicKeys":
            raise ValueError("invalid v1.1 recovery public-key format")
        if int(raw.get("version", 0)) != 1 or int(raw.get("threshold", 0)) != 2:
            raise ValueError("invalid v1.1 recovery public-key metadata")
        keys = raw.get("keys", [])
        if len(keys) != 3:
            raise ValueError("v1.1 requires exactly three recovery public keys")
        slots = set()
        clean = []
        for e in keys:
            slot = int(e["slot"])
            pub = _b64d(e["public_key"])
            if slot in slots or len(pub) != 32:
                raise ValueError("invalid recovery public key")
            if "private_key" in e:
                raise ValueError("recovery private material forbidden in v1.1 node recovery state")
            slots.add(slot)
            clean.append({"slot": slot, "public_key": _b64e(pub)})
        return {
            "format": "StevensSentinelV11RecoveryPublicKeys",
            "version": 1,
            "threshold": 2,
            "keys": sorted(clean, key=lambda x: x["slot"]),
            "created_at": int(raw.get("created_at", time.time())),
            "private_material_in_node_state": False,
        }

    def _dev_authority_file(self, slot: int) -> Path:
        d = self._v11_local_dev_recovery_root / self.data_dir.name / f"authority-{slot}"
        d.mkdir(parents=True, exist_ok=True)
        return d / "recovery_share.json"

    def _provision_local_dev_recovery_authorities(self):
        pubs = []
        self._v11_local_authority_dirs = []
        for slot in range(3):
            p = Ed25519PrivateKey.generate()
            prv = self._private_raw(p)
            pub = self._public_raw(p.public_key())
            f = self._dev_authority_file(slot)
            doc = {
                "format": "StevensSentinelV11LocalDevRecoveryShare",
                "version": 1,
                "slot": slot,
                "private_key": _b64e(prv),
                "public_key": _b64e(pub),
                "warning": "LOCAL TESTNET ONLY — move to independent HSM/KMS/off-host custody for production",
            }
            self._write_json_atomic(f, doc)
            try:
                os.chmod(f, 0o600)
            except OSError:
                pass
            self._v11_local_authority_dirs.append(f.parent)
            pubs.append({"slot": slot, "public_key": _b64e(pub)})
        return pubs

    def _migrate_v1_private_recovery_to_dev_authorities(self, raw):
        dirs = []
        for e in raw.get("keys", []):
            slot = int(e["slot"])
            f = self._dev_authority_file(slot)
            doc = {
                "format": "StevensSentinelV11LocalDevRecoveryShare",
                "version": 1,
                "slot": slot,
                "private_key": e["private_key"],
                "public_key": e["public_key"],
                "warning": "MIGRATED LOCAL TESTNET SHARE — move off-host for production",
            }
            self._write_json_atomic(f, doc)
            try:
                os.chmod(f, 0o600)
            except OSError:
                pass
            dirs.append(f.parent)
        return dirs

    def _discover_local_dev_authorities(self):
        dirs = []
        root = self._v11_local_dev_recovery_root / self.data_dir.name
        for slot in range(3):
            f = root / f"authority-{slot}" / "recovery_share.json"
            if f.exists():
                dirs.append(f.parent)
        self._v11_local_authority_dirs = dirs
        return dirs

    def _quorum_sign(self, body):
        # Preferred production path: caller-controlled external signer.
        if self._v11_recovery_signer is not None:
            sigs = self._v11_recovery_signer(body)
            if not self._verify_quorum(body, sigs, self._recovery_public_bundle(), 2):
                raise ValueError("external recovery signer did not satisfy 2-of-3 quorum")
            return sigs

        # Explicit local TESTNET mode only.
        if not self._v11_allow_local_dev_recovery:
            raise RuntimeError("recovery quorum unavailable: external signer required")
        dirs = self._v11_local_authority_dirs or self._discover_local_dev_authorities()
        sigs = []
        for d in dirs:
            f = d / "recovery_share.json"
            if not f.exists():
                continue
            doc = json.loads(f.read_text())
            prv = _b64d(doc["private_key"])
            p = Ed25519PrivateKey.from_private_bytes(prv)
            sigs.append({"slot": int(doc["slot"]), "signature": _b64e(p.sign(canonical(body)))})
            if len(sigs) >= 2:
                break
        if not self._verify_quorum(body, sigs, self._recovery_public_bundle(), 2):
            raise RuntimeError("local TESTNET recovery authorities unavailable")
        return sigs

    # ------------------------------------------------------------------
    # Trust-admin custody: public-only node state + external signer interface
    # ------------------------------------------------------------------
    def _load_or_create_trust_admin_identity(self):
        path = self.v1_trust_admin_identity_path
        if path.exists():
            raw = json.loads(path.read_text())
            if raw.get("format") == "StevensSentinelV11TrustAdminPublicIdentity":
                pub = _b64d(raw["public_key"])
                if len(pub) != 32:
                    raise ValueError("invalid v1.1 trust-admin public key")
                return raw
            if raw.get("format") == "StevensSentinelV1TrustAdminIdentity":
                # Migrate the old private key out of the node's authority file.
                pub = raw["public_key"]
                if self._v11_allow_local_dev_admin:
                    self._write_local_dev_admin_share(raw["private_key"], pub)
                elif self._v11_trust_admin_signer is None:
                    raise RuntimeError(
                        "v1.0 trust-admin private key requires explicit v1.1 migration. "
                        "Provide an external trust_admin_signer/public key, or enable local TESTNET migration explicitly."
                    )
                if self._v11_trust_admin_public_key_bootstrap is not None and self._v11_trust_admin_public_key_bootstrap != pub:
                    raise ValueError("provided trust-admin public key does not match migrated identity")
                public_doc = {
                    "format": "StevensSentinelV11TrustAdminPublicIdentity",
                    "version": 1,
                    "public_key": pub,
                    "created_at": int(raw.get("created_at", time.time())),
                    "private_material_in_node_state": False,
                }
                self._write_json_atomic(path, public_doc)
                return public_doc
            raise ValueError("unknown trust-admin identity format")

        if self._v11_trust_admin_public_key_bootstrap is not None:
            pub = _b64d(self._v11_trust_admin_public_key_bootstrap)
            if len(pub) != 32:
                raise ValueError("invalid external trust-admin public key")
            public_doc = {
                "format": "StevensSentinelV11TrustAdminPublicIdentity",
                "version": 1,
                "public_key": _b64e(pub),
                "created_at": int(time.time()),
                "private_material_in_node_state": False,
            }
            self._write_json_atomic(path, public_doc)
            return public_doc

        if not self._v11_allow_local_dev_admin:
            raise RuntimeError(
                "v1.1 secure default requires externally provisioned trust-admin signer/public key. "
                "For local TESTNET only, pass allow_local_dev_admin=True."
            )

        p = Ed25519PrivateKey.generate()
        prv = self._private_raw(p)
        pub = self._public_raw(p.public_key())
        self._write_local_dev_admin_share(_b64e(prv), _b64e(pub))
        public_doc = {
            "format": "StevensSentinelV11TrustAdminPublicIdentity",
            "version": 1,
            "public_key": _b64e(pub),
            "created_at": int(time.time()),
            "private_material_in_node_state": False,
        }
        self._write_json_atomic(path, public_doc)
        return public_doc

    def _local_dev_admin_file(self):
        d = self._v11_local_dev_admin_root / self.data_dir.name
        d.mkdir(parents=True, exist_ok=True)
        return d / "trust_admin_share.json"

    def _write_local_dev_admin_share(self, private_key_b64, public_key_b64):
        f = self._local_dev_admin_file()
        doc = {
            "format": "StevensSentinelV11LocalDevTrustAdminShare",
            "version": 1,
            "private_key": private_key_b64,
            "public_key": public_key_b64,
            "warning": "LOCAL TESTNET ONLY — use an HSM/KMS/off-host signer for production",
        }
        self._write_json_atomic(f, doc)
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass

    def _admin_sign(self, body):
        if self._v11_trust_admin_signer is not None:
            sig = self._v11_trust_admin_signer(body)
            if isinstance(sig, bytes):
                sig_b64 = _b64e(sig)
            else:
                sig_b64 = str(sig)
            Ed25519PublicKey.from_public_bytes(_b64d(self._v1_admin["public_key"])).verify(
                _b64d(sig_b64), canonical(body)
            )
            return sig_b64
        if not self._v11_allow_local_dev_admin:
            raise RuntimeError("trust-admin signer unavailable: external signer required")
        f = self._local_dev_admin_file()
        if not f.exists():
            raise RuntimeError("local TESTNET trust-admin signer unavailable")
        doc = json.loads(f.read_text())
        p = Ed25519PrivateKey.from_private_bytes(_b64d(doc["private_key"]))
        if _b64e(self._public_raw(p.public_key())) != self._v1_admin["public_key"]:
            raise ValueError("local TESTNET trust-admin public/private mismatch")
        return _b64e(p.sign(canonical(body)))

    def _admin_private(self):
        raise RuntimeError("v1.1 does not expose a trust-admin private key from node state")

    def _sign_anchor(self, b):
        return {"body": b, "signature": self._admin_sign(b)}

    def export_revocation_bundle(self, issuer_id):
        b = {
            "format": "StevensSentinelV1PeerRevocation",
            "version": 1,
            "revoker_issuer_id": self.issuer_id(),
            "revoked_issuer_id": issuer_id,
            "timestamp": int(time.time()),
            "nonce": secrets.token_hex(8),
        }
        return {"body": b, "signature": self._admin_sign(b)}

    # ------------------------------------------------------------------
    # Cross-process mutation locks
    # ------------------------------------------------------------------
    @contextmanager
    def _v11_file_lock(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        f = path.open("a+b")
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            f.close()

    def _trust_lock_path(self):
        return self.data_dir / "sentinel_v11_trust_mutation.lock"

    def _anchor_lock_path(self):
        return self.data_dir / "sentinel_v11_anchor.lock"

    # ------------------------------------------------------------------
    # Signed trust journal now also carries peer-policy state + replay ids
    # ------------------------------------------------------------------
    def _derive_trust_state_from_journal(self):
        st = {
            "format": "StevensSentinelV11TrustState",
            "version": 1,
            "revision": -1,
            "head_hash": "0"*64,
            "issuers": {},
            "trusted_revocation_admins": {},
            "peer_policies": {},
            "revocation_ops": {},
        }
        for e in self._load_trust_journal():
            b = e["body"]
            st["revision"] = int(b["revision"])
            st["head_hash"] = e["entry_hash"]
            a = b["action"]
            p = b["payload"]
            if a == "TRUST":
                st["issuers"][p["bundle"]["issuer_id"]] = {
                    "bundle": p["bundle"],
                    "label": p.get("label", p["bundle"]["issuer_id"]),
                    "revoked": False,
                }
            elif a in ("REVOKE", "PEER_REVOKE"):
                iid = p["issuer_id"]
                if iid in st["issuers"]:
                    st["issuers"][iid]["revoked"] = True
                if a == "PEER_REVOKE" and p.get("operation_id"):
                    st["revocation_ops"][p["operation_id"]] = int(b["revision"])
            elif a == "TRUST_REVOCATION_ADMIN":
                st["trusted_revocation_admins"][p["issuer_id"]] = {"public_key": p["public_key"]}
            elif a == "PEER_POLICY":
                iid = p["issuer_id"]
                signed = p["signed"]
                cur = st["peer_policies"].get(iid)
                nr = int(signed["body"]["policy_revision"])
                if cur is None or nr > int(cur["body"]["policy_revision"]):
                    st["peer_policies"][iid] = signed
        return st

    def _append_trust_journal(self, action, payload):
        # Serialize the entire read -> compare -> append -> anchor transaction.
        with self._v11_file_lock(self._trust_lock_path()):
            es = self._load_trust_journal()
            rev = len(es)
            prev = es[-1]["entry_hash"] if es else "0"*64
            b = {
                "format": "StevensSentinelV1TrustJournalEntry",
                "version": 1,
                "revision": rev,
                "previous_hash": prev,
                "timestamp": int(time.time()),
                "action": action,
                "payload": payload,
            }
            sig = self._admin_sign(b)
            core = {"body": b, "signature": sig}
            x = {
                **core,
                "entry_hash": hashlib.sha256(
                    b"Stevens-Sentinel-v1.0/trust-journal|" + canonical(core)
                ).hexdigest(),
            }
            target = self._trust_entry_file(rev)
            if target.exists():
                raise RuntimeError("concurrent trust revision collision")
            self._write_json_atomic(target, x)
            self._v1_trust_state = self._derive_trust_state_from_journal()
            self._write_json_atomic(self.v1_trust_cache_path, self._v1_trust_state)
            self._refresh_peer_policies_from_journal()
            self._update_external_anchor()
            return x

    def _load_or_create_peer_policy_state(self):
        # v1.0 JSON remains a compatibility cache only. Authority is the signed journal.
        st = self._derive_trust_state_from_journal()
        peers = {
            iid: {"body": signed["body"], "signed": signed}
            for iid, signed in st.get("peer_policies", {}).items()
        }
        cache = {"format": "StevensSentinelV11PeerPolicyCache", "version": 1, "issuers": peers}
        try:
            self._write_json_atomic(self.v1_peer_policy_state_path, cache)
        except Exception:
            pass
        return cache

    def _refresh_peer_policies_from_journal(self):
        st = self._derive_trust_state_from_journal()
        self._v1_peer_policies = {
            "format": "StevensSentinelV11PeerPolicyCache",
            "version": 1,
            "issuers": {
                iid: {"body": signed["body"], "signed": signed}
                for iid, signed in st.get("peer_policies", {}).items()
            },
        }
        try:
            self._write_json_atomic(self.v1_peer_policy_state_path, self._v1_peer_policies)
        except Exception:
            pass
        return self._v1_peer_policies

    def _remember_peer_policy(self, issuer_id, signed, trusted_bundle):
        b = self._validate_signed_policy(signed, trusted_bundle)
        st = self._derive_trust_state_from_journal()
        cur = st.get("peer_policies", {}).get(issuer_id)
        if cur:
            cr = int(cur["body"]["policy_revision"])
            nr = int(b["policy_revision"])
            if nr < cr:
                self._refresh_peer_policies_from_journal()
                return self._v1_peer_policies["issuers"][issuer_id]
            if nr == cr:
                if cur != signed:
                    raise ValueError("conflicting issuer policy revision")
                self._refresh_peer_policies_from_journal()
                return self._v1_peer_policies["issuers"][issuer_id]
        self._append_trust_journal("PEER_POLICY", {"issuer_id": issuer_id, "signed": signed})
        self._refresh_peer_policies_from_journal()
        return self._v1_peer_policies["issuers"][issuer_id]

    def _trusted_v1_bundle(self, issuer_id):
        self._v1_trust_state = self._derive_trust_state_from_journal()
        self._refresh_peer_policies_from_journal()
        e = self._v1_trust_state["issuers"].get(issuer_id)
        if not e or e.get("revoked"):
            return None
        return e["bundle"]

    # ------------------------------------------------------------------
    # Revocation replay protection
    # ------------------------------------------------------------------
    def import_revocation_bundle(self, bundle):
        b = bundle.get("body")
        if not isinstance(b, dict) or b.get("format") != "StevensSentinelV1PeerRevocation" or int(b.get("version", 0)) != 1:
            raise ValueError("invalid revocation bundle")
        self._v1_trust_state = self._derive_trust_state_from_journal()
        auth = self._v1_trust_state["trusted_revocation_admins"].get(b["revoker_issuer_id"])
        if not auth:
            raise ValueError("untrusted revocation authority")
        Ed25519PublicKey.from_public_bytes(_b64d(auth["public_key"])).verify(
            _b64d(bundle["signature"]), canonical(b)
        )
        # Stable signed operation id; identical signed bundles deduplicate.
        op_id = hashlib.sha256(
            b"Stevens-Sentinel-v1.1/revocation-op|" + canonical(bundle)
        ).hexdigest()
        st = self._derive_trust_state_from_journal()
        if op_id in st.get("revocation_ops", {}):
            raise ValueError("revocation bundle replay")
        self._append_trust_journal(
            "PEER_REVOKE",
            {
                "issuer_id": b["revoked_issuer_id"],
                "source": b["revoker_issuer_id"],
                "operation_id": op_id,
                "signed_bundle": bundle,
            },
        )
        return self.v1_trust_status()

    # ------------------------------------------------------------------
    # Explicit legacy migration; v3 disabled by default
    # ------------------------------------------------------------------
    def _ensure_legacy_migration_file(self):
        if not self.v11_legacy_migration_path.exists():
            self._write_json_atomic(
                self.v11_legacy_migration_path,
                {
                    "format": "StevensSentinelV11LegacyMigration",
                    "version": 1,
                    "enabled": False,
                    "expires_at": 0,
                },
            )

    def enable_legacy_v3_migration(self, ttl_seconds=1800):
        ttl = int(ttl_seconds)
        if ttl < 60 or ttl > 86400:
            raise ValueError("migration ttl out of range")
        self._write_json_atomic(
            self.v11_legacy_migration_path,
            {
                "format": "StevensSentinelV11LegacyMigration",
                "version": 1,
                "enabled": True,
                "expires_at": int(time.time()) + ttl,
            },
        )
        return {"enabled": True, "expires_at": int(time.time()) + ttl}

    def disable_legacy_v3_migration(self):
        self._write_json_atomic(
            self.v11_legacy_migration_path,
            {
                "format": "StevensSentinelV11LegacyMigration",
                "version": 1,
                "enabled": False,
                "expires_at": 0,
            },
        )

    def _legacy_migration_enabled(self, now=None):
        now = int(now or time.time())
        try:
            d = json.loads(self.v11_legacy_migration_path.read_text())
            return bool(d.get("enabled")) and now <= int(d.get("expires_at", 0))
        except Exception:
            return False

    def revoke_v1_issuer(self, issuer_id):
        out = super().revoke_v1_issuer(issuer_id)
        # If migration is explicitly active, also revoke the legacy registry.
        if self._legacy_migration_enabled():
            try:
                self.revoke_receipt_issuer(issuer_id)
            except Exception:
                pass
        return out

    def verify_proof_receipt(self, receipt, source_ip, client_binding=None, now=None):
        if not receipt:
            return False
        now = int(now or time.time())
        try:
            payload = json.loads(_b64d(str(receipt).split(".", 1)[0]))
            ver = int(payload.get("v", 0))
        except Exception:
            return False
        if ver == 4:
            return self._verify_v4_receipt(str(receipt), source_ip, client_binding, now)
        if ver == 3:
            if not self._legacy_migration_enabled(now):
                return False
            iid = str(payload.get("issuer", ""))
            # v1 trust/revocation state dominates legacy trust state.
            if not iid or self._trusted_v1_bundle(iid) is None:
                return False
            return ClusterSentinel.verify_proof_receipt(
                self,
                receipt,
                source_ip,
                client_binding=client_binding,
                now=now,
            )
        return False

    # ------------------------------------------------------------------
    # Fail-closed, stronger external monotonic anchor
    # ------------------------------------------------------------------
    def _anchor_state(self):
        st = self._derive_trust_state_from_journal()
        trust_rev = int(st.get("revision", -1))
        trust_head = st.get("head_hash", "0"*64)
        key_rev = int(ClusterSentinel.receipt_status(self)["committed_revision"])
        peer_digest = hashlib.sha256(
            canonical({
                iid: int(signed["body"]["policy_revision"])
                for iid, signed in sorted(st.get("peer_policies", {}).items())
            })
        ).hexdigest()
        replay_digest = hashlib.sha256(
            canonical(sorted(st.get("revocation_ops", {}).keys()))
        ).hexdigest()
        return trust_rev, key_rev, trust_head, peer_digest, replay_digest

    def _anchor_body(self, trust_revision, keyring_revision, trust_head_hash=None, peer_policy_digest=None, replay_digest=None):
        return {
            "format": "StevensSentinelV11ExternalAnchor",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "trust_admin_public_key": self._v1_admin["public_key"],
            "trust_revision": int(trust_revision),
            "keyring_revision": int(keyring_revision),
            "trust_head_hash": trust_head_hash or "0"*64,
            "peer_policy_digest": peer_policy_digest or hashlib.sha256(canonical({})).hexdigest(),
            "revocation_replay_digest": replay_digest or hashlib.sha256(canonical([])).hexdigest(),
            "updated_at": int(time.time()),
        }

    def _read_anchor(self):
        if not self.external_anchor_path.exists():
            return None
        s = json.loads(self.external_anchor_path.read_text())
        b = s.get("body")
        if not isinstance(b, dict):
            raise ValueError("invalid external anchor")
        if b.get("format") not in ("StevensSentinelV1ExternalAnchor", "StevensSentinelV11ExternalAnchor"):
            raise ValueError("invalid external anchor format")
        if b["trust_admin_public_key"] != self._v1_admin["public_key"]:
            raise ValueError("external anchor identity mismatch")
        Ed25519PublicKey.from_public_bytes(_b64d(b["trust_admin_public_key"])).verify(
            _b64d(s["signature"]), canonical(b)
        )
        return s

    def _write_external_anchor(self, tr, kr):
        tr2, kr2, head, pd, rd = self._anchor_state()
        # Caller-provided revisions may already be max-forwarded; preserve that.
        tr = max(int(tr), tr2)
        kr = max(int(kr), kr2)
        body = self._anchor_body(tr, kr, head, pd, rd)
        self.external_anchor_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(self.external_anchor_path, self._sign_anchor(body))

    def _verify_or_initialize_external_anchor(self):
        tr, kr, head, pd, rd = self._anchor_state()
        a = self._read_anchor()
        if a is None:
            # Fresh bootstrap is allowed only if the trust-admin identity did not
            # pre-exist this startup. Once provisioned, disappearance fails closed.
            if self.v1_trust_policy.require_external_anchor and self._v11_admin_preexisting:
                raise ValueError("established external anti-rollback anchor missing; fail closed")
            if self.v1_trust_policy.require_external_anchor:
                self._write_external_anchor(tr, kr)
            return
        b = a["body"]
        atr = int(b["trust_revision"])
        akr = int(b["keyring_revision"])
        if tr < atr:
            raise ValueError("trust journal rollback detected by external anchor")
        if kr < akr:
            raise ValueError("keyring journal rollback detected by external anchor")
        if b.get("format") == "StevensSentinelV11ExternalAnchor" and tr == atr:
            if b.get("trust_head_hash") != head:
                raise ValueError("trust journal head mismatch detected by external anchor")
            if b.get("peer_policy_digest") != pd:
                raise ValueError("peer policy rollback/tamper detected by external anchor")
            if b.get("revocation_replay_digest") != rd:
                raise ValueError("revocation replay-state rollback detected by external anchor")
        # Forward-migrate v1 anchors or advance stale anchors.
        if (
            b.get("format") != "StevensSentinelV11ExternalAnchor"
            or tr > atr
            or kr > akr
        ):
            self._write_external_anchor(tr, kr)

    def _update_external_anchor(self):
        if not self.v1_trust_policy.require_external_anchor:
            return
        lock_path = self.data_dir / "sentinel_v11_anchor.lock"
        with self._v11_file_lock(lock_path):
            tr, kr, head, pd, rd = self._anchor_state()
            a = self._read_anchor()
            if a is None:
                if self._v11_admin_preexisting:
                    raise ValueError("established external anti-rollback anchor missing; fail closed")
                self._write_external_anchor(tr, kr)
                return
            b = a["body"]
            tr = max(tr, int(b["trust_revision"]))
            kr = max(kr, int(b["keyring_revision"]))
            self._write_external_anchor(tr, kr)

    # ------------------------------------------------------------------
    # v4 certificate cache: recovery quorum is not needed per receipt
    # ------------------------------------------------------------------
    def _v4_certificate(self, current, now=None):
        now = int(now or time.time())
        cert_path = self.data_dir / "sentinel_v11_current_signing_certificate.json"
        if cert_path.exists():
            try:
                cert = json.loads(cert_path.read_text())
                b = cert.get("body", {})
                if (
                    b.get("kid") == current["kid"]
                    and int(b.get("signing_revision", -1)) == int(current["revision"])
                    and now <= int(b.get("not_after", 0)) - 10
                ):
                    # Verify against self bundle before reuse.
                    self._validate_v4_certificate(cert, self.export_v1_issuer_bundle(), now)
                    return cert
            except Exception:
                pass
        life = int(self.v1_trust_policy.certificate_lifetime_seconds)
        b = {
            "format": "StevensSentinelV1SigningCertificate",
            "version": 1,
            "issuer_id": self.issuer_id(),
            "kid": current["kid"],
            "public_key": current["public_key"],
            "signing_revision": int(current["revision"]),
            "not_before": now - 5,
            "not_after": now + life,
        }
        cert = {
            "body": b,
            "root_signature": _b64e(self._issuer_private_key().sign(canonical(b))),
            "recovery_signatures": self._quorum_sign(b),
        }
        self._write_json_atomic(cert_path, cert)
        return cert

    def rotate_receipt_key(self, now=None, revoke_prior=False):
        # Base v1.0 rotation creates the new key and advances policy if requested.
        out = super().rotate_receipt_key(now=now, revoke_prior=revoke_prior)
        self._reload_asym_keyring_if_changed(force=True)
        # Force certificate issuance now while the external recovery quorum is present.
        cert_path = self.data_dir / "sentinel_v11_current_signing_certificate.json"
        try:
            cert_path.unlink()
        except FileNotFoundError:
            pass
        self._v4_certificate(self._asym_keyring["current"], now=int(now or time.time()))
        self._update_external_anchor()
        out = self.v11_status()
        out["rotation_applied"] = True
        out["revoke_prior"] = bool(revoke_prior)
        return out

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def v1_trust_status(self):
        st = self._derive_trust_state_from_journal()
        return {
            "sentinel_version": VERSION,
            "trust_revision": int(st["revision"]),
            "trust_head_hash": st["head_hash"],
            "trusted_issuer_count": sum(1 for e in st["issuers"].values() if not e.get("revoked")),
            "trusted_revocation_admin_count": len(st["trusted_revocation_admins"]),
            "remembered_peer_policy_count": len(st.get("peer_policies", {})),
            "revocation_operation_count": len(st.get("revocation_ops", {})),
            "derived_from_signed_journal": True,
        }

    def v11_status(self):
        a = self._read_anchor()
        return {
            "sentinel_version": VERSION,
            "receipt_format": "ed25519-revocable-v4",
            "issuer_id": self.issuer_id(),
            "legacy_v3_default": "disabled",
            "peer_policy_authority": "signed-trust-journal",
            "revocation_replay_protection": True,
            "trust_mutation_cross_process_lock": True,
            "recovery_private_material_in_node_state": False,
            "trust_admin_private_material_in_node_state": False,
            "local_dev_recovery_enabled": self._v11_allow_local_dev_recovery,
            "local_dev_admin_enabled": self._v11_allow_local_dev_admin,
            "production_recovery_requirement": "independent external 2-of-3 signers",
            "production_trust_admin_requirement": "external HSM/KMS/off-host signer",
            "external_anchor_present": a is not None,
            "external_anchor_fail_closed_after_provisioning": True,
            "trust": self.v1_trust_status(),
        }

    def v1_status(self):
        return self.v11_status()

    def reliability_status(self):
        s = super().reliability_status()
        s.update({
            "sentinel_version": VERSION,
            "legacy_v3_default": "disabled",
            "peer_policy_monotonic": True,
            "revocation_replay_protection": True,
            "trust_mutation_cross_process_lock": True,
            "recovery_private_material_in_node_state": False,
            "antirollback_missing_anchor_behavior": "fail-closed-after-provisioning",
        })
        return s
