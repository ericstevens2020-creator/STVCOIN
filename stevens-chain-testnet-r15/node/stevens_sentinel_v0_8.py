"""
Stevens Sentinel v0.8 — Serialized Keyring Rotation + Grace Preservation + Recovery

Hardens v0.7 receipt-key management against:
- rapid rotations cutting promised grace short;
- concurrent cross-process rotation races / lost candidate keys;
- stale in-memory keyrings across worker processes;
- missing validated backup/restore procedures;
- accidental activation of broader experimental binding modes.

Key properties:
- cross-process rotation lock;
- rotation is blocked rather than evicting an unexpired previous key;
- atomic pre-rotation backup;
- validated explicit restore from backup;
- revisioned keyring + mtime refresh for multi-process readers;
- exact-IP remains default;
- cohort/client-token modes require explicit experimental opt-in.

Receipts still never bypass local CHALLENGE/QUARANTINE/ISOLATE.
No blockchain consensus rule changes. No hack-back.
TESTNET / DEFENSIVE SECURITY ONLY.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from stevens_sentinel_v0_4 import _b64d
from stevens_sentinel_v0_7 import (
    StevensSentinel as KeyringSentinel,
    ReceiptPolicy,
)
from stevens_sentinel_v0_6 import ReliabilityPolicy
from stevens_sentinel_v0_5 import FairnessPolicy
from stevens_sentinel_v0_4 import ResourcePolicy
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "0.8"


@dataclass(frozen=True)
class KeyringSafetyPolicy:
    allow_experimental_binding_modes: bool = False
    require_backup_before_rotation: bool = True
    fail_closed_on_corrupt_keyring: bool = True
    refresh_keyring_on_change: bool = True

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelKeyringSafetyPolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyringSafetyPolicy":
        if d.get("format") != "StevensSentinelKeyringSafetyPolicy":
            raise ValueError("not a Stevens Sentinel keyring safety policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported keyring safety policy version")
        defaults = cls()
        return cls(**{
            k: d.get(k, getattr(defaults, k))
            for k in defaults.__dict__
        })

    def validate(self) -> None:
        # Boolean-only policy today. Keep a validation hook for future versions.
        for name, value in self.__dict__.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be boolean")


class StevensSentinel(KeyringSentinel):
    def __init__(self, data_dir, config,
                 swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None,
                 fairness_policy: FairnessPolicy | None = None,
                 reliability_policy: ReliabilityPolicy | None = None,
                 receipt_policy: ReceiptPolicy | None = None,
                 keyring_safety_policy: KeyringSafetyPolicy | None = None):
        self._keyring_refresh_lock = threading.RLock()
        self._last_keyring_reload = 0

        super().__init__(
            data_dir, config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
            fairness_policy=fairness_policy,
            reliability_policy=reliability_policy,
            receipt_policy=receipt_policy,
        )

        self.keyring_safety_policy_path = (
            self.data_dir / "sentinel_keyring_safety_policy.json"
        )
        self.keyring_rotation_lock_path = (
            self.data_dir / "sentinel_receipt_rotation.lock"
        )
        self.receipt_keyring_backup_path = (
            self.data_dir / "sentinel_receipt_keyring.backup.json"
        )

        self.keyring_safety_policy = (
            keyring_safety_policy or self._load_or_create_keyring_safety_policy()
        )
        self.keyring_safety_policy.validate()
        self._receipt_keyring = self._normalize_and_validate_keyring(
            self._receipt_keyring
        )
        self._keyring_mtime_ns = self._keyring_stat_mtime()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        # Serialize the entire v0.8 startup, including safety-policy creation.
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "sentinel_v08_startup.lock"
        lock_file = lock_path.open("a+b")
        locked = False
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                locked = True
            except (ImportError, OSError) as exc:
                raise RuntimeError(
                    "cross-process v0.8 startup locking unavailable"
                ) from exc

            base = KeyringSentinel.load_or_create(data_dir, public_base_url)
            return cls(
                base.data_dir,
                base.config,
                swarm_policy=base.swarm_policy,
                resource_policy=base.resource_policy,
                fairness_policy=base.fairness_policy,
                reliability_policy=base.reliability_policy,
                receipt_policy=base.receipt_policy,
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
    # Safety policy / experimental binding gate
    # ------------------------------------------------------------------
    def _load_or_create_keyring_safety_policy(self) -> KeyringSafetyPolicy:
        if self.keyring_safety_policy_path.exists():
            p = KeyringSafetyPolicy.from_dict(
                json.loads(self.keyring_safety_policy_path.read_text())
            )
        else:
            p = KeyringSafetyPolicy()
            self._write_private_json(self.keyring_safety_policy_path, p.to_dict())
        return p

    def _persist_keyring_safety_policy(self) -> None:
        self.keyring_safety_policy.validate()
        self._write_private_json(self.keyring_safety_policy_path, self.keyring_safety_policy.to_dict())

    def _binding_mode_allowed(self) -> bool:
        if self.receipt_policy.binding_mode == "exact-ip":
            return True
        return bool(
            self.keyring_safety_policy.allow_experimental_binding_modes
        )

    # ------------------------------------------------------------------
    # Keyring validation / atomic IO
    # ------------------------------------------------------------------
    def _normalize_and_validate_keyring(self, kr: dict) -> dict:
        if not isinstance(kr, dict):
            raise ValueError("receipt keyring is not an object")
        if kr.get("format") != "StevensSentinelReceiptKeyring":
            raise ValueError("bad receipt keyring format")
        if int(kr.get("version", 0)) != 1:
            raise ValueError("unsupported receipt keyring version")

        current = kr.get("current")
        if not isinstance(current, dict):
            raise ValueError("receipt keyring has no current key")

        previous = kr.get("previous", [])
        if not isinstance(previous, list):
            raise ValueError("receipt keyring previous is not a list")

        kids = set()

        def validate_entry(entry: dict, previous_entry: bool) -> dict:
            if not isinstance(entry, dict):
                raise ValueError("receipt keyring entry is not an object")
            kid = str(entry.get("kid", ""))
            if len(kid) < 8:
                raise ValueError("receipt keyring entry has invalid kid")
            if kid in kids:
                raise ValueError("duplicate receipt key kid")
            kids.add(kid)

            raw = _b64d(str(entry.get("key", "")))
            if len(raw) != 32:
                raise ValueError("receipt signing key must be 32 bytes")

            created_at = int(entry.get("created_at", 0))
            if created_at <= 0:
                raise ValueError("receipt key created_at invalid")

            out = {
                "kid": kid,
                "key": entry["key"],
                "created_at": created_at,
            }
            if previous_entry:
                accept_until = int(entry.get("accept_until", 0))
                if accept_until <= 0:
                    raise ValueError("previous receipt key missing accept_until")
                out["accept_until"] = accept_until
            return out

        normalized = {
            "format": "StevensSentinelReceiptKeyring",
            "version": 1,
            "revision": max(0, int(kr.get("revision", 0))),
            "current": validate_entry(current, False),
            "previous": [validate_entry(e, True) for e in previous],
        }
        return normalized

    def _read_keyring_file(self, path: Path | None = None) -> dict:
        path = path or self.receipt_keyring_path
        try:
            raw = json.loads(path.read_text())
        except Exception as exc:
            raise ValueError(f"cannot parse receipt keyring: {exc}") from exc
        return self._normalize_and_validate_keyring(raw)

    def _write_json_atomic(self, path: Path, obj: dict) -> None:
        tmp = path.with_name(path.name + ".tmp")
        data = json.dumps(obj, indent=2) + "\n"
        with tmp.open("w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        # Best-effort directory fsync for stronger crash consistency.
        try:
            dfd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except Exception:
            pass

    def _keyring_stat_mtime(self) -> int:
        try:
            return int(self.receipt_keyring_path.stat().st_mtime_ns)
        except FileNotFoundError:
            return 0

    def _reload_keyring_if_changed(self, force: bool = False) -> None:
        if not self.keyring_safety_policy.refresh_keyring_on_change and not force:
            return
        mtime = self._keyring_stat_mtime()
        if not force and mtime == getattr(self, "_keyring_mtime_ns", 0):
            return
        with self._keyring_refresh_lock:
            mtime2 = self._keyring_stat_mtime()
            if not force and mtime2 == getattr(self, "_keyring_mtime_ns", 0):
                return
            kr = self._read_keyring_file()
            self._receipt_keyring = kr
            self._keyring_mtime_ns = mtime2
            self._last_keyring_reload = int(time.time())

    # ------------------------------------------------------------------
    # Cross-process rotation lock / grace preservation
    # ------------------------------------------------------------------
    def _rotation_lock(self):
        class _Lock:
            def __init__(inner, sentinel):
                inner.s = sentinel
                inner.f = None
                inner.locked = False

            def __enter__(inner):
                inner.f = inner.s.keyring_rotation_lock_path.open("a+b")
                try:
                    import fcntl
                    fcntl.flock(inner.f.fileno(), fcntl.LOCK_EX)
                    inner.locked = True
                except (ImportError, OSError) as exc:
                    inner.f.close()
                    raise RuntimeError(
                        "cross-process keyring locking unavailable"
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

    def _prune_expired_only(self, kr: dict, now: int) -> dict:
        kr = self._normalize_and_validate_keyring(kr)
        kr["previous"] = [
            e for e in kr.get("previous", [])
            if int(e.get("accept_until", 0)) >= now
        ]
        kr["previous"].sort(
            key=lambda x: int(x.get("accept_until", 0)),
            reverse=True,
        )
        return kr

    def _backup_keyring_locked(self, kr: dict) -> None:
        if not self.keyring_safety_policy.require_backup_before_rotation:
            return
        validated = self._normalize_and_validate_keyring(kr)
        self._write_json_atomic(
            self.receipt_keyring_backup_path,
            validated,
        )

    def rotate_receipt_key(self, now: int | None = None) -> dict:
        """
        Safe rotation semantics:
        - serialize cross-process;
        - reload latest on-disk state under lock;
        - never evict a still-graceful previous key;
        - backup before mutation;
        - increment revision;
        - atomically publish new keyring.

        If the configured previous-key capacity is full of unexpired keys,
        rotation is BLOCKED rather than violating the promised grace window.
        """
        now = int(now or time.time())

        with self._rotation_lock():
            kr = self._prune_expired_only(
                self._read_keyring_file(),
                now,
            )
            capacity = int(self.receipt_policy.max_previous_keys)
            if (
                int(self.receipt_policy.rotation_grace_seconds) > 0
                and capacity < 1
            ):
                return self._rotation_blocked_status(
                    kr, now,
                    "max_previous_keys must be at least 1 when rotation grace is enabled",
                )

            if len(kr["previous"]) >= capacity:
                return self._rotation_blocked_status(
                    kr, now,
                    "unexpired previous-key capacity is full; retry after grace expiry",
                )

            self._backup_keyring_locked(kr)

            current = dict(kr["current"])
            current["accept_until"] = (
                now + int(self.receipt_policy.rotation_grace_seconds)
            )
            previous = [current] + list(kr["previous"])
            previous.sort(
                key=lambda x: int(x.get("accept_until", 0)),
                reverse=True,
            )

            new_kr = {
                "format": "StevensSentinelReceiptKeyring",
                "version": 1,
                "revision": int(kr.get("revision", 0)) + 1,
                "current": self._new_receipt_key(now),
                "previous": previous,
            }
            new_kr = self._normalize_and_validate_keyring(new_kr)
            self._write_json_atomic(self.receipt_keyring_path, new_kr)

            self._receipt_keyring = new_kr
            self._keyring_mtime_ns = self._keyring_stat_mtime()

            status = self.receipt_status(now=now)
            status["rotation_applied"] = True
            status["rotation_blocked_reason"] = None
            return status

    def _rotation_blocked_status(self, kr: dict, now: int, reason: str) -> dict:
        self._receipt_keyring = kr
        self._keyring_mtime_ns = self._keyring_stat_mtime()
        status = self.receipt_status(now=now)
        status["rotation_applied"] = False
        status["rotation_blocked_reason"] = reason
        return status

    # ------------------------------------------------------------------
    # Validated recovery
    # ------------------------------------------------------------------
    @classmethod
    def recover_receipt_keyring_from_backup_path(cls, data_dir) -> dict:
        """
        Explicit operator recovery path that does not require a live Sentinel
        instance. Primary corruption still fails closed until this function is
        intentionally invoked.
        """
        data_dir = Path(data_dir)
        primary = data_dir / "sentinel_receipt_keyring.json"
        backup = data_dir / "sentinel_receipt_keyring.backup.json"
        lock_path = data_dir / "sentinel_receipt_rotation.lock"

        if not backup.exists():
            raise FileNotFoundError("receipt keyring backup does not exist")

        lock_file = lock_path.open("a+b")
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError) as exc:
                raise RuntimeError(
                    "cross-process keyring locking unavailable"
                ) from exc

            # Minimal standalone validation equivalent to instance validation.
            raw = json.loads(backup.read_text())
            if raw.get("format") != "StevensSentinelReceiptKeyring":
                raise ValueError("bad backup keyring format")
            if int(raw.get("version", 0)) != 1:
                raise ValueError("unsupported backup keyring version")
            if not isinstance(raw.get("current"), dict):
                raise ValueError("backup keyring has no current key")

            entries = [raw["current"]] + list(raw.get("previous", []))
            kids = set()
            for i, entry in enumerate(entries):
                kid = str(entry.get("kid", ""))
                if len(kid) < 8 or kid in kids:
                    raise ValueError("invalid or duplicate backup kid")
                kids.add(kid)
                if len(_b64d(str(entry.get("key", "")))) != 32:
                    raise ValueError("backup receipt key must be 32 bytes")
                if int(entry.get("created_at", 0)) <= 0:
                    raise ValueError("backup key created_at invalid")
                if i > 0 and int(entry.get("accept_until", 0)) <= 0:
                    raise ValueError("backup previous key missing accept_until")

            tmp = primary.with_name(primary.name + ".restore.tmp")
            with tmp.open("w") as f:
                f.write(json.dumps(raw, indent=2) + "\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, primary)
            try:
                os.chmod(primary, 0o600)
            except Exception:
                pass

            return {
                "restored": True,
                "current_kid": raw["current"]["kid"],
                "revision": int(raw.get("revision", 0)),
                "previous_key_count": len(raw.get("previous", [])),
            }
        finally:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_file.close()

    # ------------------------------------------------------------------
    # Receipt operations: refresh + safety gate
    # ------------------------------------------------------------------
    def issue_proof_receipt(self, source_ip: str,
                            client_binding: str | None = None,
                            now: int | None = None) -> str:
        self._reload_keyring_if_changed()
        if not self._binding_mode_allowed():
            raise ValueError(
                "experimental receipt binding mode is disabled by keyring safety policy"
            )
        return super().issue_proof_receipt(
            source_ip,
            client_binding=client_binding,
            now=now,
        )

    def verify_proof_receipt(self, receipt: str | None,
                             source_ip: str,
                             client_binding: str | None = None,
                             now: int | None = None) -> bool:
        try:
            self._reload_keyring_if_changed()
        except Exception:
            if self.keyring_safety_policy.fail_closed_on_corrupt_keyring:
                return False
            raise
        if not self._binding_mode_allowed():
            return False
        return super().verify_proof_receipt(
            receipt,
            source_ip,
            client_binding=client_binding,
            now=now,
        )

    def receipt_status(self, now: int | None = None) -> dict:
        self._reload_keyring_if_changed()
        status = super().receipt_status(now=now)
        status["sentinel_version"] = VERSION
        status["keyring_revision"] = int(
            self._receipt_keyring.get("revision", 0)
        )
        status["rotation_serialization"] = "cross-process-file-lock"
        status["unsafe_rapid_rotation"] = "blocked"
        status["backup_before_rotation"] = bool(
            self.keyring_safety_policy.require_backup_before_rotation
        )
        status["backup_exists"] = self.receipt_keyring_backup_path.exists()
        status["experimental_bindings_enabled"] = bool(
            self.keyring_safety_policy.allow_experimental_binding_modes
        )
        status["keyring_refresh_on_change"] = bool(
            self.keyring_safety_policy.refresh_keyring_on_change
        )
        return status

    def keyring_safety_status(self) -> dict:
        return {
            "sentinel_version": VERSION,
            "rotation_lock": "cross-process-file-lock",
            "grace_preservation": "block-unsafe-rotation",
            "atomic_keyring_write": True,
            "validated_backup_restore": True,
            "fail_closed_on_corrupt_keyring": bool(
                self.keyring_safety_policy.fail_closed_on_corrupt_keyring
            ),
            "experimental_bindings_enabled": bool(
                self.keyring_safety_policy.allow_experimental_binding_modes
            ),
            "default_binding": "exact-ip",
            "backup_path": self.receipt_keyring_backup_path.name,
        }

    def reliability_status(self) -> dict:
        status = super().reliability_status()
        status["sentinel_version"] = VERSION
        status["proof_receipt_mode"] = (
            "stateless-hmac-v2-keyring-serialized"
        )
        status["keyring_rotation_serialized"] = True
        status["unsafe_rapid_rotation_blocked"] = True
        return status

    def resource_status(self) -> dict:
        status = super().resource_status()
        status["sentinel_version"] = VERSION
        status["keyring_safety"] = self.keyring_safety_status()
        return status

    def review_bundle(self, event_limit: int = 500,
                      subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["keyring_safety"] = {
            "serialized_rotation": True,
            "grace_preserving_rotation": True,
            "atomic_backup_restore": True,
            "experimental_bindings_default_off": True,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = (
            "adaptive-swarm-resource-fairness-audit-receipt-keyring-safe-rotation"
        )
        summary["keyring_safety_status"] = self.keyring_safety_status()
        return summary
