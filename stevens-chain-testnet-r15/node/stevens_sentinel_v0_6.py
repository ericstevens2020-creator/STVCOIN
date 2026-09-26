"""
Stevens Sentinel v0.6 — Stateless Proof Receipts + Multi-Process Write Reliability

Closes the v0.5 established-botnet cache-residency weakness and hardens
cross-process audit writes.

Key changes:
- after a valid PoW, the client receives a source-bound, expiring, HMAC-authenticated
  proof receipt;
- receipt validity is stateless and does not depend on cache residency;
- the pass cache remains only an optimization;
- receipt presentation bypasses GLOBAL swarm re-challenge only, never local
  CHALLENGE/QUARANTINE/ISOLATE state;
- SQLite connections use a longer busy timeout;
- audit-chain appends retry SQLITE_BUSY/locked errors with bounded exponential backoff;
- event predecessor read + insert remains serialized with BEGIN IMMEDIATE.

No blockchain consensus rule changes. No hack-back.
TESTNET / DEFENSIVE SECURITY ONLY.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from stevens_sentinel_v0_2 import SEVERITY_WEIGHT, canonical
from stevens_sentinel_v0_4 import _b64e, _b64d
from stevens_sentinel_v0_5 import (
    StevensSentinel as FairSentinel,
    FairnessPolicy,
)
from stevens_sentinel_v0_4 import ResourcePolicy
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "0.6"


@dataclass(frozen=True)
class ReliabilityPolicy:
    proof_receipt_ttl_seconds: int = 5 * 60
    proof_receipt_clock_skew_seconds: int = 5
    sqlite_busy_timeout_ms: int = 30_000
    audit_write_retries: int = 8
    audit_retry_initial_ms: int = 10
    audit_retry_max_ms: int = 250

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelReliabilityPolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReliabilityPolicy":
        if d.get("format") != "StevensSentinelReliabilityPolicy":
            raise ValueError("not a Stevens Sentinel reliability policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported reliability policy version")
        defaults = cls()
        return cls(**{k: d.get(k, getattr(defaults, k)) for k in defaults.__dict__})

    def validate(self) -> None:
        if not (30 <= int(self.proof_receipt_ttl_seconds) <= 3600):
            raise ValueError("proof_receipt_ttl_seconds out of range")
        if not (0 <= int(self.proof_receipt_clock_skew_seconds) <= 60):
            raise ValueError("proof_receipt_clock_skew_seconds out of range")
        if not (1000 <= int(self.sqlite_busy_timeout_ms) <= 120_000):
            raise ValueError("sqlite_busy_timeout_ms out of range")
        if not (1 <= int(self.audit_write_retries) <= 20):
            raise ValueError("audit_write_retries out of range")
        if not (1 <= int(self.audit_retry_initial_ms) <= 5000):
            raise ValueError("audit_retry_initial_ms out of range")
        if not (1 <= int(self.audit_retry_max_ms) <= 10_000):
            raise ValueError("audit_retry_max_ms out of range")



class _ClosingSQLiteConnection(sqlite3.Connection):
    """Preserve sqlite3 transaction context semantics, then close the handle."""
    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


class StevensSentinel(FairSentinel):
    def __init__(self, data_dir, config, swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None,
                 fairness_policy: FairnessPolicy | None = None,
                 reliability_policy: ReliabilityPolicy | None = None):
        self._audit_counter_lock = threading.Lock()
        self._audit_retry_count = 0
        self._audit_write_failures = 0

        super().__init__(
            data_dir, config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
            fairness_policy=fairness_policy,
        )

        self.reliability_policy_path = self.data_dir / "sentinel_reliability_policy.json"
        self.reliability_policy = reliability_policy or self._load_or_create_reliability_policy()
        self.reliability_policy.validate()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        """Serialize schema/config migration across local node processes.

        Linux/Unix nodes use an advisory file lock around startup. Runtime event
        writes still rely on SQLite BEGIN IMMEDIATE + retry/backoff. Platforms
        without fcntl fall back to the SQLite busy-timeout path.
        """
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "sentinel_startup.lock"
        lock_file = lock_path.open("a+b")
        locked = False
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                locked = True
            except (ImportError, OSError):
                pass

            base = FairSentinel.load_or_create(data_dir, public_base_url)
            return cls(
                base.data_dir,
                base.config,
                swarm_policy=base.swarm_policy,
                resource_policy=base.resource_policy,
                fairness_policy=base.fairness_policy,
            )
        finally:
            if locked:
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
            lock_file.close()

    def _load_or_create_reliability_policy(self) -> ReliabilityPolicy:
        if self.reliability_policy_path.exists():
            p = ReliabilityPolicy.from_dict(
                json.loads(self.reliability_policy_path.read_text())
            )
        else:
            p = ReliabilityPolicy()
            self._write_private_json(self.reliability_policy_path, p.to_dict())
        return p

    def _persist_reliability_policy(self) -> None:
        self.reliability_policy.validate()
        self._write_private_json(self.reliability_policy_path, self.reliability_policy.to_dict())

    # ------------------------------------------------------------------
    # SQLite reliability
    # ------------------------------------------------------------------
    def _connect(self):
        timeout_s = 30.0
        if hasattr(self, "reliability_policy"):
            timeout_s = max(
                1.0, int(self.reliability_policy.sqlite_busy_timeout_ms) / 1000.0
            )
        con = sqlite3.connect(self.db_path, timeout=timeout_s, factory=_ClosingSQLiteConnection)
        busy_ms = int(timeout_s * 1000)
        con.execute(f"PRAGMA busy_timeout={busy_ms}")

        # Avoid needlessly requesting journal-mode changes on every connection.
        # The database is initialized in WAL mode; set it only if needed.
        try:
            mode = str(con.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if mode != "wal":
                con.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            # An already-initialized shared DB may briefly be busy while another
            # process owns the writer lock. The busy timeout still protects writes.
            pass
        return con

    def record(self, severity: str, category: str, source_ip: str | None = None,
               source_node_id: str | None = None, details: dict | None = None,
               affect_score: bool = True) -> str:
        severity = severity.upper()
        if severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity {severity}")
        details = details or {}
        now = int(time.time())

        retries = int(
            getattr(self, "reliability_policy", ReliabilityPolicy()).audit_write_retries
        )
        initial_ms = int(
            getattr(self, "reliability_policy", ReliabilityPolicy()).audit_retry_initial_ms
        )
        max_ms = int(
            getattr(self, "reliability_policy", ReliabilityPolicy()).audit_retry_max_ms
        )

        last_exc = None
        for attempt in range(retries + 1):
            try:
                with self._event_chain_lock:
                    con = self._connect()
                    try:
                        con.execute("BEGIN IMMEDIATE")
                        row = con.execute(
                            "SELECT event_hash FROM events ORDER BY id DESC LIMIT 1"
                        ).fetchone()
                        prev = row[0] if row else "0" * 64
                        body = {
                            "timestamp": now,
                            "severity": severity,
                            "category": category,
                            "source_ip": source_ip,
                            "source_node_id": source_node_id,
                            "details": details,
                            "previous_hash": prev,
                        }
                        event_hash = hashlib.sha256(
                            prev.encode() + canonical(body)
                        ).hexdigest()
                        con.execute("""
                            INSERT INTO events(
                                timestamp,severity,category,source_ip,source_node_id,
                                details_json,previous_hash,event_hash
                            )
                            VALUES(?,?,?,?,?,?,?,?)
                        """, (
                            now, severity, category, source_ip, source_node_id,
                            json.dumps(details, sort_keys=True), prev, event_hash
                        ))
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                    finally:
                        con.close()

                if source_ip and affect_score:
                    weight = SEVERITY_WEIGHT[severity]
                    if weight > 0:
                        self._apply_score(source_ip, weight, category)
                return event_hash

            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                last_exc = exc
                if attempt >= retries:
                    break
                delay_ms = min(max_ms, initial_ms * (2 ** attempt))
                with self._audit_counter_lock:
                    self._audit_retry_count += 1
                time.sleep(delay_ms / 1000.0)

        with self._audit_counter_lock:
            self._audit_write_failures += 1
        raise last_exc if last_exc else RuntimeError("audit event write failed")

    # ------------------------------------------------------------------
    # Stateless proof receipts
    # ------------------------------------------------------------------
    def _receipt_key(self) -> bytes:
        return hmac.new(
            self._challenge_key(),
            b"Stevens-Sentinel-v0.6/stateless-proof-receipt-key",
            hashlib.sha256,
        ).digest()

    def issue_proof_receipt(self, source_ip: str,
                            now: int | None = None) -> str:
        now = int(now or time.time())
        ttl = int(self.reliability_policy.proof_receipt_ttl_seconds)
        payload = {
            "v": 1,
            "iat": now,
            "exp": now + ttl,
            "src": self._source_tag(source_ip),
            "scope": "global-swarm-proof",
        }
        body = canonical(payload)
        sig = hmac.new(
            self._receipt_key(),
            b"receipt|" + body,
            hashlib.sha256,
        ).digest()
        return _b64e(body) + "." + _b64e(sig)

    def verify_proof_receipt(self, receipt: str | None,
                             source_ip: str,
                             now: int | None = None) -> bool:
        if not receipt:
            return False
        now = int(now or time.time())
        try:
            body64, sig64 = str(receipt).split(".", 1)
            body = _b64d(body64)
            sig = _b64d(sig64)
            # Reject alternate/non-canonical base64url encodings so a receipt
            # has one exact wire representation.
            if _b64e(body) != body64 or _b64e(sig) != sig64:
                return False
            expected = hmac.new(
                self._receipt_key(),
                b"receipt|" + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(sig, expected):
                return False
            payload = json.loads(body)
            if int(payload.get("v", 0)) != 1:
                return False
            if payload.get("scope") != "global-swarm-proof":
                return False
            if not hmac.compare_digest(
                str(payload.get("src", "")),
                self._source_tag(source_ip),
            ):
                return False
            skew = int(self.reliability_policy.proof_receipt_clock_skew_seconds)
            if int(payload.get("iat", 0)) > now + skew:
                return False
            if int(payload.get("exp", 0)) < now - skew:
                return False
            return True
        except Exception:
            return False

    def preflight(self, source_ip: str,
                  challenge_nonce: str | None = None,
                  challenge_solution: str | None = None,
                  proof_receipt: str | None = None) -> dict:
        """
        Local suspicion always wins. Proof receipts only bypass the global swarm
        challenge, not local CHALLENGE/QUARANTINE/ISOLATE.
        """
        d = self._load_subject(source_ip)
        state = d["state"]

        if state == "ISOLATE":
            return {"action": "ISOLATE", "subject": d}
        if state == "QUARANTINE":
            return {"action": "QUARANTINE", "subject": d}
        if state == "CHALLENGE":
            if self.verify_challenge(source_ip, challenge_nonce, challenge_solution):
                receipt = self.issue_proof_receipt(source_ip)
                return {
                    "action": "ALLOW",
                    "subject": self._load_subject(source_ip),
                    "challenge_passed": True,
                    "proof_receipt": receipt,
                }
            return {
                "action": "CHALLENGE",
                "subject": d,
                "challenge": self.get_or_issue_challenge(source_ip),
            }

        global_info = self.global_threat()
        if global_info["mode"] not in ("GLOBAL_CHALLENGE", "GLOBAL_HIGH"):
            return {
                "action": "ALLOW",
                "subject": d,
                "global_threat": global_info,
            }

        # v0.6 authority: a valid receipt proves the source recently paid the
        # PoW cost, regardless of cache eviction.
        if self.verify_proof_receipt(proof_receipt, source_ip):
            return {
                "action": "ALLOW",
                "subject": d,
                "global_threat": global_info,
                "proof_receipt_valid": True,
            }

        # v0.5 cache remains an optimization for clients that have not yet
        # adopted receipt headers.
        if self._recent_global_pass(source_ip):
            return {
                "action": "ALLOW",
                "subject": d,
                "global_threat": global_info,
                "global_pass": True,
            }

        if challenge_nonce and challenge_solution:
            if self.verify_challenge(source_ip, challenge_nonce, challenge_solution):
                receipt = self.issue_proof_receipt(source_ip)
                return {
                    "action": "ALLOW",
                    "subject": self.subject(source_ip),
                    "global_threat": global_info,
                    "global_pass": True,
                    "challenge_passed": True,
                    "proof_receipt": receipt,
                }

        return {
            "action": "CHALLENGE",
            "subject": d,
            "challenge": self._global_challenge(source_ip, global_info),
            "global_threat": global_info,
            "challenge_reason": "distributed_swarm_anomaly",
        }

    def reliability_status(self) -> dict:
        with self._audit_counter_lock:
            retries = int(self._audit_retry_count)
            failures = int(self._audit_write_failures)
        return {
            "sentinel_version": VERSION,
            "proof_receipt_mode": "stateless-hmac-v1",
            "proof_receipt_ttl_seconds": int(
                self.reliability_policy.proof_receipt_ttl_seconds
            ),
            "sqlite_busy_timeout_ms": int(
                self.reliability_policy.sqlite_busy_timeout_ms
            ),
            "audit_write_retries_configured": int(
                self.reliability_policy.audit_write_retries
            ),
            "audit_retry_count_process_local": retries,
            "audit_write_failures_process_local": failures,
            "proof_receipt_bypasses_local_containment": False,
        }

    def resource_status(self) -> dict:
        status = super().resource_status()
        status["sentinel_version"] = VERSION
        status["reliability"] = self.reliability_status()
        return status

    def review_bundle(self, event_limit: int = 500,
                      subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["reliability_defense"] = {
            "stateless_proof_receipts": True,
            "receipt_cache_independent": True,
            "multiprocess_write_retry_backoff": True,
            "sqlite_busy_timeout": True,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = (
            "adaptive-swarm-resource-fairness-audit-receipt-reliability"
        )
        summary["reliability_status"] = self.reliability_status()
        return summary
