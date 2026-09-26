"""
Stevens Sentinel v0.5 — Fairness + Audit Integrity

Hardens Sentinel v0.4 against the two findings from the mixed paid-botnet test:
1. proof-pass churn could evict older legitimate passes;
2. concurrent event writers could fork the tamper-evident event hash chain.

Changes:
- concurrency-safe event-chain appends using a process lock + SQLite BEGIN IMMEDIATE;
- fairness-aware pass cache with source-cohort quotas;
- active/established passes are preferred over one-shot newcomer passes;
- least-used/newest entries are evicted first under pressure;
- temporary proof access remains valid even when a new pass cannot remain cached.

No blockchain consensus rule is changed. AI remains outside consensus.
TESTNET / DEFENSIVE SECURITY ONLY. NO HACK-BACK.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from stevens_sentinel_v0_2 import SEVERITY_WEIGHT, canonical
from stevens_sentinel_v0_4 import (
    StevensSentinel as ResourceSentinel,
    ResourcePolicy,
)
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "0.5"


@dataclass(frozen=True)
class FairnessPolicy:
    ipv4_prefix_bits: int = 24
    ipv6_prefix_bits: int = 64
    max_passes_per_cohort: int = 64
    pass_touch_interval_seconds: int = 2
    established_use_count: int = 2

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelFairnessPolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FairnessPolicy":
        if d.get("format") != "StevensSentinelFairnessPolicy":
            raise ValueError("not a Stevens Sentinel fairness policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported fairness policy version")
        defaults = cls()
        return cls(**{k: d.get(k, getattr(defaults, k)) for k in defaults.__dict__})

    def validate(self, resource: ResourcePolicy) -> None:
        if not (8 <= int(self.ipv4_prefix_bits) <= 32):
            raise ValueError("ipv4_prefix_bits out of range")
        if not (32 <= int(self.ipv6_prefix_bits) <= 128):
            raise ValueError("ipv6_prefix_bits out of range")
        if int(self.max_passes_per_cohort) < 1:
            raise ValueError("max_passes_per_cohort must be positive")
        if int(self.max_passes_per_cohort) > int(resource.max_pass_rows):
            raise ValueError("max_passes_per_cohort cannot exceed global pass cap")
        if int(self.pass_touch_interval_seconds) < 0:
            raise ValueError("pass_touch_interval_seconds cannot be negative")
        if int(self.established_use_count) < 1:
            raise ValueError("established_use_count must be positive")


class StevensSentinel(ResourceSentinel):
    def __init__(self, data_dir, config, swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None,
                 fairness_policy: FairnessPolicy | None = None):
        # Must exist before super().__init__ because migration/startup code can log.
        self._event_chain_lock = threading.RLock()
        self._pass_fairness_lock = threading.RLock()

        super().__init__(
            data_dir, config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
        )

        self.fairness_policy_path = self.data_dir / "sentinel_fairness_policy.json"
        self.fairness_policy = fairness_policy or self._load_or_create_fairness_policy()
        self.fairness_policy.validate(self.resource_policy)

        self._ensure_fair_pass_schema()
        self._last_fairness_evictions = 0

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        base = ResourceSentinel.load_or_create(data_dir, public_base_url)
        return cls(
            base.data_dir,
            base.config,
            swarm_policy=base.swarm_policy,
            resource_policy=base.resource_policy,
        )

    def _load_or_create_fairness_policy(self) -> FairnessPolicy:
        if self.fairness_policy_path.exists():
            p = FairnessPolicy.from_dict(
                json.loads(self.fairness_policy_path.read_text())
            )
        else:
            p = FairnessPolicy()
            self._write_private_json(self.fairness_policy_path, p.to_dict())
        return p

    def _persist_fairness_policy(self) -> None:
        self.fairness_policy.validate(self.resource_policy)
        self._write_private_json(self.fairness_policy_path, self.fairness_policy.to_dict())

    # ---------------------------------------------------------------------
    # Audit integrity
    # ---------------------------------------------------------------------
    def record(self, severity: str, category: str, source_ip: str | None = None,
               source_node_id: str | None = None, details: dict | None = None,
               affect_score: bool = True) -> str:
        """
        Serialize event-chain appends.

        BEGIN IMMEDIATE provides database-level writer serialization in addition
        to the in-process RLock. The second writer reads the predecessor only
        after the previous writer commits.
        """
        severity = severity.upper()
        if severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity {severity}")
        now = int(time.time())
        details = details or {}

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
                    INSERT INTO events(timestamp,severity,category,source_ip,source_node_id,
                                       details_json,previous_hash,event_hash)
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

    # ---------------------------------------------------------------------
    # Fairness-aware pass cache
    # ---------------------------------------------------------------------
    def _ensure_fair_pass_schema(self) -> None:
        with self._pass_fairness_lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                columns = {
                    r[1] for r in con.execute(
                        "PRAGMA table_info(global_challenge_passes)"
                    ).fetchall()
                }
                additions = {
                    "cohort": "TEXT NOT NULL DEFAULT ''",
                    "created_ts": "INTEGER NOT NULL DEFAULT 0",
                    "last_used_ts": "INTEGER NOT NULL DEFAULT 0",
                    "use_count": "INTEGER NOT NULL DEFAULT 0",
                    "proof_count": "INTEGER NOT NULL DEFAULT 1",
                }
                for name, decl in additions.items():
                    if name not in columns:
                        con.execute(
                            f"ALTER TABLE global_challenge_passes ADD COLUMN {name} {decl}"
                        )

                rows = con.execute("""
                    SELECT source_ip,passed_ts,cohort,created_ts,last_used_ts
                    FROM global_challenge_passes
                """).fetchall()
                for source_ip, passed_ts, cohort, created_ts, last_used_ts in rows:
                    patch_cohort = cohort or self._cohort(source_ip)
                    patch_created = int(created_ts or passed_ts or int(time.time()))
                    patch_last = int(last_used_ts or passed_ts or patch_created)
                    con.execute("""
                        UPDATE global_challenge_passes
                        SET cohort=?, created_ts=?, last_used_ts=?
                        WHERE source_ip=?
                    """, (patch_cohort, patch_created, patch_last, source_ip))
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

    def _cohort(self, source_ip: str) -> str:
        try:
            addr = ipaddress.ip_address(source_ip)
            if addr.version == 4:
                net = ipaddress.ip_network(
                    f"{source_ip}/{int(self.fairness_policy.ipv4_prefix_bits)}",
                    strict=False,
                )
            else:
                net = ipaddress.ip_network(
                    f"{source_ip}/{int(self.fairness_policy.ipv6_prefix_bits)}",
                    strict=False,
                )
            return str(net)
        except Exception:
            # Non-IP source identities remain isolated into their own cohort.
            return "id:" + hashlib.sha256(source_ip.encode()).hexdigest()[:24]

    def _evict_candidate(self, con, cohort: str | None = None) -> str | None:
        params = ()
        where = ""
        if cohort is not None:
            where = "WHERE cohort=?"
            params = (cohort,)

        row = con.execute(f"""
            SELECT source_ip
            FROM global_challenge_passes
            {where}
            ORDER BY
                CASE WHEN use_count >= ? THEN 1 ELSE 0 END ASC,
                use_count ASC,
                created_ts DESC,
                last_used_ts ASC
            LIMIT 1
        """, params + (int(self.fairness_policy.established_use_count),)).fetchone()
        return row[0] if row else None

    def _enforce_pass_fairness_locked(self, con, now: int) -> int:
        evicted = 0
        max_per = int(self.fairness_policy.max_passes_per_cohort)
        max_total = int(self.resource_policy.max_pass_rows)

        # First enforce cohort quotas. One bot/NAT/prefix cannot consume the whole cache.
        over = con.execute("""
            SELECT cohort, COUNT(*) AS n
            FROM global_challenge_passes
            GROUP BY cohort
            HAVING n > ?
        """, (max_per,)).fetchall()
        for cohort, count in over:
            excess = int(count) - max_per
            for _ in range(excess):
                victim = self._evict_candidate(con, cohort=cohort)
                if victim is None:
                    break
                con.execute(
                    "DELETE FROM global_challenge_passes WHERE source_ip=?",
                    (victim,)
                )
                evicted += 1

        # Then enforce global cap. Least-used NEWER entries are sacrificed first,
        # which prevents a stream of one-shot newcomers from flushing established
        # clients merely by arriving later.
        row = con.execute("SELECT COUNT(*) FROM global_challenge_passes").fetchone()
        total = int(row[0] if row else 0)
        while total > max_total:
            victim = self._evict_candidate(con, cohort=None)
            if victim is None:
                break
            con.execute(
                "DELETE FROM global_challenge_passes WHERE source_ip=?",
                (victim,)
            )
            evicted += 1
            total -= 1

        return evicted

    def _mark_global_pass(self, source_ip: str, now: int | None = None) -> None:
        now = int(now or time.time())
        cohort = self._cohort(source_ip)

        with self._pass_fairness_lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                existing = con.execute("""
                    SELECT created_ts,proof_count
                    FROM global_challenge_passes
                    WHERE source_ip=?
                """, (source_ip,)).fetchone()

                if existing:
                    created_ts = int(existing[0] or now)
                    proof_count = int(existing[1] or 0) + 1
                    con.execute("""
                        UPDATE global_challenge_passes
                        SET passed_ts=?, cohort=?, last_used_ts=?,
                            proof_count=?, created_ts=?
                        WHERE source_ip=?
                    """, (
                        now, cohort, now, proof_count, created_ts, source_ip
                    ))
                else:
                    con.execute("""
                        INSERT INTO global_challenge_passes(
                            source_ip,passed_ts,cohort,created_ts,last_used_ts,
                            use_count,proof_count
                        )
                        VALUES(?,?,?,?,?,?,?)
                    """, (source_ip, now, cohort, now, now, 0, 1))

                evicted = self._enforce_pass_fairness_locked(con, now)
                con.commit()
                self._last_fairness_evictions = evicted
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

        self._maybe_maintenance(now)

    def _recent_global_pass(self, source_ip: str, now: int | None = None) -> bool:
        now = int(now or time.time())
        cutoff = now - int(self.swarm_policy.pass_ttl_seconds)

        with self._pass_fairness_lock:
            con = self._connect()
            try:
                row = con.execute("""
                    SELECT passed_ts,last_used_ts
                    FROM global_challenge_passes
                    WHERE source_ip=?
                """, (source_ip,)).fetchone()
                if not row or int(row[0]) < cutoff:
                    valid = False
                else:
                    valid = True
                    last_used = int(row[1] or 0)
                    if now - last_used >= int(
                        self.fairness_policy.pass_touch_interval_seconds
                    ):
                        con.execute("""
                            UPDATE global_challenge_passes
                            SET last_used_ts=?, use_count=use_count+1
                            WHERE source_ip=?
                        """, (now, source_ip))
                con.commit()
            finally:
                con.close()

        self._maybe_maintenance(now)
        return valid

    def _maybe_maintenance(self, now: int | None = None, force: bool = False) -> None:
        """
        v0.5 maintenance intentionally does NOT call v0.4's oldest-first pass
        eviction. Subject/legacy cleanup is retained, while proof-pass caps are
        enforced only through the fairness-aware policy below.
        """
        now = int(now or time.time())
        interval = int(self.resource_policy.maintenance_interval_seconds)

        with self._maintenance_lock:
            if not force and now - self._last_maintenance < interval:
                return
            self._last_maintenance = now

        pass_cutoff = now - int(self.swarm_policy.pass_ttl_seconds)
        subject_cutoff = now - int(self.resource_policy.subject_retention_seconds)
        max_subject = int(self.resource_policy.max_subject_rows)

        with self._pass_fairness_lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")

                con.execute(
                    "DELETE FROM global_challenge_passes WHERE passed_ts < ?",
                    (pass_cutoff,)
                )

                try:
                    con.execute("DELETE FROM challenges")
                except Exception:
                    pass

                con.execute("""
                    DELETE FROM subjects
                    WHERE updated_ts < ?
                      AND quarantine_until <= ?
                      AND isolate_until <= ?
                """, (subject_cutoff, now, now))

                row = con.execute("SELECT COUNT(*) FROM subjects").fetchone()
                subject_count = int(row[0] if row else 0)
                if subject_count > max_subject:
                    excess = subject_count - max_subject
                    con.execute("""
                        DELETE FROM subjects
                        WHERE source_ip IN (
                            SELECT source_ip FROM subjects
                            WHERE quarantine_until <= ? AND isolate_until <= ?
                            ORDER BY updated_ts ASC LIMIT ?
                        )
                    """, (now, now, excess))

                evicted = self._enforce_pass_fairness_locked(con, now)
                con.commit()
                self._last_fairness_evictions = evicted
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

    def fairness_status(self) -> dict:
        with self._connect() as con:
            rows = con.execute("""
                SELECT cohort,COUNT(*) AS n,
                       SUM(CASE WHEN use_count >= ? THEN 1 ELSE 0 END) AS established
                FROM global_challenge_passes
                GROUP BY cohort
                ORDER BY n DESC
            """, (int(self.fairness_policy.established_use_count),)).fetchall()
            total = int(con.execute(
                "SELECT COUNT(*) FROM global_challenge_passes"
            ).fetchone()[0])

        return {
            "sentinel_version": VERSION,
            "strategy": "cohort-quota+established-use+newcomer-resistant-eviction",
            "total_passes": total,
            "global_cap": int(self.resource_policy.max_pass_rows),
            "max_passes_per_cohort": int(self.fairness_policy.max_passes_per_cohort),
            "cohort_count": len(rows),
            "largest_cohort": int(rows[0][1]) if rows else 0,
            "established_passes": sum(int(r[2] or 0) for r in rows),
            "last_fairness_evictions": int(self._last_fairness_evictions),
        }

    def resource_status(self) -> dict:
        s = super().resource_status()
        s["sentinel_version"] = VERSION
        s["fairness"] = self.fairness_status()
        s["event_chain_write_mode"] = "serialized-rlock+sqlite-begin-immediate"
        return s

    def review_bundle(self, event_limit: int = 500, subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["fairness_defense"] = {
            "cohort_quotas": True,
            "active_established_preference": True,
            "newcomer_resistant_eviction": True,
            "concurrency_safe_event_chain": True,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = "adaptive-swarm-resource-fairness-audit-integrity"
        summary["fairness_status"] = self.fairness_status()
        summary["event_chain_write_mode"] = "serialized-rlock+sqlite-begin-immediate"
        return summary
