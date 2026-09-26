"""
Stevens Sentinel v0.4 — Stateless Resource Defense

Hardens Sentinel v0.3 against challenge-exhaustion / adaptive botnet pressure.

Key changes:
- HMAC-authenticated stateless proof-of-work challenge tokens: no challenge row per source.
- bounded pass/subject maintenance and legacy challenge cleanup.
- short-lived cached global threat snapshots to avoid rescanning SQLite on every request.
- in-memory challenge issuance budget with automatic proof-cost backpressure.
- AI remains outside consensus and cannot automatically change policy.

Consensus is unchanged. Defensive/testnet use only. No hack-back.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stevens_sentinel_v0_2 import (
    SentinelConfig,
    canonical,
    leading_zero_bits,
)
from stevens_sentinel_v0_3 import (
    StevensSentinel as SwarmSentinel,
    SwarmPolicy,
)

VERSION = "0.4"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


@dataclass(frozen=True)
class ResourcePolicy:
    global_threat_cache_seconds: float = 1.0
    challenge_budget_per_second: int = 250
    backpressure_extra_bits: int = 2
    max_pass_rows: int = 5000
    max_subject_rows: int = 20000
    subject_retention_seconds: int = 24 * 60 * 60
    maintenance_interval_seconds: int = 60
    token_clock_skew_seconds: int = 5

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelResourcePolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ResourcePolicy":
        if d.get("format") != "StevensSentinelResourcePolicy":
            raise ValueError("not a Stevens Sentinel resource policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported resource policy version")
        defaults = cls()
        return cls(**{k: d.get(k, getattr(defaults, k)) for k in defaults.__dict__})

    def validate(self, config: SentinelConfig, swarm: SwarmPolicy) -> None:
        if not (0.05 <= float(self.global_threat_cache_seconds) <= 10.0):
            raise ValueError("global_threat_cache_seconds out of range")
        if not (1 <= int(self.challenge_budget_per_second) <= 1_000_000):
            raise ValueError("challenge_budget_per_second out of range")
        if not (0 <= int(self.backpressure_extra_bits) <= 8):
            raise ValueError("backpressure_extra_bits out of range")
        worst = int(config.challenge_difficulty_bits) + int(swarm.high_extra_bits) + int(self.backpressure_extra_bits)
        if worst > 28:
            raise ValueError("combined challenge difficulty would exceed 28-bit safety cap")
        if int(self.max_pass_rows) < 100:
            raise ValueError("max_pass_rows too small")
        if int(self.max_subject_rows) < 100:
            raise ValueError("max_subject_rows too small")
        if int(self.subject_retention_seconds) < 60:
            raise ValueError("subject_retention_seconds too small")
        if int(self.maintenance_interval_seconds) < 1:
            raise ValueError("maintenance_interval_seconds too small")


class StevensSentinel(SwarmSentinel):
    def __init__(self, data_dir, config, swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None):
        super().__init__(data_dir, config, swarm_policy=swarm_policy)
        self.resource_policy_path = self.data_dir / "sentinel_resource_policy.json"
        self.resource_policy = resource_policy or self._load_or_create_resource_policy()
        self.resource_policy.validate(self.config, self.swarm_policy)

        self._cache_lock = threading.Lock()
        self._global_cache: dict[str, Any] | None = None
        self._global_cache_at = 0.0
        self._cache_hits = 0
        self._cache_misses = 0

        self._issue_lock = threading.Lock()
        self._issue_second = 0
        self._issue_count = 0
        self._last_backpressure_log_second = -1

        self._maintenance_lock = threading.Lock()
        self._last_maintenance = 0.0

        # v0.4 no longer needs server-side challenge rows. Remove legacy ephemeral
        # state at startup/migration.
        self._purge_legacy_challenges()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        # Let v0.3 load/migrate base + swarm policy first, then wrap it.
        base = SwarmSentinel.load_or_create(data_dir, public_base_url)
        return cls(base.data_dir, base.config, swarm_policy=base.swarm_policy)

    def _load_or_create_resource_policy(self) -> ResourcePolicy:
        if self.resource_policy_path.exists():
            p = ResourcePolicy.from_dict(json.loads(self.resource_policy_path.read_text()))
        else:
            p = ResourcePolicy()
            self._write_private_json(self.resource_policy_path, p.to_dict())
        return p

    def _persist_resource_policy(self) -> None:
        self.resource_policy.validate(self.config, self.swarm_policy)
        self._write_private_json(self.resource_policy_path, self.resource_policy.to_dict())

    def _challenge_key(self) -> bytes:
        # Domain-separated key derived from already-private Sentinel secrets.
        material = (self.config.operator_token + "|" + self.config.telemetry_salt).encode()
        return hmac.new(
            hashlib.sha256(material).digest(),
            b"Stevens-Sentinel-v0.4/stateless-challenge-key",
            hashlib.sha256,
        ).digest()

    def _source_tag(self, source_ip: str) -> str:
        return _b64e(hmac.new(
            self._challenge_key(),
            b"source|" + source_ip.encode(),
            hashlib.sha256,
        ).digest()[:16])

    def _make_token(self, source_ip: str, bits: int, scope: str,
                    global_mode: str | None = None,
                    now: int | None = None) -> str:
        now = int(now or time.time())
        payload = {
            "v": 1,
            "iat": now,
            "exp": now + int(self.config.challenge_ttl_seconds),
            "bits": int(bits),
            "src": self._source_tag(source_ip),
            "scope": str(scope),
            "gm": global_mode,
        }
        body = canonical(payload)
        sig = hmac.new(self._challenge_key(), b"token|" + body, hashlib.sha256).digest()
        return _b64e(body) + "." + _b64e(sig)

    def _parse_token(self, token: str, source_ip: str,
                     now: int | None = None) -> dict | None:
        now = int(now or time.time())
        try:
            body64, sig64 = token.split(".", 1)
            body = _b64d(body64)
            sig = _b64d(sig64)
            expected = hmac.new(self._challenge_key(), b"token|" + body, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                return None
            payload = json.loads(body)
            if int(payload.get("v", 0)) != 1:
                return None
            if not hmac.compare_digest(str(payload.get("src", "")), self._source_tag(source_ip)):
                return None
            skew = int(self.resource_policy.token_clock_skew_seconds)
            if int(payload.get("iat", 0)) > now + skew:
                return None
            if int(payload.get("exp", 0)) < now - skew:
                return None
            bits = int(payload.get("bits", -1))
            if not (4 <= bits <= 28):
                return None
            return payload
        except Exception:
            return None

    @staticmethod
    def challenge_digest(nonce: str, source_ip: str, solution: str) -> bytes:
        return hashlib.sha256(f"{nonce}:{source_ip}:{solution}".encode()).digest()

    def _issue_budget(self, now: int | None = None) -> tuple[int, bool]:
        now = int(now or time.time())
        with self._issue_lock:
            if self._issue_second != now:
                self._issue_second = now
                self._issue_count = 0
            self._issue_count += 1
            over = self._issue_count > int(self.resource_policy.challenge_budget_per_second)
            return self._issue_count, over

    def _stateless_challenge(self, source_ip: str, bits: int,
                             scope: str = "local-adaptive-defense",
                             global_mode: str | None = None) -> dict:
        now = int(time.time())
        issue_count, over_budget = self._issue_budget(now)
        if over_budget:
            bits = min(28, int(bits) + int(self.resource_policy.backpressure_extra_bits))
            # At most one log entry per second for backpressure, avoiding event-log
            # amplification under a challenge spray.
            with self._issue_lock:
                should_log = self._last_backpressure_log_second != now
                if should_log:
                    self._last_backpressure_log_second = now
            if should_log:
                self.record(
                    "INFO", "challenge_budget_backpressure",
                    details={
                        "issued_this_second": issue_count,
                        "budget_per_second": int(self.resource_policy.challenge_budget_per_second),
                        "difficulty_bits": bits,
                    },
                    affect_score=False,
                )

        token = self._make_token(source_ip, bits, scope, global_mode, now=now)
        return {
            "nonce": token,
            "difficulty_bits": int(bits),
            "issued_at": now,
            "expires_at": now + int(self.config.challenge_ttl_seconds),
            "algorithm": "sha256-leading-zero-bits-v1",
            "token_format": "hmac-stateless-v1",
            "scope": scope,
            "global_mode": global_mode,
            "backpressure": bool(over_budget),
        }

    def get_or_issue_challenge(self, source_ip: str) -> dict:
        # Local adaptive challenge. No database row is created.
        now = int(time.time())
        score = self._load_subject(source_ip, now)["score"]
        extra = min(4, int(max(0.0, score - self.config.challenge_score) // 8))
        bits = min(28, int(self.config.challenge_difficulty_bits) + extra)
        self._maybe_maintenance(now)
        return self._stateless_challenge(source_ip, bits)

    def verify_challenge(self, source_ip: str, nonce: str | None,
                         solution: str | None) -> bool:
        if not nonce or not solution:
            return False
        now = int(time.time())
        payload = self._parse_token(str(nonce), source_ip, now)
        if not payload:
            return False

        bits = int(payload["bits"])
        digest = self.challenge_digest(str(nonce), source_ip, str(solution))
        if leading_zero_bits(digest) < bits:
            self.record("LOW", "challenge_failed", source_ip=source_ip,
                        details={"difficulty_bits": bits})
            return False

        # Preserve v0.2 behavior: successful proof lowers local risk but cannot
        # break an active isolate timer.
        d = self._load_subject(source_ip, now)
        d["score"] = max(0.0, float(d["score"]) - self.config.challenge_credit)
        d["quarantine_until"] = 0
        if d["isolate_until"] > now:
            d["state"] = "ISOLATE"
        else:
            d["state"] = self._state_from_score(d["score"])
            if d["state"] in ("QUARANTINE", "ISOLATE"):
                d["state"] = "WATCH"
                d["score"] = min(d["score"], self.config.challenge_score - 0.001)
        d["last_score_ts"] = now
        d["updated_ts"] = now
        d["last_reason"] = "challenge_passed"
        self._save_subject(d)

        self._mark_global_pass(source_ip, now)
        self.record(
            "INFO", "challenge_passed", source_ip=source_ip,
            details={
                "new_state": d["state"],
                "new_score": round(d["score"], 3),
                "token_format": "hmac-stateless-v1",
                "scope": payload.get("scope"),
            },
            affect_score=False,
        )
        self._maybe_maintenance(now)
        return True

    def _global_challenge(self, source_ip: str, global_info: dict) -> dict:
        extra = int(global_info.get("challenge_extra_bits", 0))
        bits = min(
            28,
            int(self.config.challenge_difficulty_bits) + extra
        )
        return self._stateless_challenge(
            source_ip, bits,
            scope="global-swarm-defense",
            global_mode=global_info.get("mode"),
        )

    def _purge_legacy_challenges(self) -> None:
        try:
            with self._connect() as con:
                row = con.execute("SELECT COUNT(*) FROM challenges").fetchone()
                count = int(row[0] if row else 0)
                if count:
                    con.execute("DELETE FROM challenges")
            if count:
                self.record(
                    "INFO", "legacy_challenge_state_purged",
                    details={"rows_removed": count, "reason": "v0.4 stateless migration"},
                    affect_score=False,
                )
        except Exception:
            # Fresh DBs still initialize the legacy table through v0.2; this
            # defensive guard keeps migration non-fatal if a future schema omits it.
            pass

    def _mark_global_pass(self, source_ip: str, now: int | None = None) -> None:
        now = int(now or time.time())
        with self._connect() as con:
            con.execute("""
                INSERT INTO global_challenge_passes(source_ip,passed_ts)
                VALUES(?,?)
                ON CONFLICT(source_ip) DO UPDATE SET passed_ts=excluded.passed_ts
            """, (source_ip, now))
        self._maybe_maintenance(now)

    def _recent_global_pass(self, source_ip: str, now: int | None = None) -> bool:
        now = int(now or time.time())
        cutoff = now - int(self.swarm_policy.pass_ttl_seconds)
        with self._connect() as con:
            row = con.execute(
                "SELECT passed_ts FROM global_challenge_passes WHERE source_ip=?",
                (source_ip,)
            ).fetchone()
        self._maybe_maintenance(now)
        return bool(row and int(row[0]) >= cutoff)

    def _maybe_maintenance(self, now: int | None = None, force: bool = False) -> None:
        now = int(now or time.time())
        interval = int(self.resource_policy.maintenance_interval_seconds)
        with self._maintenance_lock:
            if not force and now - self._last_maintenance < interval:
                return
            self._last_maintenance = now

        pass_cutoff = now - int(self.swarm_policy.pass_ttl_seconds)
        subject_cutoff = now - int(self.resource_policy.subject_retention_seconds)
        max_pass = int(self.resource_policy.max_pass_rows)
        max_subject = int(self.resource_policy.max_subject_rows)

        with self._connect() as con:
            con.execute("DELETE FROM global_challenge_passes WHERE passed_ts < ?", (pass_cutoff,))

            # Legacy challenge rows are never needed in v0.4.
            try:
                con.execute("DELETE FROM challenges")
            except Exception:
                pass

            # Remove old non-active subject state first.
            con.execute("""
                DELETE FROM subjects
                WHERE updated_ts < ?
                  AND quarantine_until <= ?
                  AND isolate_until <= ?
            """, (subject_cutoff, now, now))

            row = con.execute("SELECT COUNT(*) FROM global_challenge_passes").fetchone()
            pass_count = int(row[0] if row else 0)
            if pass_count > max_pass:
                excess = pass_count - max_pass
                con.execute("""
                    DELETE FROM global_challenge_passes
                    WHERE source_ip IN (
                        SELECT source_ip FROM global_challenge_passes
                        ORDER BY passed_ts ASC LIMIT ?
                    )
                """, (excess,))

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

    def global_threat(self, now: int | None = None,
                      track_transition: bool = True) -> dict:
        # Explicit timestamps are used by deterministic tests/forensics and bypass
        # the wall-clock cache.
        if now is not None:
            return super().global_threat(now=now, track_transition=track_transition)

        monotonic_now = time.monotonic()
        ttl = float(self.resource_policy.global_threat_cache_seconds)
        with self._cache_lock:
            if self._global_cache is not None and monotonic_now - self._global_cache_at < ttl:
                self._cache_hits += 1
                return dict(self._global_cache)
            self._cache_misses += 1

        result = super().global_threat(now=None, track_transition=track_transition)
        with self._cache_lock:
            self._global_cache = dict(result)
            self._global_cache_at = time.monotonic()
        return result

    def resource_status(self) -> dict:
        with self._connect() as con:
            challenge_rows = 0
            try:
                challenge_rows = int(con.execute("SELECT COUNT(*) FROM challenges").fetchone()[0])
            except Exception:
                pass
            pass_rows = int(con.execute("SELECT COUNT(*) FROM global_challenge_passes").fetchone()[0])
            subject_rows = int(con.execute("SELECT COUNT(*) FROM subjects").fetchone()[0])
        with self._cache_lock:
            hits, misses = self._cache_hits, self._cache_misses
        total = hits + misses
        return {
            "sentinel_version": VERSION,
            "challenge_storage_mode": "stateless-hmac-v1",
            "legacy_challenge_rows": challenge_rows,
            "global_pass_rows": pass_rows,
            "subject_rows": subject_rows,
            "max_pass_rows": int(self.resource_policy.max_pass_rows),
            "max_subject_rows": int(self.resource_policy.max_subject_rows),
            "global_cache_hits": hits,
            "global_cache_misses": misses,
            "global_cache_hit_ratio": round(hits / total, 4) if total else 0.0,
            "challenge_budget_per_second": int(self.resource_policy.challenge_budget_per_second),
        }

    def review_bundle(self, event_limit: int = 500, subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["resource_defense"] = {
            "stateless_challenges": True,
            "bounded_maintenance": True,
            "global_threat_cache": True,
            "challenge_issuance_backpressure": True,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = "adaptive-swarm-plus-stateless-resource-defense"
        summary["resource_status"] = self.resource_status()
        summary["ai_in_consensus"] = False
        summary["automatic_ai_policy_changes"] = False
        return summary
