"""
Stevens Sentinel v0.2 — Adaptive Defense Loop
Defensive monitoring, deception, progressive challenge, and local containment
for Stevens Chain v0.5.2 testnet nodes.

State machine:
    NORMAL -> WATCH -> CHALLENGE -> QUARANTINE -> ISOLATE

This component is intentionally local and deterministic:
- it does not alter blockchain consensus;
- it does not attack or exploit remote systems;
- it does not let an AI model decide block/transaction validity;
- AI/LLM analysis, if used, receives a sanitized review bundle and can only
  make recommendations for human review.

TESTNET / DEFENSIVE SECURITY ONLY. NO REAL FUNDS.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERSION = "0.2"
SENTINEL_PRIVATE_JSON_MAX_BYTES = 256 * 1024

STATES = ("NORMAL", "WATCH", "CHALLENGE", "QUARANTINE", "ISOLATE")
STATE_RANK = {s: i for i, s in enumerate(STATES)}
SEVERITY_WEIGHT = {
    "INFO": 0.0,
    "LOW": 1.0,
    "MEDIUM": 3.0,
    "HIGH": 8.0,
    "CRITICAL": 20.0,
}


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _chmod600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _read_private_json_bounded(path: Path, max_bytes: int = SENTINEL_PRIVATE_JSON_MAX_BYTES):
    try:
        size = path.stat().st_size
    except OSError as e:
        raise ValueError(f"unable to read private Sentinel JSON: {path.name}") from e
    if size <= 0 or size > int(max_bytes):
        raise ValueError(f"Sentinel private JSON size invalid: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"invalid Sentinel private JSON: {path.name}") from e


def _atomic_write_private_text(path: Path, text: str) -> None:
    """Crash-consistent owner-private file replacement.

    The old file remains authoritative until a fully written+fsynced temporary
    file is atomically renamed into place. A best-effort parent directory fsync
    closes the common rename-durability window on POSIX filesystems.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd = None
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _chmod600(path)
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


def _atomic_write_private_json(path: Path, obj: Any) -> None:
    _atomic_write_private_text(path, json.dumps(obj, indent=2) + "\n")


def leading_zero_bits(digest: bytes) -> int:
    total = 0
    for b in digest:
        if b == 0:
            total += 8
            continue
        total += 8 - b.bit_length()
        break
    return total


@dataclass(frozen=True)
class SentinelConfig:
    operator_token: str
    telemetry_salt: str
    canary_paths: tuple[str, ...]
    canary_tokens: tuple[str, ...]
    honey_outpoints: tuple[str, ...]
    watch_score: float = 5.0
    challenge_score: float = 10.0
    quarantine_score: float = 20.0
    isolate_score: float = 35.0
    score_decay_per_minute: float = 1.0
    quarantine_seconds: int = 15 * 60
    isolate_seconds: int = 2 * 60 * 60
    challenge_difficulty_bits: int = 18
    challenge_ttl_seconds: int = 5 * 60
    challenge_credit: float = 8.0
    immediate_isolate_on_canary: bool = True
    immediate_isolate_on_honey_spend: bool = True

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelConfig",
            "version": 2,
            "operator_token": self.operator_token,
            "telemetry_salt": self.telemetry_salt,
            "canary_paths": list(self.canary_paths),
            "canary_tokens": list(self.canary_tokens),
            "honey_outpoints": list(self.honey_outpoints),
            "watch_score": self.watch_score,
            "challenge_score": self.challenge_score,
            "quarantine_score": self.quarantine_score,
            "isolate_score": self.isolate_score,
            "score_decay_per_minute": self.score_decay_per_minute,
            "quarantine_seconds": self.quarantine_seconds,
            "isolate_seconds": self.isolate_seconds,
            "challenge_difficulty_bits": self.challenge_difficulty_bits,
            "challenge_ttl_seconds": self.challenge_ttl_seconds,
            "challenge_credit": self.challenge_credit,
            "immediate_isolate_on_canary": self.immediate_isolate_on_canary,
            "immediate_isolate_on_honey_spend": self.immediate_isolate_on_honey_spend,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SentinelConfig":
        if d.get("format") != "StevensSentinelConfig":
            raise ValueError("not a Stevens Sentinel config")

        version = int(d.get("version", 1))
        if version == 1:
            # Safe migration from Sentinel v0.1 config.
            return cls(
                operator_token=str(d["operator_token"]),
                telemetry_salt=secrets.token_hex(32),
                canary_paths=tuple(str(x) for x in d.get("canary_paths", [])),
                canary_tokens=tuple(str(x) for x in d.get("canary_tokens", [])),
                honey_outpoints=tuple(str(x) for x in d.get("honey_outpoints", [])),
                quarantine_seconds=int(d.get("quarantine_seconds", 15 * 60)),
            )

        if version != 2:
            raise ValueError(f"unsupported Sentinel config version {version}")

        return cls(
            operator_token=str(d["operator_token"]),
            telemetry_salt=str(d.get("telemetry_salt") or secrets.token_hex(32)),
            canary_paths=tuple(str(x) for x in d.get("canary_paths", [])),
            canary_tokens=tuple(str(x) for x in d.get("canary_tokens", [])),
            honey_outpoints=tuple(str(x) for x in d.get("honey_outpoints", [])),
            watch_score=float(d.get("watch_score", 5.0)),
            challenge_score=float(d.get("challenge_score", 10.0)),
            quarantine_score=float(d.get("quarantine_score", 20.0)),
            isolate_score=float(d.get("isolate_score", 35.0)),
            score_decay_per_minute=float(d.get("score_decay_per_minute", 1.0)),
            quarantine_seconds=int(d.get("quarantine_seconds", 15 * 60)),
            isolate_seconds=int(d.get("isolate_seconds", 2 * 60 * 60)),
            challenge_difficulty_bits=int(d.get("challenge_difficulty_bits", 18)),
            challenge_ttl_seconds=int(d.get("challenge_ttl_seconds", 5 * 60)),
            challenge_credit=float(d.get("challenge_credit", 8.0)),
            immediate_isolate_on_canary=bool(d.get("immediate_isolate_on_canary", True)),
            immediate_isolate_on_honey_spend=bool(d.get("immediate_isolate_on_honey_spend", True)),
        )

    def validate(self) -> None:
        if not (0 <= self.watch_score < self.challenge_score < self.quarantine_score < self.isolate_score):
            raise ValueError("adaptive thresholds must strictly increase")
        if not (4 <= self.challenge_difficulty_bits <= 28):
            raise ValueError("challenge_difficulty_bits must be between 4 and 28")
        if self.score_decay_per_minute < 0:
            raise ValueError("score decay cannot be negative")
        if self.quarantine_seconds <= 0 or self.isolate_seconds <= 0:
            raise ValueError("containment durations must be positive")


class StevensSentinel:
    def __init__(self, data_dir: str | Path, config: SentinelConfig):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config = config
        self.config.validate()
        self.db_path = self.data_dir / "sentinel.sqlite3"
        self.config_path = self.data_dir / "sentinel_config.json"
        self._init_db()

    @classmethod
    def load_or_create(cls, data_dir: str | Path,
                       public_base_url: str = "http://127.0.0.1") -> "StevensSentinel":
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = data_dir / "sentinel_config.json"
        migrated = False

        if cfg_path.exists():
            raw = _read_private_json_bounded(cfg_path)
            migrated = int(raw.get("version", 1)) != 2
            cfg = SentinelConfig.from_dict(raw)
        else:
            unique = secrets.token_urlsafe(18)
            cfg = SentinelConfig(
                operator_token=secrets.token_urlsafe(32),
                telemetry_salt=secrets.token_hex(32),
                canary_paths=(f"/.well-known/stevens-canary/{unique}",),
                canary_tokens=(f"STV-CANARY-{secrets.token_urlsafe(24)}",),
                honey_outpoints=(),
            )

        cfg.validate()
        _atomic_write_private_json(cfg_path, cfg.to_dict())

        decoys = data_dir / "decoys"
        if not decoys.exists():
            cls._write_decoys(decoys, cfg, public_base_url)

        inst = cls(data_dir, cfg)
        if migrated:
            inst.record("INFO", "config_migrated_v1_to_v2", details={"from_version": 1, "to_version": 2},
                        affect_score=False)
        return inst

    @staticmethod
    def _write_decoys(decoy_dir: Path, cfg: SentinelConfig, public_base_url: str) -> None:
        decoy_dir.mkdir(parents=True, exist_ok=True)
        base = public_base_url.rstrip("/")
        monitor_url = base + cfg.canary_paths[0]
        common = {
            "environment": "TESTNET_HONEY_DECOY",
            "purpose": "DEFENSIVE_CANARY_ONLY_NO_REAL_FUNDS",
            "canary_token": cfg.canary_tokens[0],
            "monitor_url": monitor_url,
        }
        fake_wallet = {
            "format": "StevensWalletBackup",
            "version": 0,
            **common,
            "wallet_id": "legacy-" + secrets.token_hex(6),
            "private_key": secrets.token_hex(32),
        }
        fake_validator = {
            "format": "StevensValidatorBackup",
            "version": 0,
            **common,
            "validator_secret": secrets.token_hex(32),
        }
        fake_api = {
            "format": "StevensLegacyAPIConfig",
            "version": 0,
            **common,
            "api_key": "stv_test_" + secrets.token_urlsafe(24),
        }
        (decoy_dir / "wallet_backup_old.json").write_text(json.dumps(fake_wallet, indent=2))
        (decoy_dir / "validator_keys_backup.json").write_text(json.dumps(fake_validator, indent=2))
        (decoy_dir / "legacy_api_credentials.json").write_text(json.dumps(fake_api, indent=2))
        (decoy_dir / "README.txt").write_text(
            "Stevens Sentinel v0.2 generated decoys.\n\n"
            "NO real funds. NO production credentials.\n"
            "Use only in a segregated testnet/deception environment.\n"
            "Never commit sentinel_config.json or the decoy directory to a public repository.\n"
        )
        for p in decoy_dir.iterdir():
            if p.is_file():
                _chmod600(p)

    def _connect(self):
        con = sqlite3.connect(self.db_path, timeout=5)
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def _init_db(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_ip TEXT,
                    source_node_id TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS subjects(
                    source_ip TEXT PRIMARY KEY,
                    score REAL NOT NULL,
                    state TEXT NOT NULL,
                    last_score_ts INTEGER NOT NULL,
                    updated_ts INTEGER NOT NULL,
                    quarantine_until INTEGER NOT NULL DEFAULT 0,
                    isolate_until INTEGER NOT NULL DEFAULT 0,
                    last_reason TEXT NOT NULL DEFAULT ''
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS challenges(
                    source_ip TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    difficulty_bits INTEGER NOT NULL,
                    issued_ts INTEGER NOT NULL,
                    expires_ts INTEGER NOT NULL
                )
            """)

    def operator_authorized(self, authorization_header: str | None,
                            sentinel_header: str | None = None) -> bool:
        candidates = []
        if authorization_header and authorization_header.startswith("Bearer "):
            candidates.append(authorization_header[len("Bearer "):].strip())
        if sentinel_header:
            candidates.append(sentinel_header.strip())
        return any(hmac.compare_digest(x, self.config.operator_token) for x in candidates)

    def is_canary_path(self, path: str) -> bool:
        path = path.split("?", 1)[0]
        return any(hmac.compare_digest(path, p) for p in self.config.canary_paths)

    def contains_canary_token(self, value: str | None) -> bool:
        if not value:
            return False
        return any(tok in value for tok in self.config.canary_tokens)

    def _write_private_json(self, path: Path, obj: Any) -> None:
        _atomic_write_private_json(Path(path), obj)

    def _read_private_json(self, path: Path):
        return _read_private_json_bounded(Path(path))

    def _persist_config(self, config: SentinelConfig | None = None):
        cfg = config or self.config
        cfg.validate()
        self._write_private_json(self.config_path, cfg.to_dict())

    def _state_from_score(self, score: float) -> str:
        c = self.config
        if score >= c.isolate_score:
            return "ISOLATE"
        if score >= c.quarantine_score:
            return "QUARANTINE"
        if score >= c.challenge_score:
            return "CHALLENGE"
        if score >= c.watch_score:
            return "WATCH"
        return "NORMAL"

    def _decayed_score(self, score: float, last_ts: int, now: int) -> float:
        elapsed_minutes = max(0.0, (now - int(last_ts)) / 60.0)
        return max(0.0, float(score) - elapsed_minutes * self.config.score_decay_per_minute)

    def _load_subject(self, source_ip: str, now: int | None = None) -> dict:
        now = int(now or time.time())
        with self._connect() as con:
            row = con.execute("""
                SELECT score,state,last_score_ts,updated_ts,quarantine_until,isolate_until,last_reason
                FROM subjects WHERE source_ip=?
            """, (source_ip,)).fetchone()

        if not row:
            return {
                "source_ip": source_ip, "score": 0.0, "state": "NORMAL",
                "last_score_ts": now, "updated_ts": now,
                "quarantine_until": 0, "isolate_until": 0, "last_reason": "",
            }

        score = self._decayed_score(row[0], row[2], now)
        quarantine_until = int(row[4])
        isolate_until = int(row[5])

        if isolate_until > now:
            state = "ISOLATE"
        elif quarantine_until > now:
            state = "QUARANTINE"
        else:
            state = self._state_from_score(score)

        d = {
            "source_ip": source_ip, "score": score, "state": state,
            "last_score_ts": now, "updated_ts": now,
            "quarantine_until": quarantine_until if quarantine_until > now else 0,
            "isolate_until": isolate_until if isolate_until > now else 0,
            "last_reason": row[6],
        }
        self._save_subject(d)
        return d

    def _save_subject(self, d: dict) -> None:
        with self._connect() as con:
            con.execute("""
                INSERT INTO subjects(source_ip,score,state,last_score_ts,updated_ts,
                                     quarantine_until,isolate_until,last_reason)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    score=excluded.score,
                    state=excluded.state,
                    last_score_ts=excluded.last_score_ts,
                    updated_ts=excluded.updated_ts,
                    quarantine_until=excluded.quarantine_until,
                    isolate_until=excluded.isolate_until,
                    last_reason=excluded.last_reason
            """, (
                d["source_ip"], float(d["score"]), d["state"], int(d["last_score_ts"]),
                int(d["updated_ts"]), int(d.get("quarantine_until", 0)),
                int(d.get("isolate_until", 0)), str(d.get("last_reason", "")),
            ))

    def subject(self, source_ip: str) -> dict:
        return self._load_subject(source_ip)

    def _apply_score(self, source_ip: str, points: float, reason: str) -> dict:
        now = int(time.time())
        d = self._load_subject(source_ip, now)
        previous_state = d["state"]
        d["score"] = max(0.0, float(d["score"]) + float(points))
        scored_state = self._state_from_score(d["score"])

        # Never lower an active timed containment because of score recalculation.
        if d["isolate_until"] > now:
            new_state = "ISOLATE"
        elif d["quarantine_until"] > now:
            new_state = "QUARANTINE"
        else:
            new_state = scored_state

        if new_state == "QUARANTINE":
            d["quarantine_until"] = max(d["quarantine_until"], now + self.config.quarantine_seconds)
        elif new_state == "ISOLATE":
            d["isolate_until"] = max(d["isolate_until"], now + self.config.isolate_seconds)

        d.update({
            "state": new_state, "last_score_ts": now, "updated_ts": now,
            "last_reason": reason,
        })
        self._save_subject(d)

        if new_state != previous_state:
            self.record(
                "INFO", "adaptive_state_transition", source_ip=source_ip,
                details={"from": previous_state, "to": new_state, "score": round(d["score"], 3),
                         "reason": reason},
                affect_score=False
            )
        return d

    def force_state(self, source_ip: str, state: str, reason: str) -> dict:
        if state not in STATES:
            raise ValueError("invalid Sentinel state")
        now = int(time.time())
        d = self._load_subject(source_ip, now)
        previous_state = d["state"]

        floor = {
            "NORMAL": 0.0,
            "WATCH": self.config.watch_score,
            "CHALLENGE": self.config.challenge_score,
            "QUARANTINE": self.config.quarantine_score,
            "ISOLATE": self.config.isolate_score,
        }[state]
        d["score"] = max(float(d["score"]), floor)

        if state == "QUARANTINE":
            d["quarantine_until"] = max(d["quarantine_until"], now + self.config.quarantine_seconds)
        elif state == "ISOLATE":
            d["isolate_until"] = max(d["isolate_until"], now + self.config.isolate_seconds)

        d.update({
            "state": state, "last_score_ts": now, "updated_ts": now,
            "last_reason": reason,
        })
        self._save_subject(d)
        if previous_state != state:
            self.record(
                "INFO", "adaptive_state_transition", source_ip=source_ip,
                details={"from": previous_state, "to": state, "score": round(d["score"], 3),
                         "reason": reason, "forced": True},
                affect_score=False
            )
        return d

    def clear_subject(self, source_ip: str) -> None:
        with self._connect() as con:
            con.execute("DELETE FROM subjects WHERE source_ip=?", (source_ip,))
            con.execute("DELETE FROM challenges WHERE source_ip=?", (source_ip,))
        self.record("INFO", "operator_subject_clear", details={"source_ip": source_ip},
                    affect_score=False)

    def record(self, severity: str, category: str, source_ip: str | None = None,
               source_node_id: str | None = None, details: dict | None = None,
               affect_score: bool = True) -> str:
        severity = severity.upper()
        if severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity {severity}")
        now = int(time.time())
        details = details or {}

        with self._connect() as con:
            row = con.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
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
            event_hash = hashlib.sha256(prev.encode() + canonical(body)).hexdigest()
            con.execute("""
                INSERT INTO events(timestamp,severity,category,source_ip,source_node_id,
                                   details_json,previous_hash,event_hash)
                VALUES(?,?,?,?,?,?,?,?)
            """, (
                now, severity, category, source_ip, source_node_id,
                json.dumps(details, sort_keys=True), prev, event_hash
            ))

        if source_ip and affect_score:
            weight = SEVERITY_WEIGHT[severity]
            if weight > 0:
                self._apply_score(source_ip, weight, category)
        return event_hash

    def trigger_canary(self, source_ip: str, kind: str, detail: dict | None = None) -> dict:
        detail = detail or {}
        self.record("CRITICAL", f"canary_{kind}", source_ip=source_ip, details=detail,
                    affect_score=False)
        if self.config.immediate_isolate_on_canary:
            return self.force_state(source_ip, "ISOLATE", f"canary_{kind}")
        return self._apply_score(source_ip, SEVERITY_WEIGHT["CRITICAL"], f"canary_{kind}")

    def inspect_transaction(self, tx: dict, source_ip: str | None = None,
                            source_node_id: str | None = None) -> list[str]:
        configured = set(self.config.honey_outpoints)
        hits = []
        for inp in tx.get("inputs", []):
            txid = str(inp.get("txid", ""))
            index = inp.get("index")
            key = f"{txid}:{index}"
            if key in configured:
                hits.append(key)
        if hits:
            self.record("CRITICAL", "honey_outpoint_spend_attempt", source_ip, source_node_id,
                        {"txid": tx.get("txid"), "honey_outpoints": hits}, affect_score=False)
            if source_ip:
                if self.config.immediate_isolate_on_honey_spend:
                    self.force_state(source_ip, "ISOLATE", "honey_outpoint_spend_attempt")
                else:
                    self._apply_score(source_ip, SEVERITY_WEIGHT["CRITICAL"],
                                      "honey_outpoint_spend_attempt")
        return hits

    def register_honey_outpoint(self, txid: str, index: int) -> str:
        key = f"{txid}:{int(index)}"
        current = list(self.config.honey_outpoints)
        if key not in current:
            current.append(key)
        new_config = SentinelConfig(
            **{**self.config.__dict__, "honey_outpoints": tuple(current)}
        )
        # Persist first; a failed/crashed write must not leave memory claiming
        # a configuration that never became durable.
        self._persist_config(new_config)
        self.config = new_config
        self.record("INFO", "honey_outpoint_registered",
                    details={"outpoint": key}, affect_score=False)
        return key

    def get_or_issue_challenge(self, source_ip: str) -> dict:
        now = int(time.time())
        with self._connect() as con:
            row = con.execute("""
                SELECT nonce,difficulty_bits,issued_ts,expires_ts
                FROM challenges WHERE source_ip=?
            """, (source_ip,)).fetchone()
            if row and int(row[3]) > now:
                return {
                    "nonce": row[0], "difficulty_bits": int(row[1]),
                    "issued_at": int(row[2]), "expires_at": int(row[3]),
                    "algorithm": "sha256-leading-zero-bits-v1",
                }

            score = self._load_subject(source_ip, now)["score"]
            # Small adaptive increase, strictly capped by config validation ceiling.
            extra = min(4, int(max(0.0, score - self.config.challenge_score) // 8))
            bits = min(28, int(self.config.challenge_difficulty_bits) + extra)
            nonce = secrets.token_hex(16)
            expires = now + self.config.challenge_ttl_seconds
            con.execute("""
                INSERT INTO challenges(source_ip,nonce,difficulty_bits,issued_ts,expires_ts)
                VALUES(?,?,?,?,?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    nonce=excluded.nonce,
                    difficulty_bits=excluded.difficulty_bits,
                    issued_ts=excluded.issued_ts,
                    expires_ts=excluded.expires_ts
            """, (source_ip, nonce, bits, now, expires))
        self.record("INFO", "challenge_issued", source_ip=source_ip,
                    details={"difficulty_bits": bits, "expires_at": expires}, affect_score=False)
        return {
            "nonce": nonce, "difficulty_bits": bits, "issued_at": now,
            "expires_at": expires, "algorithm": "sha256-leading-zero-bits-v1",
        }

    @staticmethod
    def challenge_digest(nonce: str, source_ip: str, solution: str) -> bytes:
        return hashlib.sha256(f"{nonce}:{source_ip}:{solution}".encode()).digest()

    def verify_challenge(self, source_ip: str, nonce: str | None,
                         solution: str | None) -> bool:
        if not nonce or not solution:
            return False
        now = int(time.time())
        with self._connect() as con:
            row = con.execute("""
                SELECT nonce,difficulty_bits,expires_ts
                FROM challenges WHERE source_ip=?
            """, (source_ip,)).fetchone()

        if not row or int(row[2]) <= now or not hmac.compare_digest(str(row[0]), str(nonce)):
            return False

        digest = self.challenge_digest(str(nonce), source_ip, str(solution))
        if leading_zero_bits(digest) < int(row[1]):
            self.record("LOW", "challenge_failed", source_ip=source_ip,
                        details={"difficulty_bits": int(row[1])})
            return False

        with self._connect() as con:
            con.execute("DELETE FROM challenges WHERE source_ip=?", (source_ip,))

        # A successful challenge demonstrates resource expenditure and lowers risk,
        # but does not erase all history.
        d = self._load_subject(source_ip, now)
        d["score"] = max(0.0, float(d["score"]) - self.config.challenge_credit)
        d["quarantine_until"] = 0
        # Do not allow a challenge to break an explicit ISOLATE timer.
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
        self.record("INFO", "challenge_passed", source_ip=source_ip,
                    details={"new_state": d["state"], "new_score": round(d["score"], 3)},
                    affect_score=False)
        return True

    def preflight(self, source_ip: str, challenge_nonce: str | None = None,
                  challenge_solution: str | None = None) -> dict:
        d = self._load_subject(source_ip)
        state = d["state"]

        if state == "ISOLATE":
            return {"action": "ISOLATE", "subject": d}
        if state == "QUARANTINE":
            return {"action": "QUARANTINE", "subject": d}
        if state == "CHALLENGE":
            if self.verify_challenge(source_ip, challenge_nonce, challenge_solution):
                return {"action": "ALLOW", "subject": self._load_subject(source_ip),
                        "challenge_passed": True}
            return {
                "action": "CHALLENGE",
                "subject": d,
                "challenge": self.get_or_issue_challenge(source_ip)
            }
        return {"action": "ALLOW", "subject": d}

    def recent_events(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as con:
            rows = con.execute("""
                SELECT id,timestamp,severity,category,source_ip,source_node_id,
                       details_json,previous_hash,event_hash
                FROM events ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [{
            "id": r[0], "timestamp": r[1], "severity": r[2], "category": r[3],
            "source_ip": r[4], "source_node_id": r[5],
            "details": json.loads(r[6]), "previous_hash": r[7], "event_hash": r[8],
        } for r in rows]

    def subjects(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as con:
            ips = [r[0] for r in con.execute(
                "SELECT source_ip FROM subjects ORDER BY updated_ts DESC LIMIT ?", (limit,)
            ).fetchall()]
        return [self._load_subject(ip) for ip in ips]

    def _pseudonym(self, source_ip: str | None) -> str | None:
        if not source_ip:
            return None
        return hashlib.sha256(
            (self.config.telemetry_salt + "|" + source_ip).encode()
        ).hexdigest()[:16]

    def review_bundle(self, event_limit: int = 500, subject_limit: int = 100) -> dict:
        """
        Privacy-reduced telemetry for offline AI/human analysis.
        Deliberately excludes raw IPs, operator token, canary path/token, honey outpoints,
        challenge nonces/solutions, and transaction bodies.
        """
        now = int(time.time())
        events = self.recent_events(event_limit)
        subjects = self.subjects(subject_limit)

        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        reduced_events = []
        for e in events:
            category_counts[e["category"]] = category_counts.get(e["category"], 0) + 1
            severity_counts[e["severity"]] = severity_counts.get(e["severity"], 0) + 1
            safe_details = {}
            for k, v in (e.get("details") or {}).items():
                if k in {"path", "user_agent", "error", "code", "difficulty_bits",
                         "expires_at", "from", "to", "reason", "score", "new_state",
                         "new_score"}:
                    safe_details[k] = v
            reduced_events.append({
                "timestamp": e["timestamp"],
                "severity": e["severity"],
                "category": e["category"],
                "subject": self._pseudonym(e["source_ip"]),
                "details": safe_details,
            })

        return {
            "format": "StevensSentinelReviewBundle",
            "version": 1,
            "sentinel_version": VERSION,
            "generated_at": now,
            "policy": {
                "purpose": "offline defensive analysis and recommendations",
                "automatic_rule_application": False,
                "consensus_decisions_by_ai": False,
                "human_approval_required_for_policy_changes": True,
            },
            "thresholds": {
                "watch_score": self.config.watch_score,
                "challenge_score": self.config.challenge_score,
                "quarantine_score": self.config.quarantine_score,
                "isolate_score": self.config.isolate_score,
            },
            "category_counts": category_counts,
            "severity_counts": severity_counts,
            "subjects": [{
                "subject": self._pseudonym(s["source_ip"]),
                "score": round(s["score"], 3),
                "state": s["state"],
                "last_reason": s["last_reason"],
            } for s in subjects],
            "recent_events": reduced_events,
        }

    def summary(self) -> dict:
        now = int(time.time())
        cutoff = now - 24 * 60 * 60
        with self._connect() as con:
            counts = dict(con.execute("""
                SELECT severity,COUNT(*) FROM events WHERE timestamp>=? GROUP BY severity
            """, (cutoff,)).fetchall())
            cats = con.execute("""
                SELECT category,COUNT(*) FROM events WHERE timestamp>=?
                GROUP BY category ORDER BY COUNT(*) DESC LIMIT 10
            """, (cutoff,)).fetchall()
            total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        state_counts = {s: 0 for s in STATES}
        for subject in self.subjects(1000):
            state_counts[subject["state"]] += 1

        return {
            "sentinel_version": VERSION,
            "mode": "adaptive-defense-loop",
            "state_order": list(STATES),
            "subject_states": state_counts,
            "events_total": total,
            "events_24h": counts,
            "top_categories_24h": [{"category": c, "count": n} for c, n in cats],
            "honey_outpoints_registered": len(self.config.honey_outpoints),
            "canary_paths_registered": len(self.config.canary_paths),
            "log_chain_valid": self.verify_log_chain(),
            "ai_in_consensus": False,
            "automatic_ai_policy_changes": False,
        }

    def verify_log_chain(self) -> bool:
        prev = "0" * 64
        with self._connect() as con:
            rows = con.execute("""
                SELECT timestamp,severity,category,source_ip,source_node_id,
                       details_json,previous_hash,event_hash
                FROM events ORDER BY id ASC
            """).fetchall()
        for r in rows:
            body = {
                "timestamp": r[0], "severity": r[1], "category": r[2],
                "source_ip": r[3], "source_node_id": r[4],
                "details": json.loads(r[5]), "previous_hash": r[6],
            }
            if r[6] != prev:
                return False
            expected = hashlib.sha256(prev.encode() + canonical(body)).hexdigest()
            if not hmac.compare_digest(expected, r[7]):
                return False
            prev = r[7]
        return True


def solve_challenge(nonce: str, source_ip: str, difficulty_bits: int,
                    max_tries: int = 20_000_000) -> str:
    """Reference/test solver. Not used by the server itself."""
    for i in range(max_tries):
        solution = str(i)
        if leading_zero_bits(
            StevensSentinel.challenge_digest(nonce, source_ip, solution)
        ) >= difficulty_bits:
            return solution
    raise RuntimeError("challenge solution not found within max_tries")


def _cli():
    ap = argparse.ArgumentParser(description="Stevens Sentinel v0.2 Adaptive Defense")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--data-dir", required=True)
    p_init.add_argument("--public-base-url", default="http://127.0.0.1")

    p_status = sub.add_parser("status")
    p_status.add_argument("--data-dir", required=True)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--data-dir", required=True)

    p_honey = sub.add_parser("register-honey")
    p_honey.add_argument("--data-dir", required=True)
    p_honey.add_argument("--txid", required=True)
    p_honey.add_argument("--index", required=True, type=int)

    p_clear = sub.add_parser("clear-subject")
    p_clear.add_argument("--data-dir", required=True)
    p_clear.add_argument("--source-ip", required=True)

    p_export = sub.add_parser("export-review")
    p_export.add_argument("--data-dir", required=True)
    p_export.add_argument("--output", required=True)

    args = ap.parse_args()
    s = StevensSentinel.load_or_create(args.data_dir,
                                       getattr(args, "public_base_url", "http://127.0.0.1"))
    if args.cmd == "init":
        print(json.dumps({
            "initialized": True,
            "sentinel_version": VERSION,
            "data_dir": str(Path(args.data_dir).resolve()),
            "canary_path": s.config.canary_paths[0],
            "operator_token_file": str(Path(args.data_dir) / "sentinel_config.json"),
            "warning": "Keep config and decoys private; decoys contain no real funds."
        }, indent=2))
    elif args.cmd == "status":
        print(json.dumps(s.summary(), indent=2))
    elif args.cmd == "verify":
        print("PASS" if s.verify_log_chain() else "FAIL")
    elif args.cmd == "register-honey":
        print(s.register_honey_outpoint(args.txid, args.index))
    elif args.cmd == "clear-subject":
        s.clear_subject(args.source_ip)
        print("cleared", args.source_ip)
    elif args.cmd == "export-review":
        Path(args.output).write_text(json.dumps(s.review_bundle(), indent=2))
        print(args.output)


if __name__ == "__main__":
    _cli()
