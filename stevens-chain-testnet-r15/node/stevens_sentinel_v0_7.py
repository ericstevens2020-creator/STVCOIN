"""
Stevens Sentinel v0.7 — Receipt Keyring + Explicit Binding Policy

Hardens v0.6 proof receipts by separating receipt-signing material from
operator credentials/telemetry salt, adding key IDs with bounded current/previous
verification overlap, and making receipt binding behavior explicit.

Default binding remains conservative exact-IP.

Optional experimental binding modes:
- cohort: IPv4/IPv6 network-prefix binding for controlled NAT/privacy testing;
- client-token: explicit opaque client binding for controlled mobility testing.

Receipts never bypass local CHALLENGE/QUARANTINE/ISOLATE.
No blockchain consensus rule changes. No hack-back.
TESTNET / DEFENSIVE SECURITY ONLY.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from stevens_sentinel_v0_2 import canonical
from stevens_sentinel_v0_4 import _b64e, _b64d
from stevens_sentinel_v0_6 import (
    StevensSentinel as ReliableSentinel,
    ReliabilityPolicy,
)
from stevens_sentinel_v0_5 import FairnessPolicy
from stevens_sentinel_v0_4 import ResourcePolicy
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "0.7"


@dataclass(frozen=True)
class ReceiptPolicy:
    binding_mode: str = "exact-ip"
    ipv4_cohort_prefix_bits: int = 24
    ipv6_cohort_prefix_bits: int = 64
    client_binding_min_chars: int = 16
    rotation_grace_seconds: int = 10 * 60
    max_previous_keys: int = 1

    def to_dict(self) -> dict:
        return {
            "format": "StevensSentinelReceiptPolicy",
            "version": 1,
            **self.__dict__,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReceiptPolicy":
        if d.get("format") != "StevensSentinelReceiptPolicy":
            raise ValueError("not a Stevens Sentinel receipt policy")
        if int(d.get("version", 1)) != 1:
            raise ValueError("unsupported receipt policy version")
        defaults = cls()
        return cls(**{
            k: d.get(k, getattr(defaults, k))
            for k in defaults.__dict__
        })

    def validate(self) -> None:
        if self.binding_mode not in ("exact-ip", "cohort", "client-token"):
            raise ValueError("unsupported receipt binding mode")
        if not (8 <= int(self.ipv4_cohort_prefix_bits) <= 32):
            raise ValueError("ipv4_cohort_prefix_bits out of range")
        if not (32 <= int(self.ipv6_cohort_prefix_bits) <= 128):
            raise ValueError("ipv6_cohort_prefix_bits out of range")
        if not (8 <= int(self.client_binding_min_chars) <= 256):
            raise ValueError("client_binding_min_chars out of range")
        if not (0 <= int(self.rotation_grace_seconds) <= 24 * 3600):
            raise ValueError("rotation_grace_seconds out of range")
        if not (0 <= int(self.max_previous_keys) <= 4):
            raise ValueError("max_previous_keys out of range")


class StevensSentinel(ReliableSentinel):
    def __init__(self, data_dir, config,
                 swarm_policy: SwarmPolicy | None = None,
                 resource_policy: ResourcePolicy | None = None,
                 fairness_policy: FairnessPolicy | None = None,
                 reliability_policy: ReliabilityPolicy | None = None,
                 receipt_policy: ReceiptPolicy | None = None):
        super().__init__(
            data_dir, config,
            swarm_policy=swarm_policy,
            resource_policy=resource_policy,
            fairness_policy=fairness_policy,
            reliability_policy=reliability_policy,
        )

        self.receipt_policy_path = self.data_dir / "sentinel_receipt_policy.json"
        self.receipt_keyring_path = self.data_dir / "sentinel_receipt_keyring.json"

        self.receipt_policy = receipt_policy or self._load_or_create_receipt_policy()
        self.receipt_policy.validate()
        self._receipt_keyring = self._load_or_create_receipt_keyring()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1"):
        """Serialize v0.7 receipt-policy/keyring creation across processes."""
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "sentinel_v07_startup.lock"
        lock_file = lock_path.open("a+b")
        locked = False
        try:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                locked = True
            except (ImportError, OSError):
                pass

            base = ReliableSentinel.load_or_create(data_dir, public_base_url)
            return cls(
                base.data_dir,
                base.config,
                swarm_policy=base.swarm_policy,
                resource_policy=base.resource_policy,
                fairness_policy=base.fairness_policy,
                reliability_policy=base.reliability_policy,
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
    # Receipt policy
    # ------------------------------------------------------------------
    def _load_or_create_receipt_policy(self) -> ReceiptPolicy:
        if self.receipt_policy_path.exists():
            p = ReceiptPolicy.from_dict(
                json.loads(self.receipt_policy_path.read_text())
            )
        else:
            p = ReceiptPolicy()
            self._write_private_json(self.receipt_policy_path, p.to_dict())
        return p

    def _persist_receipt_policy(self) -> None:
        self.receipt_policy.validate()
        self._write_private_json(self.receipt_policy_path, self.receipt_policy.to_dict())

    # ------------------------------------------------------------------
    # Independent receipt-signing keyring
    # ------------------------------------------------------------------
    @staticmethod
    def _new_receipt_key(now: int) -> dict:
        return {
            "kid": secrets.token_hex(8),
            "key": _b64e(secrets.token_bytes(32)),
            "created_at": int(now),
        }

    def _load_or_create_receipt_keyring(self) -> dict:
        now = int(time.time())
        if self.receipt_keyring_path.exists():
            kr = json.loads(self.receipt_keyring_path.read_text())
            if kr.get("format") != "StevensSentinelReceiptKeyring":
                raise ValueError("bad receipt keyring format")
            if int(kr.get("version", 0)) != 1:
                raise ValueError("unsupported receipt keyring version")
            if not kr.get("current"):
                raise ValueError("receipt keyring has no current key")
        else:
            kr = {
                "format": "StevensSentinelReceiptKeyring",
                "version": 1,
                "current": self._new_receipt_key(now),
                "previous": [],
            }
            self._persist_receipt_keyring_obj(kr)
        return kr

    def _persist_receipt_keyring_obj(self, kr: dict) -> None:
        tmp = self.receipt_keyring_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(kr, indent=2))
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(self.receipt_keyring_path)
        try:
            os.chmod(self.receipt_keyring_path, 0o600)
        except Exception:
            pass

    def _persist_receipt_keyring(self) -> None:
        self._persist_receipt_keyring_obj(self._receipt_keyring)

    def _prune_receipt_keyring(self, now: int | None = None) -> None:
        now = int(now or time.time())
        prev = []
        for entry in self._receipt_keyring.get("previous", []):
            if int(entry.get("accept_until", 0)) >= now:
                prev.append(entry)
        max_prev = int(self.receipt_policy.max_previous_keys)
        prev.sort(key=lambda x: int(x.get("accept_until", 0)), reverse=True)
        self._receipt_keyring["previous"] = prev[:max_prev]

    def rotate_receipt_key(self, now: int | None = None) -> dict:
        """
        Rotate only proof-receipt signing material.

        The previous key remains verification-only until accept_until. Operator
        token, telemetry salt, challenge key behavior, and consensus are untouched.
        """
        now = int(now or time.time())
        self._prune_receipt_keyring(now)

        current = dict(self._receipt_keyring["current"])
        current["accept_until"] = (
            now + int(self.receipt_policy.rotation_grace_seconds)
        )

        previous = [current] + list(self._receipt_keyring.get("previous", []))
        previous.sort(
            key=lambda x: int(x.get("accept_until", 0)),
            reverse=True
        )

        self._receipt_keyring = {
            "format": "StevensSentinelReceiptKeyring",
            "version": 1,
            "current": self._new_receipt_key(now),
            "previous": previous[:int(self.receipt_policy.max_previous_keys)],
        }
        self._persist_receipt_keyring()
        return self.receipt_status(now=now)

    def _key_for_kid(self, kid: str, now: int) -> bytes | None:
        current = self._receipt_keyring.get("current", {})
        if hmac.compare_digest(str(current.get("kid", "")), str(kid)):
            try:
                return _b64d(current["key"])
            except Exception:
                return None

        for entry in self._receipt_keyring.get("previous", []):
            if not hmac.compare_digest(str(entry.get("kid", "")), str(kid)):
                continue
            if int(entry.get("accept_until", 0)) < now:
                return None
            try:
                return _b64d(entry["key"])
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------
    # Binding policy
    # ------------------------------------------------------------------
    def _canonical_ip(self, source_ip: str) -> str:
        return str(ipaddress.ip_address(source_ip))

    def _cohort_value(self, source_ip: str) -> str:
        ip = ipaddress.ip_address(source_ip)
        if ip.version == 4:
            bits = int(self.receipt_policy.ipv4_cohort_prefix_bits)
        else:
            bits = int(self.receipt_policy.ipv6_cohort_prefix_bits)
        return str(ipaddress.ip_network(f"{source_ip}/{bits}", strict=False))

    def _binding_material(self, source_ip: str,
                          client_binding: str | None,
                          mode: str | None = None) -> bytes | None:
        mode = mode or self.receipt_policy.binding_mode

        if mode == "exact-ip":
            value = self._canonical_ip(source_ip)
        elif mode == "cohort":
            value = self._cohort_value(source_ip)
        elif mode == "client-token":
            if client_binding is None:
                return None
            value = str(client_binding).strip()
            if len(value) < int(self.receipt_policy.client_binding_min_chars):
                return None
        else:
            return None

        return f"{mode}|{value}".encode()

    def _binding_tag(self, key: bytes, source_ip: str,
                     client_binding: str | None,
                     mode: str) -> str | None:
        material = self._binding_material(source_ip, client_binding, mode)
        if material is None:
            return None
        return _b64e(hmac.new(
            key,
            b"Stevens-Sentinel-v0.7/binding|" + material,
            hashlib.sha256,
        ).digest())

    # ------------------------------------------------------------------
    # Stateless proof receipts v2
    # ------------------------------------------------------------------
    def issue_proof_receipt(self, source_ip: str,
                            client_binding: str | None = None,
                            now: int | None = None) -> str:
        now = int(now or time.time())
        ttl = int(self.reliability_policy.proof_receipt_ttl_seconds)
        mode = self.receipt_policy.binding_mode
        current = self._receipt_keyring["current"]
        kid = str(current["kid"])
        key = _b64d(current["key"])
        bind = self._binding_tag(key, source_ip, client_binding, mode)
        if bind is None:
            raise ValueError("receipt binding material missing or invalid")

        payload = {
            "v": 2,
            "kid": kid,
            "iat": now,
            "exp": now + ttl,
            "scope": "global-swarm-proof",
            "bm": mode,
            "bind": bind,
        }
        body = canonical(payload)
        sig = hmac.new(
            key,
            b"Stevens-Sentinel-v0.7/receipt|" + body,
            hashlib.sha256,
        ).digest()
        return _b64e(body) + "." + _b64e(sig)

    def verify_proof_receipt(self, receipt: str | None,
                             source_ip: str,
                             client_binding: str | None = None,
                             now: int | None = None) -> bool:
        if not receipt:
            return False
        now = int(now or time.time())
        try:
            body64, sig64 = str(receipt).split(".", 1)
            body = _b64d(body64)
            sig = _b64d(sig64)
            if _b64e(body) != body64 or _b64e(sig) != sig64:
                return False

            payload = json.loads(body)
            if int(payload.get("v", 0)) != 2:
                return False
            if payload.get("scope") != "global-swarm-proof":
                return False

            mode = str(payload.get("bm", ""))
            # A policy change is a security decision. Old receipts using a
            # different binding mode do not silently survive it.
            if mode != self.receipt_policy.binding_mode:
                return False

            kid = str(payload.get("kid", ""))
            key = self._key_for_kid(kid, now)
            if key is None:
                return False

            expected = hmac.new(
                key,
                b"Stevens-Sentinel-v0.7/receipt|" + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(sig, expected):
                return False

            skew = int(self.reliability_policy.proof_receipt_clock_skew_seconds)
            if int(payload.get("iat", 0)) > now + skew:
                return False
            if int(payload.get("exp", 0)) < now - skew:
                return False

            expected_bind = self._binding_tag(
                key, source_ip, client_binding, mode
            )
            if expected_bind is None:
                return False
            if not hmac.compare_digest(
                str(payload.get("bind", "")),
                expected_bind,
            ):
                return False
            return True
        except Exception:
            return False

    def preflight(self, source_ip: str,
                  challenge_nonce: str | None = None,
                  challenge_solution: str | None = None,
                  proof_receipt: str | None = None,
                  client_binding: str | None = None) -> dict:
        d = self._load_subject(source_ip)
        state = d["state"]

        if state == "ISOLATE":
            return {"action": "ISOLATE", "subject": d}
        if state == "QUARANTINE":
            return {"action": "QUARANTINE", "subject": d}
        if state == "CHALLENGE":
            if self.verify_challenge(
                source_ip, challenge_nonce, challenge_solution
            ):
                receipt = self.issue_proof_receipt(
                    source_ip, client_binding=client_binding
                )
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

        if self.verify_proof_receipt(
            proof_receipt,
            source_ip,
            client_binding=client_binding,
        ):
            return {
                "action": "ALLOW",
                "subject": d,
                "global_threat": global_info,
                "proof_receipt_valid": True,
            }

        # Cache remains only a compatibility/performance optimization.
        if self._recent_global_pass(source_ip):
            return {
                "action": "ALLOW",
                "subject": d,
                "global_threat": global_info,
                "global_pass": True,
            }

        if challenge_nonce and challenge_solution:
            if self.verify_challenge(
                source_ip, challenge_nonce, challenge_solution
            ):
                try:
                    receipt = self.issue_proof_receipt(
                        source_ip, client_binding=client_binding
                    )
                except ValueError:
                    # For client-token mode, a proof without the required binding
                    # should not mint a weaker receipt. The current request is still
                    # allowed after valid PoW, but no receipt is issued.
                    receipt = None
                result = {
                    "action": "ALLOW",
                    "subject": self.subject(source_ip),
                    "global_threat": global_info,
                    "global_pass": True,
                    "challenge_passed": True,
                }
                if receipt:
                    result["proof_receipt"] = receipt
                return result

        return {
            "action": "CHALLENGE",
            "subject": d,
            "challenge": self._global_challenge(source_ip, global_info),
            "global_threat": global_info,
            "challenge_reason": "distributed_swarm_anomaly",
        }

    def receipt_status(self, now: int | None = None) -> dict:
        now = int(now or time.time())
        self._prune_receipt_keyring(now)
        current = self._receipt_keyring["current"]
        previous = []
        for entry in self._receipt_keyring.get("previous", []):
            previous.append({
                "kid": entry.get("kid"),
                "created_at": int(entry.get("created_at", 0)),
                "accept_until": int(entry.get("accept_until", 0)),
            })
        return {
            "sentinel_version": VERSION,
            "receipt_format": "stateless-hmac-v2",
            "binding_mode": self.receipt_policy.binding_mode,
            "exact_ip_default": True,
            "current_kid": current.get("kid"),
            "current_created_at": int(current.get("created_at", 0)),
            "previous_keys": previous,
            "rotation_grace_seconds": int(
                self.receipt_policy.rotation_grace_seconds
            ),
            "independent_from_operator_token": True,
            "independent_from_telemetry_salt": True,
            "local_containment_bypass": False,
        }

    def reliability_status(self) -> dict:
        status = super().reliability_status()
        status["sentinel_version"] = VERSION
        status["proof_receipt_mode"] = "stateless-hmac-v2-keyring"
        status["receipt_binding_mode"] = self.receipt_policy.binding_mode
        status["receipt_current_kid"] = self._receipt_keyring["current"]["kid"]
        status["receipt_keyring_independent"] = True
        return status

    def resource_status(self) -> dict:
        status = super().resource_status()
        status["sentinel_version"] = VERSION
        status["receipt"] = self.receipt_status()
        return status

    def review_bundle(self, event_limit: int = 500,
                      subject_limit: int = 100) -> dict:
        bundle = super().review_bundle(event_limit, subject_limit)
        bundle["sentinel_version"] = VERSION
        bundle["receipt_defense"] = {
            "independent_signing_key": True,
            "kid": True,
            "bounded_previous_key_overlap": True,
            "binding_mode": self.receipt_policy.binding_mode,
            "local_containment_bypass": False,
        }
        bundle["policy"]["automatic_rule_application"] = False
        bundle["policy"]["human_approval_required_for_policy_changes"] = True
        return bundle

    def summary(self) -> dict:
        summary = super().summary()
        summary["sentinel_version"] = VERSION
        summary["mode"] = (
            "adaptive-swarm-resource-fairness-audit-receipt-keyring-binding"
        )
        summary["receipt_status"] = self.receipt_status()
        return summary
