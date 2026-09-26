"""Authenticated Stevens Chain recovery snapshot distribution (testnet r7).

This module does not change consensus. It authenticates operational recovery
snapshots with two independently pinned Ed25519 authorities:

1) snapshot operator -- signs the exact snapshot content/chain metadata;
2) rollback witness  -- signs a monotonically increasing witness revision/work.

The receiver remembers the highest accepted witness statement in an external
anchor file. For real deployments that anchor must live outside the node host
(TPM/HSM/KMS/remote quorum storage). A local file is only a testnet stand-in.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

MANIFEST_FORMAT = "StevensChainSnapshotManifest-v1"
WITNESS_FORMAT = "StevensChainSnapshotWitness-v1"
WITNESS_ANCHOR_FORMAT = "StevensChainSnapshotWitnessAnchor-v1"
KEY_FORMAT = "StevensSnapshotAuthorityKey-v1"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ANCHOR_BYTES = 128 * 1024


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw_public(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(pub_hex: str) -> str:
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 32:
        raise ValueError("invalid authority public key length")
    return hashlib.sha256(b"StevensSnapshotAuthority-v1" + raw).hexdigest()[:32]


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _fsync_parent(path: Path) -> None:
    try:
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def atomic_write_json(path: str | Path, obj: dict, *, mode=0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd = None
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(obj, f, sort_keys=True, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        _fsync_parent(path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def create_authority_key(path: str | Path, role: str) -> dict:
    if role not in {"operator", "witness"}:
        raise ValueError("authority role must be operator or witness")
    path = Path(path)
    if path.exists():
        raise ValueError("authority key path already exists")
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_hex = _raw_public(priv).hex()
    doc = {
        "format": KEY_FORMAT,
        "role": role,
        "private_key": raw_priv.hex(),
        "public_key": pub_hex,
        "key_id": key_id(pub_hex),
    }
    atomic_write_json(path, doc)
    return {k: doc[k] for k in ("role", "public_key", "key_id")}


def load_authority_private(path: str | Path, expected_role: str) -> tuple[Ed25519PrivateKey, str, str]:
    path = Path(path)
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("authority key file size invalid")
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("format") != KEY_FORMAT or doc.get("role") != expected_role:
        raise ValueError("authority key format/role mismatch")
    raw = bytes.fromhex(str(doc["private_key"]))
    if len(raw) != 32:
        raise ValueError("invalid authority private key length")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub_hex = _raw_public(priv).hex()
    if doc.get("public_key") != pub_hex or doc.get("key_id") != key_id(pub_hex):
        raise ValueError("authority key integrity mismatch")
    return priv, pub_hex, key_id(pub_hex)


def verify_signature(pub_hex: str, body: dict, signature_hex: str) -> None:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError as e:
        raise ValueError("invalid signature encoding") from e
    if len(pub) != 32 or len(sig) != 64:
        raise ValueError("invalid snapshot signature length")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, canonical(body))
    except InvalidSignature as e:
        raise ValueError("invalid snapshot signature") from e


def _load_signed_witness_state(path: str | Path, witness_pub_hex: str, network_id: str,
                               genesis_hash: str | None = None) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    if p.stat().st_size <= 0 or p.stat().st_size > MAX_ANCHOR_BYTES:
        raise ValueError("witness state file size invalid")
    doc = json.loads(p.read_text(encoding="utf-8"))
    if doc.get("format") not in {WITNESS_FORMAT, WITNESS_ANCHOR_FORMAT}:
        raise ValueError("invalid witness state format")
    body = doc.get("body")
    if not isinstance(body, dict):
        raise ValueError("invalid witness state body")
    if body.get("network_id") != network_id:
        raise ValueError("witness state network mismatch")
    if genesis_hash is not None and body.get("genesis_hash") != genesis_hash:
        raise ValueError("witness state genesis mismatch")
    if doc.get("witness_pubkey") != witness_pub_hex or doc.get("witness_key_id") != key_id(witness_pub_hex):
        raise ValueError("witness state key mismatch")
    verify_signature(witness_pub_hex, body, str(doc.get("signature", "")))
    return doc


def _witness_statement(body: dict, witness_priv: Ed25519PrivateKey,
                       witness_pub_hex: str, witness_key_id: str) -> dict:
    return {
        "format": WITNESS_FORMAT,
        "body": body,
        "witness_pubkey": witness_pub_hex,
        "witness_key_id": witness_key_id,
        "signature": witness_priv.sign(canonical(body)).hex(),
    }


def sign_snapshot(snapshot_path: str | Path, manifest_path: str | Path, *,
                  network_id: str, genesis_hash: str, height: int, tip: str,
                  cumulative_work: int, operator_key_path: str | Path,
                  witness_key_path: str | Path, witness_state_path: str | Path,
                  initialize_witness_state: bool = False) -> dict:
    """Create dual-signed manifest and monotonically advance witness state."""
    snapshot_path = Path(snapshot_path)
    operator_priv, operator_pub, operator_id = load_authority_private(operator_key_path, "operator")
    witness_priv, witness_pub, witness_id = load_authority_private(witness_key_path, "witness")
    snap_hash = file_sha256(snapshot_path)
    size = snapshot_path.stat().st_size

    prior = _load_signed_witness_state(witness_state_path, witness_pub, network_id, genesis_hash)
    if prior is None and not initialize_witness_state:
        raise ValueError("snapshot witness state missing; explicit initialization required")
    prior_body = prior["body"] if prior else None
    prior_work = int(prior_body.get("cumulative_work", -1)) if prior_body else -1
    prior_rev = int(prior_body.get("revision", 0)) if prior_body else 0
    if int(cumulative_work) < prior_work:
        raise ValueError("rollback witness refuses lower-work snapshot")

    snapshot_body = {
        "format": MANIFEST_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "height": int(height),
        "tip": str(tip),
        "cumulative_work": int(cumulative_work),
        "snapshot_sha256": snap_hash,
        "snapshot_bytes": int(size),
        "operator_key_id": operator_id,
        "created_at": int(time.time()),
    }
    operator_sig = operator_priv.sign(canonical(snapshot_body)).hex()

    witness_body = {
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "revision": prior_rev + 1,
        "cumulative_work": int(cumulative_work),
        "height": int(height),
        "tip": str(tip),
        "snapshot_sha256": snap_hash,
        "operator_key_id": operator_id,
        "issued_at": int(time.time()),
    }
    statement = _witness_statement(witness_body, witness_priv, witness_pub, witness_id)

    # Advance witness state before publishing the manifest. A crash can skip a
    # revision, but cannot publish a manifest whose witness state was never
    # durably advanced.
    atomic_write_json(witness_state_path, statement)
    manifest = {
        "format": MANIFEST_FORMAT,
        "body": snapshot_body,
        "operator_pubkey": operator_pub,
        "operator_key_id": operator_id,
        "operator_signature": operator_sig,
        "witness": statement,
    }
    atomic_write_json(manifest_path, manifest, mode=0o644)
    return manifest


def verify_snapshot(snapshot_path: str | Path, manifest_path: str | Path, *,
                    network_id: str, trusted_operator_pubkeys: set[str],
                    trusted_witness_pubkeys: set[str],
                    receiver_witness_anchor: str | Path | None = None,
                    require_existing_anchor: bool = False) -> dict:
    """Verify snapshot bytes, operator signature and monotonic witness."""
    mp = Path(manifest_path)
    if mp.stat().st_size <= 0 or mp.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("snapshot manifest size invalid")
    manifest = json.loads(mp.read_text(encoding="utf-8"))
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError("snapshot manifest format mismatch")
    body = manifest.get("body")
    if not isinstance(body, dict) or body.get("format") != MANIFEST_FORMAT:
        raise ValueError("snapshot manifest body invalid")
    if body.get("network_id") != network_id:
        raise ValueError("snapshot manifest network mismatch")

    op_pub = str(manifest.get("operator_pubkey", ""))
    if op_pub not in trusted_operator_pubkeys:
        raise ValueError("snapshot operator is not trusted")
    if manifest.get("operator_key_id") != key_id(op_pub) or body.get("operator_key_id") != key_id(op_pub):
        raise ValueError("snapshot operator key id mismatch")
    verify_signature(op_pub, body, str(manifest.get("operator_signature", "")))

    snapshot_path = Path(snapshot_path)
    if snapshot_path.stat().st_size != int(body.get("snapshot_bytes", -1)):
        raise ValueError("snapshot size does not match signed manifest")
    if file_sha256(snapshot_path) != body.get("snapshot_sha256"):
        raise ValueError("snapshot hash does not match signed manifest")

    statement = manifest.get("witness")
    if not isinstance(statement, dict) or statement.get("format") != WITNESS_FORMAT:
        raise ValueError("snapshot witness statement missing/invalid")
    wb = statement.get("body")
    if not isinstance(wb, dict):
        raise ValueError("snapshot witness body invalid")
    witness_pub = str(statement.get("witness_pubkey", ""))
    if witness_pub not in trusted_witness_pubkeys:
        raise ValueError("snapshot rollback witness is not trusted")
    if statement.get("witness_key_id") != key_id(witness_pub):
        raise ValueError("snapshot witness key id mismatch")
    verify_signature(witness_pub, wb, str(statement.get("signature", "")))

    for field in ("network_id", "genesis_hash", "cumulative_work", "height", "tip", "snapshot_sha256", "operator_key_id"):
        if wb.get(field) != body.get(field):
            raise ValueError(f"witness/manifest {field} mismatch")
    if int(wb.get("revision", 0)) <= 0:
        raise ValueError("invalid witness revision")

    if receiver_witness_anchor is not None:
        ap = Path(receiver_witness_anchor)
        prior = None
        if ap.exists():
            prior = _load_signed_witness_state(ap, witness_pub, network_id, body.get("genesis_hash"))
        elif require_existing_anchor:
            raise ValueError("established snapshot rollback-witness anchor missing; fail closed")
        if prior:
            pb = prior["body"]
            if int(wb["revision"]) < int(pb.get("revision", 0)):
                raise ValueError("snapshot witness revision rollback detected")
            if int(wb["cumulative_work"]) < int(pb.get("cumulative_work", 0)):
                raise ValueError("snapshot cumulative-work rollback detected by witness anchor")
            # Equal revision must be exactly the same witnessed snapshot.
            if int(wb["revision"]) == int(pb.get("revision", 0)) and wb.get("snapshot_sha256") != pb.get("snapshot_sha256"):
                raise ValueError("snapshot witness equivocation at same revision")

    return {
        "manifest": manifest,
        "body": body,
        "witness": statement,
    }


def advance_receiver_anchor(verified: dict, receiver_witness_anchor: str | Path) -> None:
    """Persist the exact witness-signed statement as the receiver anchor."""
    statement = verified["witness"]
    doc = dict(statement)
    doc["format"] = WITNESS_ANCHOR_FORMAT
    atomic_write_json(receiver_witness_anchor, doc)
