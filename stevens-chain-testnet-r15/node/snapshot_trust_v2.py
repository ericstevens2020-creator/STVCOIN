"""Stevens Chain authenticated recovery snapshot trust v2 (testnet r8).

Adds rotation/revocation and compromise recovery to the r7 dual-signature model.
Consensus is unchanged.

Trust roles:
- offline trust root: signs a monotonic key policy;
- snapshot operator: signs exact snapshot metadata;
- rollback witness: signs a monotonic revision/work statement.

The receiver keeps two external anchors: the highest accepted root policy and the
highest accepted witness statement. For whole-host rollback resistance those
anchors must be genuinely independent of the node host in a real deployment.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.request
import urllib.error
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import snapshot_trust_v1 as v1

ROOT_KEY_FORMAT = "StevensSnapshotTrustRootKey-v1"
POLICY_FORMAT = "StevensChainSnapshotTrustPolicy-v1"
POLICY_ANCHOR_FORMAT = "StevensChainSnapshotTrustPolicyAnchor-v1"
MANIFEST_FORMAT = "StevensChainSnapshotManifest-v2"
WITNESS_FORMAT = "StevensChainSnapshotWitness-v2"
WITNESS_ANCHOR_FORMAT = "StevensChainSnapshotWitnessAnchor-v2"
MAX_POLICY_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ANCHOR_BYTES = 256 * 1024
DEFAULT_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
ALLOWED_STATUS = {"active", "revoked"}

canonical = v1.canonical
atomic_write_json = v1.atomic_write_json
file_sha256 = v1.file_sha256
verify_signature = v1.verify_signature
key_id = v1.key_id


def _raw_public(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def policy_body_hash(body: dict) -> str:
    return _sha256_hex(canonical(body))


def create_trust_root_key(path: str | Path) -> dict:
    path = Path(path)
    if path.exists():
        raise ValueError("snapshot trust-root key path already exists")
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_hex = _raw_public(priv).hex()
    doc = {
        "format": ROOT_KEY_FORMAT,
        "role": "snapshot-trust-root",
        "private_key": raw_priv.hex(),
        "public_key": pub_hex,
        "key_id": key_id(pub_hex),
    }
    atomic_write_json(path, doc)
    return {k: doc[k] for k in ("role", "public_key", "key_id")}


def load_trust_root_private(path: str | Path) -> tuple[Ed25519PrivateKey, str, str]:
    p = Path(path)
    if p.stat().st_size <= 0 or p.stat().st_size > MAX_POLICY_BYTES:
        raise ValueError("snapshot trust-root key file size invalid")
    doc = json.loads(p.read_text(encoding="utf-8"))
    if doc.get("format") != ROOT_KEY_FORMAT or doc.get("role") != "snapshot-trust-root":
        raise ValueError("snapshot trust-root key format mismatch")
    raw = bytes.fromhex(str(doc.get("private_key", "")))
    if len(raw) != 32:
        raise ValueError("invalid snapshot trust-root private key length")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = _raw_public(priv).hex()
    if doc.get("public_key") != pub or doc.get("key_id") != key_id(pub):
        raise ValueError("snapshot trust-root key integrity mismatch")
    return priv, pub, key_id(pub)


def _normalize_entries(entries: dict[str, str]) -> list[dict]:
    out = []
    seen = set()
    for pub, status in sorted(entries.items(), key=lambda kv: key_id(kv[0])):
        pub = str(pub).lower()
        status = str(status).lower()
        kid = key_id(pub)
        if kid in seen:
            raise ValueError("duplicate snapshot authority key id")
        if status not in ALLOWED_STATUS:
            raise ValueError("invalid snapshot authority status")
        seen.add(kid)
        out.append({"key_id": kid, "public_key": pub, "status": status})
    if not any(x["status"] == "active" for x in out):
        raise ValueError("snapshot authority policy must contain an active key")
    return out


def _policy_key_map(policy_body: dict, role: str) -> dict[str, dict]:
    field = "operators" if role == "operator" else "witnesses"
    rows = policy_body.get(field)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"snapshot trust policy {field} invalid")
    out = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid snapshot trust policy key entry")
        pub = str(row.get("public_key", "")).lower()
        kid = str(row.get("key_id", ""))
        status = str(row.get("status", ""))
        if kid != key_id(pub) or status not in ALLOWED_STATUS or kid in out:
            raise ValueError("invalid or duplicate snapshot trust policy key entry")
        out[kid] = {"public_key": pub, "status": status}
    if not any(x["status"] == "active" for x in out.values()):
        raise ValueError(f"snapshot trust policy has no active {role} key")
    return out


def _verify_policy_doc(doc: dict, root_pub_hex: str, network_id: str,
                       genesis_hash: str | None = None) -> dict:
    if doc.get("format") != POLICY_FORMAT:
        raise ValueError("snapshot trust policy format mismatch")
    body = doc.get("body")
    if not isinstance(body, dict) or body.get("format") != POLICY_FORMAT:
        raise ValueError("snapshot trust policy body invalid")
    if body.get("network_id") != network_id:
        raise ValueError("snapshot trust policy network mismatch")
    if genesis_hash is not None and body.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot trust policy genesis mismatch")
    root_pub_hex = root_pub_hex.lower()
    if doc.get("root_pubkey") != root_pub_hex or doc.get("root_key_id") != key_id(root_pub_hex):
        raise ValueError("snapshot trust-root key mismatch")
    if body.get("root_key_id") != key_id(root_pub_hex):
        raise ValueError("snapshot trust policy root id mismatch")
    verify_signature(root_pub_hex, body, str(doc.get("signature", "")))
    rev = int(body.get("revision", 0))
    if rev <= 0:
        raise ValueError("snapshot trust policy revision invalid")
    _policy_key_map(body, "operator")
    _policy_key_map(body, "witness")
    return {"document": doc, "body": body, "hash": policy_body_hash(body)}


def _read_json_bounded(path: str | Path, max_bytes: int, what: str) -> dict:
    p = Path(path)
    try:
        n = p.stat().st_size
    except OSError as e:
        raise ValueError(f"unable to read {what}") from e
    if n <= 0 or n > max_bytes:
        raise ValueError(f"{what} size invalid")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"invalid {what} JSON") from e


def issue_trust_policy(out_path: str | Path, *, state_path: str | Path,
                       network_id: str, genesis_hash: str,
                       root_key_path: str | Path,
                       operators: dict[str, str], witnesses: dict[str, str],
                       initialize_state: bool = False) -> dict:
    """Issue the next root-signed policy and durably advance signer state.

    The state file contains the exact previous signed policy. Missing established
    state fails closed. A crash after state advancement but before publication
    can be recovered by publishing the state file itself.
    """
    root_priv, root_pub, root_id = load_trust_root_private(root_key_path)
    sp = Path(state_path)
    prior = None
    if sp.exists():
        prior_doc = _read_json_bounded(sp, MAX_POLICY_BYTES, "snapshot policy signer state")
        prior = _verify_policy_doc(prior_doc, root_pub, network_id, genesis_hash)
        if initialize_state:
            raise ValueError("snapshot policy signer state already initialized")
    elif not initialize_state:
        raise ValueError("snapshot policy signer state missing; explicit initialization required")

    rev = int(prior["body"]["revision"]) + 1 if prior else 1
    prev_hash = prior["hash"] if prior else None
    body = {
        "format": POLICY_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "revision": rev,
        "previous_policy_sha256": prev_hash,
        "operators": _normalize_entries(operators),
        "witnesses": _normalize_entries(witnesses),
        "root_key_id": root_id,
        "issued_at": int(time.time()),
    }
    doc = {
        "format": POLICY_FORMAT,
        "body": body,
        "root_pubkey": root_pub,
        "root_key_id": root_id,
        "signature": root_priv.sign(canonical(body)).hex(),
    }
    # Advance signer state before publishing. The exact signed state file is a
    # recoverable publication artifact if the second write fails.
    atomic_write_json(sp, doc)
    if Path(out_path).resolve() != sp.resolve():
        atomic_write_json(out_path, doc, mode=0o644)
    return doc


def _load_policy_anchor(path: str | Path, root_pub_hex: str, network_id: str,
                        genesis_hash: str | None) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    doc = _read_json_bounded(p, MAX_ANCHOR_BYTES, "snapshot policy anchor")
    if doc.get("format") != POLICY_ANCHOR_FORMAT or not isinstance(doc.get("policy"), dict):
        raise ValueError("snapshot policy anchor format invalid")
    verified = _verify_policy_doc(doc["policy"], root_pub_hex, network_id, genesis_hash)
    if doc.get("policy_sha256") != verified["hash"]:
        raise ValueError("snapshot policy anchor hash mismatch")
    return verified


def verify_trust_policy(policy_path: str | Path, *, trusted_root_pubkey: str,
                        network_id: str, genesis_hash: str | None = None,
                        receiver_policy_anchor: str | Path | None = None,
                        require_existing_anchor: bool = False) -> dict:
    doc = _read_json_bounded(policy_path, MAX_POLICY_BYTES, "snapshot trust policy")
    verified = _verify_policy_doc(doc, trusted_root_pubkey.lower(), network_id, genesis_hash)
    if receiver_policy_anchor is not None:
        prior = _load_policy_anchor(receiver_policy_anchor, trusted_root_pubkey.lower(), network_id, genesis_hash)
        if prior is None:
            if require_existing_anchor:
                raise ValueError("established snapshot trust-policy anchor missing; fail closed")
        else:
            cur_rev = int(verified["body"]["revision"])
            old_rev = int(prior["body"]["revision"])
            if cur_rev < old_rev:
                raise ValueError("snapshot trust-policy rollback detected")
            if cur_rev == old_rev:
                if verified["hash"] != prior["hash"]:
                    raise ValueError("snapshot trust-root equivocation at same policy revision")
            else:
                if cur_rev != old_rev + 1:
                    raise ValueError("snapshot trust-policy transition must be sequential")
                if verified["body"].get("previous_policy_sha256") != prior["hash"]:
                    raise ValueError("snapshot trust-policy predecessor hash mismatch")
    return verified


def advance_policy_anchor(verified_policy: dict, path: str | Path) -> None:
    atomic_write_json(path, {
        "format": POLICY_ANCHOR_FORMAT,
        "policy": verified_policy["document"],
        "policy_sha256": verified_policy["hash"],
    })


def _active_key(policy: dict, role: str, pub_hex: str) -> tuple[str, dict]:
    body = policy["body"]
    rows = _policy_key_map(body, role)
    kid = key_id(pub_hex.lower())
    row = rows.get(kid)
    if row is None or row["public_key"] != pub_hex.lower():
        raise ValueError(f"snapshot {role} key is not present in trust policy")
    if row["status"] != "active":
        raise ValueError(f"snapshot {role} key is revoked")
    return kid, row


def _known_witness(policy: dict, pub_hex: str) -> dict:
    rows = _policy_key_map(policy["body"], "witness")
    kid = key_id(pub_hex.lower())
    row = rows.get(kid)
    if row is None or row["public_key"] != pub_hex.lower():
        raise ValueError("historical witness key is not present in current trust policy")
    return row


def _witness_statement(body: dict, priv: Ed25519PrivateKey, pub: str, kid: str) -> dict:
    return {
        "format": WITNESS_FORMAT,
        "body": body,
        "witness_pubkey": pub,
        "witness_key_id": kid,
        "signature": priv.sign(canonical(body)).hex(),
    }


def _verify_witness_doc(doc: dict, policy: dict, network_id: str,
                        genesis_hash: str | None = None, *, require_active=False) -> dict:
    if doc.get("format") not in {WITNESS_FORMAT, WITNESS_ANCHOR_FORMAT}:
        raise ValueError("snapshot witness state format invalid")
    body = doc.get("body")
    if not isinstance(body, dict):
        raise ValueError("snapshot witness state body invalid")
    if body.get("network_id") != network_id:
        raise ValueError("snapshot witness state network mismatch")
    if genesis_hash is not None and body.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot witness state genesis mismatch")
    pub = str(doc.get("witness_pubkey", "")).lower()
    kid = str(doc.get("witness_key_id", ""))
    if kid != key_id(pub) or body.get("witness_key_id") != kid:
        raise ValueError("snapshot witness state key id mismatch")
    row = _known_witness(policy, pub)
    if require_active and row["status"] != "active":
        raise ValueError("snapshot witness key is revoked")
    verify_signature(pub, body, str(doc.get("signature", "")))
    if int(body.get("revision", 0)) <= 0:
        raise ValueError("invalid snapshot witness revision")
    return doc


def _load_witness_state(path: str | Path, policy: dict, network_id: str,
                        genesis_hash: str | None = None) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    doc = _read_json_bounded(p, MAX_ANCHOR_BYTES, "snapshot witness state")
    return _verify_witness_doc(doc, policy, network_id, genesis_hash, require_active=False)


def sign_snapshot(snapshot_path: str | Path, manifest_path: str | Path, *,
                  network_id: str, genesis_hash: str, height: int, tip: str,
                  cumulative_work: int, operator_key_path: str | Path,
                  witness_key_path: str | Path, witness_state_path: str | Path,
                  verified_policy: dict,
                  initialize_witness_state: bool = False) -> dict:
    """Sign an r8 snapshot using active keys from a root-signed policy."""
    operator_priv, operator_pub, operator_id = v1.load_authority_private(operator_key_path, "operator")
    witness_priv, witness_pub, witness_id = v1.load_authority_private(witness_key_path, "witness")
    _active_key(verified_policy, "operator", operator_pub)
    _active_key(verified_policy, "witness", witness_pub)

    if verified_policy["body"].get("network_id") != network_id or verified_policy["body"].get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot trust policy does not match snapshot network/genesis")

    prior = _load_witness_state(witness_state_path, verified_policy, network_id, genesis_hash)
    if prior is None and not initialize_witness_state:
        raise ValueError("snapshot witness state missing; explicit initialization required")
    if prior is not None and initialize_witness_state:
        raise ValueError("snapshot witness state already initialized")
    pb = prior["body"] if prior else None
    prior_work = int(pb.get("cumulative_work", -1)) if pb else -1
    prior_rev = int(pb.get("revision", 0)) if pb else 0
    if int(cumulative_work) < prior_work:
        raise ValueError("rollback witness refuses lower-work snapshot")

    snapshot_path = Path(snapshot_path)
    snap_hash = file_sha256(snapshot_path)
    size = snapshot_path.stat().st_size
    policy_hash = verified_policy["hash"]
    policy_rev = int(verified_policy["body"]["revision"])

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
        "policy_revision": policy_rev,
        "policy_sha256": policy_hash,
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
        "witness_key_id": witness_id,
        "policy_revision": policy_rev,
        "policy_sha256": policy_hash,
        "issued_at": int(time.time()),
    }
    statement = _witness_statement(witness_body, witness_priv, witness_pub, witness_id)

    # Advance monotonic witness state before publishing the manifest. A failure
    # can skip a revision but cannot publish a statement whose state was not
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


def _preverify_manifest_doc(manifest: dict, *, network_id: str, verified_policy: dict) -> dict:
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError("snapshot manifest format mismatch")
    body = manifest.get("body")
    if not isinstance(body, dict) or body.get("format") != MANIFEST_FORMAT:
        raise ValueError("snapshot manifest body invalid")
    if body.get("network_id") != network_id:
        raise ValueError("snapshot manifest network mismatch")
    if int(body.get("policy_revision", 0)) != int(verified_policy["body"]["revision"]) or body.get("policy_sha256") != verified_policy["hash"]:
        raise ValueError("snapshot manifest is not bound to current trust policy")

    op_pub = str(manifest.get("operator_pubkey", "")).lower()
    op_id, _ = _active_key(verified_policy, "operator", op_pub)
    if manifest.get("operator_key_id") != op_id or body.get("operator_key_id") != op_id:
        raise ValueError("snapshot operator key id mismatch")
    verify_signature(op_pub, body, str(manifest.get("operator_signature", "")))

    statement = manifest.get("witness")
    if not isinstance(statement, dict):
        raise ValueError("snapshot witness statement missing/invalid")
    _verify_witness_doc(statement, verified_policy, network_id, body.get("genesis_hash"), require_active=True)
    wb = statement["body"]
    for field in (
        "network_id", "genesis_hash", "cumulative_work", "height", "tip",
        "snapshot_sha256", "operator_key_id", "policy_revision", "policy_sha256",
    ):
        if wb.get(field) != body.get(field):
            raise ValueError(f"witness/manifest {field} mismatch")
    if int(wb.get("revision", 0)) <= 0:
        raise ValueError("invalid snapshot witness revision")
    return {"manifest": manifest, "body": body, "witness": statement}


def preverify_manifest(manifest_path: str | Path, *, network_id: str,
                       verified_policy: dict) -> dict:
    manifest = _read_json_bounded(manifest_path, MAX_MANIFEST_BYTES, "snapshot manifest")
    return _preverify_manifest_doc(manifest, network_id=network_id, verified_policy=verified_policy)


def verify_snapshot(snapshot_path: str | Path, manifest_path: str | Path, *,
                    network_id: str, verified_policy: dict,
                    receiver_witness_anchor: str | Path | None = None,
                    require_existing_anchor: bool = False) -> dict:
    verified = preverify_manifest(manifest_path, network_id=network_id, verified_policy=verified_policy)
    body = verified["body"]
    snapshot_path = Path(snapshot_path)
    try:
        size = snapshot_path.stat().st_size
    except OSError as e:
        raise ValueError("unable to stat snapshot") from e
    if size != int(body.get("snapshot_bytes", -1)):
        raise ValueError("snapshot size does not match signed manifest")
    if file_sha256(snapshot_path) != body.get("snapshot_sha256"):
        raise ValueError("snapshot hash does not match signed manifest")

    wb = verified["witness"]["body"]
    if receiver_witness_anchor is not None:
        ap = Path(receiver_witness_anchor)
        prior = None
        if ap.exists():
            prior_doc = _read_json_bounded(ap, MAX_ANCHOR_BYTES, "snapshot witness anchor")
            prior = _verify_witness_doc(prior_doc, verified_policy, network_id, body.get("genesis_hash"), require_active=False)
        elif require_existing_anchor:
            raise ValueError("established snapshot rollback-witness anchor missing; fail closed")
        if prior:
            pb = prior["body"]
            if int(wb["revision"]) < int(pb.get("revision", 0)):
                raise ValueError("snapshot witness revision rollback detected")
            if int(wb["cumulative_work"]) < int(pb.get("cumulative_work", 0)):
                raise ValueError("snapshot cumulative-work rollback detected by witness anchor")
            if int(wb["revision"]) == int(pb.get("revision", 0)):
                if wb.get("snapshot_sha256") != pb.get("snapshot_sha256") or wb.get("tip") != pb.get("tip"):
                    raise ValueError("snapshot witness equivocation at same revision")
    return verified


def advance_receiver_anchor(verified: dict, path: str | Path) -> None:
    doc = dict(verified["witness"])
    doc["format"] = WITNESS_ANCHOR_FORMAT
    atomic_write_json(path, doc)



class _NoSnapshotRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "snapshot transport redirect rejected", headers, fp)


_SNAPSHOT_OPENER = urllib.request.build_opener(_NoSnapshotRedirect())

def _snapshot_urlopen(url: str, timeout: float):
    return _SNAPSHOT_OPENER.open(url, timeout=timeout)

def _bounded_http_bytes(url: str, max_bytes: int, timeout: float) -> bytes:
    try:
        with _snapshot_urlopen(url, timeout=timeout) as r:
            cl = r.headers.get("Content-Length")
            if cl is not None:
                try:
                    if int(cl) > max_bytes:
                        raise ValueError("remote object exceeds configured size limit")
                except ValueError as e:
                    if str(e) == "remote object exceeds configured size limit":
                        raise
                    raise ValueError("invalid remote Content-Length") from e
            data = r.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("remote object exceeds configured size limit")
            return data
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("snapshot transport read failed") from e


def fetch_authenticated_bundle(*, manifest_url: str, snapshot_url: str,
                               out_dir: str | Path, network_id: str,
                               verified_policy: dict, timeout: float = 10.0,
                               max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES) -> dict:
    """Bounded, staged HTTP fetch for one authenticated snapshot generation."""
    raw_manifest = _bounded_http_bytes(manifest_url, MAX_MANIFEST_BYTES, timeout)
    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("invalid transported snapshot manifest") from e
    pre = _preverify_manifest_doc(manifest, network_id=network_id, verified_policy=verified_policy)
    body = pre["body"]
    expected = int(body.get("snapshot_bytes", -1))
    if expected <= 0 or expected > int(max_snapshot_bytes):
        raise ValueError("transported snapshot size outside safety bounds")
    expected_hash = str(body.get("snapshot_sha256", ""))
    if len(expected_hash) != 64:
        raise ValueError("transported snapshot hash invalid")
    try:
        bytes.fromhex(expected_hash)
    except ValueError as e:
        raise ValueError("transported snapshot hash invalid") from e

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    snap_final = out_dir / f"snapshot-{expected_hash}.sqlite3"
    manifest_final = out_dir / f"manifest-{expected_hash}.json"
    tmp = out_dir / f".snapshot-{expected_hash}.tmp-{secrets.token_hex(8)}"
    fd = None
    try:
        h = hashlib.sha256()
        total = 0
        try:
            with _snapshot_urlopen(snapshot_url, timeout=timeout) as r:
                cl = r.headers.get("Content-Length")
                if cl is not None:
                    try:
                        declared = int(cl)
                    except ValueError as e:
                        raise ValueError("invalid snapshot Content-Length") from e
                    if declared != expected:
                        raise ValueError("snapshot Content-Length does not match signed size")
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    fd = None
                    while True:
                        chunk = r.read(min(1024 * 1024, expected - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > expected:
                            raise ValueError("snapshot transport sent extra bytes")
                        h.update(chunk)
                        f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
        except ValueError:
            raise
        except Exception as e:
            raise ValueError("snapshot transport interrupted") from e
        if total != expected:
            raise ValueError("snapshot transport truncated")
        if h.hexdigest() != expected_hash:
            raise ValueError("snapshot transport hash mismatch")
        os.replace(tmp, snap_final)
        v1._fsync_parent(snap_final)
        # The manifest is published last. If the process dies after publishing
        # snapshot bytes but before this write, the orphaned content-hash file is
        # harmless and cannot be imported as an authenticated generation.
        atomic_write_json(manifest_final, manifest, mode=0o644)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    return {
        "snapshot": str(snap_final),
        "manifest": str(manifest_final),
        "sha256": expected_hash,
        "bytes": expected,
    }
