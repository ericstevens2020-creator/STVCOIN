"""Stevens Chain snapshot trust v3 (testnet r9).

Adds compromise-resistant trust-root governance and cross-node witness
snapshot-equivocation detection to the r8 snapshot trust model.

Security model:
- Every normal snapshot authority policy requires the active offline root AND a
  threshold of independently custodied recovery guardians (default 2-of-3).
- Emergency root replacement does not require the compromised root. It requires
  the guardian threshold, a strict next root epoch, and exact binding to the
  receiver's currently anchored policy revision/hash.
- The recovery guardian set is locally pinned during explicit initialization and
  is not editable by the root or by normal policies in r9.
- Snapshot witness statements are independently verifiable. Nodes may exchange
  observations; two different valid statements from the same witness at the
  same revision are durable cryptographic equivocation evidence.

Consensus is unchanged. This module only governs authenticated recovery
snapshots. For host-compromise resistance, root-trust state, policy anchors,
witness anchors, and equivocation journals must be stored independently of the
node database in a real deployment.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import snapshot_trust_v1 as v1
import snapshot_trust_v2 as v2

ROOT_TRUST_STATE_FORMAT = "StevensChainSnapshotRootTrustState-v1"
GUARDIAN_KEY_FORMAT = "StevensSnapshotRecoveryGuardianKey-v1"
QUORUM_POLICY_FORMAT = "StevensChainSnapshotTrustPolicy-v3"
QUORUM_POLICY_ANCHOR_FORMAT = "StevensChainSnapshotTrustPolicyAnchor-v3"
ROOT_RECOVERY_FORMAT = "StevensChainSnapshotRootRecovery-v1"
OBSERVATION_JOURNAL_FORMAT = "StevensChainSnapshotObservationJournal-v1"
EQUIVOCATION_EVIDENCE_FORMAT = "StevensChainSnapshotEquivocationEvidence-v1"
MAX_ROOT_STATE_BYTES = 512 * 1024
MAX_RECOVERY_CERT_BYTES = 512 * 1024
MAX_OBSERVATION_BYTES = 8 * 1024 * 1024
MAX_OBSERVATIONS = 10000
MIN_GUARDIANS = 3

canonical = v1.canonical
atomic_write_json = v1.atomic_write_json
verify_signature = v1.verify_signature
key_id = v1.key_id
policy_body_hash = v2.policy_body_hash


def _raw_public(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


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


def _guardian_set_hash(rows: list[dict], threshold: int) -> str:
    body = {
        "threshold": int(threshold),
        "guardians": sorted(
            [{"key_id": r["key_id"], "public_key": r["public_key"]} for r in rows],
            key=lambda x: x["key_id"],
        ),
    }
    return hashlib.sha256(canonical(body)).hexdigest()


def create_recovery_guardian_key(path: str | Path) -> dict:
    path = Path(path)
    if path.exists():
        raise ValueError("snapshot recovery-guardian key path already exists")
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = _raw_public(priv).hex()
    doc = {
        "format": GUARDIAN_KEY_FORMAT,
        "role": "snapshot-recovery-guardian",
        "private_key": raw_priv.hex(),
        "public_key": pub,
        "key_id": key_id(pub),
    }
    atomic_write_json(path, doc)
    return {k: doc[k] for k in ("role", "public_key", "key_id")}


def load_recovery_guardian_private(path: str | Path) -> tuple[Ed25519PrivateKey, str, str]:
    doc = _read_json_bounded(path, v2.MAX_POLICY_BYTES, "snapshot recovery-guardian key")
    if doc.get("format") != GUARDIAN_KEY_FORMAT or doc.get("role") != "snapshot-recovery-guardian":
        raise ValueError("snapshot recovery-guardian key format mismatch")
    try:
        raw = bytes.fromhex(str(doc.get("private_key", "")))
    except ValueError as e:
        raise ValueError("invalid snapshot recovery-guardian private key") from e
    if len(raw) != 32:
        raise ValueError("invalid snapshot recovery-guardian private key length")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = _raw_public(priv).hex()
    if doc.get("public_key") != pub or doc.get("key_id") != key_id(pub):
        raise ValueError("snapshot recovery-guardian key integrity mismatch")
    return priv, pub, key_id(pub)


def initialize_root_trust_state(path: str | Path, *, network_id: str,
                                genesis_hash: str, root_pubkey: str,
                                guardian_pubkeys: list[str], threshold: int = 2) -> dict:
    """Explicit one-time receiver provisioning for r9 root recovery trust."""
    path = Path(path)
    if path.exists():
        raise ValueError("snapshot root-trust state already exists")
    root_pub = str(root_pubkey).lower()
    try:
        if len(bytes.fromhex(root_pub)) != 32:
            raise ValueError
    except ValueError as e:
        raise ValueError("invalid snapshot root public key") from e
    uniq = {}
    for pub0 in guardian_pubkeys:
        pub = str(pub0).lower()
        try:
            if len(bytes.fromhex(pub)) != 32:
                raise ValueError
        except ValueError as e:
            raise ValueError("invalid recovery guardian public key") from e
        uniq[key_id(pub)] = pub
    if len(uniq) < MIN_GUARDIANS:
        raise ValueError("at least three independent recovery guardians required")
    threshold = int(threshold)
    if threshold < 2 or threshold > len(uniq):
        raise ValueError("invalid recovery guardian threshold")
    guardians = [{"key_id": kid, "public_key": pub} for kid, pub in sorted(uniq.items())]
    doc = {
        "format": ROOT_TRUST_STATE_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "guardian_threshold": threshold,
        "guardians": guardians,
        "guardian_set_sha256": _guardian_set_hash(guardians, threshold),
        "current_root_epoch": 1,
        "current_root_key_id": key_id(root_pub),
        "roots": [{
            "epoch": 1,
            "key_id": key_id(root_pub),
            "public_key": root_pub,
            "status": "active",
        }],
        "created_at": int(time.time()),
    }
    atomic_write_json(path, doc)
    return doc


def load_root_trust_state(path: str | Path, *, network_id: str,
                          genesis_hash: str) -> dict:
    doc = _read_json_bounded(path, MAX_ROOT_STATE_BYTES, "snapshot root-trust state")
    if doc.get("format") != ROOT_TRUST_STATE_FORMAT:
        raise ValueError("snapshot root-trust state format mismatch")
    if doc.get("network_id") != network_id or doc.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot root-trust state network/genesis mismatch")
    rows = doc.get("guardians")
    if not isinstance(rows, list) or len(rows) < MIN_GUARDIANS:
        raise ValueError("snapshot recovery guardian set invalid")
    seen = set()
    norm = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("snapshot recovery guardian row invalid")
        pub = str(row.get("public_key", "")).lower()
        kid = str(row.get("key_id", ""))
        try:
            if len(bytes.fromhex(pub)) != 32:
                raise ValueError
        except ValueError as e:
            raise ValueError("snapshot recovery guardian public key invalid") from e
        if kid != key_id(pub) or kid in seen:
            raise ValueError("snapshot recovery guardian id invalid/duplicate")
        seen.add(kid)
        norm.append({"key_id": kid, "public_key": pub})
    threshold = int(doc.get("guardian_threshold", 0))
    if threshold < 2 or threshold > len(norm):
        raise ValueError("snapshot recovery guardian threshold invalid")
    if doc.get("guardian_set_sha256") != _guardian_set_hash(norm, threshold):
        raise ValueError("snapshot recovery guardian set hash mismatch")
    roots = doc.get("roots")
    if not isinstance(roots, list) or not roots:
        raise ValueError("snapshot root history invalid")
    root_seen = set()
    current_epoch = int(doc.get("current_root_epoch", 0))
    current_id = str(doc.get("current_root_key_id", ""))
    active = []
    for row in roots:
        if not isinstance(row, dict):
            raise ValueError("snapshot root history row invalid")
        epoch = int(row.get("epoch", 0))
        pub = str(row.get("public_key", "")).lower()
        kid = str(row.get("key_id", ""))
        status = str(row.get("status", ""))
        if epoch <= 0 or kid != key_id(pub) or epoch in root_seen or status not in {"active", "revoked"}:
            raise ValueError("snapshot root history row invalid")
        root_seen.add(epoch)
        if status == "active":
            active.append(row)
    if len(active) != 1 or int(active[0]["epoch"]) != current_epoch or active[0]["key_id"] != current_id:
        raise ValueError("snapshot active root state invalid")
    return doc


def _root_for_epoch(state: dict, epoch: int) -> dict:
    for row in state["roots"]:
        if int(row["epoch"]) == int(epoch):
            return row
    raise ValueError("snapshot policy references unknown root epoch")


def _guardian_map(state: dict) -> dict[str, str]:
    return {row["key_id"]: row["public_key"] for row in state["guardians"]}


def _verify_guardian_signatures(body: dict, signatures: list[dict], state: dict) -> list[str]:
    if not isinstance(signatures, list):
        raise ValueError("snapshot guardian signatures missing")
    gm = _guardian_map(state)
    valid = []
    seen = set()
    for sigrow in signatures:
        if not isinstance(sigrow, dict):
            raise ValueError("snapshot guardian signature row invalid")
        kid = str(sigrow.get("guardian_key_id", ""))
        if kid in seen:
            continue
        pub = gm.get(kid)
        if pub is None:
            continue
        try:
            verify_signature(pub, body, str(sigrow.get("signature", "")))
        except Exception:
            continue
        seen.add(kid)
        valid.append(kid)
    if len(valid) < int(state["guardian_threshold"]):
        raise ValueError("snapshot recovery-guardian quorum not satisfied")
    return sorted(valid)


def _policy_key_map(policy_body: dict, role: str) -> dict[str, dict]:
    # Reuse r8 strict key normalization/validation.
    return v2._policy_key_map(policy_body, role)


def _verify_quorum_policy_doc(doc: dict, root_state: dict, *, network_id: str,
                              genesis_hash: str, require_current_root: bool = True) -> dict:
    if doc.get("format") != QUORUM_POLICY_FORMAT:
        raise ValueError("snapshot quorum policy format mismatch")
    body = doc.get("body")
    if not isinstance(body, dict) or body.get("format") != QUORUM_POLICY_FORMAT:
        raise ValueError("snapshot quorum policy body invalid")
    if body.get("network_id") != network_id or body.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot quorum policy network/genesis mismatch")
    rev = int(body.get("revision", 0))
    epoch = int(body.get("root_epoch", 0))
    if rev <= 0 or epoch <= 0:
        raise ValueError("snapshot quorum policy revision/root epoch invalid")
    root = _root_for_epoch(root_state, epoch)
    if require_current_root:
        if epoch != int(root_state["current_root_epoch"]) or root["status"] != "active":
            raise ValueError("snapshot quorum policy is not signed by current active root")
    root_pub = str(doc.get("root_pubkey", "")).lower()
    if root_pub != root["public_key"] or doc.get("root_key_id") != root["key_id"] or body.get("root_key_id") != root["key_id"]:
        raise ValueError("snapshot quorum policy root key mismatch")
    verify_signature(root_pub, body, str(doc.get("root_signature", "")))
    guardians = _verify_guardian_signatures(body, doc.get("guardian_signatures", []), root_state)
    _policy_key_map(body, "operator")
    _policy_key_map(body, "witness")
    if body.get("guardian_set_sha256") != root_state["guardian_set_sha256"]:
        raise ValueError("snapshot quorum policy guardian-set binding mismatch")
    return {"document": doc, "body": body, "hash": policy_body_hash(body), "guardian_signers": guardians}


def _sign_guardian_quorum(body: dict, guardian_key_paths: list[str | Path], state: dict) -> list[dict]:
    gm = _guardian_map(state)
    rows = []
    seen = set()
    for path in guardian_key_paths:
        priv, pub, kid = load_recovery_guardian_private(path)
        if kid in seen or gm.get(kid) != pub:
            continue
        seen.add(kid)
        rows.append({"guardian_key_id": kid, "signature": priv.sign(canonical(body)).hex()})
    if len(rows) < int(state["guardian_threshold"]):
        raise ValueError("insufficient distinct recovery-guardian signing keys")
    return sorted(rows, key=lambda x: x["guardian_key_id"])


def _load_quorum_policy_anchor(path: str | Path, root_state: dict, *, network_id: str,
                               genesis_hash: str) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    doc = _read_json_bounded(p, v2.MAX_ANCHOR_BYTES, "snapshot quorum policy anchor")
    if doc.get("format") != QUORUM_POLICY_ANCHOR_FORMAT or not isinstance(doc.get("policy"), dict):
        raise ValueError("snapshot quorum policy anchor format invalid")
    vp = _verify_quorum_policy_doc(doc["policy"], root_state, network_id=network_id,
                                   genesis_hash=genesis_hash, require_current_root=False)
    if doc.get("policy_sha256") != vp["hash"]:
        raise ValueError("snapshot quorum policy anchor hash mismatch")
    return vp


def issue_quorum_policy(out_path: str | Path, *, state_path: str | Path,
                        root_trust_state_path: str | Path,
                        network_id: str, genesis_hash: str,
                        root_key_path: str | Path,
                        guardian_key_paths: list[str | Path],
                        operators: dict[str, str], witnesses: dict[str, str],
                        initialize_state: bool = False) -> dict:
    root_state = load_root_trust_state(root_trust_state_path, network_id=network_id, genesis_hash=genesis_hash)
    root_priv, root_pub, root_id = v2.load_trust_root_private(root_key_path)
    if root_id != root_state["current_root_key_id"]:
        raise ValueError("policy signer root is not current active root")
    root_epoch = int(root_state["current_root_epoch"])
    sp = Path(state_path)
    prior = None
    if sp.exists():
        prior_doc = _read_json_bounded(sp, v2.MAX_POLICY_BYTES, "snapshot quorum policy signer state")
        prior = _verify_quorum_policy_doc(prior_doc, root_state, network_id=network_id,
                                          genesis_hash=genesis_hash, require_current_root=False)
        if initialize_state:
            raise ValueError("snapshot quorum policy signer state already initialized")
    elif not initialize_state:
        raise ValueError("snapshot quorum policy signer state missing; explicit initialization required")
    rev = int(prior["body"]["revision"]) + 1 if prior else 1
    prev_hash = prior["hash"] if prior else None
    body = {
        "format": QUORUM_POLICY_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "revision": rev,
        "previous_policy_sha256": prev_hash,
        "root_epoch": root_epoch,
        "root_key_id": root_id,
        "guardian_set_sha256": root_state["guardian_set_sha256"],
        "operators": v2._normalize_entries(operators),
        "witnesses": v2._normalize_entries(witnesses),
        "issued_at": int(time.time()),
    }
    doc = {
        "format": QUORUM_POLICY_FORMAT,
        "body": body,
        "root_pubkey": root_pub,
        "root_key_id": root_id,
        "root_signature": root_priv.sign(canonical(body)).hex(),
        "guardian_signatures": _sign_guardian_quorum(body, guardian_key_paths, root_state),
    }
    # Signer state advances before publication, matching r8 fail-closed behavior.
    atomic_write_json(sp, doc)
    if Path(out_path).resolve() != sp.resolve():
        atomic_write_json(out_path, doc, mode=0o644)
    return doc


def verify_quorum_policy(policy_path: str | Path, *, root_trust_state_path: str | Path,
                         network_id: str, genesis_hash: str,
                         receiver_policy_anchor: str | Path | None = None,
                         require_existing_anchor: bool = False) -> dict:
    state = load_root_trust_state(root_trust_state_path, network_id=network_id, genesis_hash=genesis_hash)
    doc = _read_json_bounded(policy_path, v2.MAX_POLICY_BYTES, "snapshot quorum policy")
    vp = _verify_quorum_policy_doc(doc, state, network_id=network_id, genesis_hash=genesis_hash,
                                   require_current_root=True)
    if receiver_policy_anchor is not None:
        prior = _load_quorum_policy_anchor(receiver_policy_anchor, state, network_id=network_id,
                                           genesis_hash=genesis_hash)
        if prior is None:
            if require_existing_anchor:
                raise ValueError("established snapshot quorum-policy anchor missing; fail closed")
        else:
            cur_rev = int(vp["body"]["revision"])
            old_rev = int(prior["body"]["revision"])
            if cur_rev < old_rev:
                raise ValueError("snapshot quorum-policy rollback detected")
            if cur_rev == old_rev:
                if vp["hash"] != prior["hash"]:
                    raise ValueError("snapshot quorum-policy equivocation at same revision")
            else:
                if cur_rev != old_rev + 1:
                    raise ValueError("snapshot quorum-policy transition must be sequential")
                if vp["body"].get("previous_policy_sha256") != prior["hash"]:
                    raise ValueError("snapshot quorum-policy predecessor hash mismatch")
    return vp


def advance_quorum_policy_anchor(verified_policy: dict, path: str | Path) -> None:
    atomic_write_json(path, {
        "format": QUORUM_POLICY_ANCHOR_FORMAT,
        "policy": verified_policy["document"],
        "policy_sha256": verified_policy["hash"],
    })


def issue_root_recovery_certificate(out_path: str | Path, *,
                                    root_trust_state_path: str | Path,
                                    policy_anchor_path: str | Path,
                                    network_id: str, genesis_hash: str,
                                    new_root_pubkey: str,
                                    guardian_key_paths: list[str | Path],
                                    reason: str = "emergency-root-recovery") -> dict:
    state = load_root_trust_state(root_trust_state_path, network_id=network_id, genesis_hash=genesis_hash)
    prior_policy = _load_quorum_policy_anchor(policy_anchor_path, state, network_id=network_id,
                                              genesis_hash=genesis_hash)
    if prior_policy is None:
        raise ValueError("emergency root recovery requires established policy anchor")
    new_pub = str(new_root_pubkey).lower()
    try:
        if len(bytes.fromhex(new_pub)) != 32:
            raise ValueError
    except ValueError as e:
        raise ValueError("invalid replacement root public key") from e
    if key_id(new_pub) == state["current_root_key_id"]:
        raise ValueError("replacement root must differ from current root")
    body = {
        "format": ROOT_RECOVERY_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "new_root_epoch": int(state["current_root_epoch"]) + 1,
        "previous_root_key_id": state["current_root_key_id"],
        "new_root_key_id": key_id(new_pub),
        "new_root_pubkey": new_pub,
        "guardian_set_sha256": state["guardian_set_sha256"],
        "anchored_policy_revision": int(prior_policy["body"]["revision"]),
        "anchored_policy_sha256": prior_policy["hash"],
        "reason": str(reason)[:256],
        "issued_at": int(time.time()),
    }
    doc = {
        "format": ROOT_RECOVERY_FORMAT,
        "body": body,
        "guardian_signatures": _sign_guardian_quorum(body, guardian_key_paths, state),
    }
    atomic_write_json(out_path, doc, mode=0o644)
    return doc


def verify_root_recovery_certificate(cert_path: str | Path, *,
                                     root_trust_state_path: str | Path,
                                     policy_anchor_path: str | Path,
                                     network_id: str, genesis_hash: str) -> dict:
    state = load_root_trust_state(root_trust_state_path, network_id=network_id, genesis_hash=genesis_hash)
    cert = _read_json_bounded(cert_path, MAX_RECOVERY_CERT_BYTES, "snapshot root recovery certificate")
    if cert.get("format") != ROOT_RECOVERY_FORMAT or not isinstance(cert.get("body"), dict):
        raise ValueError("snapshot root recovery certificate format invalid")
    body = cert["body"]
    if body.get("format") != ROOT_RECOVERY_FORMAT or body.get("network_id") != network_id or body.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot root recovery certificate network/genesis mismatch")
    if body.get("guardian_set_sha256") != state["guardian_set_sha256"]:
        raise ValueError("snapshot root recovery guardian-set mismatch")
    if int(body.get("new_root_epoch", 0)) != int(state["current_root_epoch"]) + 1:
        raise ValueError("snapshot root recovery epoch is not the strict next epoch")
    if body.get("previous_root_key_id") != state["current_root_key_id"]:
        raise ValueError("snapshot root recovery previous-root mismatch")
    new_pub = str(body.get("new_root_pubkey", "")).lower()
    if body.get("new_root_key_id") != key_id(new_pub):
        raise ValueError("snapshot root recovery replacement key mismatch")
    prior_policy = _load_quorum_policy_anchor(policy_anchor_path, state, network_id=network_id,
                                              genesis_hash=genesis_hash)
    if prior_policy is None:
        raise ValueError("snapshot root recovery requires established policy anchor")
    if int(body.get("anchored_policy_revision", -1)) != int(prior_policy["body"]["revision"]) or body.get("anchored_policy_sha256") != prior_policy["hash"]:
        raise ValueError("snapshot root recovery is not bound to current anchored policy")
    signers = _verify_guardian_signatures(body, cert.get("guardian_signatures", []), state)
    return {"document": cert, "body": body, "guardian_signers": signers, "state": state}


def apply_root_recovery_certificate(cert_path: str | Path, *,
                                    root_trust_state_path: str | Path,
                                    policy_anchor_path: str | Path,
                                    network_id: str, genesis_hash: str) -> dict:
    vr = verify_root_recovery_certificate(
        cert_path, root_trust_state_path=root_trust_state_path,
        policy_anchor_path=policy_anchor_path, network_id=network_id,
        genesis_hash=genesis_hash,
    )
    state = vr["state"]
    body = vr["body"]
    for row in state["roots"]:
        if row["key_id"] == state["current_root_key_id"]:
            row["status"] = "revoked"
    state["roots"].append({
        "epoch": int(body["new_root_epoch"]),
        "key_id": body["new_root_key_id"],
        "public_key": body["new_root_pubkey"],
        "status": "active",
    })
    state["current_root_epoch"] = int(body["new_root_epoch"])
    state["current_root_key_id"] = body["new_root_key_id"]
    state["last_recovery_certificate_sha256"] = hashlib.sha256(canonical(vr["document"])).hexdigest()
    state["recovered_at"] = int(time.time())
    atomic_write_json(root_trust_state_path, state)
    return state


def sign_snapshot(*args, **kwargs):
    """r9 snapshots retain the r8 manifest/witness format, bound to r9 policy hash."""
    return v2.sign_snapshot(*args, **kwargs)


def preverify_manifest(*args, **kwargs):
    return v2.preverify_manifest(*args, **kwargs)


def fetch_authenticated_bundle(*args, **kwargs):
    return v2.fetch_authenticated_bundle(*args, **kwargs)


def _statement_identity(statement: dict) -> tuple[str, int]:
    if not isinstance(statement, dict) or statement.get("format") not in {v2.WITNESS_FORMAT, v2.WITNESS_ANCHOR_FORMAT}:
        raise ValueError("snapshot witness observation format invalid")
    body = statement.get("body")
    if not isinstance(body, dict):
        raise ValueError("snapshot witness observation body invalid")
    return str(statement.get("witness_key_id", "")), int(body.get("revision", 0))


def _statement_digest(statement: dict) -> str:
    # Signature is included so evidence retains the exact signed artifact.
    return hashlib.sha256(canonical(statement)).hexdigest()


def _load_observation_journal(path: str | Path, *, network_id: str,
                              genesis_hash: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {
            "format": OBSERVATION_JOURNAL_FORMAT,
            "network_id": network_id,
            "genesis_hash": genesis_hash,
            "observations": {},
            "equivocations": {},
        }
    doc = _read_json_bounded(p, MAX_OBSERVATION_BYTES, "snapshot observation journal")
    if doc.get("format") != OBSERVATION_JOURNAL_FORMAT or doc.get("network_id") != network_id or doc.get("genesis_hash") != genesis_hash:
        raise ValueError("snapshot observation journal scope mismatch")
    if not isinstance(doc.get("observations"), dict) or not isinstance(doc.get("equivocations"), dict):
        raise ValueError("snapshot observation journal structure invalid")
    return doc


def observe_witness_statement(statement: dict, *, verified_policy: dict,
                              network_id: str, genesis_hash: str,
                              journal_path: str | Path) -> dict:
    # Historical/revoked witnesses remain verifiable so old evidence can be merged
    # after an authorized rotation.
    verified = v2._verify_witness_doc(statement, verified_policy, network_id, genesis_hash,
                                      require_active=False)
    kid, rev = _statement_identity(verified)
    if rev <= 0:
        raise ValueError("snapshot witness observation revision invalid")
    journal = _load_observation_journal(journal_path, network_id=network_id, genesis_hash=genesis_hash)
    eq = journal["equivocations"]
    if kid in eq:
        raise ValueError("snapshot witness is quarantined for prior equivocation")
    key = f"{kid}:{rev}"
    digest = _statement_digest(verified)
    prior = journal["observations"].get(key)
    if prior is None:
        if len(journal["observations"]) >= MAX_OBSERVATIONS:
            raise ValueError("snapshot observation journal capacity exhausted; fail closed")
        journal["observations"][key] = {"digest": digest, "statement": verified}
        atomic_write_json(journal_path, journal)
        return {"status": "new", "witness_key_id": kid, "revision": rev, "digest": digest}
    if prior.get("digest") == digest:
        return {"status": "known", "witness_key_id": kid, "revision": rev, "digest": digest}

    # Both statements have already passed cryptographic verification under the
    # policy. Persist evidence before raising/quarantining.
    evidence = {
        "format": EQUIVOCATION_EVIDENCE_FORMAT,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "witness_key_id": kid,
        "revision": rev,
        "statement_a": prior.get("statement"),
        "statement_b": verified,
        "detected_at": int(time.time()),
    }
    eq[kid] = evidence
    atomic_write_json(journal_path, journal)
    raise ValueError("snapshot witness equivocation detected; witness quarantined")


def observe_manifest(manifest_path: str | Path, *, verified_policy: dict,
                     network_id: str, genesis_hash: str,
                     journal_path: str | Path) -> dict:
    pre = v2.preverify_manifest(manifest_path, network_id=network_id, verified_policy=verified_policy)
    return observe_witness_statement(pre["witness"], verified_policy=verified_policy,
                                     network_id=network_id, genesis_hash=genesis_hash,
                                     journal_path=journal_path)


def merge_observation_journal(peer_journal_path: str | Path, *,
                              local_journal_path: str | Path,
                              verified_policy: dict,
                              network_id: str, genesis_hash: str) -> dict:
    peer = _load_observation_journal(peer_journal_path, network_id=network_id, genesis_hash=genesis_hash)
    processed = 0
    equivocations = 0
    # The peer journal is untrusted transport. Every statement is independently
    # verified before it can affect local state.
    for row in peer["observations"].values():
        stmt = row.get("statement") if isinstance(row, dict) else None
        try:
            observe_witness_statement(stmt, verified_policy=verified_policy,
                                      network_id=network_id, genesis_hash=genesis_hash,
                                      journal_path=local_journal_path)
            processed += 1
        except ValueError as e:
            if "equivocation" in str(e):
                equivocations += 1
                processed += 1
            else:
                raise
    return {"processed": processed, "equivocations": equivocations}


def verify_snapshot(snapshot_path: str | Path, manifest_path: str | Path, *,
                    network_id: str, verified_policy: dict,
                    receiver_witness_anchor: str | Path | None = None,
                    require_existing_anchor: bool = False,
                    observation_journal: str | Path | None = None) -> dict:
    verified = v2.verify_snapshot(
        snapshot_path, manifest_path, network_id=network_id,
        verified_policy=verified_policy,
        receiver_witness_anchor=receiver_witness_anchor,
        require_existing_anchor=require_existing_anchor,
    )
    if observation_journal is not None:
        observe_witness_statement(
            verified["witness"], verified_policy=verified_policy,
            network_id=network_id, genesis_hash=verified["body"]["genesis_hash"],
            journal_path=observation_journal,
        )
    return verified


def advance_receiver_anchor(*args, **kwargs):
    return v2.advance_receiver_anchor(*args, **kwargs)
