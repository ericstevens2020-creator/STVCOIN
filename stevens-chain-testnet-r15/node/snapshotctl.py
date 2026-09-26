#!/usr/bin/env python3
"""Stevens Chain authenticated snapshot CLI (testnet r8).

Default path uses root-signed key policy v2 with operator/witness rotation and
revocation. snapshotctl_r7_legacy.py is retained only for reproducibility of the
older r7 tests; new operations should use this CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import snapshot_trust_v1 as legacy
import snapshot_trust_v2 as trust
import stevens_testnet_v0_5 as base
import stevens_chain_v0_3 as core


def read_pub(path: str) -> str:
    s = Path(path).read_text(encoding="utf-8").strip()
    if s.startswith("{"):
        d = json.loads(s)
        s = str(d.get("public_key", d.get("root_pubkey", "")))
    raw = bytes.fromhex(s)
    if len(raw) != 32:
        raise ValueError("trusted public key must be 32 bytes")
    return s.lower()


def parse_role_specs(values: list[str]) -> dict[str, str]:
    out = {}
    for item in values:
        try:
            path, status = item.rsplit(":", 1)
        except ValueError as e:
            raise ValueError("authority policy entries must be PATH:active or PATH:revoked") from e
        status = status.lower()
        if status not in trust.ALLOWED_STATUS:
            raise ValueError("authority policy status must be active or revoked")
        pub = read_pub(path)
        if pub in out:
            raise ValueError("duplicate authority public key in policy arguments")
        out[pub] = status
    return out


def load_chain(data_dir: str) -> base.TestnetChain:
    chain = base.TestnetChain(data_dir)
    chain.load()
    if not chain.blocks:
        raise ValueError("chain database contains no genesis")
    chain.validate_chain(rebuild=True)
    return chain


def verify_policy(args, genesis_hash: str | None = None, *, anchor_attr="policy_anchor", init_attr="initialize_policy_anchor"):
    root_pub = read_pub(args.trusted_root_pub)
    anchor = getattr(args, anchor_attr, None)
    initialize = bool(getattr(args, init_attr, False))
    return trust.verify_trust_policy(
        args.trust_policy,
        trusted_root_pubkey=root_pub,
        network_id=base.NETWORK_ID,
        genesis_hash=genesis_hash,
        receiver_policy_anchor=anchor,
        require_existing_anchor=(bool(anchor) and not initialize),
    )


def main():
    ap = argparse.ArgumentParser(description="Stevens Chain authenticated snapshot utility r8")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key")
    g.add_argument("--role", choices=["root", "operator", "witness"], required=True)
    g.add_argument("--out", required=True)

    p = sub.add_parser("issue-policy")
    p.add_argument("--root-key", required=True)
    p.add_argument("--policy-state", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--genesis-hash", required=True)
    p.add_argument("--operator", action="append", default=[], help="PATH:active or PATH:revoked")
    p.add_argument("--witness", action="append", default=[], help="PATH:active or PATH:revoked")
    p.add_argument("--initialize-policy-state", action="store_true")

    e = sub.add_parser("export")
    e.add_argument("--data-dir", required=True)
    e.add_argument("--snapshot", required=True)
    e.add_argument("--manifest", required=True)
    e.add_argument("--operator-key", required=True)
    e.add_argument("--witness-key", required=True)
    e.add_argument("--witness-state", required=True)
    e.add_argument("--trust-policy", required=True)
    e.add_argument("--trusted-root-pub", required=True)
    e.add_argument("--policy-anchor", required=True, help="signer-side monotonic policy anchor")
    e.add_argument("--initialize-policy-anchor", action="store_true")
    e.add_argument("--initialize-witness-state", action="store_true")

    f = sub.add_parser("fetch")
    f.add_argument("--manifest-url", required=True)
    f.add_argument("--snapshot-url", required=True)
    f.add_argument("--out-dir", required=True)
    f.add_argument("--trust-policy", required=True)
    f.add_argument("--trusted-root-pub", required=True)
    f.add_argument("--policy-anchor")
    f.add_argument("--require-existing-policy-anchor", action="store_true")
    f.add_argument("--timeout", type=float, default=10.0)

    v = sub.add_parser("verify")
    for x in (v,):
        x.add_argument("--snapshot", required=True)
        x.add_argument("--manifest", required=True)
        x.add_argument("--trust-policy", required=True)
        x.add_argument("--trusted-root-pub", required=True)
        x.add_argument("--policy-anchor")
        x.add_argument("--witness-anchor")
        x.add_argument("--require-existing-anchors", action="store_true")

    i = sub.add_parser("import")
    i.add_argument("--data-dir", required=True)
    i.add_argument("--snapshot", required=True)
    i.add_argument("--manifest", required=True)
    i.add_argument("--trust-policy", required=True)
    i.add_argument("--trusted-root-pub", required=True)
    i.add_argument("--policy-anchor", required=True)
    i.add_argument("--witness-anchor", required=True)
    i.add_argument("--initialize-anchors", action="store_true")

    args = ap.parse_args()

    if args.cmd == "gen-key":
        if args.role == "root":
            result = trust.create_trust_root_key(args.out)
        else:
            result = legacy.create_authority_key(args.out, args.role)
        print(json.dumps(result, indent=2))
        return

    if args.cmd == "issue-policy":
        operators = parse_role_specs(args.operator)
        witnesses = parse_role_specs(args.witness)
        doc = trust.issue_trust_policy(
            args.out, state_path=args.policy_state,
            network_id=base.NETWORK_ID, genesis_hash=args.genesis_hash,
            root_key_path=args.root_key,
            operators=operators, witnesses=witnesses,
            initialize_state=args.initialize_policy_state,
        )
        print(json.dumps({"policy_revision": doc["body"]["revision"], "policy_sha256": trust.policy_body_hash(doc["body"])}, indent=2))
        return

    if args.cmd == "fetch":
        root_pub = read_pub(args.trusted_root_pub)
        vp = trust.verify_trust_policy(
            args.trust_policy, trusted_root_pubkey=root_pub,
            network_id=base.NETWORK_ID,
            receiver_policy_anchor=args.policy_anchor,
            require_existing_anchor=args.require_existing_policy_anchor,
        )
        result = trust.fetch_authenticated_bundle(
            manifest_url=args.manifest_url, snapshot_url=args.snapshot_url,
            out_dir=args.out_dir, network_id=base.NETWORK_ID,
            verified_policy=vp, timeout=args.timeout,
            max_snapshot_bytes=core.MAX_SNAPSHOT_BYTES,
        )
        print(json.dumps(result, indent=2))
        return

    if args.cmd == "export":
        chain = load_chain(args.data_dir)
        vp = verify_policy(args, chain.blocks[0]["hash"])
        meta = chain.export_snapshot(args.snapshot)
        manifest = trust.sign_snapshot(
            args.snapshot, args.manifest,
            network_id=base.NETWORK_ID, genesis_hash=chain.blocks[0]["hash"],
            height=meta["height"], tip=meta["tip"], cumulative_work=meta["cumulative_work"],
            operator_key_path=args.operator_key, witness_key_path=args.witness_key,
            witness_state_path=args.witness_state, verified_policy=vp,
            initialize_witness_state=args.initialize_witness_state,
        )
        # Anchor the root policy only after the signing operation succeeded.
        trust.advance_policy_anchor(vp, args.policy_anchor)
        print(json.dumps({
            "snapshot": meta, "manifest": manifest["body"],
            "witness_revision": manifest["witness"]["body"]["revision"],
            "policy_revision": vp["body"]["revision"],
        }, indent=2))
        return

    root_pub = read_pub(args.trusted_root_pub)
    if args.cmd == "verify":
        vp = trust.verify_trust_policy(
            args.trust_policy, trusted_root_pubkey=root_pub,
            network_id=base.NETWORK_ID,
            receiver_policy_anchor=args.policy_anchor,
            require_existing_anchor=(args.require_existing_anchors and bool(args.policy_anchor)),
        )
        verified = trust.verify_snapshot(
            args.snapshot, args.manifest, network_id=base.NETWORK_ID,
            verified_policy=vp, receiver_witness_anchor=args.witness_anchor,
            require_existing_anchor=(args.require_existing_anchors and bool(args.witness_anchor)),
        )
        print(json.dumps({"verified": True, "body": verified["body"], "witness": verified["witness"]["body"], "policy_revision": vp["body"]["revision"]}, indent=2))
        return

    # import
    chain = load_chain(args.data_dir)
    vp = trust.verify_trust_policy(
        args.trust_policy, trusted_root_pubkey=root_pub,
        network_id=base.NETWORK_ID, genesis_hash=chain.blocks[0]["hash"],
        receiver_policy_anchor=args.policy_anchor,
        require_existing_anchor=not args.initialize_anchors,
    )
    verified = trust.verify_snapshot(
        args.snapshot, args.manifest, network_id=base.NETWORK_ID,
        verified_policy=vp, receiver_witness_anchor=args.witness_anchor,
        require_existing_anchor=not args.initialize_anchors,
    )
    body = verified["body"]
    blocks, _ = chain._validate_snapshot_file(args.snapshot)
    if blocks[-1]["hash"] != body["tip"] or len(blocks)-1 != int(body["height"]):
        raise ValueError("authenticated manifest does not match validated snapshot chain")
    if base.cumulative_work(blocks) != int(body["cumulative_work"]):
        raise ValueError("authenticated manifest cumulative work mismatch")
    result = chain.import_snapshot(args.snapshot)
    # External anchors advance only after successful database replacement.
    trust.advance_policy_anchor(vp, args.policy_anchor)
    trust.advance_receiver_anchor(verified, args.witness_anchor)
    print(json.dumps({"imported": result, "witness_revision": verified["witness"]["body"]["revision"], "policy_revision": vp["body"]["revision"]}, indent=2))


if __name__ == "__main__":
    main()
