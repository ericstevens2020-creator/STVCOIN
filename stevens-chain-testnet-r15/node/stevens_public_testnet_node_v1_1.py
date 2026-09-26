#!/usr/bin/env python3
"""Stevens Chain public-testnet node entrypoint.

Operational wrapper around Stevens Chain v0.5.2 + Sentinel v1.1.
It preserves the existing consensus/network rules and exposes an explicit
external anti-rollback anchor file for Sentinel v1.1.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import stevens_testnet_v0_5 as base
from stevens_sentinel_v1_1 import StevensSentinel
from stevens_testnet_v0_5_2_sentinel_v1_1 import V11TrustSentinelHandler


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with a hard cap on active request handlers."""
    daemon_threads = True
    request_queue_size = 64
    MAX_ACTIVE_REQUESTS = 64

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._request_slots = threading.BoundedSemaphore(self.MAX_ACTIVE_REQUESTS)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def serve(data_dir: str, genesis_file: str, host: str, port: int,
          peers=None, faucet_wallet_file=None, faucet_password=None,
          public_url=None, admin_token_file=None, sentinel_dir=None,
          sentinel_anchor_file=None, trusted_proxies=None, sentinel_local_dev_recovery=False,
          bootstrap_policy_file=None, build_identity_file=None):
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True)

    doc = json.load(open(genesis_file))
    if doc.get('network') != base.NETWORK_ID:
        raise ValueError(
            f"genesis network mismatch: got {doc.get('network')!r}, expected {base.NETWORK_ID!r}"
        )
    canonical_genesis = doc['block']

    chain = base.TestnetChain(data)
    chain.load()
    if not chain.blocks:
        chain.initialize_from_genesis_block(canonical_genesis)
    elif chain.blocks[0]['hash'] != canonical_genesis['hash']:
        raise ValueError('existing data directory belongs to a different genesis/testnet')

    identity = base.NodeIdentity.load_or_create(data / 'node_identity.json')
    self_url = (public_url or f'http://{host}:{port}').rstrip('/')
    node = base.TestnetNode(chain, identity, self_url)

    if bootstrap_policy_file:
        policy = base.load_bootstrap_policy(bootstrap_policy_file)
        node.configure_bootstrap_policy(policy)
        for spec in policy['specs']:
            try:
                node.add_bootstrap_peer(spec)
            except Exception:
                pass
        health = node.bootstrap_health()
        if policy.get('require_quorum', True) and not health['quorum_met']:
            raise ValueError(
                'bootstrap operator quorum not satisfied at startup: ' +
                f"active_groups={health['active_operator_groups']} " +
                f"required={health['minimum_operator_groups']}"
            )

    configured_peers = [str(p).rstrip("/") for p in (peers or [])]

    for p in configured_peers:
        try:
            node.add_peer(p)
        except Exception:
            pass

    def _retry_persisted_peers():
        from concurrent.futures import (
            ThreadPoolExecutor,
            as_completed,
        )

        # Persisted candidates were validated locally by
        # TestnetNode._load_persisted_peers(). Snapshot them
        # while holding the same lock used when the candidate
        # cache is refreshed.
        try:
            with node.peers.lock:
                candidates = [
                    (
                        str(
                            item.get("url")
                            or url
                        ).rstrip("/"),
                        str(
                            item.get("node_id")
                            or ""
                        ).lower(),
                    )
                    for url, item
                    in node.persisted_peer_candidates.items()
                    if isinstance(item, dict)
                ]
        except Exception as e:
            print(
                "[testnet] persisted-peer "
                "candidate snapshot warning:",
                e,
            )
            return

        pending = []
        seen_urls = set()

        for (
            peer_url,
            expected_node_id,
        ) in candidates:

            if not peer_url:
                continue

            if peer_url in seen_urls:
                continue

            seen_urls.add(
                peer_url
            )

            if (
                len(expected_node_id) != 32
                or any(
                    c not in
                    "0123456789abcdef"
                    for c in expected_node_id
                )
            ):
                continue

            with node.peers.lock:
                already_present = (
                    peer_url
                    in node.peers.records
                )

            if already_present:
                continue

            pending.append(
                (
                    peer_url,
                    expected_node_id,
                )
            )

        if not pending:
            return

        # Fixed worker bound prevents a persisted-peer list
        # from creating unbounded retry threads/resources.
        worker_count = min(
            4,
            len(pending),
        )

        def _attempt_peer(
            peer_url,
            expected_node_id,
        ):
            # Another path may have admitted the peer while
            # this retry batch was being prepared.
            with node.peers.lock:
                if (
                    peer_url
                    in node.peers.records
                ):
                    return (
                        "present",
                        peer_url,
                    )

            try:
                rec = node.add_peer(
                    peer_url,
                    expected_node_id=(
                        expected_node_id
                    ),
                    persist=False,
                )

                if rec is None:
                    return (
                        "skipped",
                        peer_url,
                    )

                return (
                    "restored",
                    peer_url,
                )

            except Exception:
                return (
                    "failed",
                    peer_url,
                )

        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix=(
                "stevens-peer-retry"
            ),
        ) as pool:

            futures = [
                pool.submit(
                    _attempt_peer,
                    peer_url,
                    expected_node_id,
                )
                for (
                    peer_url,
                    expected_node_id,
                )
                in pending
            ]

            for future in as_completed(
                futures
            ):
                try:
                    status, peer_url = (
                        future.result()
                    )
                except Exception as e:
                    print(
                        "[testnet] persisted-peer "
                        "retry task warning:",
                        e,
                    )
                    continue

                if status == "restored":
                    print(
                        "[testnet] restored "
                        "persisted peer",
                        peer_url,
                    )

    def _persisted_peer_retry_worker():
        while True:
            try:
                _retry_persisted_peers()
            except Exception as e:
                print(
                    "[testnet] persisted-peer worker warning:",
                    e,
                )

            time.sleep(10)

    def _auto_sync_worker():
        while True:
            try:
                # Reconnect configured peers that may have been offline.
                for peer_url in configured_peers:
                    try:
                        if peer_url not in node.peers.records:
                            node.add_peer(peer_url)
                    except Exception:
                        pass

                # Uses existing verified headers-first synchronization.
                adopted, source = node.headers_first_sync()

                if adopted:
                    print(
                        "[testnet] auto-sync adopted chain from",
                        source,
                        "height",
                        node.chain.public_status()["height"],
                    )
            except Exception as e:
                print("[testnet] auto-sync warning:", e)

            time.sleep(10)

    V11TrustSentinelHandler.node = node
    V11TrustSentinelHandler.faucet = None
    V11TrustSentinelHandler.admin_token = None
    V11TrustSentinelHandler.sentinel = None
    V11TrustSentinelHandler.trusted_proxy_networks = []
    V11TrustSentinelHandler.build_identity = None

    if build_identity_file:
        bp = Path(build_identity_file)
        if not bp.is_file() or bp.stat().st_size > 65536:
            raise ValueError('build identity file missing or oversized')
        build_identity = json.loads(bp.read_text(encoding='utf-8'))
        if (build_identity.get('format') != 'StevensBuildIdentity' or
                int(build_identity.get('version', 0)) != 1 or
                build_identity.get('network_id') != base.NETWORK_ID):
            raise ValueError('build identity file invalid or wrong network')
        V11TrustSentinelHandler.build_identity = build_identity

    for item in trusted_proxies or []:
        if '/' in item:
            net = ipaddress.ip_network(item, strict=False)
        else:
            addr = ipaddress.ip_address(item)
            net = ipaddress.ip_network(f'{addr}/{addr.max_prefixlen}', strict=False)
        V11TrustSentinelHandler.trusted_proxy_networks.append(net)

    if admin_token_file:
        token = Path(admin_token_file).read_text().strip()
        if len(token) < base.MIN_ADMIN_TOKEN_CHARS:
            raise ValueError(
                f'admin token must be at least {base.MIN_ADMIN_TOKEN_CHARS} characters'
            )
        V11TrustSentinelHandler.admin_token = token

    if sentinel_dir:
        V11TrustSentinelHandler.sentinel = StevensSentinel.load_or_create(
            sentinel_dir,
            public_base_url=self_url,
            external_anchor_path=(
                Path(sentinel_anchor_file) if sentinel_anchor_file else None
            ),
            allow_local_dev_recovery=bool(sentinel_local_dev_recovery),
            allow_local_dev_admin=bool(sentinel_local_dev_recovery),
        )

    if faucet_wallet_file:
        if not faucet_password:
            raise ValueError('faucet password required when faucet wallet is enabled')
        fw = base.ledger.Wallet.load(faucet_wallet_file, faucet_password)
        V11TrustSentinelHandler.faucet = base.Faucet(chain, fw, data)

    server = BoundedThreadingHTTPServer((host, port), V11TrustSentinelHandler)
    print(f'Stevens Chain public-testnet node on http://{host}:{port}')
    print('network:', base.NETWORK_ID)
    print('node id:', identity.node_id)
    print('height:', chain.public_status()['height'])
    if sentinel_anchor_file:
        print('sentinel external anchor:', sentinel_anchor_file)

    persisted_retry_thread = threading.Thread(
        target=_persisted_peer_retry_worker,
        name="stevens-persisted-peer-retry",
        daemon=True,
    )
    persisted_retry_thread.start()

    sync_thread = threading.Thread(
        target=_auto_sync_worker,
        name="stevens-auto-sync",
        daemon=True,
    )
    sync_thread.start()

    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description='Stevens Chain Public Testnet Node + Sentinel v1.1')
    ap.add_argument('--data-dir', required=True)
    ap.add_argument('--genesis-file', required=True)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--peer', action='append', default=[])
    ap.add_argument('--faucet-wallet')
    ap.add_argument('--faucet-password')
    ap.add_argument('--faucet-password-file',
                    help='Read faucet wallet password from a bounded local file instead of process arguments')
    ap.add_argument('--public-url')
    ap.add_argument('--admin-token-file')
    ap.add_argument('--sentinel-dir')
    ap.add_argument('--sentinel-anchor-file')
    ap.add_argument('--trusted-proxy', action='append', default=[])
    ap.add_argument('--bootstrap-policy', help='Optional pinned bootstrap peer/operator-diversity policy JSON')
    ap.add_argument('--build-identity-file', help='Bounded packaged build identity JSON exposed on /hello')
    ap.add_argument('--sentinel-local-dev-recovery', action='store_true',
                    help='TESTNET ONLY: local recovery/admin shares outside node state. Use external HSM/KMS/off-host signers for production.')
    args = ap.parse_args()
    if args.faucet_password and args.faucet_password_file:
        ap.error('use only one of --faucet-password or --faucet-password-file')
    faucet_password = args.faucet_password
    if args.faucet_password_file:
        fp = Path(args.faucet_password_file)
        try:
            if fp.stat().st_size <= 0 or fp.stat().st_size > 4096:
                raise ValueError('faucet password file size is invalid or exceeds 4096 bytes')
            faucet_password = fp.read_text(encoding='utf-8').rstrip('\r\n')
        except OSError as e:
            ap.error(f'unable to read faucet password file: {e}')
        if not faucet_password:
            ap.error('faucet password file is empty')
    serve(
        args.data_dir, args.genesis_file, args.host, args.port,
        peers=args.peer,
        faucet_wallet_file=args.faucet_wallet,
        faucet_password=faucet_password,
        public_url=args.public_url,
        admin_token_file=args.admin_token_file,
        sentinel_dir=args.sentinel_dir,
        sentinel_anchor_file=args.sentinel_anchor_file,
        trusted_proxies=args.trusted_proxy,
        sentinel_local_dev_recovery=args.sentinel_local_dev_recovery,
        bootstrap_policy_file=args.bootstrap_policy,
        build_identity_file=args.build_identity_file,
    )

if __name__ == '__main__':
    main()
