"""
Stevens Chain v0.5.2 + Stevens Sentinel v1.1 Strong-Attack Fixes.

Consensus/network rules remain Stevens Chain v0.5.2.
Sentinel is a local HTTP/telemetry defense layer only.
"""

from __future__ import annotations

import json
import ipaddress
import secrets
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import stevens_testnet_v0_5 as base
from stevens_sentinel_v1_1 import StevensSentinel

NODE_HARDENING_VERSION = "0.5.2-sentinel1.1-r3"
NETWORK_ID = base.NETWORK_ID


class V11TrustSentinelHandler(base.Handler):
    sentinel: StevensSentinel | None = None
    trusted_proxy_networks = []

    def _ip(self):
        raw = self.client_address[0]
        try:
            raw_addr = ipaddress.ip_address(raw)
        except ValueError:
            return raw

        if any(raw_addr in net for net in self.trusted_proxy_networks):
            forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
            if forwarded:
                try:
                    return str(ipaddress.ip_address(forwarded))
                except ValueError:
                    pass
        return raw

    def _sentinel_operator_ok(self) -> bool:
        if not self.sentinel:
            return False
        return self.sentinel.operator_authorized(
            self.headers.get("Authorization"),
            self.headers.get("X-Stevens-Sentinel-Token")
        )

    def _trusted_operator(self) -> bool:
        # Adaptive bypass requires an explicit secret. Do NOT treat loopback
        # source address alone as a Sentinel bypass because a reverse proxy may
        # connect from loopback. Existing v0.5.2 admin-route authorization is
        # unchanged for the admin routes themselves.
        if self._sentinel_operator_ok():
            return True
        token = self.admin_token
        if not token:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return secrets.compare_digest(auth[len("Bearer "):].strip(), token)

    def _canary_header_hit(self) -> bool:
        if not self.sentinel:
            return False
        fields = [
            self.headers.get("Authorization"),
            self.headers.get("X-API-Key"),
            self.headers.get("X-Stevens-Sentinel-Token"),
        ]
        return any(self.sentinel.contains_canary_token(v) for v in fields)

    def _adaptive_preflight(self) -> bool:
        if not self.sentinel or self._trusted_operator():
            return True

        ip = self._ip()
        self._sentinel_receipt_to_issue = None
        decision = self.sentinel.preflight(
            ip,
            self.headers.get("X-Stevens-Challenge-Nonce"),
            self.headers.get("X-Stevens-Challenge-Solution"),
            self.headers.get("X-Stevens-Proof-Receipt"),
            self.headers.get("X-Stevens-Receipt-Binding"),
        )
        action = decision["action"]

        if action == "ALLOW":
            if decision.get("proof_receipt"):
                self._sentinel_receipt_to_issue = decision["proof_receipt"]
            return True

        if action == "CHALLENGE":
            c = decision["challenge"]
            self.sentinel.record(
                "INFO", "request_challenged", source_ip=ip,
                details={"path": urlparse(self.path).path,
                         "difficulty_bits": c["difficulty_bits"],
                         "expires_at": c["expires_at"]},
                affect_score=False
            )
            base.Handler._send(self, 428, {
                "error": "adaptive challenge required",
                "challenge": c,
                "observed_source_ip": ip,
                "proof_headers": {
                    "nonce": "X-Stevens-Challenge-Nonce",
                    "solution": "X-Stevens-Challenge-Solution",
                    "receipt": "X-Stevens-Proof-Receipt",
                    "binding": "X-Stevens-Receipt-Binding"
                }
            })
            return False

        if action == "QUARANTINE":
            subject = decision["subject"]
            retry = max(1, int(subject["quarantine_until"]) - __import__("time").time())
            self.sentinel.record(
                "INFO", "quarantine_block", source_ip=ip,
                details={"path": urlparse(self.path).path, "retry_after": int(retry)},
                affect_score=False
            )
            base.Handler._send(self, 403, {
                "error": "temporarily quarantined",
                "retry_after_seconds": int(retry)
            })
            return False

        if action == "ISOLATE":
            self.sentinel.record(
                "INFO", "isolation_block", source_ip=ip,
                details={"path": urlparse(self.path).path},
                affect_score=False
            )
            # Conceal the adaptive-control surface from an isolated source.
            base.Handler._send(self, 404, {"error": "not found"})
            return False

        return True

    def _rate_check(self):
        if not self._adaptive_preflight():
            return False
        return super()._rate_check()

    def _verified_payload(self, expected_kind: str):
        node_id, payload = super()._verified_payload(expected_kind)
        if self.sentinel and expected_kind == "tx":
            self.sentinel.inspect_transaction(
                payload.get("transaction", {}), self._ip(), node_id
            )
        return node_id, payload

    def _send(self, code, obj, ctype="application/json"):
        if self.sentinel and code >= 400:
            details = {"path": urlparse(self.path).path, "code": int(code)}
            if isinstance(obj, dict) and "error" in obj:
                details["error"] = str(obj["error"])[:500]

            severity = "LOW"
            category = "http_rejection"
            error = details.get("error", "").lower()

            if code == 429:
                severity = "MEDIUM"
                category = "rate_limit_rejection"
            if any(x in error for x in (
                "invalid spend signature", "bad transaction id",
                "wrong coinbase reward", "multiple coinbase",
                "invalid proof of work", "replayed peer message",
                "invalid peer signature", "downgraded note encryption",
                "admin authorization required",
            )):
                severity = "HIGH"
                category = "security_rejection"

            # Do not score adaptive control responses again; those use
            # base.Handler._send directly.
            self.sentinel.record(
                severity, category, self._ip(),
                details=details, affect_score=True
            )
        if ctype == "application/json":
            data = json.dumps(obj, indent=2).encode()
        else:
            data = obj.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Stevens-Network", NETWORK_ID)
        receipt = getattr(self, "_sentinel_receipt_to_issue", None)
        if code < 400 and receipt:
            self.send_header("X-Stevens-Proof-Receipt", receipt)
            self._sentinel_receipt_to_issue = None
        self.end_headers()
        self.wfile.write(data)
        return None

    def _handle_sentinel_canary(self) -> bool:
        if not self.sentinel:
            return False
        path = urlparse(self.path).path
        ip = self._ip()

        if self._canary_header_hit():
            self.sentinel.trigger_canary(
                ip, "token_presented", {"path": path}
            )
            base.Handler._send(self, 404, {"error": "not found"})
            return True

        if self.sentinel.is_canary_path(path):
            self.sentinel.trigger_canary(
                ip, "path_hit",
                {"path": path, "user_agent": self.headers.get("User-Agent", "")}
            )
            base.Handler._send(self, 404, {"error": "not found"})
            return True
        return False

    def do_GET(self):
        if self._handle_sentinel_canary():
            return

        path = urlparse(self.path).path
        if self.sentinel and path.startswith("/sentinel/"):
            if not self._sentinel_operator_ok():
                return base.Handler._send(self, 404, {"error": "not found"})

            if path == "/sentinel/status":
                return base.Handler._send(self, 200, self.sentinel.summary())

            if path == "/sentinel/global-threat":
                return base.Handler._send(self, 200, self.sentinel.global_threat())

            if path == "/sentinel/resource-status":
                return base.Handler._send(self, 200, self.sentinel.resource_status())

            if path == "/sentinel/fairness-status":
                return base.Handler._send(self, 200, self.sentinel.fairness_status())

            if path == "/sentinel/reliability-status":
                return base.Handler._send(self, 200, self.sentinel.reliability_status())

            if path == "/sentinel/receipt-status":
                return base.Handler._send(self, 200, self.sentinel.receipt_status())

            if path == "/sentinel/keyring-safety-status":
                return base.Handler._send(self, 200, self.sentinel.keyring_safety_status())

            if path == "/sentinel/issuer-bundle":
                return base.Handler._send(self, 200, self.sentinel.export_receipt_issuer_bundle())

            if path == "/sentinel/cluster-trust-status":
                return base.Handler._send(self, 200, self.sentinel.cluster_trust_status())

            if path == "/sentinel/cluster-receipt-status":
                return base.Handler._send(self, 200, self.sentinel.cluster_receipt_status())

            if path == "/sentinel/v1-status":
                return base.Handler._send(self, 200, self.sentinel.v1_status())

            if path == "/sentinel/v1-trust-status":
                return base.Handler._send(self, 200, self.sentinel.v1_trust_status())

            if path == "/sentinel/v1-issuer-bundle":
                return base.Handler._send(self, 200, self.sentinel.export_v1_issuer_bundle())

            if path == "/sentinel/v1-issuer-policy":
                return base.Handler._send(self, 200, self.sentinel.export_issuer_policy_bundle())

            if path == "/sentinel/events":
                q = parse_qs(urlparse(self.path).query)
                limit = int(q.get("limit", [100])[0])
                return base.Handler._send(self, 200, {
                    "events": self.sentinel.recent_events(limit)
                })

            if path == "/sentinel/subjects":
                q = parse_qs(urlparse(self.path).query)
                limit = int(q.get("limit", [100])[0])
                return base.Handler._send(self, 200, {
                    "subjects": self.sentinel.subjects(limit)
                })

            if path == "/sentinel/review-bundle":
                return base.Handler._send(self, 200, self.sentinel.review_bundle())

            return base.Handler._send(self, 404, {"error": "not found"})

        return super().do_GET()

    def do_POST(self):
        if self._handle_sentinel_canary():
            return

        path = urlparse(self.path).path
        if self.sentinel and path.startswith("/sentinel/"):
            if not self._sentinel_operator_ok():
                return base.Handler._send(self, 404, {"error": "not found"})

            if path == "/sentinel/subject/clear":
                body = self._read_json()
                source_ip = str(body["source_ip"])
                self.sentinel.clear_subject(source_ip)
                return base.Handler._send(self, 200, {"cleared": source_ip})

            if path == "/sentinel/honey/register":
                body = self._read_json()
                outpoint = self.sentinel.register_honey_outpoint(
                    str(body["txid"]), int(body["index"])
                )
                return base.Handler._send(self, 200, {"registered": outpoint})

            return base.Handler._send(self, 404, {"error": "not found"})

        return super().do_POST()


def serve(data_dir: str, genesis_file: str, host: str, port: int,
          peers=None, faucet_wallet_file=None, faucet_password=None,
          public_url=None, admin_token_file=None, sentinel_dir=None,
          trusted_proxies=None, sentinel_local_dev_recovery=False,
          bootstrap_policy_file=None):
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True)

    doc = json.load(open(genesis_file))
    if doc.get("network") != base.NETWORK_ID:
        raise ValueError(
            f"genesis network mismatch: got {doc.get('network')!r}, expected {base.NETWORK_ID!r}"
        )
    canonical_genesis = doc["block"]

    chain = base.TestnetChain(data)
    chain.load()
    if not chain.blocks:
        chain.initialize_from_genesis_block(canonical_genesis)
    elif chain.blocks[0]["hash"] != canonical_genesis["hash"]:
        raise ValueError("existing data directory belongs to a different genesis/testnet")

    identity = base.NodeIdentity.load_or_create(data / "node_identity.json")
    self_url = (public_url or f"http://{host}:{port}").rstrip("/")
    node = base.TestnetNode(chain, identity, self_url)

    if bootstrap_policy_file:
        policy = base.load_bootstrap_policy(bootstrap_policy_file)
        node.configure_bootstrap_policy(policy)
        for spec in policy["specs"]:
            try:
                node.add_bootstrap_peer(spec)
            except Exception:
                pass
        health = node.bootstrap_health()
        if policy.get("require_quorum", True) and not health["quorum_met"]:
            raise ValueError(
                "bootstrap operator quorum not satisfied at startup: "
                f"active_groups={health['active_operator_groups']} "
                f"required={health['minimum_operator_groups']}"
            )

    for p in peers or []:
        try:
            node.add_peer(p)
        except Exception:
            pass

    V11TrustSentinelHandler.node = node
    V11TrustSentinelHandler.faucet = None
    V11TrustSentinelHandler.admin_token = None
    V11TrustSentinelHandler.sentinel = None
    V11TrustSentinelHandler.trusted_proxy_networks = []
    for item in trusted_proxies or []:
        try:
            # Exact addresses and CIDRs are accepted.
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
            else:
                addr = ipaddress.ip_address(item)
                net = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
            V11TrustSentinelHandler.trusted_proxy_networks.append(net)
        except ValueError as e:
            raise ValueError(f"invalid trusted proxy {item!r}: {e}")

    if admin_token_file:
        token = Path(admin_token_file).read_text().strip()
        if len(token) < base.MIN_ADMIN_TOKEN_CHARS:
            raise ValueError(
                f"admin token must be at least {base.MIN_ADMIN_TOKEN_CHARS} characters"
            )
        V11TrustSentinelHandler.admin_token = token

    if sentinel_dir:
        V11TrustSentinelHandler.sentinel = StevensSentinel.load_or_create(
            sentinel_dir, public_base_url=self_url,
            allow_local_dev_recovery=bool(sentinel_local_dev_recovery)
        )

    if faucet_wallet_file:
        if not faucet_password:
            raise ValueError("faucet password required when faucet wallet is enabled")
        fw = base.ledger.Wallet.load(faucet_wallet_file, faucet_password)
        V11TrustSentinelHandler.faucet = base.Faucet(chain, fw, data)

    server = ThreadingHTTPServer((host, port), V11TrustSentinelHandler)
    print(f"Stevens Chain v0.5.2 + Sentinel v1.1: {self_url}", flush=True)
    print(f"network_id={base.NETWORK_ID}", flush=True)
    print(f"node_id={identity.node_id}", flush=True)
    print(f"height={len(chain.blocks)-1} tip={chain.blocks[-1]['hash']}", flush=True)
    if V11TrustSentinelHandler.sentinel:
        print("adaptive + swarm + fail-closed-anchor + replay-defense + serialized-trust: ENABLED",
              flush=True)
        if V11TrustSentinelHandler.trusted_proxy_networks:
            print("trusted proxies: " + ", ".join(map(str, V11TrustSentinelHandler.trusted_proxy_networks)),
                  flush=True)
        print("AI is outside consensus; review bundles are recommendation-only.", flush=True)
    else:
        print("adaptive defense: disabled (use --sentinel-dir)", flush=True)
    print("TESTNET ONLY — no real funds.", flush=True)
    server.serve_forever()
