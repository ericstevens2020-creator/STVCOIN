"""Stevens Sentinel v1.0 — Revocable trust + anti-rollback hardening.

Defensive/testnet code. No blockchain consensus changes.
"""
from __future__ import annotations

import hashlib, json, os, secrets, threading, time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from stevens_sentinel_v0_2 import canonical
from stevens_sentinel_v0_4 import _b64e, _b64d
from stevens_sentinel_v0_9 import StevensSentinel as ClusterSentinel, ClusterReceiptPolicy
from stevens_sentinel_v0_8 import KeyringSafetyPolicy
from stevens_sentinel_v0_7 import ReceiptPolicy
from stevens_sentinel_v0_6 import ReliabilityPolicy
from stevens_sentinel_v0_5 import FairnessPolicy
from stevens_sentinel_v0_4 import ResourcePolicy
from stevens_sentinel_v0_3 import SwarmPolicy

VERSION = "1.0"

@dataclass(frozen=True)
class V1TrustPolicy:
    certificate_lifetime_seconds: int = 15 * 60
    recovery_signature_threshold: int = 2
    recovery_key_count: int = 3
    auto_advance_embedded_issuer_policy: bool = True
    allow_legacy_v3_receipts: bool = True
    require_external_anchor: bool = True

    def to_dict(self):
        return {"format":"StevensSentinelV1TrustPolicy","version":1,**self.__dict__}

    @classmethod
    def from_dict(cls, d):
        if d.get("format") != "StevensSentinelV1TrustPolicy" or int(d.get("version",0)) != 1:
            raise ValueError("invalid v1 trust policy")
        x = cls()
        return cls(**{k:d.get(k,getattr(x,k)) for k in x.__dict__})

    def validate(self):
        if not (60 <= int(self.certificate_lifetime_seconds) <= 86400):
            raise ValueError("certificate lifetime out of range")
        if int(self.recovery_key_count) != 3 or int(self.recovery_signature_threshold) != 2:
            raise ValueError("v1 requires 2-of-3 recovery signatures")

class StevensSentinel(ClusterSentinel):
    def __init__(self, data_dir, config, swarm_policy=None, resource_policy=None,
                 fairness_policy=None, reliability_policy=None, receipt_policy=None,
                 keyring_safety_policy=None, cluster_receipt_policy=None,
                 v1_trust_policy=None, external_anchor_path=None):
        self._v1_lock = threading.RLock()
        super().__init__(data_dir, config, swarm_policy=swarm_policy,
                         resource_policy=resource_policy,
                         fairness_policy=fairness_policy,
                         reliability_policy=reliability_policy,
                         receipt_policy=receipt_policy,
                         keyring_safety_policy=keyring_safety_policy,
                         cluster_receipt_policy=cluster_receipt_policy)
        self.v1_trust_policy_path = self.data_dir / "sentinel_v1_trust_policy.json"
        self.v1_recovery_keys_path = self.data_dir.parent / f".{self.data_dir.name}.sentinel_v1_recovery_keys.json"
        self.v1_issuer_policy_path = self.data_dir / "sentinel_v1_issuer_policy.json"
        self.v1_peer_policy_state_path = self.data_dir / "sentinel_v1_peer_policy_state.json"
        self.v1_trust_admin_identity_path = self.data_dir.parent / f".{self.data_dir.name}.sentinel_v1_trust_admin_identity.json"
        self.v1_trust_journal_dir = self.data_dir / "sentinel_v1_trust_journal"
        self.v1_trust_cache_path = self.data_dir / "sentinel_v1_trust_cache.json"
        self.external_anchor_path = Path(external_anchor_path or (self.data_dir.parent / f".{self.data_dir.name}.sentinel_v1_anchor.json"))

        self.v1_trust_policy = v1_trust_policy or self._load_or_create_v1_trust_policy()
        self.v1_trust_policy.validate()
        self._v1_recovery = self._load_or_create_recovery_keys()
        self._v1_admin = self._load_or_create_trust_admin_identity()
        self._v1_issuer_policy = self._load_or_create_issuer_policy()
        self._v1_peer_policies = self._load_or_create_peer_policy_state()
        self._v1_trust_state = self._load_or_create_trust_state()
        if self.issuer_id() not in self._v1_trust_state["issuers"]:
            self._journal_trust_issuer(self.export_v1_issuer_bundle(), "self")
            self._v1_trust_state = self._derive_trust_state_from_journal()
        self._verify_or_initialize_external_anchor()

    @classmethod
    def load_or_create(cls, data_dir, public_base_url="http://127.0.0.1", external_anchor_path=None):
        data_dir = Path(data_dir); data_dir.mkdir(parents=True, exist_ok=True)
        lf = (data_dir / "sentinel_v10_startup.lock").open("a+b")
        try:
            import fcntl; fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            base = ClusterSentinel.load_or_create(data_dir, public_base_url)
            return cls(base.data_dir, base.config, swarm_policy=base.swarm_policy,
                       resource_policy=base.resource_policy, fairness_policy=base.fairness_policy,
                       reliability_policy=base.reliability_policy, receipt_policy=base.receipt_policy,
                       keyring_safety_policy=base.keyring_safety_policy,
                       cluster_receipt_policy=base.cluster_receipt_policy,
                       external_anchor_path=external_anchor_path)
        finally:
            try:
                import fcntl; fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            except Exception: pass
            lf.close()

    @staticmethod
    def _private_raw(k):
        return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    @staticmethod
    def _public_raw(k):
        return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _load_or_create_v1_trust_policy(self):
        if self.v1_trust_policy_path.exists():
            return V1TrustPolicy.from_dict(json.loads(self.v1_trust_policy_path.read_text()))
        p=V1TrustPolicy(); self._write_json_atomic(self.v1_trust_policy_path,p.to_dict()); return p
    def _persist_v1_trust_policy(self):
        self.v1_trust_policy.validate(); self._write_json_atomic(self.v1_trust_policy_path,self.v1_trust_policy.to_dict())

    def _load_or_create_recovery_keys(self):
        if self.v1_recovery_keys_path.exists():
            return self._validate_recovery_keys(json.loads(self.v1_recovery_keys_path.read_text()))
        keys=[]
        for i in range(3):
            p=Ed25519PrivateKey.generate(); keys.append({"slot":i,"private_key":_b64e(self._private_raw(p)),"public_key":_b64e(self._public_raw(p.public_key()))})
        raw={"format":"StevensSentinelV1RecoveryKeys","version":1,"threshold":2,"keys":keys,"created_at":int(time.time())}
        self._write_json_atomic(self.v1_recovery_keys_path,raw); return self._validate_recovery_keys(raw)

    def _validate_recovery_keys(self, raw):
        if raw.get("format")!="StevensSentinelV1RecoveryKeys" or int(raw.get("version",0))!=1 or int(raw.get("threshold",0))!=2:
            raise ValueError("invalid recovery key set")
        if len(raw.get("keys",[]))!=3: raise ValueError("three recovery keys required")
        clean=[]
        for i,e in enumerate(raw["keys"]):
            prv=_b64d(e["private_key"]); pub=_b64d(e["public_key"])
            if len(prv)!=32 or len(pub)!=32: raise ValueError("recovery key length")
            p=Ed25519PrivateKey.from_private_bytes(prv)
            if self._public_raw(p.public_key())!=pub: raise ValueError("recovery key mismatch")
            clean.append({"slot":int(e.get("slot",i)),"private_key":_b64e(prv),"public_key":_b64e(pub)})
        return {"format":"StevensSentinelV1RecoveryKeys","version":1,"threshold":2,"keys":clean,"created_at":int(raw.get("created_at",time.time()))}

    def _recovery_public_bundle(self):
        return [{"slot":e["slot"],"public_key":e["public_key"]} for e in self._v1_recovery["keys"]]
    def _quorum_sign(self, body):
        out=[]
        for e in self._v1_recovery["keys"][:2]:
            p=Ed25519PrivateKey.from_private_bytes(_b64d(e["private_key"]))
            out.append({"slot":e["slot"],"signature":_b64e(p.sign(canonical(body)))})
        return out
    @staticmethod
    def _verify_quorum(body,sigs,pubs,threshold=2):
        pm={int(e["slot"]):_b64d(e["public_key"]) for e in pubs}; good=set()
        for s in sigs or []:
            slot=int(s.get("slot",-1))
            if slot in good or slot not in pm: continue
            try:
                Ed25519PublicKey.from_public_bytes(pm[slot]).verify(_b64d(s["signature"]),canonical(body)); good.add(slot)
            except Exception: pass
        return len(good)>=threshold

    def _load_or_create_trust_admin_identity(self):
        if self.v1_trust_admin_identity_path.exists():
            raw=json.loads(self.v1_trust_admin_identity_path.read_text())
        else:
            p=Ed25519PrivateKey.generate(); raw={"format":"StevensSentinelV1TrustAdminIdentity","version":1,"private_key":_b64e(self._private_raw(p)),"public_key":_b64e(self._public_raw(p.public_key())),"created_at":int(time.time())}; self._write_json_atomic(self.v1_trust_admin_identity_path,raw)
        prv=_b64d(raw["private_key"]); pub=_b64d(raw["public_key"]); p=Ed25519PrivateKey.from_private_bytes(prv)
        if self._public_raw(p.public_key())!=pub: raise ValueError("trust admin mismatch")
        return raw
    def _admin_private(self): return Ed25519PrivateKey.from_private_bytes(_b64d(self._v1_admin["private_key"]))
    def export_trust_admin_bundle(self): return {"format":"StevensSentinelV1TrustAdminBundle","version":1,"issuer_id":self.issuer_id(),"public_key":self._v1_admin["public_key"]}

    def _trust_entry_file(self, rev):
        self.v1_trust_journal_dir.mkdir(parents=True,exist_ok=True); return self.v1_trust_journal_dir / f"rev-{rev:012d}.json"
    def _load_trust_journal(self):
        self.v1_trust_journal_dir.mkdir(parents=True,exist_ok=True); files=sorted(self.v1_trust_journal_dir.glob("rev-*.json")); entries=[]; prev="0"*64
        pub=Ed25519PublicKey.from_public_bytes(_b64d(self._v1_admin["public_key"]))
        for rev,path in enumerate(files):
            x=json.loads(path.read_text()); b=x["body"]
            if int(b["revision"])!=rev or b["previous_hash"]!=prev: raise ValueError("trust journal rollback/link error")
            pub.verify(_b64d(x["signature"]),canonical(b)); core={"body":b,"signature":x["signature"]}; h=hashlib.sha256(b"Stevens-Sentinel-v1.0/trust-journal|"+canonical(core)).hexdigest()
            if h!=x["entry_hash"]: raise ValueError("trust journal hash mismatch")
            entries.append({**core,"entry_hash":h}); prev=h
        return entries
    def _append_trust_journal(self,action,payload):
        es=self._load_trust_journal(); rev=len(es); prev=es[-1]["entry_hash"] if es else "0"*64
        b={"format":"StevensSentinelV1TrustJournalEntry","version":1,"revision":rev,"previous_hash":prev,"timestamp":int(time.time()),"action":action,"payload":payload}
        sig=_b64e(self._admin_private().sign(canonical(b))); core={"body":b,"signature":sig}; x={**core,"entry_hash":hashlib.sha256(b"Stevens-Sentinel-v1.0/trust-journal|"+canonical(core)).hexdigest()}
        self._write_json_atomic(self._trust_entry_file(rev),x); self._v1_trust_state=self._derive_trust_state_from_journal(); self._write_json_atomic(self.v1_trust_cache_path,self._v1_trust_state); self._update_external_anchor(); return x
    def _derive_trust_state_from_journal(self):
        st={"format":"StevensSentinelV1TrustState","version":1,"revision":-1,"issuers":{},"trusted_revocation_admins":{}}
        for e in self._load_trust_journal():
            b=e["body"]; st["revision"]=int(b["revision"]); a=b["action"]; p=b["payload"]
            if a=="TRUST": st["issuers"][p["bundle"]["issuer_id"]]={"bundle":p["bundle"],"label":p.get("label",p["bundle"]["issuer_id"]),"revoked":False}
            elif a in ("REVOKE","PEER_REVOKE"):
                iid=p["issuer_id"]
                if iid in st["issuers"]: st["issuers"][iid]["revoked"]=True
            elif a=="TRUST_REVOCATION_ADMIN": st["trusted_revocation_admins"][p["issuer_id"]]={"public_key":p["public_key"]}
        return st
    def _load_or_create_trust_state(self):
        st=self._derive_trust_state_from_journal(); self._write_json_atomic(self.v1_trust_cache_path,st); return st

    # ---------- V1 issuer bundles and trust operations ----------
    def export_v1_issuer_bundle(self):
        return {"format":"StevensSentinelV1IssuerBundle","version":1,
                "issuer_id":self.issuer_id(),
                "issuer_root_public_key":self._issuer_identity["public_key"],
                "recovery_threshold":2,
                "recovery_public_keys":self._recovery_public_bundle(),
                "trust_admin_public_key":self._v1_admin["public_key"]}

    @staticmethod
    def _validate_v1_issuer_bundle(bundle):
        if bundle.get("format")!="StevensSentinelV1IssuerBundle" or int(bundle.get("version",0))!=1:
            raise ValueError("invalid v1 issuer bundle")
        if len(_b64d(bundle["issuer_root_public_key"]))!=32: raise ValueError("issuer root key invalid")
        if int(bundle.get("recovery_threshold",0))!=2 or len(bundle.get("recovery_public_keys",[]))!=3: raise ValueError("invalid recovery bundle")
        slots=set()
        for e in bundle["recovery_public_keys"]:
            if len(_b64d(e["public_key"]))!=32 or int(e["slot"]) in slots: raise ValueError("invalid recovery key")
            slots.add(int(e["slot"]))
        if len(_b64d(bundle["trust_admin_public_key"]))!=32: raise ValueError("trust admin public key invalid")
        return json.loads(json.dumps(bundle))

    def _journal_trust_issuer(self,bundle,label):
        bundle=self._validate_v1_issuer_bundle(bundle)
        return self._append_trust_journal("TRUST",{"bundle":bundle,"label":label or bundle["issuer_id"]})
    def trust_v1_issuer(self,bundle,label=""):
        self._journal_trust_issuer(bundle,label); return self.v1_trust_status()
    def revoke_v1_issuer(self,issuer_id):
        if issuer_id==self.issuer_id(): raise ValueError("cannot revoke self")
        self._append_trust_journal("REVOKE",{"issuer_id":issuer_id}); return self.v1_trust_status()
    def _trusted_v1_bundle(self,issuer_id):
        self._v1_trust_state=self._derive_trust_state_from_journal(); e=self._v1_trust_state["issuers"].get(issuer_id)
        if not e or e.get("revoked"): return None
        return e["bundle"]

    # ---------- Signed peer revocation propagation ----------
    def trust_peer_revocation_admin(self,admin_bundle):
        if admin_bundle.get("format")!="StevensSentinelV1TrustAdminBundle" or len(_b64d(admin_bundle["public_key"]))!=32: raise ValueError("invalid trust-admin bundle")
        self._append_trust_journal("TRUST_REVOCATION_ADMIN",{"issuer_id":admin_bundle["issuer_id"],"public_key":admin_bundle["public_key"]}); return self.v1_trust_status()
    def export_revocation_bundle(self,issuer_id):
        b={"format":"StevensSentinelV1PeerRevocation","version":1,"revoker_issuer_id":self.issuer_id(),"revoked_issuer_id":issuer_id,"timestamp":int(time.time()),"nonce":secrets.token_hex(8)}
        return {"body":b,"signature":_b64e(self._admin_private().sign(canonical(b)))}
    def import_revocation_bundle(self,bundle):
        b=bundle.get("body")
        if not isinstance(b,dict) or b.get("format")!="StevensSentinelV1PeerRevocation" or int(b.get("version",0))!=1: raise ValueError("invalid revocation bundle")
        self._v1_trust_state=self._derive_trust_state_from_journal(); auth=self._v1_trust_state["trusted_revocation_admins"].get(b["revoker_issuer_id"])
        if not auth: raise ValueError("untrusted revocation authority")
        Ed25519PublicKey.from_public_bytes(_b64d(auth["public_key"])).verify(_b64d(bundle["signature"]),canonical(b))
        self._append_trust_journal("PEER_REVOKE",{"issuer_id":b["revoked_issuer_id"],"source":b["revoker_issuer_id"]}); return self.v1_trust_status()

    # ---------- Issuer policy ----------
    def _policy_body(self,revision,min_signing_revision,revoked_kids):
        return {"format":"StevensSentinelV1IssuerPolicy","version":1,"issuer_id":self.issuer_id(),"policy_revision":int(revision),"min_signing_revision":int(min_signing_revision),"revoked_kids":sorted(set(revoked_kids)),"certificate_lifetime_seconds":int(self.v1_trust_policy.certificate_lifetime_seconds),"issued_at":int(time.time())}
    def _sign_policy_body(self,b):
        return {"body":b,"root_signature":_b64e(self._issuer_private_key().sign(canonical(b))),"recovery_signatures":self._quorum_sign(b)}
    def _validate_signed_policy(self,signed,trusted_bundle):
        b=signed.get("body")
        if not isinstance(b,dict) or b.get("format")!="StevensSentinelV1IssuerPolicy" or int(b.get("version",0))!=1 or b.get("issuer_id")!=trusted_bundle["issuer_id"]: raise ValueError("invalid issuer policy")
        Ed25519PublicKey.from_public_bytes(_b64d(trusted_bundle["issuer_root_public_key"])).verify(_b64d(signed["root_signature"]),canonical(b))
        if not self._verify_quorum(b,signed.get("recovery_signatures",[]),trusted_bundle["recovery_public_keys"],trusted_bundle["recovery_threshold"]): raise ValueError("issuer policy recovery quorum invalid")
        return b
    def _load_or_create_issuer_policy(self):
        if self.v1_issuer_policy_path.exists():
            s=json.loads(self.v1_issuer_policy_path.read_text()); b=self._validate_signed_policy(s,self.export_v1_issuer_bundle()); return {"signed":s,"body":b}
        b=self._policy_body(0,0,[]); s=self._sign_policy_body(b); self._write_json_atomic(self.v1_issuer_policy_path,s); return {"signed":s,"body":b}
    def _load_or_create_peer_policy_state(self):
        if self.v1_peer_policy_state_path.exists():
            x=json.loads(self.v1_peer_policy_state_path.read_text())
            if x.get("format")!="StevensSentinelV1PeerPolicyState": raise ValueError("bad peer policy state")
            return x
        x={"format":"StevensSentinelV1PeerPolicyState","version":1,"issuers":{}}; self._write_json_atomic(self.v1_peer_policy_state_path,x); return x
    def _remember_peer_policy(self,issuer_id,signed,trusted_bundle):
        b=self._validate_signed_policy(signed,trusted_bundle); cur=self._v1_peer_policies["issuers"].get(issuer_id)
        if cur:
            cr=int(cur["body"]["policy_revision"]); nr=int(b["policy_revision"])
            if nr<cr: return cur
            if nr==cr and cur["signed"]!=signed: raise ValueError("conflicting issuer policy revision")
        self._v1_peer_policies["issuers"][issuer_id]={"body":b,"signed":signed}; self._write_json_atomic(self.v1_peer_policy_state_path,self._v1_peer_policies); return self._v1_peer_policies["issuers"][issuer_id]
    def export_issuer_policy_bundle(self): return json.loads(self.v1_issuer_policy_path.read_text())
    def import_issuer_policy_bundle(self,signed):
        iid=signed["body"]["issuer_id"]; tb=self._trusted_v1_bundle(iid)
        if tb is None: raise ValueError("issuer not trusted")
        return self._remember_peer_policy(iid,signed,tb)
    def _advance_local_issuer_policy(self,min_signing_revision,revoked_kids):
        c=self._v1_issuer_policy["body"]; b=self._policy_body(int(c["policy_revision"])+1,max(int(c["min_signing_revision"]),int(min_signing_revision)),list(c.get("revoked_kids",[]))+list(revoked_kids)); s=self._sign_policy_body(b); self._write_json_atomic(self.v1_issuer_policy_path,s); self._v1_issuer_policy={"signed":s,"body":b}; return s

    # ---------- External anti-rollback anchor ----------
    def _anchor_body(self,trust_revision,keyring_revision):
        return {"format":"StevensSentinelV1ExternalAnchor","version":1,"issuer_id":self.issuer_id(),"trust_admin_public_key":self._v1_admin["public_key"],"trust_revision":int(trust_revision),"keyring_revision":int(keyring_revision),"updated_at":int(time.time())}
    def _sign_anchor(self,b): return {"body":b,"signature":_b64e(self._admin_private().sign(canonical(b)))}
    def _read_anchor(self):
        if not self.external_anchor_path.exists(): return None
        s=json.loads(self.external_anchor_path.read_text()); b=s.get("body")
        if not isinstance(b,dict) or b.get("format")!="StevensSentinelV1ExternalAnchor": raise ValueError("invalid external anchor")
        if b["trust_admin_public_key"]!=self._v1_admin["public_key"]: raise ValueError("external anchor identity mismatch")
        Ed25519PublicKey.from_public_bytes(_b64d(b["trust_admin_public_key"])).verify(_b64d(s["signature"]),canonical(b)); return s
    def _current_monotonic_revisions(self): return int(self._derive_trust_state_from_journal().get("revision",-1)), int(super().receipt_status()["committed_revision"])
    def _write_external_anchor(self,tr,kr):
        self.external_anchor_path.parent.mkdir(parents=True,exist_ok=True); self._write_json_atomic(self.external_anchor_path,self._sign_anchor(self._anchor_body(tr,kr)))
    def _verify_or_initialize_external_anchor(self):
        tr,kr=self._current_monotonic_revisions(); a=self._read_anchor()
        if a is None:
            if self.v1_trust_policy.require_external_anchor: self._write_external_anchor(tr,kr)
            return
        b=a["body"]
        if tr<int(b["trust_revision"]): raise ValueError("trust journal rollback detected by external anchor")
        if kr<int(b["keyring_revision"]): raise ValueError("keyring journal rollback detected by external anchor")
        if tr>int(b["trust_revision"]) or kr>int(b["keyring_revision"]): self._write_external_anchor(tr,kr)
    def _update_external_anchor(self):
        if not self.v1_trust_policy.require_external_anchor: return
        tr,kr=self._current_monotonic_revisions(); a=self._read_anchor()
        if a: tr=max(tr,int(a["body"]["trust_revision"])); kr=max(kr,int(a["body"]["keyring_revision"]))
        self._write_external_anchor(tr,kr)

    # ---------- V4 certificates and receipts ----------
    def _v4_certificate(self,current,now=None):
        now=int(now or time.time()); life=int(self.v1_trust_policy.certificate_lifetime_seconds)
        b={"format":"StevensSentinelV1SigningCertificate","version":1,"issuer_id":self.issuer_id(),"kid":current["kid"],"public_key":current["public_key"],"signing_revision":int(current["revision"]),"not_before":now-5,"not_after":now+life}
        return {"body":b,"root_signature":_b64e(self._issuer_private_key().sign(canonical(b))),"recovery_signatures":self._quorum_sign(b)}
    def _validate_v4_certificate(self,cert,trusted_bundle,now):
        b=cert.get("body")
        if not isinstance(b,dict) or b.get("format")!="StevensSentinelV1SigningCertificate" or int(b.get("version",0))!=1 or b.get("issuer_id")!=trusted_bundle["issuer_id"]: raise ValueError("invalid signing certificate")
        Ed25519PublicKey.from_public_bytes(_b64d(trusted_bundle["issuer_root_public_key"])).verify(_b64d(cert["root_signature"]),canonical(b))
        if not self._verify_quorum(b,cert.get("recovery_signatures",[]),trusted_bundle["recovery_public_keys"],trusted_bundle["recovery_threshold"]): raise ValueError("certificate recovery quorum invalid")
        if now<int(b["not_before"]) or now>int(b["not_after"]): raise ValueError("certificate expired/not yet valid")
        if self._signing_kid_from_public(_b64d(b["public_key"]))!=b["kid"]: raise ValueError("certificate kid mismatch")
        return b

    def issue_proof_receipt(self,source_ip,client_binding=None,now=None):
        self._reload_asym_keyring_if_changed()
        if not self._binding_mode_allowed(): raise ValueError("experimental receipt binding disabled")
        now=int(now or time.time()); ttl=int(self.reliability_policy.proof_receipt_ttl_seconds); mode=self.receipt_policy.binding_mode; nonce=os.urandom(12).hex(); cur=self._asym_keyring["current"]
        bind=self._binding_hash_v3(source_ip,client_binding,mode,nonce)
        if bind is None: raise ValueError("receipt binding material missing")
        payload={"v":4,"issuer":self.issuer_id(),"kid":cur["kid"],"signing_revision":int(cur["revision"]),"iat":now,"exp":now+ttl,"scope":"global-swarm-proof","bm":mode,"nonce":nonce,"bind":bind,"cert":self._v4_certificate(cur,now),"issuer_policy":self.export_issuer_policy_bundle()}
        body=canonical(payload); priv=Ed25519PrivateKey.from_private_bytes(_b64d(cur["private_key"])); return _b64e(body)+"."+_b64e(priv.sign(body))

    def _verify_v4_receipt(self,receipt,source_ip,client_binding,now):
        try:
            body64,sig64=receipt.split(".",1); body=_b64d(body64); sig=_b64d(sig64)
            if _b64e(body)!=body64 or _b64e(sig)!=sig64: return False
            p=json.loads(body)
            if int(p.get("v",0))!=4 or p.get("scope")!="global-swarm-proof": return False
            iid=p["issuer"]; tb=self._trusted_v1_bundle(iid)
            if tb is None: return False
            cb=self._validate_v4_certificate(p["cert"],tb,now)
            if cb["kid"]!=p["kid"] or int(cb["signing_revision"])!=int(p["signing_revision"]): return False
            signed_policy=p["issuer_policy"]; pb=self._validate_signed_policy(signed_policy,tb); remembered=self._v1_peer_policies["issuers"].get(iid)
            if remembered and int(pb["policy_revision"])<int(remembered["body"]["policy_revision"]): return False
            if self.v1_trust_policy.auto_advance_embedded_issuer_policy:
                remembered=self._remember_peer_policy(iid,signed_policy,tb); pb=remembered["body"]
            remembered=self._v1_peer_policies["issuers"].get(iid)
            if remembered and int(remembered["body"]["policy_revision"])>int(pb["policy_revision"]): pb=remembered["body"]
            if int(p["signing_revision"])<int(pb["min_signing_revision"]): return False
            if p["kid"] in set(pb.get("revoked_kids",[])): return False
            Ed25519PublicKey.from_public_bytes(_b64d(cb["public_key"])).verify(sig,body)
            skew=int(self.reliability_policy.proof_receipt_clock_skew_seconds)
            if int(p["iat"])>now+skew or int(p["exp"])<now-skew: return False
            if p["bm"]!=self.receipt_policy.binding_mode: return False
            expected=self._binding_hash_v3(source_ip,client_binding,p["bm"],p["nonce"])
            return expected is not None and expected==p["bind"]
        except Exception:
            return False

    def verify_proof_receipt(self,receipt,source_ip,client_binding=None,now=None):
        if not receipt: return False
        now=int(now or time.time())
        try: ver=int(json.loads(_b64d(str(receipt).split(".",1)[0])).get("v",0))
        except Exception: return False
        if ver==4: return self._verify_v4_receipt(str(receipt),source_ip,client_binding,now)
        if ver==3 and self.v1_trust_policy.allow_legacy_v3_receipts: return super().verify_proof_receipt(receipt,source_ip,client_binding=client_binding,now=now)
        return False

    # ---------- Rotation / compromise recovery ----------
    def rotate_receipt_key(self,now=None,revoke_prior=False):
        super().rotate_receipt_key(now=now); self._reload_asym_keyring_if_changed(force=True)
        if revoke_prior:
            self._advance_local_issuer_policy(int(self._asym_keyring["current"]["revision"]),[])
        self._update_external_anchor(); out=self.v1_status(); out["rotation_applied"]=True; out["revoke_prior"]=bool(revoke_prior); return out
    def revoke_signing_kid(self,kid):
        c=self._v1_issuer_policy["body"]; self._advance_local_issuer_policy(int(c["min_signing_revision"]),[kid]); return self.v1_status()

    # ---------- Status ----------
    def v1_trust_status(self):
        st=self._derive_trust_state_from_journal(); return {"sentinel_version":VERSION,"trust_revision":int(st["revision"]),"trusted_issuer_count":sum(1 for e in st["issuers"].values() if not e.get("revoked")),"trusted_revocation_admin_count":len(st["trusted_revocation_admins"]),"derived_from_signed_journal":True}
    def v1_status(self):
        a=self._read_anchor(); return {"sentinel_version":VERSION,"receipt_format":"ed25519-revocable-v4","issuer_id":self.issuer_id(),"current_kid":self._asym_keyring["current"]["kid"],"current_signing_revision":int(self._asym_keyring["current"]["revision"]),"issuer_policy_revision":int(self._v1_issuer_policy["body"]["policy_revision"]),"min_signing_revision":int(self._v1_issuer_policy["body"]["min_signing_revision"]),"certificate_lifetime_seconds":int(self.v1_trust_policy.certificate_lifetime_seconds),"recovery_signatures_required":"2-of-3","external_anchor_path":str(self.external_anchor_path),"external_anchor_present":a is not None,"trust":self.v1_trust_status()}
    def reliability_status(self):
        s=super().reliability_status(); s.update({"sentinel_version":VERSION,"proof_receipt_mode":"ed25519-revocable-v4","signed_trust_journal":True,"recovery_quorum":"2-of-3","external_antirollback_anchor":True}); return s
    def review_bundle(self,event_limit=500,subject_limit=100):
        b=super().review_bundle(event_limit,subject_limit); b["sentinel_version"]=VERSION; b["v1_trust_defense"]={"revocable_signing_revisions":True,"certificate_validity_windows":True,"recovery_quorum_signatures":"2-of-3","signed_trust_journal":True,"external_antirollback_anchor":True,"peer_revocation_bundle_import":True}; b["policy"]["automatic_rule_application"]=False; b["policy"]["human_approval_required_for_policy_changes"]=True; return b
