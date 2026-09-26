"""
Stevens Chain v0.5.2 note-security core
Experimental local cryptocurrency / blockchain prototype.

Highlights:
- UTXO ledger
- dual-layer Stevens-128 + ChaCha20-Poly1305 encrypted spendable notes
- Ed25519 spend authorization
- X25519 + HKDF per-note key agreement
- password-protected persistent wallet files
- public amounts in v0.2
- transaction fees
- mining rewards
- mempool
- proof-of-work blocks
- complete chain replay/validation
- disk persistence

SECURITY STATUS:
Research/testnet prototype only. Defense-in-depth release; not audited or production-ready.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag

import stevens128_v1_0 as stevens


CHAIN_NAME = "Stevens Chain"
CHAIN_VERSION = "0.5.2"
TOKEN_SYMBOL = "STV"
TOKEN_DECIMALS = 6
UNIT = 10 ** TOKEN_DECIMALS

GENESIS_SUPPLY = 100 * UNIT
BLOCK_REWARD = 50 * UNIT

# Permanent Stevens Chain consensus hard cap.
#
# This is not a runtime/configuration value. Any software that
# changes this constant defines incompatible consensus rules.
MAX_SUPPLY_STV = 30_000_000
MAX_SUPPLY = MAX_SUPPLY_STV * UNIT

POW_DIFFICULTY_BITS = 12

NOTE_INFO = b"StevensChain-v0.5-legacy-note-key"
NOTE_INFO_STEVENS = b"StevensChain-v0.5-note-key/stevens128"
NOTE_INFO_CHACHA = b"StevensChain-v0.5-note-key/chacha20poly1305"
NOTE_SCHEME = "STEVENS128+CHACHA20POLY1305-V2"
REQUIRED_STEVENS_ROUNDS = stevens.ROUNDS
ADDRESS_TAG = b"StevensChain-v0.2-address"
TX_TAG = b"StevensChain-v0.2-tx"
BLOCK_TAG = b"StevensChain-v0.2-block"
WALLET_AAD = b"StevensChain-v0.2-wallet"

# Wallet-format hardening v2. These settings do not affect consensus or addresses.
WALLET_FORMAT_VERSION = 2
WALLET_PASSWORD_MIN_CHARS = 12
WALLET_SCRYPT_N = 2 ** 17
WALLET_SCRYPT_R = 8
WALLET_SCRYPT_P = 1

# Loader safety bounds. Legacy v1 wallets used N=2**14 and remain readable.
WALLET_SCRYPT_MIN_N = 2 ** 14
WALLET_SCRYPT_MAX_N = 2 ** 19
WALLET_SCRYPT_MAX_R = 16
WALLET_SCRYPT_MAX_P = 4
WALLET_SALT_MIN_BYTES = 16
WALLET_SALT_MAX_BYTES = 64
WALLET_MAX_FILE_BYTES = 1024 * 1024


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raw_public_key(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def raw_private_key(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _secure_atomic_write_text(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp-" + secrets.token_hex(8))
    fd = None
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            # Permission semantics vary on Windows; encryption remains authoritative.
            pass
        # Make the rename itself durable where the platform supports directory
        # fsync. Without this, a power loss after rename can still lose the new
        # directory entry even though the wallet contents were fsynced.
        try:
            dfd = os.open(str(target.parent), os.O_RDONLY)
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


def _read_wallet_text_bounded(path: str | Path) -> str:
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError as e:
        raise ValueError("unable to read wallet file") from e
    if size <= 0 or size > WALLET_MAX_FILE_BYTES:
        raise ValueError("wallet file size is invalid or exceeds safety limit")
    return target.read_text(encoding="utf-8")


def address_from_keys(sign_pub_raw: bytes, enc_pub_raw: bytes) -> str:
    digest = hashlib.sha256(
        ADDRESS_TAG + sign_pub_raw + enc_pub_raw
    ).hexdigest()
    return "STV1" + digest[:40]


def fmt_amount(amount_units: int) -> str:
    return f"{amount_units / UNIT:.6f} {TOKEN_SYMBOL}"


def parse_amount(text: str) -> int:
    # Exact decimal parser; avoids float accounting.
    text = text.strip()
    if not text:
        raise ValueError("empty amount")
    neg = text.startswith("-")
    if neg:
        text = text[1:]
    if "." in text:
        whole, frac = text.split(".", 1)
    else:
        whole, frac = text, ""
    if not whole:
        whole = "0"
    if not whole.isdigit() or (frac and not frac.isdigit()):
        raise ValueError("invalid decimal amount")
    if len(frac) > TOKEN_DECIMALS:
        raise ValueError(f"STV supports at most {TOKEN_DECIMALS} decimals")
    value = int(whole) * UNIT + int((frac + "0" * TOKEN_DECIMALS)[:TOKEN_DECIMALS])
    return -value if neg else value


@dataclass(frozen=True)
class PublicIdentity:
    address: str
    sign_pub: bytes
    enc_pub: bytes

    @classmethod
    def from_dict(cls, d: dict) -> "PublicIdentity":
        sign_pub = bytes.fromhex(d["sign_pub"])
        enc_pub = bytes.fromhex(d["enc_pub"])
        addr = address_from_keys(sign_pub, enc_pub)
        if d.get("address") and d["address"] != addr:
            raise ValueError("public identity address mismatch")
        return cls(addr, sign_pub, enc_pub)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "sign_pub": self.sign_pub.hex(),
            "enc_pub": self.enc_pub.hex(),
        }



def derive_note_keys(shared_secret: bytes, kdf_salt: bytes) -> tuple[bytes, bytes]:
    """Derive independent 256-bit keys for the two note-encryption layers."""
    if len(kdf_salt) != 32:
        raise ValueError("note KDF salt must be exactly 32 bytes")

    stevens_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        info=NOTE_INFO_STEVENS,
    ).derive(shared_secret)

    chacha_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        info=NOTE_INFO_CHACHA,
    ).derive(shared_secret)

    if stevens_key == chacha_key:
        raise RuntimeError("domain-separated note keys unexpectedly collided")
    return stevens_key, chacha_key


def note_aad(output: dict) -> bytes:
    """Bind the standardized outer AEAD layer to public UTXO metadata."""
    return canonical_json({
        "scheme": output["encryption_scheme"],
        "owner_address": output["owner_address"],
        "owner_sign_pub": output["owner_sign_pub"],
        "owner_enc_pub": output["owner_enc_pub"],
        "amount": int(output["amount"]),
        "ephemeral_enc_pub": output["ephemeral_enc_pub"],
        "kdf_salt": output["kdf_salt"],
        "note_commitment": output["note_commitment"],
        "inner_stevens_rounds": int(output["inner_stevens_rounds"]),
    })


@dataclass
class Wallet:
    sign_private: Ed25519PrivateKey
    enc_private: X25519PrivateKey

    @classmethod
    def generate(cls) -> "Wallet":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @property
    def sign_public_raw(self) -> bytes:
        return raw_public_key(self.sign_private.public_key())

    @property
    def enc_public_raw(self) -> bytes:
        return raw_public_key(self.enc_private.public_key())

    @property
    def address(self) -> str:
        return address_from_keys(self.sign_public_raw, self.enc_public_raw)

    def public_identity(self) -> PublicIdentity:
        return PublicIdentity(
            self.address, self.sign_public_raw, self.enc_public_raw
        )

    def sign(self, msg: bytes) -> bytes:
        return self.sign_private.sign(msg)

    @staticmethod
    def _validate_wallet_kdf(kd: dict) -> tuple[int, int, int, bytes]:
        if kd.get("name") != "scrypt":
            raise ValueError("unsupported wallet KDF")
        try:
            n = int(kd["n"])
            r = int(kd["r"])
            p_cost = int(kd["p"])
            salt = bytes.fromhex(kd["salt"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("invalid wallet KDF parameters") from e
        if n < WALLET_SCRYPT_MIN_N or n > WALLET_SCRYPT_MAX_N or (n & (n - 1)) != 0:
            raise ValueError("unsafe wallet scrypt N parameter")
        if not (1 <= r <= WALLET_SCRYPT_MAX_R):
            raise ValueError("unsafe wallet scrypt r parameter")
        if not (1 <= p_cost <= WALLET_SCRYPT_MAX_P):
            raise ValueError("unsafe wallet scrypt p parameter")
        if not (WALLET_SALT_MIN_BYTES <= len(salt) <= WALLET_SALT_MAX_BYTES):
            raise ValueError("invalid wallet KDF salt length")
        return n, r, p_cost, salt

    @staticmethod
    def _wallet_v2_aad(doc: dict) -> bytes:
        # Authenticate all security-relevant cleartext wallet metadata.
        meta = {
            "format": doc["format"],
            "version": int(doc["version"]),
            "chain_version": doc["chain_version"],
            "address": doc["address"],
            "public_identity": doc["public_identity"],
            "kdf": doc["kdf"],
            "cipher_name": doc["cipher"]["name"],
        }
        return WALLET_AAD + b"\x00v2\x00" + canonical_json(meta)

    def save(self, path: str | Path, password: str) -> None:
        if len(password) < WALLET_PASSWORD_MIN_CHARS:
            raise ValueError(
                f"wallet password must be at least {WALLET_PASSWORD_MIN_CHARS} characters"
            )
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        kdf = Scrypt(
            salt=salt, length=32,
            n=WALLET_SCRYPT_N, r=WALLET_SCRYPT_R, p=WALLET_SCRYPT_P
        )
        key = kdf.derive(password.encode("utf-8"))
        payload = canonical_json({
            "sign_private": raw_private_key(self.sign_private).hex(),
            "enc_private": raw_private_key(self.enc_private).hex(),
        })
        doc = {
            "format": "StevensChainWallet",
            "version": WALLET_FORMAT_VERSION,
            "chain_version": CHAIN_VERSION,
            "address": self.address,
            "public_identity": self.public_identity().to_dict(),
            "kdf": {
                "name": "scrypt",
                "n": WALLET_SCRYPT_N,
                "r": WALLET_SCRYPT_R,
                "p": WALLET_SCRYPT_P,
                "salt": salt.hex(),
            },
            "cipher": {
                "name": "AES-256-GCM",
                "nonce": nonce.hex(),
                "ciphertext": "",
            },
        }
        aad = self._wallet_v2_aad(doc)
        ct = AESGCM(key).encrypt(nonce, payload, aad)
        doc["cipher"]["ciphertext"] = base64.b64encode(ct).decode("ascii")
        _secure_atomic_write_text(path, json.dumps(doc, indent=2))

    @classmethod
    def load(cls, path: str | Path, password: str) -> "Wallet":
        doc = json.loads(_read_wallet_text_bounded(path))
        if doc.get("format") != "StevensChainWallet":
            raise ValueError("not a Stevens Chain wallet file")
        version = int(doc.get("version", 1))
        if version not in (1, WALLET_FORMAT_VERSION):
            raise ValueError("unsupported Stevens wallet format version")
        kd = doc.get("kdf")
        if not isinstance(kd, dict):
            raise ValueError("invalid wallet KDF metadata")
        n, r, p_cost, salt = cls._validate_wallet_kdf(kd)
        cipher = doc.get("cipher")
        if not isinstance(cipher, dict) or cipher.get("name") != "AES-256-GCM":
            raise ValueError("unsupported wallet cipher")
        try:
            nonce = bytes.fromhex(cipher["nonce"])
            ct = base64.b64decode(cipher["ciphertext"], validate=True)
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("invalid wallet cipher metadata") from e
        if len(nonce) != 12:
            raise ValueError("invalid AES-GCM wallet nonce length")

        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p_cost)
        key = kdf.derive(password.encode("utf-8"))
        aad = WALLET_AAD if version == 1 else cls._wallet_v2_aad(doc)
        try:
            payload = AESGCM(key).decrypt(nonce, ct, aad)
        except InvalidTag as e:
            raise ValueError("incorrect password or damaged wallet") from e
        pld = json.loads(payload)
        wallet = cls(
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(pld["sign_private"])),
            X25519PrivateKey.from_private_bytes(bytes.fromhex(pld["enc_private"])),
        )
        if wallet.address != doc.get("address"):
            raise ValueError("wallet integrity/address mismatch")
        if doc.get("public_identity") != wallet.public_identity().to_dict():
            raise ValueError("wallet public-identity metadata mismatch")
        return wallet

    def decrypt_output(self, output: dict) -> Optional[dict]:
        """Decrypt a v0.5.1 dual-layer Stevens Note."""
        if output["owner_address"] != self.address:
            return None

        validate_output_shape(output)

        eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(output["ephemeral_enc_pub"])
        )
        shared = self.enc_private.exchange(eph_pub)
        salt = bytes.fromhex(output["kdf_salt"])
        stevens_key, chacha_key = derive_note_keys(shared, salt)

        outer_nonce = bytes.fromhex(output["outer_nonce"])
        outer_blob = base64.b64decode(output["encrypted_note"])

        try:
            inner_blob = ChaCha20Poly1305(chacha_key).decrypt(
                outer_nonce,
                outer_blob,
                note_aad(output),
            )
        except InvalidTag as e:
            raise ValueError("outer note authentication failed") from e

        # The Stevens sealed format carries the round count in the byte
        # immediately following MAGIC.  v0.5.1 refuses any authenticated
        # note whose actual embedded count is not the frozen Stevens-128
        # v1.0 round count.  This closes the v0.5 sender-controlled inner
        # round downgrade.
        if not inner_blob.startswith(stevens.MAGIC):
            raise ValueError("invalid Stevens inner note header")
        pos = len(stevens.MAGIC)
        if len(inner_blob) <= pos:
            raise ValueError("truncated Stevens inner note")
        actual_rounds = int(inner_blob[pos])
        declared_rounds = int(output["inner_stevens_rounds"])
        if actual_rounds != REQUIRED_STEVENS_ROUNDS or declared_rounds != REQUIRED_STEVENS_ROUNDS:
            raise ValueError(
                f"Stevens inner round-count mismatch: actual={actual_rounds}, "
                f"declared={declared_rounds}, required={REQUIRED_STEVENS_ROUNDS}"
            )

        plaintext = stevens.open_sealed(inner_blob, stevens_key)
        note = json.loads(plaintext.decode("utf-8"))

        if sha256_hex(plaintext) != output["note_commitment"]:
            raise ValueError("note commitment mismatch")
        if note["owner_address"] != self.address:
            raise ValueError("decrypted owner mismatch")
        if int(note["amount"]) != int(output["amount"]):
            raise ValueError("decrypted amount mismatch")
        if int(note.get("note_version", 0)) != 3:
            raise ValueError("unexpected Stevens Note version")
        return note


def validate_output_shape(output: dict) -> None:
    _require_exact_keys(
        output,
        {
            "owner_address",
            "owner_sign_pub",
            "owner_enc_pub",
            "amount",
            "ephemeral_enc_pub",
            "kdf_salt",
            "note_commitment",
            "encrypted_note",
            "encryption_scheme",
            "outer_nonce",
            "inner_stevens_rounds",
        },
        "output",
    )
    required = [
        "owner_address", "owner_sign_pub", "owner_enc_pub", "amount",
        "ephemeral_enc_pub", "kdf_salt", "note_commitment", "encrypted_note",
        "encryption_scheme", "outer_nonce", "inner_stevens_rounds",
    ]
    for k in required:
        if k not in output:
            raise ValueError(f"missing output field: {k}")

    if output["encryption_scheme"] != NOTE_SCHEME:
        raise ValueError("unsupported or downgraded note encryption scheme")

    inner_rounds = _require_consensus_int(
        output["inner_stevens_rounds"],
        "output inner_stevens_rounds",
    )

    if inner_rounds != REQUIRED_STEVENS_ROUNDS:
        raise ValueError(
            f"unsupported Stevens inner round count: {output['inner_stevens_rounds']} "
            f"(required {REQUIRED_STEVENS_ROUNDS})"
        )

    sign_pub = bytes.fromhex(output["owner_sign_pub"])
    enc_pub = bytes.fromhex(output["owner_enc_pub"])
    if len(sign_pub) != 32 or len(enc_pub) != 32:
        raise ValueError("bad owner public key length")
    expected_addr = address_from_keys(sign_pub, enc_pub)
    if output["owner_address"] != expected_addr:
        raise ValueError("output owner address/public-key mismatch")

    amount = _require_consensus_int(
        output["amount"],
        "output amount",
    )

    if amount <= 0:
        raise ValueError("output amount must be positive")

    if amount > MAX_SUPPLY:
        raise ValueError("output amount exceeds maximum supply")
    if len(bytes.fromhex(output["ephemeral_enc_pub"])) != 32:
        raise ValueError("bad ephemeral X25519 public key")
    if len(bytes.fromhex(output["kdf_salt"])) != 32:
        raise ValueError("bad note KDF salt")
    if len(bytes.fromhex(output["note_commitment"])) != 32:
        raise ValueError("bad note commitment")
    if len(bytes.fromhex(output["outer_nonce"])) != 12:
        raise ValueError("bad ChaCha20-Poly1305 nonce")
    blob = base64.b64decode(output["encrypted_note"], validate=True)
    if len(blob) < 16:
        raise ValueError("outer ciphertext too short")


def encrypt_note(recipient: PublicIdentity | Wallet, amount: int, memo: str = "") -> dict:
    """Create a v0.5.1 dual-layer Stevens Note."""
    if isinstance(recipient, Wallet):
        recipient = recipient.public_identity()
    if amount <= 0:
        raise ValueError("output amount must be positive")

    note = {
        "note_version": 3,
        "note_id": secrets.token_hex(16),
        "amount": int(amount),
        "symbol": TOKEN_SYMBOL,
        "owner_address": recipient.address,
        "memo": memo,
        "nonce": secrets.token_hex(16),
    }
    plaintext = canonical_json(note)

    eph = X25519PrivateKey.generate()
    eph_pub_raw = raw_public_key(eph.public_key())
    recip_enc = X25519PublicKey.from_public_bytes(recipient.enc_pub)
    shared = eph.exchange(recip_enc)
    kdf_salt = secrets.token_bytes(32)
    stevens_key, chacha_key = derive_note_keys(shared, kdf_salt)

    inner_blob = stevens.seal(plaintext, stevens_key)

    output = {
        "owner_address": recipient.address,
        "owner_sign_pub": recipient.sign_pub.hex(),
        "owner_enc_pub": recipient.enc_pub.hex(),
        "amount": int(amount),
        "ephemeral_enc_pub": eph_pub_raw.hex(),
        "kdf_salt": kdf_salt.hex(),
        "note_commitment": sha256_hex(plaintext),
        "encryption_scheme": NOTE_SCHEME,
        "inner_stevens_rounds": REQUIRED_STEVENS_ROUNDS,
        "outer_nonce": secrets.token_bytes(12).hex(),
    }

    outer_blob = ChaCha20Poly1305(chacha_key).encrypt(
        bytes.fromhex(output["outer_nonce"]),
        inner_blob,
        note_aad(output),
    )
    output["encrypted_note"] = base64.b64encode(outer_blob).decode("ascii")

    validate_output_shape(output)
    return output


def unsigned_payment_body(inputs: List[dict], outputs: List[dict], fee: int) -> dict:
    return {
        "version": 2,
        "chain": CHAIN_NAME,
        "kind": "payment",
        "fee": int(fee),
        "inputs": [{"txid": x["txid"], "index": int(x["index"])} for x in inputs],
        "outputs": outputs,
    }


def sighash_for_input(unsigned_body: dict, input_index: int) -> bytes:
    return hashlib.sha256(
        TX_TAG + canonical_json({
            "body": unsigned_body,
            "input_index": int(input_index),
        })
    ).digest()


def txid_of_body(tx_without_txid: dict) -> str:
    return sha256_hex(TX_TAG + canonical_json(tx_without_txid))


def check_txid(tx: dict) -> bool:
    body = {k: v for k, v in tx.items() if k != "txid"}
    return tx.get("txid") == txid_of_body(body)


def make_payment_tx(
    wallet: Wallet,
    selected_refs: List[Tuple[str, int]],
    selected_outputs: List[dict],
    recipients: List[Tuple[PublicIdentity | Wallet, int, str]],
    fee: int,
    change_amount: int = 0,
) -> dict:
    if fee < 0:
        raise ValueError("fee cannot be negative")
    if len(selected_refs) != len(selected_outputs):
        raise ValueError("reference/output count mismatch")
    if not selected_refs:
        raise ValueError("no payment inputs")

    inputs = [{"txid": t, "index": int(i)} for t, i in selected_refs]
    outputs = [encrypt_note(r, amount, memo) for r, amount, memo in recipients]
    if change_amount:
        outputs.append(encrypt_note(wallet, change_amount, "change"))

    body = unsigned_payment_body(inputs, outputs, fee)
    signed_inputs = []
    for idx, ref in enumerate(inputs):
        signed_inputs.append({
            **ref,
            "signature": wallet.sign(sighash_for_input(body, idx)).hex(),
        })

    tx = {
        "version": 2,
        "chain": CHAIN_NAME,
        "kind": "payment",
        "fee": int(fee),
        "inputs": signed_inputs,
        "outputs": outputs,
    }
    tx["txid"] = txid_of_body(tx)
    return tx


def make_coinbase_tx(recipient: PublicIdentity | Wallet, amount: int,
                     height: int, memo: str) -> dict:
    tx = {
        "version": 2,
        "chain": CHAIN_NAME,
        "kind": "coinbase",
        "height": int(height),
        "inputs": [],
        "fee": 0,
        "outputs": [encrypt_note(recipient, amount, memo)],
    }
    tx["txid"] = txid_of_body(tx)
    return tx


def make_genesis_tx(recipient: PublicIdentity | Wallet) -> dict:
    tx = {
        "version": 2,
        "chain": CHAIN_NAME,
        "kind": "genesis",
        "height": 0,
        "inputs": [],
        "fee": 0,
        "outputs": [encrypt_note(recipient, GENESIS_SUPPLY, "genesis allocation")],
    }
    tx["txid"] = txid_of_body(tx)
    return tx


def merkle_root(txids: List[str]) -> str:
    if not txids:
        return "00" * 32
    layer = [bytes.fromhex(x) for x in txids]
    while len(layer) > 1:
        if len(layer) & 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(layer[i] + layer[i + 1]).digest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0].hex()


def _require_consensus_int(value, name: str) -> int:
    """Require an actual canonical integer at a consensus boundary.

    Python bool is intentionally rejected even though bool subclasses int.
    Consensus validation must never silently coerce strings, floats, bools,
    or other representations into integer header fields.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"non-canonical {name}: integer required"
        )
    return value


def _require_exact_keys(obj, expected, name: str) -> None:
    """Require an exact object schema at a consensus boundary.

    Unknown fields are rejected rather than ignored. This prevents
    multiple structurally different consensus objects from being
    accepted under validators that only inspect a subset of fields.
    """
    if not isinstance(obj, dict):
        raise ValueError(
            f"invalid {name}: object required"
        )

    expected = set(expected)
    actual = set(obj)

    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)

        raise ValueError(
            f"non-canonical {name} fields: "
            f"missing={missing}, extra={extra}"
        )


def block_header(block: dict) -> dict:
    return {
        "version": block["version"],
        "chain": block["chain"],
        "height": block["height"],
        "previous_hash": block["previous_hash"],
        "timestamp": block["timestamp"],
        "merkle_root": block["merkle_root"],
        "difficulty_bits": block["difficulty_bits"],
        "nonce": block["nonce"],
    }


def block_hash(block: dict) -> str:
    return sha256_hex(BLOCK_TAG + canonical_json(block_header(block)))


def pow_valid(h: str, difficulty_bits: int) -> bool:
    return int(h, 16) < (1 << (256 - difficulty_bits))


def mine_block(height: int, previous_hash: str, txs: List[dict],
               difficulty_bits: int = POW_DIFFICULTY_BITS,
               timestamp: int | None = None) -> dict:
    block = {
        "version": 2,
        "chain": CHAIN_NAME,
        "height": int(height),
        "previous_hash": previous_hash,
        "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        "merkle_root": merkle_root([tx["txid"] for tx in txs]),
        "difficulty_bits": int(difficulty_bits),
        "nonce": 0,
        "transactions": txs,
    }
    while True:
        h = block_hash(block)
        if pow_valid(h, difficulty_bits):
            block["hash"] = h
            return block
        block["nonce"] += 1


class Blockchain:
    def __init__(self, data_dir: Optional[str | Path] = None):
        self.data_dir = Path(data_dir) if data_dir else None
        self.blocks: List[dict] = []
        self.utxos: Dict[Tuple[str, int], dict] = {}

        # Derived, non-consensus indexes rebuilt from validated canonical
        # UTXO state. They are never persisted as an independent source
        # of truth.
        self._utxo_refs_by_address: Dict[
            str, List[Tuple[str, int]]
        ] = {}
        self._utxo_balance_by_address: Dict[str, int] = {}

        # Derived position of each canonical UTXO within its owner's
        # address-local reference list. This permits high-offset pagination
        # to jump directly into the list rather than walking from index 0.
        self._utxo_position_by_ref: Dict[
            Tuple[str, int], int
        ] = {}

        self.mempool: List[dict] = []
        if self.data_dir:
            self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def chain_path(self) -> Optional[Path]:
        return self.data_dir / "chain.json" if self.data_dir else None

    @property
    def mempool_path(self) -> Optional[Path]:
        return self.data_dir / "mempool.json" if self.data_dir else None

    def save(self) -> None:
        if not self.data_dir:
            return
        self.chain_path.write_text(json.dumps({
            "chain": CHAIN_NAME,
            "version": CHAIN_VERSION,
            "blocks": self.blocks,
        }, indent=2))
        self.mempool_path.write_text(json.dumps(self.mempool, indent=2))

    def load(self) -> None:
        if not self.data_dir:
            raise ValueError("no data directory configured")
        if not self.chain_path.exists():
            return
        doc = json.loads(self.chain_path.read_text())
        self.blocks = doc["blocks"]
        self.validate_chain(rebuild=True)

        if self.mempool_path.exists():
            candidates = json.loads(self.mempool_path.read_text())
            self.mempool = []
            for tx in candidates:
                try:
                    self.submit_tx(tx, save=False)
                except ValueError:
                    pass

    @staticmethod
    def _build_utxo_address_index(
        utxos: Dict[Tuple[str, int], dict],
    ):
        refs_by_address: Dict[
            str, List[Tuple[str, int]]
        ] = {}
        balances_by_address: Dict[str, int] = {}

        for ref, out in utxos.items():
            address = out["owner_address"]

            refs_by_address.setdefault(
                address,
                [],
            ).append(ref)

            balances_by_address[address] = (
                balances_by_address.get(
                    address,
                    0,
                )
                + int(out["amount"])
            )

        return (
            refs_by_address,
            balances_by_address,
        )

    @staticmethod
    def _build_utxo_position_index(
        refs_by_address: Dict[
            str, List[Tuple[str, int]]
        ],
    ) -> Dict[Tuple[str, int], int]:
        positions: Dict[Tuple[str, int], int] = {}

        for refs in refs_by_address.values():
            for position, ref in enumerate(refs):
                if ref in positions:
                    raise ValueError(
                        "duplicate UTXO reference in address index"
                    )

                positions[ref] = position

        return positions

    def _apply_payment(self, tx: dict, temp_utxos: dict) -> int:
        _require_exact_keys(
            tx,
            {
                "version",
                "chain",
                "kind",
                "fee",
                "inputs",
                "outputs",
                "txid",
            },
            "payment transaction",
        )

        if tx.get("kind") != "payment":
            raise ValueError("expected payment transaction")
        if not check_txid(tx):
            raise ValueError("bad transaction id")
        version = _require_consensus_int(
            tx.get("version"),
            "payment version",
        )

        if tx.get("chain") != CHAIN_NAME or version != 2:
            raise ValueError("wrong transaction chain/version")

        fee = _require_consensus_int(
            tx.get("fee"),
            "payment fee",
        )

        if fee < 0:
            raise ValueError("invalid fee")
        if not tx.get("inputs") or not tx.get("outputs"):
            raise ValueError("payment requires inputs and outputs")

        for inp in tx["inputs"]:
            _require_exact_keys(
                inp,
                {
                    "txid",
                    "index",
                    "signature",
                },
                "payment input",
            )

        refs = [
            (
                x["txid"],
                _require_consensus_int(
                    x.get("index"),
                    "payment input index",
                ),
            )
            for x in tx["inputs"]
        ]
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate input in transaction")

        for out in tx["outputs"]:
            validate_output_shape(out)

        unsigned = unsigned_payment_body(tx["inputs"], tx["outputs"], fee)

        total_in = 0
        for idx, inp in enumerate(tx["inputs"]):
            ref = (
                inp["txid"],
                _require_consensus_int(
                    inp.get("index"),
                    "payment input index",
                ),
            )
            prev = temp_utxos.get(ref)
            if prev is None:
                raise ValueError(f"missing or already-spent input {ref}")

            pub = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(prev["owner_sign_pub"])
            )
            try:
                pub.verify(
                    bytes.fromhex(inp["signature"]),
                    sighash_for_input(unsigned, idx),
                )
            except InvalidSignature as e:
                raise ValueError("invalid spend signature") from e
            total_in += _require_consensus_int(
                prev["amount"],
                "UTXO amount",
            )

        total_out = sum(
            _require_consensus_int(
                x["amount"],
                "payment output amount",
            )
            for x in tx["outputs"]
        )
        if total_in != total_out + fee:
            raise ValueError(
                f"value mismatch: input={total_in}, output={total_out}, fee={fee}"
            )

        for ref in refs:
            del temp_utxos[ref]
        for idx, out in enumerate(tx["outputs"]):
            temp_utxos[(tx["txid"], idx)] = out
        return fee

    def _validate_genesis(self, block: dict, temp_utxos: dict) -> None:
        if block["height"] != 0 or block["previous_hash"] != "00" * 32:
            raise ValueError("invalid genesis header linkage")
        if len(block["transactions"]) != 1:
            raise ValueError("genesis must have exactly one transaction")
        tx = block["transactions"][0]

        _require_exact_keys(
            tx,
            {
                "version",
                "chain",
                "kind",
                "height",
                "inputs",
                "fee",
                "outputs",
                "txid",
            },
            "genesis transaction",
        )

        tx_version = _require_consensus_int(
            tx.get("version"),
            "genesis transaction version",
        )
        tx_height = _require_consensus_int(
            tx.get("height"),
            "genesis transaction height",
        )
        tx_fee = _require_consensus_int(
            tx.get("fee"),
            "genesis transaction fee",
        )

        if (
            tx.get("kind") != "genesis"
            or tx.get("chain") != CHAIN_NAME
            or tx_version != 2
            or tx_height != 0
            or tx_fee != 0
        ):
            raise ValueError("invalid genesis transaction")

        if not check_txid(tx):
            raise ValueError("bad genesis txid")
        if tx.get("inputs"):
            raise ValueError("genesis cannot have inputs")
        if len(tx.get("outputs", [])) != 1:
            raise ValueError("genesis must have one output")
        out = tx["outputs"][0]
        validate_output_shape(out)
        genesis_amount = _require_consensus_int(
            out["amount"],
            "genesis output amount",
        )

        if genesis_amount != GENESIS_SUPPLY:
            raise ValueError("wrong genesis supply")
        temp_utxos[(tx["txid"], 0)] = out

    def _validate_normal_block(self, block: dict, temp_utxos: dict) -> None:
        txs = block["transactions"]
        if not txs or txs[0].get("kind") != "coinbase":
            raise ValueError("normal block must begin with coinbase")
        if any(tx.get("kind") == "coinbase" for tx in txs[1:]):
            raise ValueError("multiple coinbase transactions")

        fees = 0
        for tx in txs[1:]:
            fees += self._apply_payment(tx, temp_utxos)

        cb = txs[0]

        _require_exact_keys(
            cb,
            {
                "version",
                "chain",
                "kind",
                "height",
                "inputs",
                "fee",
                "outputs",
                "txid",
            },
            "coinbase transaction",
        )

        if not check_txid(cb):
            raise ValueError("bad coinbase txid")

        cb_version = _require_consensus_int(
            cb.get("version"),
            "coinbase version",
        )
        cb_height = _require_consensus_int(
            cb.get("height"),
            "coinbase height",
        )
        cb_fee = _require_consensus_int(
            cb.get("fee"),
            "coinbase fee",
        )

        if cb.get("chain") != CHAIN_NAME or cb_version != 2:
            raise ValueError("wrong coinbase chain/version")

        if cb_height != block["height"]:
            raise ValueError("coinbase height mismatch")

        if cb_fee != 0:
            raise ValueError("coinbase fee must be zero")

        if cb.get("inputs"):
            raise ValueError("coinbase cannot have inputs")
        if len(cb.get("outputs", [])) != 1:
            raise ValueError("coinbase must have one output")
        out = cb["outputs"][0]
        validate_output_shape(out)
        expected = BLOCK_REWARD + fees

        coinbase_amount = _require_consensus_int(
            out["amount"],
            "coinbase output amount",
        )

        if coinbase_amount != expected:
            raise ValueError(
                f"wrong coinbase reward: got {out['amount']}, expected {expected}"
            )

        subsidy = coinbase_amount - fees
        if subsidy < 0:
            raise ValueError("negative block subsidy")

        temp_utxos[(cb["txid"], 0)] = out
        return subsidy

    def validate_chain(self, rebuild: bool = False) -> bool:
        temp: Dict[Tuple[str, int], dict] = {}
        previous = "00" * 32
        minted_supply = 0

        for height, block in enumerate(self.blocks):
            _require_exact_keys(
                block,
                {
                    "version",
                    "chain",
                    "height",
                    "previous_hash",
                    "timestamp",
                    "merkle_root",
                    "difficulty_bits",
                    "nonce",
                    "transactions",
                    "hash",
                },
                "block",
            )

            version = _require_consensus_int(
                block.get("version"),
                "block version",
            )
            block_height = _require_consensus_int(
                block.get("height"),
                "block height",
            )
            _require_consensus_int(
                block.get("timestamp"),
                "block timestamp",
            )
            difficulty_bits = _require_consensus_int(
                block.get("difficulty_bits"),
                "block difficulty_bits",
            )
            _require_consensus_int(
                block.get("nonce"),
                "block nonce",
            )

            if block.get("chain") != CHAIN_NAME or version != 2:
                raise ValueError("bad block chain/version")
            if block_height != height:
                raise ValueError("block height mismatch")
            if block["previous_hash"] != previous:
                raise ValueError("broken previous-hash linkage")

            txids = [
                tx["txid"]
                for tx in block["transactions"]
            ]

            if len(txids) != len(set(txids)):
                raise ValueError(
                    "duplicate transaction id in block"
                )

            if block["merkle_root"] != merkle_root(txids):
                raise ValueError("bad merkle root")

            if block.get("hash") != block_hash(block):
                raise ValueError("bad block hash")
            if not pow_valid(block["hash"], difficulty_bits):
                raise ValueError("invalid proof of work")

            if height == 0:
                self._validate_genesis(block, temp)

                genesis_out = block["transactions"][0]["outputs"][0]
                minted_supply += int(genesis_out["amount"])
            else:
                subsidy = self._validate_normal_block(block, temp)
                minted_supply += subsidy

            if minted_supply > MAX_SUPPLY:
                raise ValueError(
                    "Stevens Chain 30M hard supply cap exceeded"
                )

            previous = block["hash"]

        if rebuild:
            (
                refs_by_address,
                balances_by_address,
            ) = self._build_utxo_address_index(temp)

            positions_by_ref = (
                self._build_utxo_position_index(
                    refs_by_address
                )
            )

            self.utxos = temp
            self._utxo_refs_by_address = refs_by_address
            self._utxo_balance_by_address = balances_by_address
            self._utxo_position_by_ref = positions_by_ref

        return True

    def add_genesis(self, recipient: PublicIdentity | Wallet) -> dict:
        if self.blocks:
            raise ValueError("genesis already exists")
        tx = make_genesis_tx(recipient)
        block = mine_block(0, "00" * 32, [tx])
        self.blocks = [block]
        self.validate_chain(rebuild=True)
        self.save()
        return block

    def _mempool_view(self) -> Dict[Tuple[str, int], dict]:
        temp = dict(self.utxos)
        for tx in self.mempool:
            self._apply_payment(tx, temp)
        return temp

    def submit_tx(self, tx: dict, save: bool = True) -> str:
        if not self.blocks:
            raise ValueError("chain not initialized")
        if any(x.get("txid") == tx.get("txid") for x in self.mempool):
            raise ValueError("transaction already in mempool")
        temp = self._mempool_view()
        self._apply_payment(tx, temp)
        self.mempool.append(tx)
        if save:
            self.save()
        return tx["txid"]

    def mine_mempool(self, miner: PublicIdentity | Wallet) -> dict:
        if not self.blocks:
            raise ValueError("chain not initialized")

        # Re-validate mempool against current confirmed UTXOs.
        temp = dict(self.utxos)
        valid_txs = []
        total_fees = 0
        for tx in self.mempool:
            try:
                fee = self._apply_payment(tx, temp)
            except ValueError:
                continue
            valid_txs.append(tx)
            total_fees += fee

        height = len(self.blocks)
        coinbase = make_coinbase_tx(
            miner,
            BLOCK_REWARD + total_fees,
            height,
            f"block {height} mining reward + fees",
        )
        block = mine_block(
            height,
            self.blocks[-1]["hash"],
            [coinbase] + valid_txs,
        )

        # Validate as part of a candidate extended chain before committing.
        old_blocks = self.blocks
        self.blocks = old_blocks + [block]
        try:
            self.validate_chain(rebuild=True)
        except Exception:
            self.blocks = old_blocks
            self.validate_chain(rebuild=True)
            raise

        mined_ids = {x["txid"] for x in valid_txs}
        self.mempool = [
            x for x in self.mempool if x.get("txid") not in mined_ids
        ]
        self.save()
        return block

    def spendable_for_address(self, address: str, include_mempool: bool = False):
        view = self._mempool_view() if include_mempool else self.utxos
        return [
            (ref, out) for ref, out in view.items()
            if out["owner_address"] == address
        ]

    def utxo_page_for_address(
        self,
        address: str,
        start: int,
        limit: int,
        include_mempool: bool = False,
    ):
        start = max(0, int(start))
        limit = max(1, int(limit))

        confirmed_refs = self._utxo_refs_by_address.get(
            address,
            [],
        )

        balance = int(
            self._utxo_balance_by_address.get(
                address,
                0,
            )
        )

        spent_confirmed = set()
        added = {}

        if include_mempool:
            # The mempool is already admission-validated and bounded.
            # Apply only effects relevant to this address rather than
            # rebuilding the complete global UTXO view.
            for tx in self.mempool:
                for inp in tx["inputs"]:
                    ref = (
                        inp["txid"],
                        int(inp["index"]),
                    )

                    if ref in added:
                        prior = added.pop(ref)
                        balance -= int(
                            prior["amount"]
                        )
                        continue

                    prev = self.utxos.get(ref)

                    if (
                        prev is not None
                        and
                        prev["owner_address"] == address
                        and
                        ref not in spent_confirmed
                    ):
                        spent_confirmed.add(ref)
                        balance -= int(
                            prev["amount"]
                        )

                txid = tx["txid"]

                for index, out in enumerate(
                    tx["outputs"]
                ):
                    if (
                        out["owner_address"]
                        != address
                    ):
                        continue

                    ref = (
                        txid,
                        index,
                    )

                    added[ref] = out
                    balance += int(
                        out["amount"]
                    )

        total_utxos = (
            len(confirmed_refs)
            - len(spent_confirmed)
            + len(added)
        )

        if balance < 0 or total_utxos < 0:
            raise ValueError(
                "derived UTXO address view is inconsistent"
            )

        page = []

        surviving_confirmed = (
            len(confirmed_refs)
            - len(spent_confirmed)
        )

        if start < surviving_confirmed:
            # Resolve the logical filtered offset to a raw position in the
            # canonical address list. Only mempool-spent confirmed refs can
            # shift this position, so work here is bounded by the mempool
            # rather than by the requested start offset.
            spent_positions = []

            for ref in spent_confirmed:
                position = self._utxo_position_by_ref.get(
                    ref
                )

                if (
                    position is None
                    or
                    position >= len(confirmed_refs)
                    or
                    confirmed_refs[position] != ref
                ):
                    raise ValueError(
                        "UTXO address position index out of sync"
                    )

                spent_positions.append(
                    position
                )

            spent_positions.sort()

            raw_index = start

            for position in spent_positions:
                if position <= raw_index:
                    raw_index += 1
                else:
                    break

            while (
                raw_index < len(confirmed_refs)
                and
                len(page) < limit
            ):
                ref = confirmed_refs[raw_index]
                raw_index += 1

                if ref in spent_confirmed:
                    continue

                out = self.utxos.get(ref)

                if (
                    out is None
                    or
                    out["owner_address"]
                    != address
                ):
                    raise ValueError(
                        "UTXO address index out of sync"
                    )

                page.append(
                    (ref, out)
                )

        if len(page) < limit:
            added_start = max(
                0,
                start - surviving_confirmed,
            )

            added_index = 0

            for ref, out in added.items():
                if added_index < added_start:
                    added_index += 1
                    continue

                page.append(
                    (ref, out)
                )

                if len(page) >= limit:
                    break

                added_index += 1

        return (
            page,
            balance,
            total_utxos,
        )

    def balance_address(self, address: str, include_mempool: bool = False) -> int:
        return sum(
            int(out["amount"])
            for _, out in self.spendable_for_address(address, include_mempool)
        )

    def decrypted_notes(self, wallet: Wallet) -> List[dict]:
        notes = []
        for ref, output in self.spendable_for_address(wallet.address):
            note = wallet.decrypt_output(output)
            notes.append({"ref": [ref[0], ref[1]], "note": note})
        return notes

    def public_status(self) -> dict:
        return {
            "chain": CHAIN_NAME,
            "version": CHAIN_VERSION,
            "height": len(self.blocks) - 1,
            "tip": self.blocks[-1]["hash"] if self.blocks else None,
            "mempool_size": len(self.mempool),
            "utxo_count": len(self.utxos),
            "block_reward_units": BLOCK_REWARD,
            "block_reward": fmt_amount(BLOCK_REWARD),
            "difficulty_bits": POW_DIFFICULTY_BITS,
        }


def create_simple_payment(
    chain: Blockchain,
    sender: Wallet,
    recipient: PublicIdentity | Wallet,
    amount: int,
    fee: int,
    memo: str = "",
) -> dict:
    if amount <= 0:
        raise ValueError("amount must be positive")
    if fee < 0:
        raise ValueError("fee cannot be negative")
    need = amount + fee
    spendable = chain.spendable_for_address(sender.address, include_mempool=True)

    refs = []
    outs = []
    total = 0
    for ref, out in spendable:
        refs.append(ref)
        outs.append(out)
        total += int(out["amount"])
        if total >= need:
            break

    if total < need:
        raise ValueError("insufficient funds")

    return make_payment_tx(
        sender,
        refs,
        outs,
        [(recipient, amount, memo)],
        fee=fee,
        change_amount=total - need,
    )
