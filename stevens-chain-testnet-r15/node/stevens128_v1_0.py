"""
Stevens Cipher 128 v1.0
Frozen experimental reference implementation
Date frozen: 2026-08-19

Core:
- 128-bit block
- 256-bit key
- 16-round Feistel network
- 64-bit round function with parity-selected branches
- custom 256-bit key schedule

SECURITY STATUS:
Experimental and unaudited. This implementation is provided for research,
reproducibility, and cryptanalysis. Do not treat Stevens-128 as a replacement
for standardized, reviewed constructions such as AES-GCM or ChaCha20-Poly1305.

The block cipher defined by encrypt_block/decrypt_block is the normative v1.0
core. The CTR + HMAC wrapper at the bottom is a non-normative convenience
prototype retained from development.
"""

import hashlib
import hmac
import secrets

VERSION = "1.0"
BLOCK_BYTES = 16
KEY_BYTES = 32
ROUNDS = 16
MASK64 = (1 << 64) - 1

P1 = 0x243F6A8885A308D3
P2 = 0x13198A2E03707344
P3 = 0xA4093822299F31D1
P4 = 0x082EFA98EC4E6C89
P5 = 0x452821E638D01377
P6 = 0xBE5466CF34E90C6C
P7 = 0xC0AC29B7C97C50DD
P8 = 0x3F84D5B5B5470917

MAGIC = b"STV128\x01"


def rotl64(x: int, r: int) -> int:
    r &= 63
    if r == 0:
        return x & MASK64
    return ((x << r) | (x >> (64 - r))) & MASK64


def expand_key_256(key: bytes, rounds: int = ROUNDS):
    """Return `rounds` 64-bit round keys."""
    if len(key) != KEY_BYTES:
        raise ValueError("key must be exactly 32 bytes")
    if not (1 <= rounds <= 255):
        raise ValueError("rounds must be in 1..255")

    k0, k1, k2, k3 = [
        int.from_bytes(key[i:i + 8], "big")
        for i in range(0, 32, 8)
    ]

    out = []
    for i in range(rounds):
        k0 = (rotl64((k0 + P1 + i * P5) & MASK64, 13) ^ k3) & MASK64
        k1 = (rotl64((k1 ^ ((k0 * P3) & MASK64) ^ P6), 29)
              + i * P2) & MASK64
        k2 = (rotl64((k2 + ((k1 * P7) & MASK64) + P4) & MASK64, 37)
              ^ k0) & MASK64
        k3 = (rotl64((k3 ^ ((k2 * P5) & MASK64) ^ P8), 43)
              + k1) & MASK64

        rk = (
            k0
            ^ rotl64(k1, 11)
            ^ rotl64(k2, 23)
            ^ rotl64(k3, 47)
            ^ (((i + 1) * P2) & MASK64)
        ) & MASK64
        out.append(rk)

    return out


def F(r: int, rk: int, rnd: int) -> int:
    """Stevens-128 v1.0 64-bit round function."""
    r &= MASK64
    rk &= MASK64

    if (r & 1) == 0:
        z = (r * P1 + rk + (rnd + 1) * P2) & MASK64
        z ^= rotl64(r, 17)
        z = (z * P5 + P7) & MASK64
        z ^= rotl64(z, 31)
        return rotl64(z, 23)

    z = ((((3 * r + 1) & MASK64) * P3)
         + rk + (rnd + 1) * P4) & MASK64
    z ^= rotl64(r, 41)
    z = (z * P7 + P5) & MASK64
    z ^= rotl64(z, 27)
    return rotl64(z, 37)


def encrypt_block_int(block128: int, key: bytes, rounds: int = ROUNDS) -> int:
    """Encrypt one 128-bit integer block."""
    if not (0 <= block128 < (1 << 128)):
        raise ValueError("block128 must be a 128-bit unsigned integer")

    L = (block128 >> 64) & MASK64
    R = block128 & MASK64

    for rnd, rk in enumerate(expand_key_256(key, rounds)):
        L, R = R, (L ^ F(R, rk, rnd)) & MASK64

    return (L << 64) | R


def decrypt_block_int(block128: int, key: bytes, rounds: int = ROUNDS) -> int:
    """Decrypt one 128-bit integer block."""
    if not (0 <= block128 < (1 << 128)):
        raise ValueError("block128 must be a 128-bit unsigned integer")

    L = (block128 >> 64) & MASK64
    R = block128 & MASK64
    rks = expand_key_256(key, rounds)

    for rnd in range(rounds - 1, -1, -1):
        L, R = (R ^ F(L, rks[rnd], rnd)) & MASK64, L

    return (L << 64) | R


def encrypt_block(block: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("block must be exactly 16 bytes")
    x = int.from_bytes(block, "big")
    return encrypt_block_int(x, key, rounds).to_bytes(BLOCK_BYTES, "big")


def decrypt_block(block: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("block must be exactly 16 bytes")
    x = int.from_bytes(block, "big")
    return decrypt_block_int(x, key, rounds).to_bytes(BLOCK_BYTES, "big")


# ---------------------------------------------------------------------------
# Non-normative data wrapper (CTR-style stream + HMAC-SHA256 authentication)
# ---------------------------------------------------------------------------

def _mac_key(key: bytes) -> bytes:
    return hashlib.sha256(b"StevensCipher128-MAC-v1" + key).digest()


def crypt_ctr(data: bytes, key: bytes, nonce: bytes, rounds: int = ROUNDS) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be exactly 32 bytes")
    if len(nonce) != 8:
        raise ValueError("nonce must be exactly 8 bytes")

    out = bytearray(len(data))
    for ctr, off in enumerate(range(0, len(data), BLOCK_BYTES)):
        if ctr >= (1 << 64):
            raise ValueError("message too long for 64-bit counter")
        counter_block = nonce + ctr.to_bytes(8, "big")
        ks = encrypt_block(counter_block, key, rounds)
        chunk = data[off:off + BLOCK_BYTES]
        for j, b in enumerate(chunk):
            out[off + j] = b ^ ks[j]
    return bytes(out)


def seal(data: bytes, key: bytes, nonce: bytes | None = None,
         rounds: int = ROUNDS) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be exactly 32 bytes")
    nonce = secrets.token_bytes(8) if nonce is None else nonce
    if len(nonce) != 8:
        raise ValueError("nonce must be exactly 8 bytes")

    ct = crypt_ctr(data, key, nonce, rounds)
    header = MAGIC + bytes([rounds]) + nonce + len(ct).to_bytes(8, "big")
    tag = hmac.new(_mac_key(key), header + ct, hashlib.sha256).digest()
    return header + ct + tag


def open_sealed(blob: bytes, key: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be exactly 32 bytes")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("invalid header")

    pos = len(MAGIC)
    if len(blob) < pos + 1 + 8 + 8 + 32:
        raise ValueError("truncated ciphertext")

    rounds = blob[pos]
    pos += 1
    nonce = blob[pos:pos + 8]
    pos += 8
    n = int.from_bytes(blob[pos:pos + 8], "big")
    pos += 8

    ct = blob[pos:pos + n]
    tag = blob[pos + n:pos + n + 32]
    if len(ct) != n or len(tag) != 32:
        raise ValueError("truncated ciphertext")

    header = blob[:pos]
    expected = hmac.new(_mac_key(key), header + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")

    return crypt_ctr(ct, key, nonce, rounds)


def self_test():
    vectors = [
        (
            "000102030405060708090A0B0C0D0E0F"
            "101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF",
            "A6410E2A2B574AC69376C41EFB370454",
        ),
        (
            "00" * 32,
            "00" * 16,
            "E03C0E8FACC0976F545DB4976A39A65E",
        ),
        (
            "FF" * 32,
            "FF" * 16,
            "761D76FA5BB823742C958C55E8393DFD",
        ),
    ]
    for key_hex, pt_hex, expected_hex in vectors:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct = encrypt_block(pt, key)
        assert ct.hex().upper() == expected_hex
        assert decrypt_block(ct, key) == pt
    return True


if __name__ == "__main__":
    self_test()
    key = bytes(range(32))
    block = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    ct = encrypt_block(block, key)
    print("Stevens Cipher 128 v1.0 self-test: PASS")
    print("plaintext :", block.hex().upper())
    print("ciphertext:", ct.hex().upper())
    print("recovered :", decrypt_block(ct, key).hex().upper())
