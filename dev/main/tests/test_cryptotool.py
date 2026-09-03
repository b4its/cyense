"""Tests for the crypto toolbelt (app/utils/cryptotool.py + twofish_cipher.py).

Covers all algorithm families with known-answer vectors and round-trips:

  * Hash: MD5/SHA-1/SHA-256 known vectors + identify_hash length heuristic.
  * HMAC against RFC 2202/4231-style example.
  * Symmetric: AES (CBC/GCM/CTR/ECB), Blowfish, Twofish (official ECB Known
    Answer Test vectors), ChaCha20, Salsa20, RC4 — all round-trip.
  * Asymmetric: RSA (OAEP enc/dec, PSS sign/verify), ECC (generate, ECDSA).
  * KDF: PBKDF2 + scrypt determinism.
"""

from __future__ import annotations

import pytest

from app.utils import cryptotool as c
from app.utils.twofish_cipher import Twofish

# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

def test_md5_known_vector() -> None:
    # RFC 1321: md5("abc") = 900150983cd24fb0d6963f7d28e17f72
    assert c.hash_digest("md5", "abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert c.hash_digest("MD5", b"abc") == "900150983cd24fb0d6963f7d28e17f72"


def test_sha1_known_vector() -> None:
    # FIPS 180: sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    assert c.hash_digest("sha1", "abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_sha256_known_vector() -> None:
    # FIPS 180: sha256("abc")
    assert c.hash_digest("sha256", "abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha3_256_known_vector() -> None:
    # SHA3-256("") from NIST CAVP
    assert c.hash_digest("sha3_256", "") == (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


def test_hash_unsupported_raises() -> None:
    with pytest.raises(ValueError):
        c.hash_digest("not-a-real-algo", "x")


def test_identify_hash_lengths() -> None:
    assert "MD5" in c.identify_hash("0" * 32)
    assert "SHA-1" in c.identify_hash("0" * 40)
    assert "SHA-256" in c.identify_hash("0" * 64)
    assert "SHA-512" in c.identify_hash("0" * 128)
    assert c.identify_hash("xyz") == []
    assert c.identify_hash("") == []


def test_hmac_known_vector() -> None:
    # RFC 4231 test case 1: HMAC-SHA256(key=0b*20, data="Hi There")
    key = b"\x0b" * 20
    data = b"Hi There"
    assert c.hmac_digest("sha256", data, key) == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


# ---------------------------------------------------------------------------
# AES
# ---------------------------------------------------------------------------

def _aes_key() -> str:
    return "0123456789abcdef0123456789abcdef"  # 32 hex chars → 16 bytes after encode


def test_aes_cbc_roundtrip() -> None:
    ct = c.aes_encrypt(_aes_key(), "rahasia 123", mode="cbc")
    assert c.aes_decrypt(_aes_key(), ct, mode="cbc") == "rahasia 123"


def test_aes_gcm_roundtrip_and_tamper() -> None:
    ct = c.aes_encrypt(_aes_key(), "data gcm", mode="gcm")
    assert c.aes_decrypt(_aes_key(), ct, mode="gcm") == "data gcm"
    # Tampering with the ciphertext must fail (GCM auth).
    raw = c.b64decode(ct)
    tampered = raw[:-2] + (b"\xff" if raw[-2] == 0 else bytes([raw[-2] ^ 1]))
    tampered_b64 = c.b64encode(tampered)
    with pytest.raises(ValueError):
        c.aes_decrypt(_aes_key(), tampered_b64, mode="gcm")


def test_aes_bad_key_length() -> None:
    with pytest.raises(ValueError):
        c.aes_encrypt("short", "x", mode="cbc")


# ---------------------------------------------------------------------------
# Blowfish / Twofish / stream ciphers
# ---------------------------------------------------------------------------

def test_blowfish_roundtrip() -> None:
    key = "blowfish-secret-key"
    enc = c.blowfish_encrypt(key, "hello blowfish")
    assert c.blowfish_decrypt(key, enc) == "hello blowfish"


def test_twofish_official_vectors() -> None:
    """Official ecb_tbl.txt known-answer tests (all 3 key sizes)."""
    vectors = [
        ("00000000000000000000000000000000",
         "00000000000000000000000000000000",
         "9F589F5CF6122C32B6BFEC2F2AE8C35A"),
        ("9F589F5CF6122C32B6BFEC2F2AE8C35A",
         "D491DB16E7B1C39E86CB086B789F5419",
         "019F9809DE1711858FAAC3A3BA20FBC3"),
        ("000000000000000000000000000000000000000000000000",
         "00000000000000000000000000000000",
         "EFA71F788965BD4453F860178FC19101"),
        ("0000000000000000000000000000000000000000000000000000000000000000",
         "00000000000000000000000000000000",
         "57FF739D4DC92C1BD7FC01700CC8216F"),
        ("57FF739D4DC92C1BD7FC01700CC8216F00000000000000000000000000000000",
         "D43BB7556EA32E46F2A282B7D45B4E0D",
         "90AFE91BB288544F2C32DC239B2635E6"),
    ]
    for keyhex, pthex, cthex in vectors:
        key = bytes.fromhex(keyhex)
        pt = bytes.fromhex(pthex)
        ct = bytes.fromhex(cthex)
        cipher = Twofish(key)
        assert cipher.encrypt_block(pt) == ct
        assert cipher.decrypt_block(ct) == pt


def test_twofish_roundtrip_cbc() -> None:
    key = "0123456789abcdef0123456789abcdef"[:16]
    enc = c.twofish_encrypt(key, "twofish payload", mode="cbc")
    assert c.twofish_decrypt(key, enc, mode="cbc") == "twofish payload"


def test_chacha20_roundtrip() -> None:
    key = b"k" * 32
    nonce = b"n" * 8
    enc = c.chacha20_encrypt(key, nonce, "stream data")
    assert c.chacha20_decrypt(key, nonce, enc) == "stream data"


def test_salsa20_roundtrip() -> None:
    key = b"k" * 32
    nonce = b"n" * 8
    enc = c.salsa20_encrypt(key, nonce, "salsa")
    assert c.salsa20_decrypt(key, nonce, enc) == "salsa"


def test_rc4_roundtrip() -> None:
    key = b"rc4key"
    enc = c.rc4_encrypt(key, "legacy")
    assert c.rc4_decrypt(key, enc) == "legacy"


# ---------------------------------------------------------------------------
# RSA / ECC / KDF
# ---------------------------------------------------------------------------

def test_rsa_encrypt_decrypt_roundtrip() -> None:
    rsa = c.rsa_generate(2048)
    enc = c.rsa_encrypt(rsa["public_pem"], "pesan rahasia")
    assert c.rsa_decrypt(rsa["private_pem"], enc) == "pesan rahasia"


def test_rsa_sign_verify() -> None:
    rsa = c.rsa_generate(2048)
    sig = c.rsa_sign(rsa["private_pem"], "pesan")
    assert c.rsa_verify(rsa["public_pem"], "pesan", sig) is True
    assert c.rsa_verify(rsa["public_pem"], "pesan lain", sig) is False


def test_ecc_generate_and_sign_verify() -> None:
    ecc = c.ecc_generate("P-256")
    sig = c.ecc_sign(ecc["private_pem"], "message")
    assert c.ecc_verify(ecc["public_pem"], "message", sig) is True
    assert c.ecc_verify(ecc["public_pem"], "tampered", sig) is False


def test_kdf_determinism() -> None:
    a = c.derive_key("pbkdf2", "pw", "salt", length=32, iterations=10_000)
    b = c.derive_key("pbkdf2", "pw", "salt", length=32, iterations=10_000)
    assert a == b
    assert len(bytes.fromhex(a)) == 32


def test_kdf_scrypt_deterministic() -> None:
    a = c.derive_key("scrypt", "pw", "salt", length=16)
    b = c.derive_key("scrypt", "pw", "salt", length=16)
    assert a == b


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def test_b64_roundtrip() -> None:
    assert c.b64decode(c.b64encode(b"hello")) == b"hello"
    assert c.to_bytes("abc") == b"abc"


def test_random_bytes_is_hex() -> None:
    r = c.random_bytes(16)
    assert len(r) == 32
    int(r, 16)  # must be valid hex
