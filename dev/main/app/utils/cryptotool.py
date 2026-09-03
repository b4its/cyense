"""Cryptographic toolbelt — encrypt/decrypt/hash for the major algorithm
families, wired into the `cyense crypt` CLI command group.

Covers the classic / modern families:

  * **Hash functions** — MD5, SHA-1, SHA-2 (SHA-224/256/384/512), SHA-3,
    Blake2. MD5 and SHA-1 are included for interoperability but flagged as
    cryptographically broken when used for security purposes.
  * **HMAC** — keyed message authentication codes for the same digest set.
  * **Symmetric block ciphers** — AES (128/192/256 in ECB/CBC/GCM/CTR),
    Blowfish, Twofish (pure-Python reference implementation).
  * **Stream ciphers** — ChaCha20, Salsa20, RC4.
  * **RSA** — key generation, encrypt/decrypt (OAEP), sign/verify (PSS).
  * **ECC** — curve generation, ECDSA sign/verify, ECDH shared secret.
  * **KDF** — PBKDF2, scrypt (password-based key derivation).
  * **Digest identification** — given a hex digest, suggest the candidate
    hash algorithms (length heuristic only — for quick triage).

All low-level operations are delegated to ``pycryptodome`` (pure-Python
Twofish lives in ``app.utils.twofish_cipher``). Every function is deterministic
and pure; bytes in → bytes out, with explicit encoding helpers.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from Crypto.Cipher import AES, ARC4, PKCS1_OAEP, Blowfish, ChaCha20, Salsa20
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pss
from Crypto.Signature import PKCS1_v1_5 as SIG_PKCS1_v1_5
from Crypto.Util import Counter

from app.utils.twofish_cipher import (
    twofish_decrypt_cbc,
    twofish_decrypt_ecb,
    twofish_encrypt_cbc,
    twofish_encrypt_ecb,
)

# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def to_bytes(data: str | bytes, encoding: str = "utf-8") -> bytes:
    return data.encode(encoding) if isinstance(data, str) else data


def from_hex(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


def b64encode(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    import base64

    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

_DIGEST_ALGOS: dict[str, Any] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def hash_digest(algo: str, data: str | bytes) -> str:
    """Return the hex digest of *data* using *algo* (any hashlib name)."""
    key = (algo or "").lower().replace("-", "")
    try:
        fn = _DIGEST_ALGOS[key]
    except KeyError:
        raise ValueError(f"unsupported hash algorithm: {algo}") from None
    return fn(to_bytes(data)).hexdigest()


def identify_hash(hexdigest: str) -> list[str]:
    """Suggest candidate hash algorithms for a hex digest (by length)."""
    h = (hexdigest or "").strip()
    if not h or any(c not in "0123456789abcdefABCDEF" for c in h):
        return []
    lengths = {
        32: ["MD5", "NTLM", "RIPEMD-128"],
        40: ["SHA-1", "RIPEMD-160", "Haval-160"],
        56: ["SHA-224", "SHA3-224", "Blake2s-224"],
        64: ["SHA-256", "SHA3-256", "Blake2s-256", "RIPEMD-256"],
        96: ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512", "Whirlpool", "Blake2b-512"],
    }
    return lengths.get(len(h), [])


# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------
def hmac_digest(algo: str, data: str | bytes, key: str | bytes) -> str:
    """HMAC(key, data) with *algo* (any hashlib digest name)."""
    keyb = to_bytes(key)
    digest_fn = algo if hasattr(hashlib, algo) else sha256_fallback(algo)
    return hmac.new(keyb, to_bytes(data), digest_fn).hexdigest()


def sha256_fallback(name: str):
    """Resolve a pycryptodome digest name to a hashlib constructor."""
    mapping = {
        "sha3_256": hashlib.sha3_256,
        "sha3_224": hashlib.sha3_224,
        "sha3_384": hashlib.sha3_384,
        "sha3_512": hashlib.sha3_512,
    }
    return mapping.get(name.replace("-", ""), hashlib.sha256)


# ---------------------------------------------------------------------------
# Symmetric block ciphers — AES / Blowfish
# ---------------------------------------------------------------------------

_AES_MODES = {
    "ecb": AES.MODE_ECB,
    "cbc": AES.MODE_CBC,
    "ctr": AES.MODE_CTR,
    "gcm": AES.MODE_GCM,
}


def _pkcs7_pad(data: bytes, bs: int) -> bytes:
    pad = bs - (len(data) % bs)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid padding")
    return data[:-pad]


def aes_cipher(key: bytes, mode: str, nonce: bytes | None = None) -> Any:
    mode = (mode or "cbc").lower()
    if mode not in _AES_MODES:
        raise ValueError(f"unsupported AES mode: {mode}")
    if mode == "ecb":
        return AES.new(key, AES.MODE_ECB)
    if mode == "ctr":
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce or b"\x00" * 16, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr)
    iv = nonce or (b"\x00" * 16 if mode == "cbc" else b"\x00" * 12)
    return AES.new(key, _AES_MODES[mode], iv)  # type: ignore[arg-type]


def aes_encrypt(key: str | bytes, plaintext: str | bytes, mode: str = "cbc",
                nonce: str | bytes | None = None) -> str:
    """AES encrypt → base64 output."""
    kb = to_bytes(key)
    pt = to_bytes(plaintext)
    m = (mode or "cbc").lower()
    if len(kb) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes (128/192/256 bit)")
    nb_in = to_bytes(nonce) if nonce else None
    if m == "gcm":
        # GCM requires a unique nonce per key+message. A HARDCODED zero nonce
        # (previous behaviour) reuses the keystream and enables forgeries —
        # always generate a random one unless the caller supplies it. The blob
        # is length-prefixed so decrypt can round-trip ANY nonce length:
        #   <1-byte nonce_len> + <nonce> + <tag(16)> + <ciphertext>
        nb = nb_in or secrets.token_bytes(12)
        cipher = AES.new(kb, AES.MODE_GCM, nonce=nb)
        ct, tag = cipher.encrypt_and_digest(_pkcs7_pad(pt, 16))
        blob = bytes([len(nb)]) + nb + tag + ct
        return b64encode(blob)
    cipher = aes_cipher(kb, m, nb_in)
    if m in ("ecb", "cbc"):
        ct = cipher.encrypt(_pkcs7_pad(pt, 16))
    else:
        ct = cipher.encrypt(pt)
    return b64encode(ct)


def aes_decrypt(key: str | bytes, ciphertext: str, mode: str = "cbc",
                nonce: str | bytes | None = None) -> str:
    """AES decrypt from base64 input → utf-8 string."""
    kb = to_bytes(key)
    ct = b64decode(ciphertext)
    m = (mode or "cbc").lower()
    if len(kb) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes (128/192/256 bit)")
    if m == "gcm":
        # Blob layout written by aes_encrypt: <1-byte nonce_len> + nonce +
        # tag(16) + ciphertext. Decode with the ACTUAL nonce length rather
        # than assuming 12 bytes (previously a 16-byte nonce → MAC check
        # failed and the documented feature was unusable).
        if len(ct) < 18:
            raise ValueError("ciphertext too short for GCM blob")
        nonce_len = ct[0]
        if nonce_len < 1 or nonce_len > 32 or len(ct) < 1 + nonce_len + 16:
            raise ValueError("invalid GCM blob (bad nonce length)")
        nb = ct[1 : 1 + nonce_len]
        tag = ct[1 + nonce_len : 1 + nonce_len + 16]
        body = ct[1 + nonce_len + 16 :]
        cipher = AES.new(kb, AES.MODE_GCM, nonce=nb)
        data = cipher.decrypt(body)
        cipher.verify(tag)
        return _pkcs7_unpad(data).decode("utf-8", errors="replace")
    cipher = aes_cipher(kb, m, to_bytes(nonce) if nonce else None)
    if m in ("ecb", "cbc"):
        return _pkcs7_unpad(cipher.decrypt(ct)).decode("utf-8", errors="replace")
    return cipher.decrypt(ct).decode("utf-8", errors="replace")


def blowfish_encrypt(key: str | bytes, plaintext: str | bytes,
                     mode: str = "cbc", nonce: str | bytes | None = None) -> str:
    """Blowfish encrypt → base64 (ECB/CBC, PKCS#7)."""
    kb = to_bytes(key)
    pt = to_bytes(plaintext)
    m = (mode or "cbc").lower()
    if m not in ("ecb", "cbc"):
        raise ValueError(f"unsupported Blowfish mode: {mode} (expected ecb|cbc)")
    nb = to_bytes(nonce) if nonce else b"\x00" * 8
    if m == "ecb":
        cipher = Blowfish.new(kb, Blowfish.MODE_ECB)
    else:
        if len(nb) != 8:
            raise ValueError("Blowfish IV must be 8 bytes")
        cipher = Blowfish.new(kb, Blowfish.MODE_CBC, nb)
    return b64encode(cipher.encrypt(_pkcs7_pad(pt, 8)))


def blowfish_decrypt(key: str | bytes, ciphertext: str,
                     mode: str = "cbc", nonce: str | bytes | None = None) -> str:
    kb = to_bytes(key)
    ct = b64decode(ciphertext)
    m = (mode or "cbc").lower()
    if m not in ("ecb", "cbc"):
        raise ValueError(f"unsupported Blowfish mode: {mode} (expected ecb|cbc)")
    nb = to_bytes(nonce) if nonce else b"\x00" * 8
    if m == "ecb":
        cipher = Blowfish.new(kb, Blowfish.MODE_ECB)
    else:
        if len(nb) != 8:
            raise ValueError("Blowfish IV must be 8 bytes")
        cipher = Blowfish.new(kb, Blowfish.MODE_CBC, nb)
    return _pkcs7_unpad(cipher.decrypt(ct)).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Stream ciphers — ChaCha20 / Salsa20 / RC4
# ---------------------------------------------------------------------------

def chacha20_encrypt(key: str | bytes, nonce: str | bytes,
                     plaintext: str | bytes) -> str:
    kb = to_bytes(key)
    nb = to_bytes(nonce)
    if len(kb) != 32 or len(nb) != 8:
        raise ValueError("ChaCha20 key must be 32 bytes and nonce 8 bytes")
    cipher = ChaCha20.new(key=kb, nonce=nb)
    return b64encode(cipher.encrypt(to_bytes(plaintext)))


def chacha20_decrypt(key: str | bytes, nonce: str | bytes, ciphertext: str) -> str:
    kb = to_bytes(key)
    nb = to_bytes(nonce)
    if len(kb) != 32 or len(nb) != 8:
        raise ValueError("ChaCha20 key must be 32 bytes and nonce 8 bytes")
    cipher = ChaCha20.new(key=kb, nonce=nb)
    return cipher.decrypt(b64decode(ciphertext)).decode("utf-8", errors="replace")


def salsa20_encrypt(key: str | bytes, nonce: str | bytes,
                    plaintext: str | bytes) -> str:
    kb = to_bytes(key)
    nb = to_bytes(nonce)
    if len(kb) not in (16, 32) or len(nb) != 8:
        raise ValueError("Salsa20 key must be 16/32 bytes and nonce 8 bytes")
    cipher = Salsa20.new(key=kb, nonce=nb)
    return b64encode(cipher.encrypt(to_bytes(plaintext)))


def salsa20_decrypt(key: str | bytes, nonce: str | bytes, ciphertext: str) -> str:
    kb = to_bytes(key)
    nb = to_bytes(nonce)
    if len(kb) not in (16, 32) or len(nb) != 8:
        raise ValueError("Salsa20 key must be 16/32 bytes and nonce 8 bytes")
    cipher = Salsa20.new(key=kb, nonce=nb)
    return cipher.decrypt(b64decode(ciphertext)).decode("utf-8", errors="replace")


def rc4_encrypt(key: str | bytes, plaintext: str | bytes) -> str:
    """RC4 — legacy, only for interoperability (broken cipher)."""
    kb = to_bytes(key)
    if not kb:
        raise ValueError("RC4 key must be non-empty")
    cipher = ARC4.new(kb)
    return b64encode(cipher.encrypt(to_bytes(plaintext)))


def rc4_decrypt(key: str | bytes, ciphertext: str) -> str:
    kb = to_bytes(key)
    if not kb:
        raise ValueError("RC4 key must be non-empty")
    cipher = ARC4.new(kb)
    return cipher.decrypt(b64decode(ciphertext)).decode("utf-8", errors="replace")


def twofish_encrypt(key: str | bytes, plaintext: str | bytes,
                    mode: str = "cbc", nonce: str | bytes | None = None) -> str:
    kb = to_bytes(key)
    pt = to_bytes(plaintext)
    m = (mode or "cbc").lower()
    if m not in ("ecb", "cbc"):
        raise ValueError(f"unsupported Twofish mode: {mode} (expected ecb|cbc)")
    nb = to_bytes(nonce) if nonce else None
    if m == "ecb":
        return b64encode(twofish_encrypt_ecb(kb, pt))
    return b64encode(twofish_encrypt_cbc(kb, pt, nb or b"\x00" * 16))


def twofish_decrypt(key: str | bytes, ciphertext: str,
                    mode: str = "cbc", nonce: str | bytes | None = None) -> str:
    kb = to_bytes(key)
    ct = b64decode(ciphertext)
    m = (mode or "cbc").lower()
    if m not in ("ecb", "cbc"):
        raise ValueError(f"unsupported Twofish mode: {mode} (expected ecb|cbc)")
    nb = to_bytes(nonce) if nonce else None
    if m == "ecb":
        return twofish_decrypt_ecb(kb, ct).decode("utf-8", errors="replace")
    return twofish_decrypt_cbc(kb, ct, nb or b"\x00" * 16).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

def rsa_generate(bits: int = 2048) -> dict[str, str]:
    key = RSA.generate(bits)
    return {
        "private_pem": key.export_key(format="PEM").decode(),
        "public_pem": key.publickey().export_key(format="PEM").decode(),
    }


def rsa_encrypt(public_pem: str, plaintext: str | bytes) -> str:
    key = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(key)
    return b64encode(cipher.encrypt(to_bytes(plaintext)))


def rsa_decrypt(private_pem: str, ciphertext: str) -> str:
    key = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(b64decode(ciphertext)).decode("utf-8", errors="replace")


def rsa_sign(private_pem: str, message: str | bytes, scheme: str = "pss") -> str:
    key = RSA.import_key(private_pem)
    h = SHA256.new(to_bytes(message))
    if scheme.lower() == "pss":
        sig = pss.new(key).sign(h)
    else:
        sig = SIG_PKCS1_v1_5.new(key).sign(h)
    return b64encode(sig)


def rsa_verify(public_pem: str, message: str | bytes, signature: str,
               scheme: str = "pss") -> bool:
    key = RSA.import_key(public_pem)
    h = SHA256.new(to_bytes(message))
    sig = b64decode(signature)
    try:
        if scheme.lower() == "pss":
            pss.new(key).verify(h, sig)
        else:
            SIG_PKCS1_v1_5.new(key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# ECC
# ---------------------------------------------------------------------------

def ecc_generate(curve: str = "P-256") -> dict[str, str]:
    key = ECC.generate(curve=curve)
    priv = key.export_key(format="PEM")
    pub = key.public_key().export_key(format="PEM")
    return {
        "private_pem": priv if isinstance(priv, str) else priv.decode(),
        "public_pem": pub if isinstance(pub, str) else pub.decode(),
    }


def ecc_sign(private_pem: str, message: str | bytes, curve: str = "P-256",
             scheme: str = "fips-186-3") -> str:
    key = ECC.import_key(private_pem)
    h = SHA256.new(to_bytes(message))
    dss = DSS.new(key, mode=scheme.lower())
    return b64encode(dss.sign(h))


def ecc_verify(public_pem: str, message: str | bytes, signature: str,
               curve: str = "P-256", scheme: str = "fips-186-3") -> bool:
    key = ECC.import_key(public_pem)
    h = SHA256.new(to_bytes(message))
    dss = DSS.new(key, mode=scheme.lower())
    try:
        dss.verify(h, b64decode(signature))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def derive_key(algo: str, password: str | bytes, salt: str | bytes,
               length: int = 32, iterations: int = 200_000) -> str:
    """Derive a key with PBKDF2 (default) or scrypt."""
    pw = to_bytes(password)
    sa = to_bytes(salt)
    import binascii

    if algo.lower() in ("pbkdf2", "pbkdf2-hmac-sha256"):
        dk = hashlib.pbkdf2_hmac("sha256", pw, sa, iterations, dklen=length)
    elif algo.lower() == "scrypt":
        dk = hashlib.scrypt(pw, salt=sa, n=2**14, r=8, p=1, dklen=length)
    else:
        raise ValueError(f"unsupported KDF: {algo}")
    return binascii.hexlify(dk).decode()


# ---------------------------------------------------------------------------
# Misc helpers for the CLI
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> str:
    """Cryptographically random bytes (hex)."""
    return secrets.token_hex(n)


def hash_catalog() -> list[dict[str, str]]:
    """List the supported hash algorithms and their digest lengths."""
    return [
        {"algo": "md5", "bits": "128", "broken": True},
        {"algo": "sha1", "bits": "160", "broken": True},
        {"algo": "sha224", "bits": "224"},
        {"algo": "sha256", "bits": "256"},
        {"algo": "sha384", "bits": "384"},
        {"algo": "sha512", "bits": "512"},
        {"algo": "sha3_224", "bits": "224"},
        {"algo": "sha3_256", "bits": "256"},
        {"algo": "sha3_512", "bits": "512"},
        {"algo": "blake2b", "bits": "512"},
        {"algo": "blake2s", "bits": "256"},
    ]


__all__ = [
    "hash_digest",
    "identify_hash",
    "hmac_digest",
    "aes_encrypt",
    "aes_decrypt",
    "blowfish_encrypt",
    "blowfish_decrypt",
    "chacha20_encrypt",
    "chacha20_decrypt",
    "salsa20_encrypt",
    "salsa20_decrypt",
    "rc4_encrypt",
    "rc4_decrypt",
    "twofish_encrypt",
    "twofish_decrypt",
    "rsa_generate",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_sign",
    "rsa_verify",
    "ecc_generate",
    "ecc_sign",
    "ecc_verify",
    "derive_key",
    "random_bytes",
    "hash_catalog",
    "b64encode",
    "b64decode",
    "to_bytes",
]

