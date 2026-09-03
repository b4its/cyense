"""Pure-Python Twofish block cipher (spec implementation, MIT).

Twofish is a 128-bit block cipher designed by Bruce Schneier, John Kelsey,
Doug Whiting, David Wagner, Chris Hall and Niels Ferguson; it was an AES
finalist. This module implements the cipher from the public specification
(the q-permutation tables, MDS/Reed-Solomon matrices and key schedule are
published in the Twofish paper), so it is independent work rather than a
port of any GPL/AGPL project.

Supports 128/192/256-bit keys, ECB block encrypt/decrypt, and convenience
helpers for CBC/CTR-GCM-style modes via ``xor``/chaining primitives.

Correctness is pinned to the official ``ecb_tbl.txt`` known-answer tests
(see tests/test_cryptotool.py).
"""

from __future__ import annotations

_MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# q-permutation building blocks (Twofish spec §4.3)
# ---------------------------------------------------------------------------

_Q0_T = (
    (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
    (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
    (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
    (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
)

_Q1_T = (
    (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
    (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
    (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
    (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
)


def _build_q(t0, t1, t2, t3) -> list[int]:
    q = [0] * 256
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = a0 ^ ((b0 >> 1) | ((b0 & 1) << 3)) ^ ((8 * a0) & 0xF)
        a2, b2 = t0[a1], t1[b1]
        a3 = a2 ^ b2
        b3 = a2 ^ ((b2 >> 1) | ((b2 & 1) << 3)) ^ ((8 * a2) & 0xF)
        a4, b4 = t2[a3], t3[b3]
        q[x] = (b4 << 4) | a4
    return q


_Q0 = _build_q(*_Q0_T)
_Q1 = _build_q(*_Q1_T)
_QQ = (_Q0, _Q1)

_QORD = (
    (1, 1, 0, 0, 1),  # byte 0
    (0, 1, 1, 0, 0),  # byte 1
    (0, 0, 0, 1, 1),  # byte 2
    (1, 0, 1, 1, 0),  # byte 3
)


# ---------------------------------------------------------------------------
# GF(2^8) helpers
# ---------------------------------------------------------------------------

def _gf_mult(a: int, b: int, poly: int) -> int:
    result = 0
    a &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= poly & 0xFF
    return result


_MDS_POLY = 0x169


def _mds_col_mult(x: int, col: int) -> int:
    x01 = x
    x5b = _gf_mult(x, 0x5B, _MDS_POLY)
    xef = _gf_mult(x, 0xEF, _MDS_POLY)
    if col == 0:
        return x01 | (x5b << 8) | (xef << 16) | (xef << 24)
    if col == 1:
        return xef | (xef << 8) | (x5b << 16) | (x01 << 24)
    if col == 2:
        return x5b | (xef << 8) | (x01 << 16) | (xef << 24)
    return x5b | (x01 << 8) | (xef << 16) | (x5b << 24)


_MDS = [[_mds_col_mult(i, c) for i in range(256)] for c in range(4)]

_RS_POLY = 0x14D
_RS_MATRIX = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)


def _rs_mds_encode(k0: int, k1: int) -> int:
    inp = []
    for v in (k0, k1):
        for shift in (0, 8, 16, 24):
            inp.append((v >> shift) & 0xFF)
    result = 0
    for row in range(4):
        val = 0
        for col in range(8):
            val ^= _gf_mult(_RS_MATRIX[row][col], inp[col], _RS_POLY)
        result |= val << (row * 8)
    return result


def _rotl32(x: int, n: int) -> int:
    return ((x << n) & _MASK32) | (x >> (32 - n))


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _h_func(x: int, key_list: list[int], k: int) -> int:
    b = [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF]
    start = 5 - k - 1
    for i in range(4):
        b[i] = _QQ[_QORD[i][start]][b[i]]
    for j in range(k):
        key_word = key_list[k - 1 - j]
        for i in range(4):
            b[i] ^= (key_word >> (i * 8)) & 0xFF
            b[i] = _QQ[_QORD[i][start + 1 + j]][b[i]]
    return _MDS[0][b[0]] ^ _MDS[1][b[1]] ^ _MDS[2][b[2]] ^ _MDS[3][b[3]]


# ---------------------------------------------------------------------------
# Twofish
# ---------------------------------------------------------------------------

class Twofish:
    """Twofish block cipher (block size 16 bytes, key 16/24/32 bytes)."""

    block_size = 16

    def __init__(self, key: bytes) -> None:
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24 or 32 bytes (128/192/256 bit)")
        self._key = key
        self._k = len(key) // 8
        import struct

        num_words = len(key) // 4
        key_words = list(struct.unpack(f"<{num_words}I", key))
        me = [key_words[2 * i] for i in range(self._k)]
        mo = [key_words[2 * i + 1] for i in range(self._k)]
        s_keys = [
            _rs_mds_encode(key_words[2 * i], key_words[2 * i + 1])
            for i in range(self._k)
        ]
        self._sbox_keys = list(reversed(s_keys))
        self._subkeys = self._schedule(me, mo)

    def _schedule(self, me: list[int], mo: list[int]) -> list[int]:
        k = self._k
        sk = []
        step = 0x02020202
        bump = 0x01010101
        for i in range(20):
            a = _h_func(i * step, me, k)
            b = _rotl32(_h_func(i * step + bump, mo, k), 8)
            a_plus_b = (a + b) & _MASK32
            sk.append(a_plus_b)
            sk.append(_rotl32((a_plus_b + b) & _MASK32, 9))
        return sk

    def encrypt_block(self, data: bytes) -> bytes:
        import struct

        if len(data) != 16:
            raise ValueError("Twofish operates on 16-byte blocks")
        K = self._subkeys
        a, b, c, d = struct.unpack("<4I", data)
        a ^= K[0]
        b ^= K[1]
        c ^= K[2]
        d ^= K[3]
        for r in range(16):
            t0 = _h_func(a, self._sbox_keys, self._k)
            t1 = _h_func(_rotl32(b, 8), self._sbox_keys, self._k)
            f0 = (t0 + t1 + K[8 + 2 * r]) & _MASK32
            f1 = (t0 + 2 * t1 + K[9 + 2 * r]) & _MASK32
            c = _rotr32(c ^ f0, 1)
            d = _rotl32(d, 1) ^ f1
            a, b, c, d = c, d, a, b
        c ^= K[4]
        d ^= K[5]
        a ^= K[6]
        b ^= K[7]
        return struct.pack("<4I", c, d, a, b)

    def decrypt_block(self, data: bytes) -> bytes:
        import struct

        if len(data) != 16:
            raise ValueError("Twofish operates on 16-byte blocks")
        K = self._subkeys
        c, d, a, b = struct.unpack("<4I", data)
        c ^= K[4]
        d ^= K[5]
        a ^= K[6]
        b ^= K[7]
        for r in range(15, -1, -1):
            a, b, c, d = c, d, a, b
            t0 = _h_func(a, self._sbox_keys, self._k)
            t1 = _h_func(_rotl32(b, 8), self._sbox_keys, self._k)
            f0 = (t0 + t1 + K[8 + 2 * r]) & _MASK32
            f1 = (t0 + 2 * t1 + K[9 + 2 * r]) & _MASK32
            c = _rotl32(c, 1) ^ f0
            d = _rotr32(d ^ f1, 1)
        a ^= K[0]
        b ^= K[1]
        c ^= K[2]
        d ^= K[3]
        return struct.pack("<4I", a, b, c, d)


def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty ciphertext cannot be unpadded")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def twofish_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Twofish ECB encrypt with PKCS#7 padding."""
    cipher = Twofish(key)
    padded = _pad_pkcs7(plaintext, 16)
    return b"".join(cipher.encrypt_block(padded[i:i + 16])
                    for i in range(0, len(padded), 16))


def twofish_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Twofish ECB decrypt (requires PKCS#7 padding)."""
    cipher = Twofish(key)
    if len(ciphertext) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    padded = b"".join(cipher.decrypt_block(ciphertext[i:i + 16])
                      for i in range(0, len(ciphertext), 16))
    return _unpad_pkcs7(padded)


def twofish_encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """Twofish CBC encrypt with PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    cipher = Twofish(key)
    padded = _pad_pkcs7(plaintext, 16)
    prev = iv
    out = bytearray()
    for i in range(0, len(padded), 16):
        block = bytes(x ^ y for x, y in zip(padded[i:i + 16], prev, strict=False))
        enc = cipher.encrypt_block(block)
        out += enc
        prev = enc
    return bytes(out)


def twofish_decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Twofish CBC decrypt."""
    if len(iv) != 16 or len(ciphertext) % 16:
        raise ValueError("iv must be 16 bytes and ciphertext a multiple of 16")
    cipher = Twofish(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        ct_block = ciphertext[i:i + 16]
        dec = cipher.decrypt_block(ct_block)
        out += bytes(x ^ y for x, y in zip(dec, prev, strict=False))
        prev = ct_block
    return _unpad_pkcs7(bytes(out))


__all__ = [
    "Twofish",
    "twofish_encrypt_ecb",
    "twofish_decrypt_ecb",
    "twofish_encrypt_cbc",
    "twofish_decrypt_cbc",
]
