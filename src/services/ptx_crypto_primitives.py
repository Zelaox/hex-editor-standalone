"""Low-level XOR / SHA / entropy / AES-128 primitives for PTX crypto analysis."""

from __future__ import annotations

import hashlib
import math
from typing import Dict, Iterable, List, Sequence, Tuple

# AES S-box (FIPS-197) — used for detection and pure-Python AES-128 ECB trial decrypt.
_AES_SBOX: Tuple[int, ...] = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_AES_RCON: Tuple[int, ...] = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte <= 126)
    return round(printable / len(data), 4)


def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    key_len = len(key)
    for index, byte in enumerate(data):
        out[index] = byte ^ key[index % key_len]
    return bytes(out)


def is_identity_transform(cipher: bytes, transformed: bytes) -> bool:
    return cipher == transformed


def pt12_signature_key(magic: bytes = b"\x03\x30\x30\x31") -> int:
    return sum(magic) % 256


def aes_sbox_density(data: bytes) -> float:
    if not data:
        return 0.0
    sbox = set(_AES_SBOX)
    hits = sum(1 for byte in data if byte in sbox)
    return round(hits / len(data), 4)


def _xtime(value: int) -> int:
    value <<= 1
    return value ^ 0x1B if value & 0x100 else value


def _aes128_key_expansion(key: bytes) -> List[List[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    words: List[int] = list(key)
    for index in range(4, 44):
        temp = words[(index - 1) * 4 : index * 4]
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _AES_RCON[index // 4]
        for byte_index in range(4):
            words.append(words[(index - 4) * 4 + byte_index] ^ temp[byte_index])
    round_keys = []
    for round_index in range(11):
        chunk = words[round_index * 16 : (round_index + 1) * 16]
        round_keys.append([list(chunk[index : index + 4]) for index in range(0, 16, 4)])
    return round_keys


def _aes128_decrypt_block(block: bytes, round_keys: Sequence[Sequence[Sequence[int]]]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = [list(block[row * 4 : (row + 1) * 4]) for row in range(4)]

    def add_round_key(state_matrix, round_key):
        return [[state_matrix[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

    def inv_sub_bytes(state_matrix):
        inv = {value: index for index, value in enumerate(_AES_SBOX)}
        return [[inv[state_matrix[r][c]] for c in range(4)] for r in range(4)]

    def inv_shift_rows(state_matrix):
        return [
            [state_matrix[0][0], state_matrix[0][1], state_matrix[0][2], state_matrix[0][3]],
            [state_matrix[1][3], state_matrix[1][0], state_matrix[1][1], state_matrix[1][2]],
            [state_matrix[2][2], state_matrix[2][3], state_matrix[2][0], state_matrix[2][1]],
            [state_matrix[3][1], state_matrix[3][2], state_matrix[3][3], state_matrix[3][0]],
        ]

    def inv_mix_columns(state_matrix):
        def mul(a, b):
            result = 0
            for bit in range(8):
                if b & 1:
                    result ^= a
                high = a & 0x80
                a = (a << 1) & 0xFF
                if high:
                    a ^= 0x1B
                b >>= 1
            return result

        out = [[0] * 4 for _ in range(4)]
        for col in range(4):
            out[0][col] = mul(0x0E, state_matrix[0][col]) ^ mul(0x0B, state_matrix[1][col]) ^ mul(0x0D, state_matrix[2][col]) ^ mul(0x09, state_matrix[3][col])
            out[1][col] = mul(0x09, state_matrix[0][col]) ^ mul(0x0E, state_matrix[1][col]) ^ mul(0x0B, state_matrix[2][col]) ^ mul(0x0D, state_matrix[3][col])
            out[2][col] = mul(0x0D, state_matrix[0][col]) ^ mul(0x09, state_matrix[1][col]) ^ mul(0x0E, state_matrix[2][col]) ^ mul(0x0B, state_matrix[3][col])
            out[3][col] = mul(0x0B, state_matrix[0][col]) ^ mul(0x0D, state_matrix[1][col]) ^ mul(0x09, state_matrix[2][col]) ^ mul(0x0E, state_matrix[3][col])
        return out

    state = add_round_key(state, round_keys[10])
    for round_index in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return bytes(state[row][col] for row in range(4) for col in range(4))


def aes128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 ECB requires 16-byte key")
    if len(data) % 16 != 0:
        data = data[: len(data) - (len(data) % 16)]
    round_keys = _aes128_key_expansion(key)
    blocks = []
    for offset in range(0, len(data), 16):
        blocks.append(_aes128_decrypt_block(data[offset : offset + 16], round_keys))
    return b"".join(blocks)


def aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 CBC requires 16-byte key")
    if len(iv) != 16:
        raise ValueError("AES-128 CBC requires 16-byte IV")
    if len(data) % 16 != 0:
        data = data[: len(data) - (len(data) % 16)]
    round_keys = _aes128_key_expansion(key)
    prev = iv
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        decrypted = _aes128_decrypt_block(block, round_keys)
        plain = bytes(a ^ b for a, b in zip(decrypted, prev))
        out.extend(plain)
        prev = block
    return bytes(out)


def aes128_ctr_decrypt(data: bytes, key: bytes, nonce: bytes, *, counter_start: int = 0) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 CTR requires 16-byte key")
    if len(nonce) != 16:
        raise ValueError("AES-128 CTR requires 16-byte nonce/counter block")
    round_keys = _aes128_key_expansion(key)
    out = bytearray()
    counter = int(counter_start)
    for offset in range(0, len(data), 16):
        counter_block = bytearray(nonce)
        counter_block[12:16] = (counter).to_bytes(4, "big")
        keystream = _aes128_decrypt_block(bytes(counter_block), round_keys)
        chunk = data[offset : offset + 16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
        counter += 1
    return bytes(out)


def derive_iv_from_spec(raw: bytes, spec: str) -> bytes:
    """Resolve IV/nonce from registry spec — prefix_slice:0:16 or sha256_prefix:64:16."""
    text = str(spec or "").strip()
    if text.startswith("prefix_slice:"):
        parts = text.split(":")
        start = int(parts[1]) if len(parts) > 1 else 0
        length = int(parts[2]) if len(parts) > 2 else 16
        slice_bytes = raw[start : start + length]
        if len(slice_bytes) < length:
            slice_bytes = slice_bytes + b"\x00" * (length - len(slice_bytes))
        return slice_bytes[:length]
    if text.startswith("sha256_prefix:"):
        parts = text.split(":")
        prefix_len = int(parts[1]) if len(parts) > 1 else 64
        out_len = int(parts[2]) if len(parts) > 2 else 16
        return hashlib.sha256(raw[:prefix_len]).digest()[:out_len]
    raise ValueError(f"unknown iv derivation spec: {spec}")


def pkcs7_unpad(data: bytes) -> Tuple[bytes, bool]:
    if not data:
        return data, False
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        return data, False
    if data[-pad:] != bytes([pad]) * pad:
        return data, False
    return data[:-pad], True


def derive_aes_candidate_keys(seed: bytes) -> List[bytes]:
    """Derive bounded AES-128 key candidates from file prefix / PT12 signature."""
    candidates: List[bytes] = []
    if len(seed) >= 16:
        candidates.append(seed[:16])
    if len(seed) >= 32:
        candidates.append(seed[16:32])
    if len(seed) >= 4:
        sig = bytes([pt12_signature_key(seed[:4])]) * 16
        candidates.append(sig)
    doubled = (seed[:8] * 2)[:16] if seed else b"\x00" * 16
    candidates.append(doubled)
    digest = hashlib.sha256(seed[:64]).digest()[:16]
    candidates.append(digest)
    unique: Dict[bytes, None] = {}
    for item in candidates:
        if len(item) == 16:
            unique[item] = None
    return list(unique.keys())
