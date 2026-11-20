"""Mechanical executors selected by the validated key-hunt transform registry."""

from __future__ import annotations

from typing import Any, Mapping


def apply_xor_descriptor(source: bytes, descriptor: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(descriptor["constraints"]["key_hex"]))
    if not key:
        raise ValueError("XOR descriptor key is empty")
    result = bytearray(source)
    for source_range in descriptor["source_ranges"]:
        start, length = int(source_range["offset"]), int(source_range["length"])
        for index in range(length):
            result[start + index] ^= key[index % len(key)]
    return bytes(result)
