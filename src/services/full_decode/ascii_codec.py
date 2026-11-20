"""Canonical, streaming-friendly 7-bit ASCII representation of arbitrary bytes."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

_HEADER = re.compile(r"^FULL-DECODE-ASCII/1 size=([0-9]+) sha256=([0-9a-f]{64}) width=([0-9]+)$")
_DATA = re.compile(r"^@([0-9a-f]{16}):((?: [0-9a-f]{2})*)$")
_FOOTER = re.compile(r"^END sha256=([0-9a-f]{64})$")


def encode_lossless_ascii(data: bytes, *, bytes_per_line: int) -> str:
    """Encode bytes into one canonical ASCII document."""
    width = int(bytes_per_line)
    if width < 1:
        raise ValueError("bytes_per_line must be positive")
    digest = hashlib.sha256(data).hexdigest()
    lines = [f"FULL-DECODE-ASCII/1 size={len(data)} sha256={digest} width={width}"]
    for offset in range(0, len(data), width):
        payload = "".join(f" {value:02x}" for value in data[offset:offset + width])
        lines.append(f"@{offset:016x}:{payload}")
    lines.append(f"END sha256={digest}")
    result = "\n".join(lines) + "\n"
    result.encode("ascii", errors="strict")
    return result


def decode_lossless_ascii(document: str) -> bytes:
    """Decode and strictly canonicalize a lossless ASCII document."""
    document.encode("ascii", errors="strict")
    if not document.endswith("\n") or "\r" in document:
        raise ValueError("lossless ASCII must use one final LF and no CR characters")
    lines = document[:-1].split("\n")
    if len(lines) < 2:
        raise ValueError("lossless ASCII document is incomplete")
    header = _HEADER.fullmatch(lines[0])
    footer = _FOOTER.fullmatch(lines[-1])
    if not header or not footer:
        raise ValueError("invalid lossless ASCII header or footer")
    expected_size, expected_digest, width = int(header.group(1)), header.group(2), int(header.group(3))
    if width < 1 or footer.group(1) != expected_digest:
        raise ValueError("lossless ASCII metadata mismatch")
    output = bytearray()
    expected_offset = 0
    for line in lines[1:-1]:
        match = _DATA.fullmatch(line)
        if not match:
            raise ValueError("invalid lossless ASCII data line")
        offset = int(match.group(1), 16)
        if offset != expected_offset:
            raise ValueError("lossless ASCII address discontinuity")
        raw = match.group(2).strip()
        values = bytes.fromhex(raw) if raw else b""
        if not values or len(values) > width:
            raise ValueError("invalid lossless ASCII line width")
        if len(values) != width and offset + len(values) != expected_size:
            raise ValueError("short lossless ASCII row before end of data")
        output.extend(values); expected_offset += len(values)
    result = bytes(output)
    if len(result) != expected_size:
        raise ValueError("lossless ASCII length mismatch")
    if hashlib.sha256(result).hexdigest() != expected_digest:
        raise ValueError("lossless ASCII digest mismatch")
    if encode_lossless_ascii(result, bytes_per_line=width) != document:
        raise ValueError("lossless ASCII document is not canonical")
    return result
