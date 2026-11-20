"""Forensic text encoding inspection for binary data."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Dict, Optional

from src.services.binary_inspection import DEFAULT_MAX_READ, HARD_MAX_READ, _file

TEXT_ENCODINGS = {
    "utf-8": "utf-8",
    "ascii": "ascii",
    "latin-1": "latin-1",
    "utf-16-le": "utf-16-le",
    "utf-16-be": "utf-16-be",
}

BOM_SIGNATURES = {
    b"\xef\xbb\xbf": "utf-8",
    b"\xff\xfe": "utf-16-le",
    b"\xfe\xff": "utf-16-be",
}


def _validate_errors_mode(errors: str) -> str:
    if errors not in {"strict", "replace", "ignore"}:
        raise ValueError("errors must be one of: strict, replace, ignore")
    return errors


def _validate_encoding(encoding: str) -> str:
    codec = TEXT_ENCODINGS.get(encoding.lower(), encoding)
    if codec not in TEXT_ENCODINGS.values():
        raise ValueError(
            "encoding must be one of: " + ", ".join(sorted(TEXT_ENCODINGS))
        )
    return codec


def detect_bom(data: bytes) -> Optional[str]:
    for signature, name in BOM_SIGNATURES.items():
        if data.startswith(signature):
            return name
    return None


def analyze_bytes(
    data: bytes,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
    offset: int = 0,
) -> Dict[str, Any]:
    codec = _validate_encoding(encoding)
    errors = _validate_errors_mode(errors)

    bom = detect_bom(data)
    non_ascii = sum(1 for value in data if value > 127)

    decode_error = None
    decoded = ""
    replacement_count = 0

    try:
        decoded = data.decode(codec, errors=errors)
        if errors == "replace":
            replacement_count = decoded.count("\ufffd")
    except UnicodeDecodeError as exc:
        decode_error = {
            "reason": exc.reason,
            "start": exc.start,
            "end": exc.end,
            "absolute_start": offset + exc.start,
            "absolute_end": offset + exc.end,
            "problem_bytes_hex": data[exc.start : exc.end].hex(" "),
        }
        if errors != "strict":
            decoded = data.decode(codec, errors=errors)
            if errors == "replace":
                replacement_count = decoded.count("\ufffd")

    return {
        "ok": decode_error is None or errors != "strict",
        "operation": "binary_decode_range",
        "encoding": codec,
        "errors_mode": errors,
        "offset": offset,
        "requested_length": len(data),
        "returned_length": len(data),
        "byte_count": len(data),
        "non_ascii_byte_count": non_ascii,
        "bom_detected": bom,
        "decoded_text": decoded,
        "hex": data.hex(" "),
        "binary": " ".join(f"{value:08b}" for value in data),
        "base64": base64.b64encode(data).decode("ascii"),
        "bytes_decimal": " ".join(str(value) for value in data),
        "decode_error": decode_error,
        "replacement_count": replacement_count,
        "is_valid_ascii": non_ascii == 0,
        "note": (
            "Bytes above 127 are not 7-bit ASCII. Use UTF-8 (or Latin-1) "
            "for Swedish letters such as ä and å."
            if non_ascii
            else None
        ),
    }


def binary_decode_range(
    path: str | Path,
    offset: int = 0,
    length: int = DEFAULT_MAX_READ,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> Dict[str, Any]:
    source = _file(path)
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length < 0 or length > HARD_MAX_READ:
        raise ValueError(f"length must be between 0 and {HARD_MAX_READ}")

    with source.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)

    result = analyze_bytes(data, encoding=encoding, errors=errors, offset=offset)
    result["source"] = {
        "path": str(source),
        "name": source.name,
        "size": source.stat().st_size,
    }
    result["truncated_at_eof"] = len(data) < length
    return result
