"""Pre-filter binary behavior — compression/packing detection before crypto probes."""

from __future__ import annotations

import zlib
from typing import Any, Dict, Mapping, Optional

from src.services.ptx_crypto_primitives import shannon_entropy
from src.services.transform_registry import merge_crypto_defaults


_GZIP_MAGIC = b"\x1f\x8b"
_ZLIB_HEADERS = (b"\x78\x01", b"\x78\x9c", b"\x78\xda")


def magic_scan(data: bytes, *, offset: int = 0, scan_length: int = 4096) -> Dict[str, Any]:
    start = max(0, int(offset))
    end = min(len(data), start + max(64, int(scan_length)))
    window = data[start:end]
    hits: list[dict[str, Any]] = []
    if window.startswith(_GZIP_MAGIC):
        hits.append({"format": "gzip", "offset": start})
    for header in _ZLIB_HEADERS:
        pos = window.find(header)
        if pos >= 0:
            hits.append({"format": "zlib", "offset": start + pos, "header": header.hex()})
    return {"hits": hits, "count": len(hits)}


def entropy_profile(data: bytes, *, offset: int = 0, length: int = 4096) -> Dict[str, Any]:
    start = max(0, int(offset))
    end = min(len(data), start + max(64, int(length)))
    window = data[start:end]
    entropy = shannon_entropy(window)
    return {"offset": start, "length": len(window), "entropy": entropy}


def try_decompress(data: bytes, *, offset: int = 0) -> Dict[str, Any]:
    start = max(0, int(offset))
    payload = data[start:]
    if payload.startswith(_GZIP_MAGIC):
        try:
            import gzip

            decompressed = gzip.decompress(payload)
            return {"success": True, "format": "gzip", "decompressed_length": len(decompressed)}
        except OSError as exc:
            return {"success": False, "format": "gzip", "error": str(exc)}
    for header in _ZLIB_HEADERS:
        pos = payload.find(header)
        if pos >= 0:
            try:
                decompressed = zlib.decompress(payload[pos:])
                return {"success": True, "format": "zlib", "decompressed_length": len(decompressed)}
            except zlib.error as exc:
                return {"success": False, "format": "zlib", "error": str(exc)}
    return {"success": False, "format": None}


def classify_binary(
    data: bytes,
    *,
    defaults: Optional[Mapping[str, Any]] = None,
    transform_start: int = 0,
) -> Dict[str, Any]:
    base = merge_crypto_defaults(dict(defaults) if defaults else None)
    classifier_cfg = dict(base.get("classifier") or {})
    high_entropy = float(classifier_cfg.get("entropy_high_threshold") or 7.2)
    low_entropy = float(classifier_cfg.get("entropy_low_threshold") or 4.5)
    skip_crypto = bool(classifier_cfg.get("skip_crypto_on_compression", True))

    magic = magic_scan(data, offset=transform_start)
    entropy = entropy_profile(data, offset=transform_start)
    decompression = try_decompress(data, offset=transform_start) if magic.get("hits") else {"success": False}

    is_compressed = bool(magic.get("hits"))
    ent = float(entropy.get("entropy") or 0)
    likely_encrypted = ent >= high_entropy and not is_compressed
    likely_plaintext = ent <= low_entropy and not is_compressed

    skip_crypto_lanes = skip_crypto and is_compressed and decompression.get("success")

    return {
        "magic_scan": magic,
        "entropy_profile": entropy,
        "decompression_success": bool(decompression.get("success")),
        "decompression": decompression,
        "is_compressed": is_compressed,
        "likely_encrypted": likely_encrypted,
        "likely_plaintext": likely_plaintext,
        "skip_crypto_lanes": skip_crypto_lanes,
        "recommended_action": "decompress_first" if skip_crypto_lanes else "probe_crypto",
    }
