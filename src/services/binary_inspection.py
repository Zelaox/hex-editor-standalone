"""Bounded, read-only binary inspection primitives."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

from src.services.path_utils import resolve_existing_file

DEFAULT_MAX_READ = 65_536
HARD_MAX_READ = 1_048_576
DEFAULT_MAX_MATCHES = 200
HASH_CHUNK = 1024 * 1024


def _source(path: Path, *, include_hash: bool = True) -> Dict[str, Any]:
    stat = path.stat()
    result: Dict[str, Any] = {
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
    }
    if include_hash:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
                digest.update(chunk)
        result["sha256"] = digest.hexdigest()
    return result


def _file(path: str | Path) -> Path:
    return resolve_existing_file(path)


def binary_file_info(path: str | Path) -> Dict[str, Any]:
    source = _file(path)
    with source.open("rb") as handle:
        prefix = handle.read(32)
    return {
        "ok": True,
        "operation": "binary_file_info",
        "source": _source(source),
        "prefix_hex": prefix.hex(" "),
        "is_ptx_extension": source.suffix.lower() == ".ptx",
    }


def binary_read_range(
    path: str | Path,
    offset: int = 0,
    length: int = DEFAULT_MAX_READ,
) -> Dict[str, Any]:
    source = _file(path)
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length < 0 or length > HARD_MAX_READ:
        raise ValueError(f"length must be between 0 and {HARD_MAX_READ}")
    with source.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    return {
        "ok": True,
        "operation": "binary_read_range",
        "source": _source(source, include_hash=False),
        "offset": offset,
        "requested_length": length,
        "returned_length": len(data),
        "hex": data.hex(" "),
        "ascii": "".join(chr(value) if 32 <= value <= 126 else "." for value in data),
        "truncated_at_eof": len(data) < length,
    }


def _needle_bytes(query: str, encoding: str) -> bytes:
    if encoding == "hex":
        try:
            return bytes.fromhex(query)
        except ValueError as exc:
            raise ValueError("query is not valid hexadecimal bytes") from exc
    if encoding not in {"utf-8", "ascii"}:
        raise ValueError("encoding must be one of: hex, utf-8, ascii")
    return query.encode(encoding)


def binary_search(
    path: str | Path,
    query: str,
    encoding: str = "hex",
    max_matches: int = DEFAULT_MAX_MATCHES,
) -> Dict[str, Any]:
    source = _file(path)
    needle = _needle_bytes(query, encoding)
    if not needle:
        raise ValueError("query must not be empty")
    if max_matches < 1 or max_matches > 10_000:
        raise ValueError("max_matches must be between 1 and 10000")

    matches: List[int] = []
    overlap = max(0, len(needle) - 1)
    position = 0
    tail = b""
    with source.open("rb") as handle:
        while len(matches) < max_matches:
            block = handle.read(HASH_CHUNK)
            if not block:
                break
            searchable = tail + block
            base = position - len(tail)
            start = 0
            while len(matches) < max_matches:
                found = searchable.find(needle, start)
                if found < 0:
                    break
                absolute = base + found
                if not matches or absolute != matches[-1]:
                    matches.append(absolute)
                start = found + 1
            position += len(block)
            tail = searchable[-overlap:] if overlap else b""

    return {
        "ok": True,
        "operation": "binary_search",
        "source": _source(source, include_hash=False),
        "query": query,
        "encoding": encoding,
        "matches": matches,
        "match_count": len(matches),
        "limit_reached": len(matches) == max_matches,
    }
