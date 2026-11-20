"""Bounded binary mutation primitives (fixed-size patch and full-file replace)."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from src.services.path_utils import normalize_input_path, resolve_existing_file

MAX_PATCH_BYTES = 1_048_576
MAX_WRITE_BYTES = 50_000_000
HASH_CHUNK = 1024 * 1024


def _parse_hex(data_hex: str) -> bytes:
    cleaned = str(data_hex or "").replace(" ", "").replace("\n", "").strip()
    if not cleaned:
        raise ValueError("data_hex must not be empty")
    if len(cleaned) % 2:
        raise ValueError("data_hex must contain an even number of hex digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("data_hex is not valid hexadecimal") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
        "sha256": _sha256(path),
    }


def _write_patch_runs(handle, patches: Iterable[Tuple[int, bytes]]) -> None:
    for offset, chunk in patches:
        handle.seek(offset)
        handle.write(chunk)


def _atomic_patch(source: Path, patches: Iterable[Tuple[int, bytes]]) -> None:
    ordered = sorted(patches, key=lambda item: item[0])
    if not ordered:
        raise ValueError("patch list must not be empty")
    total = sum(len(chunk) for _, chunk in ordered)
    if total > MAX_PATCH_BYTES:
        raise ValueError(f"patch exceeds maximum of {MAX_PATCH_BYTES} bytes")
    source_size = source.stat().st_size
    for offset, chunk in ordered:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if offset + len(chunk) > source_size:
            raise ValueError("patch would extend file size; inserting bytes is not supported")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{source.name}.",
        suffix=".tmp",
        dir=str(source.parent),
    )
    os.close(descriptor)
    try:
        shutil.copy2(source, temporary_name)
        with open(temporary_name, "r+b") as handle:
            _write_patch_runs(handle, ordered)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.getsize(temporary_name) != source_size:
            raise RuntimeError("patched file size changed unexpectedly")
        os.replace(temporary_name, source)
    finally:
        if os.path.exists(temporary_name):
            os.remove(temporary_name)


def binary_patch_range(
    path: str | Path,
    offset: int,
    data_hex: str,
    *,
    confirmed: bool = False,
) -> Dict[str, Any]:
    if confirmed is not True:
        raise ValueError("Binary mutation requires confirmed=true")
    source = resolve_existing_file(path)
    patch = _parse_hex(data_hex)
    before = _identity(source)
    _atomic_patch(source, [(int(offset), patch)])
    after = _identity(source)
    return {
        "ok": True,
        "operation": "binary_patch_range",
        "source_path": str(source),
        "source_before": before,
        "source_after": after,
        "offset": int(offset),
        "patched_bytes": len(patch),
        "fixed_size_preserved": before["size"] == after["size"],
    }


def binary_write_file(
    path: str | Path,
    data_hex: str,
    *,
    confirmed: bool = False,
) -> Dict[str, Any]:
    if confirmed is not True:
        raise ValueError("Binary mutation requires confirmed=true")
    normalized = normalize_input_path(path)
    if not normalized:
        raise ValueError("path is required")
    payload = _parse_hex(data_hex)
    if len(payload) > MAX_WRITE_BYTES:
        raise ValueError(f"write exceeds maximum of {MAX_WRITE_BYTES} bytes")
    target = Path(normalized).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    existed = target.is_file()
    before = _identity(target) if existed else None
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, target)
    after = _identity(target)
    return {
        "ok": True,
        "operation": "binary_write_file",
        "source_path": str(target),
        "path": str(target),
        "source_before": before,
        "source_after": after,
        "bytes_written": len(payload),
        "created": not existed,
        "overwritten": existed,
    }
