"""Immutable bounded byte source."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Mapping


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ByteSource:
    """Bounded immutable byte source backed by a file or candidate bytes."""

    def __init__(self, data: bytes, *, identity: Mapping[str, Any]):
        self._data = bytes(data)
        self.identity: Dict[str, Any] = dict(identity)
        self.identity.setdefault("size", len(self._data))
        self.identity.setdefault("sha256", _digest(self._data))

    @classmethod
    def from_path(cls, path: str | Path, *, max_bytes: int | None = None) -> "ByteSource":
        resolved = Path(path).expanduser().resolve()
        stat = resolved.stat()
        if max_bytes is not None and stat.st_size > max_bytes:
            raise ValueError(f"source exceeds configured byte budget ({stat.st_size} > {max_bytes})")
        data = resolved.read_bytes()
        return cls(
            data,
            identity={
                "path": str(resolved),
                "size": len(data),
                "sha256": _digest(data),
                "modified_ns": stat.st_mtime_ns,
                "suffix": resolved.suffix.lower(),
            },
        )

    @classmethod
    def from_bytes(cls, data: bytes, *, descriptor: Mapping[str, Any] | None = None) -> "ByteSource":
        return cls(data, identity={"candidate_descriptor": dict(descriptor or {}), "suffix": ""})

    @property
    def size(self) -> int:
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError("read exceeds source bounds")
        return self._data[offset : offset + length]

    def bytes(self) -> bytes:
        return self._data
