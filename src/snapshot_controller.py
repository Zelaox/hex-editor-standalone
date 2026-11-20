"""Snapshot controller — immutable snapshot lifecycle for Binary Inspector."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from src.parsing.semantic_validator import validate_binary_snapshot
from src.services.binary_runtime import analyze_binary_snapshot, binary_waterfall_payload


class SnapshotController:
    """Holds the current static snapshot and optional runtime execution merge."""

    def __init__(self) -> None:
        self._static: Optional[Dict[str, Any]] = None
        self._runtime: Optional[Dict[str, Any]] = None
        self._merge: Optional[Dict[str, Any]] = None
        self._source_path: Optional[Path] = None
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def source_path(self) -> Optional[Path]:
        return self._source_path

    def static_snapshot(self) -> Optional[Dict[str, Any]]:
        return self._static

    def runtime_snapshot(self) -> Optional[Dict[str, Any]]:
        return self._runtime

    def merge_view(self) -> Optional[Dict[str, Any]]:
        return self._merge

    def load_path(self, path: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        resolved = Path(path).expanduser().resolve()
        result = analyze_binary_snapshot(resolved, policy=policy)
        return self.adopt_analysis(result, source_path=resolved)

    def adopt_analysis(self, result: Mapping[str, Any], *, source_path: str | Path) -> Dict[str, Any]:
        resolved = Path(source_path).expanduser().resolve()
        snapshot = dict(result["snapshot"])
        validation = validate_binary_snapshot(snapshot)
        self._source_path = resolved
        self._static = snapshot
        self._runtime = None
        self._merge = None
        self._generation += 1
        return {
            "generation": self._generation,
            "snapshot": snapshot,
            "validation": validation,
            "waterfall": binary_waterfall_payload(snapshot),
        }

    def attach_runtime(self, runtime_snapshot: Mapping[str, Any], *, merge: Mapping[str, Any] | None = None) -> None:
        self._runtime = dict(runtime_snapshot)
        self._merge = dict(merge) if merge else None
        self._generation += 1

    def clear(self) -> None:
        self._static = None
        self._runtime = None
        self._merge = None
        self._source_path = None
        self._generation += 1

    def is_stale(self, generation: int) -> bool:
        return generation != self._generation
