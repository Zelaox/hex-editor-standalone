"""Mechanical printable ASCII run discovery — policy-driven, no semantic labels."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from src.services.local_transform.core import _load_bundle as load_local_transform_bundle, _printable_runs


def _scan_policy(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    scan = dict(bundle["policy"].get("scan") or {})
    required = ("minimum_text_run_bytes", "maximum_preview_bytes")
    missing = [key for key in required if key not in scan]
    if missing:
        raise ValueError(f"local_transform policy scan missing: {', '.join(missing)}")
    return scan


def discover_printable_runs(data: bytes, *, policy: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    bundle = dict(policy or load_local_transform_bundle())
    scan = _scan_policy(bundle)
    minimum = int(scan["minimum_text_run_bytes"])
    preview_limit = int(scan["maximum_preview_bytes"])
    rows: List[Dict[str, Any]] = []
    for offset, run in _printable_runs(data, minimum):
        preview = run[:preview_limit].decode("ascii", errors="replace")
        rows.append(
            {
                "offset": int(offset),
                "length": len(run),
                "preview": preview,
                "digest": hashlib.sha256(run).hexdigest(),
            }
        )
    return rows


def discover_printable_runs_for_path(path: str | Path, *, policy: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"plaintext run source missing: {resolved}")
    return discover_printable_runs(resolved.read_bytes(), policy=policy)


def discover_repeated_digest_clusters(
    runs: Sequence[Mapping[str, Any]],
    *,
    minimum_occurrences: int,
) -> List[Dict[str, Any]]:
    if minimum_occurrences < 2:
        raise ValueError("minimum_occurrences must be at least 2")
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in runs:
        digest = str(row.get("digest") or "")
        if not digest:
            continue
        grouped.setdefault(digest, []).append(dict(row))
    clusters: List[Dict[str, Any]] = []
    for digest, items in grouped.items():
        if len(items) < minimum_occurrences:
            continue
        clusters.append(
            {
                "digest": digest,
                "occurrence_count": len(items),
                "spans": [{"offset": int(item["offset"]), "length": int(item["length"])} for item in items],
                "preview": str(items[0].get("preview") or ""),
            }
        )
    clusters.sort(key=lambda item: (-int(item["occurrence_count"]), str(item["digest"])))
    return clusters
