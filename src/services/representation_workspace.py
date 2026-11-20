"""Workspace-level representation sweep for unknown binary regions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.representation_registry import load_representation_policy
from src.services.representation_sweep import load_representation_brief_cache, sweep_region, write_representation_brief_cache


def sweep_unknown_regions_in_workspace(
    workspace: str | Path,
    *,
    source_bytes: bytes | None = None,
    policy: Optional[Mapping[str, Any]] = None,
    region_ids: Optional[List[str]] = None,
    force: bool = False,
    include_representation_sweep: Optional[bool] = None,
) -> Dict[str, Any]:
    """Run representation sweeps for unknown regions and cache RepresentationBrief artifacts."""
    root = Path(workspace).expanduser().resolve()
    active_policy = dict(policy or load_representation_policy())
    enabled = (
        bool(include_representation_sweep)
        if include_representation_sweep is not None
        else bool(active_policy.get("workspace_sweep_on_export"))
    )
    if not enabled and not force:
        return {
            "ok": True,
            "operation": "representation_workspace_sweep",
            "skipped": True,
            "reason": "representation_sweep_disabled",
        }

    regions_path = root / "unknown" / "regions.json"
    if not regions_path.is_file():
        raise FileNotFoundError(f"missing unknown regions index: {regions_path}")
    import json

    regions = json.loads(regions_path.read_text(encoding="utf-8"))
    allowed = {str(value) for value in region_ids} if region_ids else None
    swept: List[Dict[str, Any]] = []
    skipped: List[str] = []

    for region in regions:
        if not isinstance(region, dict):
            continue
        region_id = str(region.get("region_id") or "")
        if not region_id:
            continue
        if allowed is not None and region_id not in allowed:
            continue
        if not force and load_representation_brief_cache(root, region_id) is not None:
            skipped.append(region_id)
            continue
        span = dict(region.get("span") or {})
        offset = int(span.get("offset") or 0)
        length = int(span.get("length") or 0)
        if length <= 0:
            continue
        data = _region_bytes(root, region_id, source_bytes=source_bytes, offset=offset, length=length)
        brief = sweep_region(data, offset=offset, policy=active_policy, include_binary_decimal=True)
        write_representation_brief_cache(root, region_id, brief)
        swept.append({"region_id": region_id, "offset": offset, "length": length, "signal_count": len(brief.get("interpreter_signals") or [])})

    return {
        "ok": True,
        "operation": "representation_workspace_sweep",
        "workspace": str(root),
        "swept_count": len(swept),
        "skipped_cached_count": len(skipped),
        "regions": swept,
    }


def _region_bytes(
    workspace: Path,
    region_id: str,
    *,
    source_bytes: bytes | None,
    offset: int,
    length: int,
) -> bytes:
    block_path = workspace / "unknown" / f"{region_id}.bin"
    if block_path.is_file():
        return block_path.read_bytes()
    if source_bytes is not None:
        end = offset + length
        if offset < 0 or end > len(source_bytes):
            raise ValueError("unknown region span exceeds source bytes")
        return source_bytes[offset:end]
    raise FileNotFoundError(f"unknown region bytes missing: {block_path}")
