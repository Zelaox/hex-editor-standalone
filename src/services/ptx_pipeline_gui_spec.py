"""Build pipeline source specs from GUI form state (no Qt)."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def build_source_spec(
    *,
    kind: str,
    filesystem_path: str = "",
    archive_id: str = "",
    materialization_rail: str = "",
    materialization_run_id: str = "",
    use_candidate: bool = False,
    require_promotion: bool = True,
) -> Dict[str, Any]:
    normalized = str(kind or "").strip().lower()
    if normalized == "filesystem":
        path = str(filesystem_path or "").strip()
        if not path:
            raise ValueError("Choose a PTX file for filesystem binding")
        return {"kind": "filesystem", "path": path}
    if normalized == "archive":
        aid = str(archive_id or "").strip()
        if not aid:
            raise ValueError("Select an archive entry")
        return {"kind": "archive", "archive_id": aid}
    if normalized == "materialization":
        rail = str(materialization_rail or "").strip()
        run_id = str(materialization_run_id or "").strip()
        if not rail or not run_id:
            raise ValueError("Materialization requires rail and run id")
        spec: Dict[str, Any] = {
            "kind": "materialization",
            "rail": rail,
            "run_id": run_id,
        }
        if use_candidate:
            spec["use_candidate"] = True
        if not require_promotion:
            spec["require_promotion"] = False
        return spec
    raise ValueError(f"Unsupported source kind: {kind}")


def stages_from_selection(selected: Mapping[str, bool], *, include_bind: bool) -> list[str]:
    order = ["bind", "analyze", "extract", "graph", "export"]
    stages: list[str] = []
    for name in order:
        if name == "bind" and not include_bind:
            continue
        if selected.get(name):
            stages.append(name)
    if not stages:
        raise ValueError("Select at least one pipeline stage")
    return stages


def list_archive_ids(registry: Mapping[str, Any]) -> list[str]:
    archives = dict(registry.get("archives") or {})
    return sorted(str(key) for key in archives)


def list_materialization_rails(pipeline_policy: Mapping[str, Any]) -> list[str]:
    rails = dict(pipeline_policy.get("rails") or {})
    return sorted(str(key) for key in rails)


def export_formats_from_policy(converter_policy: Mapping[str, Any]) -> list[str]:
    formats = dict(converter_policy.get("formats") or {})
    enabled: list[str] = []
    for name, cfg in formats.items():
        if isinstance(cfg, Mapping) and cfg.get("enabled"):
            enabled.append(str(name))
    return sorted(enabled)
