"""Policy-bounded SnapshotBrief compiler — never serializes full graph to model context."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.artifact_pointer import resolve_workspace_path, verify_artifact_pointer
from src.services.hex_checkpoint_policy import load_hex_checkpoint_policy
from src.services.full_coverage_policy import load_full_coverage_policy


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_brief_bytes(brief: Mapping[str, Any]) -> bytes:
    return (json.dumps(brief, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode(
        "utf-8"
    )


def brief_digest(brief: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_brief_bytes(brief)).hexdigest()


def _trim_region_features(features: Mapping[str, Any], max_context_bytes: int) -> Dict[str, Any]:
    out = dict(features or {})
    for key in list(out.keys()):
        value = out[key]
        if isinstance(value, str) and len(value.encode("utf-8")) > max_context_bytes:
            out[key] = value[: max_context_bytes // 2] + "…"
        if isinstance(value, list) and len(json.dumps(value, default=str)) > max_context_bytes:
            out[key] = value[: max(1, len(value) // 4)]
    return out


def compile_snapshot_brief(
    pointer_or_workspace: Mapping[str, Any] | str | Path,
    *,
    inspect_cursor: Optional[Mapping[str, Any]] = None,
    checkpoint_policy: Optional[Mapping[str, Any]] = None,
    full_coverage_policy: Optional[Mapping[str, Any]] = None,
    lab_root: str | Path | None = None,
) -> Dict[str, Any]:
    """Compile bounded brief from cold workspace — reads locally, returns hot summary only."""
    ckpt = dict(checkpoint_policy or load_hex_checkpoint_policy())
    gemma = dict((full_coverage_policy or load_full_coverage_policy()).get("gemma_packet") or {})
    budgets = dict(ckpt.get("brief_budgets") or {})
    max_regions = int(gemma.get("max_regions") or 0)
    max_context = int(gemma.get("max_context_bytes_per_region") or 0)
    include_raw_anchors = bool(gemma.get("include_raw_anchor_values"))

    if isinstance(pointer_or_workspace, (str, Path)):
        workspace = Path(pointer_or_workspace).expanduser().resolve()
        pointer = None
    else:
        mapping = dict(pointer_or_workspace)
        if mapping.get("operation_id") and mapping.get("manifest_sha256"):
            verify_artifact_pointer(mapping, lab_root=lab_root)
            workspace = resolve_workspace_path(mapping, lab_root=lab_root)
            pointer = mapping
        else:
            workspace = Path(str(mapping.get("workspace") or mapping.get("artifact_directory") or "")).resolve()
            pointer = mapping.get("artifact_pointer") if isinstance(mapping.get("artifact_pointer"), dict) else None
            if pointer:
                verify_artifact_pointer(pointer, lab_root=lab_root)
                workspace = resolve_workspace_path(pointer, lab_root=lab_root)

    manifest = _read_json(workspace / "manifest.json") or {}
    details = dict(manifest.get("details") or {})
    coverage_summary = _read_json(workspace / "coverage.json") or {}
    unknown_regions = list(_read_json(workspace / "unknown" / "regions.json") or [])
    anchors = list(_read_json(workspace / "anchors.json") or [])
    record_families = list(_read_json(workspace / "records" / "families.json") or [])
    diagnostics = list(_read_json(workspace / "diagnostics" / "parser.json") or [])
    experiments = list((_read_json(workspace / "experiments" / "index.json") or {}).get("experiments") or [])
    if not experiments and isinstance(_read_json(workspace / "experiments" / "index.json"), list):
        experiments = list(_read_json(workspace / "experiments" / "index.json") or [])

    cursor = dict(inspect_cursor or {})
    region_index = int(cursor.get("region_index") or 0)
    if region_index < 0:
        region_index = 0

    top_unknown: List[Dict[str, Any]] = []
    slice_start = region_index
    slice_end = slice_start + max_regions if max_regions > 0 else len(unknown_regions)
    for item in unknown_regions[slice_start:slice_end]:
        if not isinstance(item, dict):
            continue
        region = {
            "region_id": item.get("region_id"),
            "span": item.get("span"),
            "classification": item.get("classification"),
            "confidence": item.get("confidence"),
            "features": _trim_region_features(dict(item.get("features") or {}), max_context),
            "neighbor_anchor_ids": list(item.get("neighbor_anchor_ids") or [])[:16],
        }
        top_unknown.append(region)

    from src.services.representation_registry import load_representation_policy

    rep_policy = load_representation_policy()
    rep_gemma = dict(rep_policy.get("gemma_packet") or {})
    include_representation_brief = bool(
        rep_gemma.get("include_representation_brief") or gemma.get("include_representation_brief")
    )
    if include_representation_brief:
        from src.services.representation_sweep import load_representation_brief_cache

        max_rep_bytes = int(rep_gemma.get("max_representation_bytes_per_region") or max_context or 0)
        for region in top_unknown:
            region_id = str(region.get("region_id") or "")
            cached = load_representation_brief_cache(workspace, region_id) if region_id else None
            if cached:
                region["representation_brief"] = _trim_region_features(dict(cached), max_rep_bytes)

    anchor_samples: List[Dict[str, Any]] = []
    for anchor in anchors[: int(budgets.get("max_anchor_samples") or 0)]:
        if not isinstance(anchor, dict):
            continue
        sample = {
            "anchor_id": anchor.get("anchor_id"),
            "family_id": anchor.get("family_id"),
            "kind": anchor.get("kind"),
            "span": anchor.get("span"),
            "occurrence_count": anchor.get("occurrence_count"),
        }
        if include_raw_anchors and anchor.get("label"):
            sample["label"] = str(anchor.get("label"))[:128]
        anchor_samples.append(sample)

    record_family_samples: List[Dict[str, Any]] = []
    for family in record_families[: int(budgets.get("max_record_family_samples") or 0)]:
        if not isinstance(family, dict):
            continue
        record_family_samples.append(
            {
                "family_id": family.get("family_id"),
                "kind": family.get("kind"),
                "support": family.get("support"),
                "anchor_ids": list(family.get("anchor_ids") or [])[:8],
            }
        )

    experiment_head: List[Dict[str, Any]] = []
    for experiment in experiments[: int(budgets.get("max_experiment_head") or 0)]:
        if not isinstance(experiment, dict):
            continue
        experiment_head.append(
            {
                "experiment_id": experiment.get("experiment_id") or experiment.get("id"),
                "status": experiment.get("status"),
                "delta_summary": experiment.get("delta_summary") or experiment.get("summary"),
            }
        )

    brief: Dict[str, Any] = {
        "schema_version": 1,
        "snapshot_id": str(details.get("snapshot_id") or (pointer or {}).get("snapshot_id") or ""),
        "snapshot_sha256": str(details.get("snapshot_sha256") or (pointer or {}).get("snapshot_sha256") or ""),
        "format_plugin": str(details.get("format_plugin") or (pointer or {}).get("format_plugin") or "unknown"),
        "coverage_summary": coverage_summary,
        "top_unknown_regions": top_unknown,
        "anchor_samples": anchor_samples,
        "record_family_samples": record_family_samples,
        "diagnostics": diagnostics[: int(budgets.get("max_diagnostics") or 0)],
        "experiment_head": experiment_head,
        "inspect_cursor": {
            "region_index": region_index,
            "regions_total": len(unknown_regions),
            "next_region_id": (
                str(unknown_regions[region_index].get("region_id"))
                if region_index < len(unknown_regions)
                else ""
            ),
        },
    }

    max_bytes = int(ckpt.get("max_brief_bytes") or 0)
    if max_bytes > 0:
        encoded = _canonical_brief_bytes(brief)

        def _shrink_once() -> bool:
            if brief.get("top_unknown_regions"):
                regions = list(brief["top_unknown_regions"])
                last = dict(regions[-1])
                features = dict(last.get("features") or {})
                if features.get("top_sequence_hashes"):
                    hashes = list(features["top_sequence_hashes"])
                    features["top_sequence_hashes"] = hashes[: max(0, len(hashes) - 4)]
                    last["features"] = features
                    regions[-1] = last
                    brief["top_unknown_regions"] = regions
                    return True
                if features.get("numeric_candidates"):
                    features["numeric_candidates"] = []
                    last["features"] = features
                    regions[-1] = last
                    brief["top_unknown_regions"] = regions
                    return True
                if last.get("representation_brief"):
                    last["representation_brief"] = {}
                    regions[-1] = last
                    brief["top_unknown_regions"] = regions
                    return True
                brief["top_unknown_regions"] = regions[:-1]
                return True
            if brief.get("anchor_samples"):
                brief["anchor_samples"] = brief["anchor_samples"][:-1]
                return True
            if brief.get("record_family_samples"):
                brief["record_family_samples"] = brief["record_family_samples"][:-1]
                return True
            if brief.get("diagnostics"):
                brief["diagnostics"] = brief["diagnostics"][:-1]
                return True
            summary = dict(brief.get("coverage_summary") or {})
            for key in list(summary.keys()):
                if key not in {"coverage_complete", "coverage_ratio", "known_bytes", "unknown_bytes"}:
                    summary.pop(key, None)
                    brief["coverage_summary"] = summary
                    return True
            return False

        while len(encoded) > max_bytes and _shrink_once():
            encoded = _canonical_brief_bytes(brief)
        if len(encoded) > max_bytes:
            brief["top_unknown_regions"] = []
            brief["anchor_samples"] = []
            brief["record_family_samples"] = []
            brief["diagnostics"] = []
            encoded = _canonical_brief_bytes(brief)
        if len(encoded) > max_bytes:
            raise ValueError("snapshot brief exceeds policy max_brief_bytes even after trimming")

    brief["brief_digest"] = brief_digest(brief)
    return brief


def format_brief_for_packet(brief: Mapping[str, Any]) -> List[str]:
    """Render brief as compact lines for hex_model_packet."""
    lines = ["snapshot_brief:"]
    summary = dict(brief.get("coverage_summary") or {})
    lines.append(
        f"- coverage_complete={summary.get('coverage_complete')} "
        f"known={summary.get('known_bytes')} unknown={summary.get('unknown_bytes')} "
        f"ratio={summary.get('coverage_ratio')}"
    )
    cursor = dict(brief.get("inspect_cursor") or {})
    lines.append(
        f"- inspect_cursor index={cursor.get('region_index')} "
        f"total={cursor.get('regions_total')} next={cursor.get('next_region_id') or 'none'}"
    )
    for region in list(brief.get("top_unknown_regions") or [])[:6]:
        span = dict(region.get("span") or {})
        features = dict(region.get("features") or {})
        lines.append(
            f"- unknown {region.get('region_id')} @{span.get('offset')}+{span.get('length')} "
            f"entropy={features.get('entropy')} printable={features.get('printable_ratio')}"
        )
    lines.append(f"- brief_digest={brief.get('brief_digest')}")
    return lines
