"""Orchestrate region classification, coalescence, production, and artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from src.services.binary_inspection import binary_file_info

from .coalesce import coalesce_regions
from .cooperative_merge import audit_region_map, format_plugin_from_regions
from .ir import append_byte_markers, build_ir_document, load_pseudocode_ir_policy
from .ledger_merge import apply_ledger_to_regions, load_proof_spans_for_source
from .policies import load_merge_policy, load_pseudocode_navigation_policy, load_region_routing_policy
from .producers import decompiler_sub_source_entries, produce_region_lines
from .region_map import RegionSpan, classify_raw_regions


def _digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _span_from_dict(region_dict: Mapping[str, Any]) -> RegionSpan:
    region = RegionSpan(
        offset=int(region_dict["offset"]),
        length=int(region_dict["length"]),
        region_class=str(region_dict["region_class"]),
        producer_id=str(region_dict["producer_id"]),
        format_plugin=str(region_dict["format_plugin"]),
        confidence=float(region_dict.get("confidence") or 0.0),
    )
    region.meta = dict(region_dict.get("meta") or {})
    return region


def build_coalesced_regions(
    path: str | Path,
    *,
    routing: Optional[Mapping[str, Any]] = None,
    ir_policy: Optional[Mapping[str, Any]] = None,
) -> Tuple[List[RegionSpan], Dict[str, Any], Mapping[str, Any]]:
    routing_policy = dict(routing or load_region_routing_policy())
    merge_policy = load_merge_policy(routing=routing_policy)
    ir_cfg = dict(ir_policy or load_pseudocode_ir_policy())
    resolved = Path(path).expanduser().resolve()
    info = binary_file_info(resolved)
    raw = classify_raw_regions(resolved, routing=routing_policy)
    coalesced, audit = coalesce_regions(raw, merge_policy=merge_policy, file_size=int(info["source"]["size"]))
    augment = dict(ir_cfg.get("learning_db_augmentation") or {})
    proof_rows = load_proof_spans_for_source(
        str(info["source"].get("sha256") or ""),
        limit=int(augment.get("proof_span_query_limit") or 256),
        enabled=bool(augment.get("enabled")),
    )
    coalesced = apply_ledger_to_regions(coalesced, proof_rows, merge_policy=merge_policy)
    plugin = format_plugin_from_regions(coalesced)
    violations = audit_region_map(
        coalesced,
        file_size=int(info["source"]["size"]),
        format_plugin=plugin,
        merge_policy=merge_policy,
    )
    meta = {
        "source": info["source"],
        "routing_policy_id": routing_policy.get("policy_id"),
        "merge_policy_id": merge_policy.get("policy_id"),
        "raw_region_count": len(raw),
        "region_count": len(coalesced),
        "coalescence_audit": audit,
        "ledger_proof_span_count": len(proof_rows),
        "format_plugin": plugin,
        "merge_violations": violations,
    }
    return coalesced, meta, merge_policy


def build_region_map_document(path: str | Path, *, routing: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    coalesced, meta, _merge = build_coalesced_regions(path, routing=routing)
    document = {
        "schema_version": 1,
        "kind": "pseudocode_region_map",
        "source": meta["source"],
        "routing_policy_id": meta["routing_policy_id"],
        "merge_policy_id": meta["merge_policy_id"],
        "raw_region_count": meta["raw_region_count"],
        "region_count": meta["region_count"],
        "regions": [region.to_dict() for region in coalesced],
        "coalescence_audit": meta["coalescence_audit"],
        "ledger_proof_span_count": meta["ledger_proof_span_count"],
        "format_plugin": meta.get("format_plugin"),
        "merge_violations": meta.get("merge_violations") or [],
        "merge_mode": "cooperative",
        "digest": _digest([region.to_dict() for region in coalesced]),
    }
    return document


def render_region_routed_bundle(path: str | Path, *, routing: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    routing_policy = dict(routing or load_region_routing_policy())
    merge_policy = load_merge_policy(routing=routing_policy)
    ir_policy = load_pseudocode_ir_policy()
    navigation_policy = load_pseudocode_navigation_policy(ir_policy=ir_policy)
    resolved = Path(path).expanduser().resolve()
    data = resolved.read_bytes()
    region_map_document = build_region_map_document(resolved, routing=routing_policy)
    coalesced = [_span_from_dict(item) for item in region_map_document.get("regions") or []]

    lines: List[str] = [
        "/* Region-routed pseudocode — evidence view, not recovered source. */",
        f"/* region_map_digest={region_map_document.get('digest')} regions={region_map_document.get('region_count')} */",
        f"/* learning_db_augmentation={'on' if (ir_policy.get('learning_db_augmentation') or {}).get('enabled') else 'off'} ledger_spans={region_map_document.get('ledger_proof_span_count')} */",
        f"/* merge_mode=cooperative format_plugin={region_map_document.get('format_plugin')} generic_scope=gaps_only */",
        "region_routed_document {",
    ]
    violation_count = len(region_map_document.get("merge_violations") or [])
    if violation_count:
        lines.append(f"    /* merge_violations={violation_count} — inspect region_map.json */")
    region_bodies: List[Dict[str, Any]] = []

    for region in coalesced:
        line_start = len(lines)
        lines.append(
            f"    /* region class={region.region_class} producer={region.producer_id} plugin={region.format_plugin} @ 0x{region.offset:X}[{region.length}] */"
        )
        body = produce_region_lines(
            resolved,
            data,
            region,
            routing=routing_policy,
            ir_policy=ir_policy,
            merge_policy=merge_policy,
        )
        body_line_start = len(lines)
        for line in body:
            if line.startswith("/*") or line.startswith("verified") or line.startswith("semantic") or line.startswith("    "):
                lines.append(line)
            else:
                lines.append(f"    {line}")
        sub_entries = decompiler_sub_source_entries(body, region=region, line_start=body_line_start)
        from .source_map_build import policy_block_source_entries

        sub_entries.extend(
            policy_block_source_entries(
                body,
                region_offset=int(region.offset),
                producer_id=str(region.producer_id),
                line_start=body_line_start,
                file_size=len(data),
                source_path=resolved,
                navigation_policy=navigation_policy,
            )
        )
        region_bodies.append(
            {
                "line_start": line_start,
                "line_end": len(lines) - 1,
                "sub_entries": sub_entries,
            }
        )
    lines.append("}")

    ir_document = build_ir_document(region_map_document, coalesced, region_bodies=region_bodies)
    source_map = list(ir_document.get("source_map") or [])
    from .source_map_build import normalize_source_map, prioritize_source_map_entries

    source_map = normalize_source_map(source_map, file_size=len(data))
    max_entries = int((ir_policy.get("source_map") or {}).get("max_entries") or 0)
    source_map = prioritize_source_map_entries(source_map, max_entries=max_entries)
    ir_document["source_map"] = source_map

    if bool((ir_policy.get("source_map") or {}).get("include_line_markers_in_text")):
        marker_prefix = str((ir_policy.get("source_map") or {}).get("byte_marker_prefix") or "@byte:")
        lines = append_byte_markers(lines, source_map, marker_prefix=marker_prefix, file_size=len(data))

    augmentation = "partial" if int(region_map_document.get("ledger_proof_span_count") or 0) > 0 else "off"
    if (ir_policy.get("learning_db_augmentation") or {}).get("enabled"):
        augmentation = "on" if augmentation == "off" else augmentation

    from .navigation import generation_tokens_from_bundle

    generation = generation_tokens_from_bundle({"region_map_document": region_map_document})
    generation["source_path"] = str(resolved)

    return {
        "lines": lines,
        "source_map": source_map,
        "ir_document": ir_document,
        "region_map_document": region_map_document,
        "navigation_generation": generation,
        "banner": {
            "route": "decompiler+structural+unknown",
            "learning_db_augmentation": augmentation,
        },
    }


def render_region_routed_pseudocode_for_path(path: str | Path, *, routing: Optional[Mapping[str, Any]] = None) -> List[str]:
    return list(render_region_routed_bundle(path, routing=routing)["lines"])


def _artifact_root() -> Path:
    from src.services.ptx_pipeline_policy import hex_editor_root

    cfg_path = hex_editor_root() / "config" / "hex_editor.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    rel = str(cfg.get("artifact_root") or "data/artifacts/hex_editor")
    return (hex_editor_root() / rel).resolve()


def run_region_routed_pseudocode_job(path: str | Path, *, output_root: str | Path | None = None) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    bundle = render_region_routed_bundle(resolved)
    document = bundle["region_map_document"]
    lines = bundle["lines"]
    root = Path(output_root).expanduser().resolve() if output_root else _artifact_root() / "region_routed_pseudocode" / document["digest"][:16]
    root.mkdir(parents=True, exist_ok=True)
    region_map_path = root / "region_map.json"
    pseudocode_path = root / "pseudocode.txt"
    coalescence_path = root / "coalescence_audit.json"
    source_map_path = root / "source_map.json"
    ir_path = root / "pseudocode_ir.json"
    summary_path = root / "summary.json"

    region_map_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    pseudocode_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    coalescence_path.write_text(json.dumps(document.get("coalescence_audit") or {}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    source_map_path.write_text(json.dumps(bundle["source_map"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ir_path.write_text(json.dumps(bundle["ir_document"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "ok": True,
        "operation": "binary_pseudocode_render",
        "source": document["source"],
        "region_map_path": str(region_map_path),
        "pseudocode_path": str(pseudocode_path),
        "source_map_path": str(source_map_path),
        "ir_document_path": str(ir_path),
        "region_count": document.get("region_count"),
        "digest": document.get("digest"),
        "banner": bundle.get("banner"),
        "indexed_at": _utc_now(),
    }
    temporary = summary_path.with_name(f".{summary_path.name}.tmp")
    temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, summary_path)

    try:
        from src.services.learning_db.core import index_pseudocode_region_map

        index_pseudocode_region_map(root, summary=summary, region_map=document)
    except Exception:
        pass

    return summary


def offset_for_pseudocode_line(path: str | Path, line_number: int) -> Dict[str, Any]:
    bundle = render_region_routed_bundle(path)
    from .navigation import offset_for_line
    from .policies import load_pseudocode_navigation_policy

    nav_policy = load_pseudocode_navigation_policy()
    file_offset = offset_for_line(
        bundle["source_map"],
        int(line_number),
    )
    return {
        "ok": file_offset is not None,
        "operation": "binary_pseudocode_offset_for_line",
        "line_number": int(line_number),
        "file_offset": file_offset,
        "offset": file_offset,
        "source": bundle["region_map_document"].get("source"),
        "navigation_generation": bundle.get("navigation_generation"),
    }


def range_for_pseudocode_selection(
    path: str | Path,
    *,
    start_line: int,
    end_line: int,
) -> Dict[str, Any]:
    bundle = render_region_routed_bundle(path)
    from .navigation import ranges_for_selection
    from .policies import load_pseudocode_navigation_policy

    nav_policy = load_pseudocode_navigation_policy()
    resolved = Path(path).expanduser().resolve()
    file_size = len(resolved.read_bytes()) if resolved.is_file() else 0
    result = ranges_for_selection(
        bundle["source_map"],
        start_line=int(start_line),
        end_line=int(end_line),
        navigation_policy=nav_policy,
        line_texts=bundle.get("lines"),
        file_size=file_size,
        source_path=resolved,
    )
    return {
        "ok": result is not None,
        "operation": "binary_pseudocode_range_for_selection",
        "start_line": int(start_line),
        "end_line": int(end_line),
        "selection": result,
        "source": bundle["region_map_document"].get("source"),
        "navigation_generation": bundle.get("navigation_generation"),
    }
