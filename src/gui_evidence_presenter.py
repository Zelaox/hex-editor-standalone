"""Read-only presenters: snapshot and investigation artifacts → GUI view models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _hex_range(start: int, length: int) -> str:
    end = start + max(0, length - 1)
    return f"0x{start:X}–0x{end:X}"


def _ratio(changed: int, total: int) -> str:
    if total <= 0:
        return "0%"
    return f"{(changed / total) * 100:.3f}%"


def present_coverage_rows(snapshot: Mapping[str, Any], *, db_parser: Mapping[str, Any] | None = None) -> List[Tuple[str, Any]]:
    summary = dict(snapshot.get("coverage_summary") or {})
    rows: List[Tuple[str, Any]] = []
    if "unknown_bytes" not in summary:
        by_class = dict(summary.get("bytes_by_class") or {})
        if "unknown" in by_class:
            summary = {**summary, "unknown_bytes": int(by_class["unknown"])}
    if db_parser:
        rows.append(("parser_metrics_source", str(db_parser.get("metrics_source") or "learning_db_sources")))
        if db_parser.get("unknown_bytes") is not None:
            rows.append(("parser_unknown_bytes_db", int(db_parser["unknown_bytes"])))
        if db_parser.get("coverage_complete") is not None:
            rows.append(("parser_coverage_complete_db", bool(db_parser["coverage_complete"])))
        if db_parser.get("timecode_count") is not None:
            rows.append(("parser_timecode_count_db", int(db_parser["timecode_count"])))
        if db_parser.get("plaintext_run_count") is not None:
            rows.append(("parser_plaintext_run_count_db", int(db_parser["plaintext_run_count"])))
    for key in ("total_bytes", "known_bytes", "unknown_bytes", "unknown_ratio"):
        if key in summary:
            rows.append((key, summary[key]))
    by_class = dict(summary.get("bytes_by_class") or {})
    for class_name, value in sorted(by_class.items()):
        rows.append((f"bytes_by_class.{class_name}", value))
    return rows


def present_anchor_rows(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for anchor in snapshot.get("anchors") or []:
        span = dict(anchor.get("span") or {})
        rows.append(
            {
                "anchor_id": str(anchor.get("anchor_id") or ""),
                "kind": str(anchor.get("kind") or ""),
                "offset": int(span.get("offset") or 0),
                "length": int(span.get("length") or 0),
                "occurrence_count": int(anchor.get("occurrence_count") or 0),
                "evidence_level": str(anchor.get("evidence_level") or ""),
            }
        )
    return rows


def present_unknown_rows(snapshot: Mapping[str, Any], *, policy: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    from src.services.ui_policy import format_display_scalar, load_ui_policy

    ui_policy = dict(policy or load_ui_policy())
    rows = []
    for region in snapshot.get("unknown_regions") or []:
        span = dict(region.get("span") or {})
        features = dict(region.get("features") or {})
        entropy = features.get("entropy")
        if entropy is not None:
            entropy = format_display_scalar(entropy, policy=ui_policy)
        rows.append(
            {
                "region_id": str(region.get("region_id") or ""),
                "offset": int(span.get("offset") or 0),
                "length": int(span.get("length") or 0),
                "classification": str(region.get("classification") or ""),
                "entropy": entropy,
                "neighbor_anchors": ", ".join(str(item) for item in region.get("neighbor_anchor_ids") or []),
            }
        )
    return rows


def present_plaintext_run_rows(file_path: str | Path, *, policy: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    if not file_path:
        return []
    try:
        from src.services.plaintext_runs import discover_printable_runs_for_path
        from src.services.ui_policy import load_budget, load_ui_policy

        ui_policy = load_ui_policy()
        row_limit = load_budget(ui_policy, "max_inspector_table_rows")
        runs = discover_printable_runs_for_path(file_path, policy=policy)
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    for row in runs:
        if row_limit > 0 and len(rows) >= row_limit:
            break
        rows.append(
            {
                "offset": int(row.get("offset") or 0),
                "length": int(row.get("length") or 0),
                "preview": str(row.get("preview") or ""),
                "digest": str(row.get("digest") or ""),
            }
        )
    return rows


def present_record_family_rows(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for family in snapshot.get("record_families") or []:
        rows.append(
            {
                "family_id": str(family.get("family_id") or ""),
                "kind": str(family.get("kind") or ""),
                "support": int(family.get("support") or 0),
                "evidence_level": str(family.get("evidence_level") or ""),
                "anchor_ids": ", ".join(str(item) for item in family.get("anchor_ids") or []),
            }
        )
    return rows


def present_waterfall_rows(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in snapshot.get("coverage") or []:
        rows.append(
            {
                "offset": int(item.get("offset") or 0),
                "length": int(item.get("length") or 0),
                "class": str(item.get("class") or "unknown"),
                "objects": ", ".join(str(node) for node in item.get("node_ids") or []),
                "role": "coverage",
                "theme_token": f"binary_waterfall.{item.get('class') or 'unknown'}",
            }
        )
    for anchor in snapshot.get("anchors") or []:
        span = dict(anchor.get("span") or {})
        level = str(anchor.get("evidence_level") or "candidate")
        token = "anchor.verified" if level == "verified" else "anchor.candidate"
        rows.append(
            {
                "offset": int(span.get("offset") or 0),
                "length": int(span.get("length") or 0),
                "class": f"anchor:{anchor.get('kind') or ''}",
                "objects": str(anchor.get("anchor_id") or ""),
                "role": "anchor",
                "theme_token": token,
            }
        )
    for region in snapshot.get("unknown_regions") or []:
        span = dict(region.get("span") or {})
        rows.append(
            {
                "offset": int(span.get("offset") or 0),
                "length": int(span.get("length") or 0),
                "class": str(region.get("classification") or "unknown"),
                "objects": str(region.get("region_id") or ""),
                "role": "unknown",
                "theme_token": "binary_waterfall.unknown",
            }
        )
    return rows


def _tail_jsonl(path: Path, *, limit: int) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    rows = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def present_investigation_artifacts(investigation_root: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    from src.services.investigation_key_hunt.policy import load_investigation_key_hunt_policy

    root = Path(investigation_root).resolve()
    hunt_policy = load_investigation_key_hunt_policy()
    layout = dict(hunt_policy.get("artifact_layout") or {})
    ledger_path = root / str(layout.get("probe_ledger") or "probe_ledger/events.jsonl")
    best_rejected_path = root / str(layout.get("best_rejected") or "probe_ledger/best_rejected.json")
    derived_path = root / str(layout.get("derived_windows") or "probe_ledger/derived_windows.json")
    max_events = int(hunt_policy["budgets"]["max_ledger_events"])
    ledger_events = _tail_jsonl(ledger_path, limit=min(max_events, 256))
    best_rejected = _read_json(best_rejected_path) if best_rejected_path.is_file() else {}
    derived = _read_json(derived_path) if derived_path.is_file() else {}
    derived_windows = list(derived.get("windows") or [])
    return {
        "investigation_root": str(root),
        "ledger_events": ledger_events,
        "best_rejected": best_rejected,
        "derived_windows": derived_windows,
    }


def discover_scope_run_json(source_sha256: str, *, artifact_root: Path | None = None, scan_limit: int | None = None) -> Optional[Path]:
    from src.snapshot_run_catalog import artifact_root as default_root

    root = artifact_root or default_root()
    if not root.is_dir():
        return None
    matches: List[Tuple[str, Path]] = []
    scanned = 0
    limit = int(scan_limit) if scan_limit is not None else 256
    for path in root.rglob("run.json"):
        scanned += 1
        if scanned > limit:
            break
        try:
            payload = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        source = dict(payload.get("source") or {})
        if str(source.get("sha256") or "") != str(source_sha256 or ""):
            continue
        matches.append((str(payload.get("run_id") or path.parent.name), path))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def present_transform_scope_evidence(run_json_path: str | Path) -> Dict[str, Any]:
    run_path = Path(run_json_path).resolve()
    run = _read_json(run_path)
    source = dict(run.get("source") or {})
    total_bytes = int(source.get("size") or 0)
    transform_relation = ""
    candidate_hex = ""
    observations_path = Path(str((run.get("artifacts") or {}).get("observations") or ""))
    if observations_path.is_file():
        for obs in _read_json(observations_path):
            if str(obs.get("kind") or "") == "transform_candidate":
                candidate_hex = str(obs.get("value_hex") or "")
                transform_relation = f"XOR 0x{candidate_hex.upper()}" if candidate_hex else ""
                break
    range_rows: List[Dict[str, Any]] = []
    changed_bytes = 0
    first_changed: Optional[int] = None
    last_changed: Optional[int] = None
    operation = str(run.get("operation") or "")
    if "alternate" in operation or (run_path.parent / "windows" / "roles.json").is_file():
        from src.services.alternate_scope import inspect_alternate_scope_run

        inspected = inspect_alternate_scope_run(run_path)
        overlay = dict(inspected.get("waterfall_overlay") or {})
        for item in overlay.get("ranges") or []:
            offset = int(item.get("offset") or 0)
            length = int(item.get("length") or 0)
            role = str(item.get("class") or item.get("role") or "")
            range_rows.append(
                {
                    "range": _hex_range(offset, length),
                    "offset": offset,
                    "length": length,
                    "transform": "xor" if candidate_hex else str(item.get("transform") or ""),
                    "role": role.replace("_body", "") if role else role,
                    "theme_token": str(item.get("theme_token") or ""),
                }
            )
        results_path = Path(str((run.get("artifacts") or {}).get("results") or ""))
        if results_path.is_file():
            for result in _read_json(results_path):
                for window in result.get("window_results") or []:
                    changed_bytes += int(window.get("changed_bytes") or 0)
        scopes_path = Path(str((run.get("artifacts") or {}).get("scopes") or ""))
        if scopes_path.is_file() and not range_rows:
            for entry in _read_json(scopes_path):
                for scope in entry.get("scopes") or []:
                    offset = int(scope.get("offset") or 0)
                    length = int(scope.get("length") or 0)
                    range_rows.append(
                        {
                            "range": _hex_range(offset, length),
                            "offset": offset,
                            "length": length,
                            "transform": "xor" if candidate_hex else "",
                            "role": "candidate",
                            "theme_token": "binary_waterfall.candidate_body",
                        }
                    )
    else:
        window_results_path = Path(str((run.get("artifacts") or {}).get("window_results") or ""))
        if window_results_path.is_file():
            for item in _read_json(window_results_path):
                offset = int(item.get("offset") or 0)
                length = int(item.get("length") or 0)
                changed = int(item.get("changed_bytes") or 0)
                changed_bytes += changed
                range_rows.append(
                    {
                        "range": _hex_range(offset, length),
                        "offset": offset,
                        "length": length,
                        "transform": "xor" if candidate_hex else str(item.get("algorithm") or ""),
                        "role": "candidate",
                        "theme_token": "binary_waterfall.candidate_body",
                    }
                )
    if range_rows:
        offsets = [int(row["offset"]) for row in range_rows]
        lengths = [int(row["length"]) for row in range_rows]
        first_changed = min(offsets)
        last_changed = max(offset + length - 1 for offset, length in zip(offsets, lengths))
    if changed_bytes <= 0 and range_rows:
        changed_bytes = sum(int(row["length"]) for row in range_rows if row.get("role") != "preserve")
    summary = {
        "changed_bytes": changed_bytes,
        "total_bytes": total_bytes,
        "changed_ratio": _ratio(changed_bytes, total_bytes),
        "first_changed_offset": f"0x{first_changed:X}" if first_changed is not None else "",
        "last_changed_offset": f"0x{last_changed:X}" if last_changed is not None else "",
        "transform_relation": transform_relation,
        "range_count": len(range_rows),
        "run_id": str(run.get("run_id") or ""),
    }
    return {"summary": summary, "ranges": range_rows, "run_path": str(run_path)}


def present_representation_rows(
    snapshot: Mapping[str, Any],
    *,
    workspace_root: str | Path | None = None,
) -> List[Dict[str, Any]]:
    from src.services.representation_falsification import falsify_representation_brief
    from src.services.representation_sweep import load_representation_brief_cache

    rows: List[Dict[str, Any]] = []
    workspace = Path(workspace_root).resolve() if workspace_root else None
    for region in snapshot.get("unknown_regions") or []:
        region_id = str(region.get("region_id") or "")
        brief = load_representation_brief_cache(workspace, region_id) if workspace else None
        if not brief:
            rows.append(
                {
                    "region_id": region_id,
                    "brief_digest": "",
                    "falsification_status": "missing",
                    "rule_id": "",
                    "promotion_allowed": False,
                }
            )
            continue
        result = falsify_representation_brief(brief, region_id=region_id)
        hypotheses = list(result.get("hypotheses") or [])
        top = hypotheses[0] if hypotheses else {}
        rows.append(
            {
                "region_id": region_id,
                "brief_digest": str(result.get("brief_digest") or brief.get("brief_digest") or "")[:16],
                "falsification_status": str(top.get("status") or "inconclusive"),
                "rule_id": str(top.get("rule_id") or ""),
                "promotion_allowed": bool(result.get("promotion_allowed") is True),
            }
        )
    return rows


def build_hex_overlay_spans(
    *,
    snapshot: Mapping[str, Any] | None = None,
    derived_windows: Sequence[Mapping[str, Any]] | None = None,
    scope_inspected: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    from src.services.ui_policy import hex_overlay_enabled

    spans: List[Dict[str, Any]] = []
    priority = list((policy.get("hex_overlays") or {}).get("overlay_priority") or [])

    def add_span(offset: int, length: int, theme_token: str, role: str, source_id: str = "") -> None:
        if length <= 0:
            return
        spans.append(
            {
                "offset": int(offset),
                "length": int(length),
                "theme_token": theme_token,
                "role": role,
                "source_id": source_id,
                "priority": priority.index(role) if role in priority else len(priority),
            }
        )

    snap = dict(snapshot or {})
    if hex_overlay_enabled(policy, "show_anchors"):
        for anchor in snap.get("anchors") or []:
            span = dict(anchor.get("span") or {})
            level = str(anchor.get("evidence_level") or "candidate")
            token = "anchor.verified" if level == "verified" else "anchor.candidate"
            add_span(int(span.get("offset") or 0), int(span.get("length") or 0), token, "anchor", str(anchor.get("anchor_id") or ""))

    if hex_overlay_enabled(policy, "show_probe_windows"):
        for window in derived_windows or []:
            add_span(int(window.get("offset") or 0), int(window.get("length") or 0), "probe_window", "probe_window", str(window.get("name") or ""))

    inspected = dict(scope_inspected or {})
    overlay = dict(inspected.get("waterfall_overlay") or {})
    if hex_overlay_enabled(policy, "show_alternate_scope_ranges"):
        for item in overlay.get("ranges") or []:
            role = str(item.get("class") or "candidate_body")
            token = str(item.get("theme_token") or f"binary_waterfall.{role}")
            add_span(int(item.get("offset") or 0), int(item.get("length") or 0), token, role.replace("_body", ""), str(item.get("source_id") or ""))

    if hex_overlay_enabled(policy, "show_scope_boundaries"):
        for boundary in overlay.get("boundaries") or []:
            position = int(boundary.get("position") or 0)
            add_span(position, 1, "binary_waterfall.boundary", "boundary", str(boundary.get("source_id") or ""))

    spans.sort(key=lambda item: (int(item.get("priority") or 0), int(item.get("offset") or 0)))
    max_spans = int((policy.get("load_budgets") or {}).get("max_forensic_overlay_spans") or 0)
    if max_spans > 0 and len(spans) > max_spans:
        spans = spans[:max_spans]
    return spans


def build_record_family_overlay_spans(
    inspected: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    from src.services.ui_policy import hex_overlay_enabled

    priority = list((policy.get("hex_overlays") or {}).get("overlay_priority") or [])
    spans: List[Dict[str, Any]] = []
    overlay = dict(inspected.get("waterfall_overlay") or {})
    for item in overlay.get("ranges") or []:
        role = str(item.get("class") or "")
        if role == "record_family_training" and not hex_overlay_enabled(policy, "show_record_family_training"):
            continue
        if role == "record_family_holdout" and not hex_overlay_enabled(policy, "show_record_family_holdout"):
            continue
        if role not in {"record_family_training", "record_family_holdout"}:
            continue
        token = str(item.get("theme_token") or f"binary_waterfall.{role}")
        spans.append(
            {
                "offset": int(item.get("offset") or 0),
                "length": int(item.get("length") or 0),
                "theme_token": token,
                "role": role,
                "source_id": str(item.get("source_id") or item.get("record_family_id") or "record_family"),
                "priority": priority.index(role) if role in priority else len(priority),
            }
        )
    spans.sort(key=lambda item: (int(item.get("priority") or 0), int(item.get("offset") or 0)))
    max_spans = int((policy.get("load_budgets") or {}).get("max_forensic_overlay_spans") or 0)
    if max_spans > 0 and len(spans) > max_spans:
        spans = spans[:max_spans]
    return spans


def build_pair_diff_overlay_spans(
    *,
    source_path: str | Path,
    candidate_path: str | Path,
    policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    from src.services.binary_byte_diff import build_pair_diff_spans

    source = Path(source_path).expanduser().resolve().read_bytes()
    candidate = Path(candidate_path).expanduser().resolve().read_bytes()
    return build_pair_diff_spans(source, candidate, policy=policy)


def build_scope_evidence_overlay_spans(
    scope_evidence: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    priority = list((policy.get("hex_overlays") or {}).get("overlay_priority") or [])
    spans: List[Dict[str, Any]] = []
    for row in scope_evidence.get("ranges") or []:
        role = str(row.get("role") or "candidate_body")
        token = str(row.get("theme_token") or f"binary_waterfall.{role}")
        spans.append(
            {
                "offset": int(row.get("offset") or 0),
                "length": int(row.get("length") or 0),
                "theme_token": token,
                "role": role,
                "source_id": str(row.get("range") or "scope_evidence"),
                "priority": priority.index(role) if role in priority else len(priority),
            }
        )
    max_spans = int((policy.get("load_budgets") or {}).get("max_forensic_overlay_spans") or 0)
    if max_spans > 0 and len(spans) > max_spans:
        spans = spans[:max_spans]
    return spans


def _cap_rows(rows: List[Any], policy: Mapping[str, Any]) -> List[Any]:
    limit = int((policy.get("load_budgets") or {}).get("max_inspector_table_rows") or 0)
    if limit <= 0 or len(rows) <= limit:
        return rows
    return rows[:limit]


def discover_full_decode_run(source_sha256: str, *, scan_limit: int) -> Dict[str, Any]:
    """Return the newest verified full-decode run matching the loaded file identity."""
    if not source_sha256:
        return {}
    try:
        from src.services.learning_db import discover_rail_run_via_learning_db

        db_result = discover_rail_run_via_learning_db("full_decode", source_sha256)
        inspected = dict(db_result.get("inspected") or {})
        if db_result.get("verified") and inspected:
            inspected["state_source"] = str(db_result.get("state_source") or "learning_db")
            inspected["run_id"] = db_result.get("run_id")
            inspected["run_path"] = db_result.get("run_path")
            return inspected
    except Exception:
        pass
    try:
        from src.services.candidate_lineage import discover_verified_run_for_rail

        discovery = discover_verified_run_for_rail("full_decode", source_sha256, scan_limit=scan_limit)
        inspected = dict(discovery.get("inspected") or {})
        if discovery.get("verified") and inspected:
            inspected["state_source"] = "artifact_scan"
            inspected["run_id"] = discovery.get("run_id")
            inspected["run_path"] = discovery.get("run_path")
            return inspected
    except Exception:
        pass
    return {}


def discover_unresolved_inference_run(source_sha256: str, *, scan_limit: int) -> Dict[str, Any]:
    """Return the newest verified unresolved-inference graph matching the loaded file."""
    if not source_sha256:
        return {}
    try:
        from src.services.learning_db import discover_rail_run_via_learning_db

        db_result = discover_rail_run_via_learning_db("unresolved_inference", source_sha256)
        inspected = dict(db_result.get("inspected") or {})
        if db_result.get("verified") and inspected:
            inspected["state_source"] = str(db_result.get("state_source") or "learning_db")
            inspected["run_id"] = db_result.get("run_id")
            inspected["run_path"] = db_result.get("run_path")
            graph_path = Path(str((inspected.get("artifacts") or {}).get("semantic_graph") or ""))
            if graph_path.is_file():
                graph = _read_json(graph_path)
                inspected["graph_nodes"] = graph.get("nodes") or []
                inspected["graph_edges"] = graph.get("edges") or []
            return inspected
    except Exception:
        pass
    try:
        from src.services.candidate_lineage import discover_verified_run_for_rail

        discovery = discover_verified_run_for_rail("unresolved_inference", source_sha256, scan_limit=scan_limit)
        inspected = dict(discovery.get("inspected") or {})
        if not discovery.get("verified") or not inspected:
            return {}
        graph_path = Path(str((inspected.get("artifacts") or {}).get("semantic_graph") or ""))
        if graph_path.is_file():
            graph = _read_json(graph_path)
            inspected["graph_nodes"] = graph.get("nodes") or []
            inspected["graph_edges"] = graph.get("edges") or []
        inspected["state_source"] = "artifact_scan"
        inspected["run_id"] = discovery.get("run_id")
        inspected["run_path"] = discovery.get("run_path")
        return inspected
    except Exception:
        return {}


def build_forensic_context(
    *,
    source_path: str | Path,
    snapshot: Mapping[str, Any],
    investigation_root: str | Path | None = None,
    workspace_root: str | Path | None = None,
    policy: Mapping[str, Any] | None = None,
    include_representation: bool = True,
    include_scope_discovery: bool = True,
    include_lineage_discovery: bool = True,
) -> Dict[str, Any]:
    from src.services.ui_policy import load_ui_policy

    ui_policy = dict(policy or load_ui_policy())
    source = dict(snapshot.get("source") or {})
    source_sha = str(source.get("sha256") or "")
    investigation = {}
    if investigation_root:
        investigation = present_investigation_artifacts(investigation_root)
    scope_evidence: Dict[str, Any] = {}
    scope_inspected: Dict[str, Any] = {}
    full_decode: Dict[str, Any] = {}
    unresolved_inference: Dict[str, Any] = {}
    candidate_lineage: Dict[str, Any] = {}
    if include_lineage_discovery and source_sha:
        try:
            from src.services.candidate_lineage import resolve_candidate_lineage

            candidate_lineage = resolve_candidate_lineage(source_sha256=source_sha)
        except Exception:
            candidate_lineage = {}
    if candidate_lineage:
        try:
            from src.services.candidate_lineage.graph_bridge import full_decode_from_lineage, unresolved_inference_from_lineage

            if not full_decode:
                full_decode = full_decode_from_lineage(candidate_lineage)
            if not unresolved_inference or not unresolved_inference.get("graph_nodes"):
                hydrated = unresolved_inference_from_lineage(candidate_lineage)
                if hydrated:
                    unresolved_inference = {**unresolved_inference, **hydrated}
        except Exception:
            pass
    if include_scope_discovery:
        scan_limit = int((ui_policy.get("load_budgets") or {}).get("scope_run_scan_limit") or 256)
        scope_run = discover_scope_run_json(source_sha, scan_limit=scan_limit)
        if scope_run is not None:
            scope_evidence = present_transform_scope_evidence(scope_run)
            try:
                from src.services.alternate_scope import inspect_alternate_scope_run

                scope_inspected = inspect_alternate_scope_run(scope_run)
            except Exception:
                scope_inspected = {"waterfall_overlay": {"ranges": scope_evidence.get("ranges") or []}}
        if not full_decode:
            full_decode = discover_full_decode_run(source_sha, scan_limit=scan_limit)
        if not unresolved_inference or not unresolved_inference.get("graph_nodes"):
            unresolved_inference = discover_unresolved_inference_run(source_sha, scan_limit=scan_limit)
    db_parser = None
    if source_sha:
        try:
            from src.services.learning_db import lookup_parser_coverage

            db_parser = lookup_parser_coverage(source_sha)
        except Exception:
            db_parser = None
    overlays = build_hex_overlay_spans(
        snapshot=snapshot,
        derived_windows=investigation.get("derived_windows") or [],
        scope_inspected=scope_inspected,
        policy=ui_policy,
    )
    if full_decode:
        priority = list((ui_policy.get("hex_overlays") or {}).get("overlay_priority") or [])
        for row in (full_decode.get("waterfall_overlay") or {}).get("ranges") or []:
            role = str(row.get("class") or "unresolved")
            overlays.append({"offset": int(row.get("offset") or 0), "length": int(row.get("length") or 0), "theme_token": str(row.get("theme_token") or f"binary_waterfall.{role}"), "role": role, "source_id": str(row.get("source_id") or "full_decode"), "priority": priority.index(role) if role in priority else len(priority)})
    if unresolved_inference:
        priority = list((ui_policy.get("hex_overlays") or {}).get("overlay_priority") or [])
        for row in (unresolved_inference.get("waterfall_overlay") or {}).get("ranges") or []:
            role = str(row.get("class") or "unresolved")
            overlays.append({"offset": int(row.get("offset") or 0), "length": int(row.get("length") or 0), "theme_token": str(row.get("theme_token") or f"binary_waterfall.{role}"), "role": role, "source_id": str(row.get("source_id") or "unresolved_inference"), "priority": priority.index(role) if role in priority else len(priority)})
    representation_rows: List[Dict[str, Any]] = []
    if include_representation:
        representation_rows = present_representation_rows(snapshot, workspace_root=workspace_root)
    lineage_file_match: Dict[str, Any] = {}
    if candidate_lineage and source_sha:
        try:
            from src.services.candidate_lineage.present import present_lineage_file_match

            lineage_file_match = present_lineage_file_match(file_sha256=source_sha, packet=candidate_lineage)
        except Exception:
            lineage_file_match = {}
    plaintext_run_rows: List[Dict[str, Any]] = []
    try:
        plaintext_run_rows = present_plaintext_run_rows(source_path, policy=ui_policy)
    except Exception:
        plaintext_run_rows = []
    return {
        "ui_policy": ui_policy,
        "coverage_rows": present_coverage_rows(snapshot, db_parser=db_parser),
        "anchor_rows": _cap_rows(present_anchor_rows(snapshot), ui_policy),
        "unknown_rows": _cap_rows(present_unknown_rows(snapshot, policy=ui_policy), ui_policy),
        "record_family_rows": _cap_rows(present_record_family_rows(snapshot), ui_policy),
        "plaintext_run_rows": _cap_rows(plaintext_run_rows, ui_policy),
        "waterfall_rows": _cap_rows(present_waterfall_rows(snapshot), ui_policy),
        "representation_rows": _cap_rows(representation_rows, ui_policy),
        "investigation": investigation,
        "scope_evidence": scope_evidence,
        "scope_inspected": scope_inspected,
        "full_decode": full_decode,
        "unresolved_inference": unresolved_inference,
        "candidate_lineage": candidate_lineage,
        "lineage_file_match": lineage_file_match,
        "hex_overlay_spans": overlays,
    }
