"""Bounded delta context packets for parser and Gemma advisory rails."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from .core import _read, _lineage_dir, lineage_key_from_run, load_proof_ledger_bundle


def build_delta_context_packet(
    delta: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any] | None = None,
    allowed_next_measurements: Sequence[str] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    advisory = dict(bundle["policy"]["advisory_packet"])
    max_entries = int(advisory.get("max_span_entries") or 32)
    summary = dict(delta.get("summary") or {})
    spans = dict(delta.get("spans") or {})
    lost = list(spans.get("lost_proof_owned_spans") or [])[:max_entries]
    gained = list(spans.get("gained_proof_owned_spans") or [])[:max_entries]
    improved_axes: List[str] = []
    regressed_axes: List[str] = []
    for axis in bundle["policy"]["acceptance_axes"]:
        axis_id = str(axis["axis_id"])
        if int(summary.get(f"{axis_id}_delta") or 0) > 0 and str(axis.get("direction")) == "maximize":
            improved_axes.append(axis_id)
        if int(summary.get(f"{axis_id}_delta") or 0) < 0 and str(axis.get("direction")) == "minimize":
            improved_axes.append(axis_id)
        if int(summary.get(f"{axis_id}_delta") or 0) < 0 and str(axis.get("direction")) == "maximize":
            regressed_axes.append(axis_id)
        if int(summary.get(f"{axis_id}_delta") or 0) > 0 and str(axis.get("direction")) == "minimize":
            regressed_axes.append(axis_id)
    violations = []
    if int(summary.get("lost_proof_owned_span_count") or 0) > 0:
        violations.append("proof_owned_non_regression")
    packet = {
        "schema_version": 1,
        "lineage_key": str(delta.get("lineage_key") or ""),
        "from_candidate_id": str((delta.get("from") or {}).get("candidate_id") or ""),
        "to_candidate_id": str((delta.get("to") or {}).get("candidate_id") or ""),
        "improved_axes": improved_axes,
        "regressed_axes": regressed_axes,
        "lost_proof_owned_span_count": int(summary.get("lost_proof_owned_span_count") or 0),
        "gained_proof_owned_span_count": int(summary.get("preserved_proof_owned_span_count") or 0),
        "unresolved_byte_delta": int(summary.get("unresolved_byte_delta") or 0),
        "required_preservation_violations": violations,
        "allowed_next_measurements": list(allowed_next_measurements or []),
        "lost_proof_owned_spans": lost,
        "gained_proof_owned_spans": gained,
    }
    if not bool(advisory.get("include_plaintext_preview")):
        packet["plaintext_preview_included"] = False
    return {"delta_context": packet, "cross_run_delta_ref": str(delta.get("delta_id") or ""), "delta_summary": summary}


def _latest_delta_for_lineage(lineage_key: str, *, bundle: Mapping[str, Any]) -> Dict[str, Any] | None:
    deltas_dir = _lineage_dir(bundle, lineage_key) / "deltas"
    if not deltas_dir.is_dir():
        return None
    paths = sorted(deltas_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not paths:
        return None
    return _read(paths[0])


def attach_advisory_delta_context(
    packet: Mapping[str, Any],
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
    allowed_next_measurements: Sequence[str] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    path = Path(run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    if not run_file.is_file():
        return dict(packet)
    run = _read(run_file)
    lineage_key = lineage_key_from_run(run, bundle=bundle)
    delta = _latest_delta_for_lineage(lineage_key, bundle=bundle)
    if not delta:
        run_root = run_file.parent
        decision_path = run_root / "final" / "decision.json"
        decision = _read(decision_path) if decision_path.is_file() else {}
        return {
            **dict(packet),
            "delta_context": {
                "schema_version": 1,
                "lineage_key": lineage_key,
                "preservation_blocked": bool(decision.get("preservation_blocked")),
                "decision_reason": str(decision.get("reason") or ""),
                "lost_proof_owned_span_count": 0,
                "gained_proof_owned_span_count": 0,
                "unresolved_byte_delta": 0,
                "required_preservation_violations": [],
                "allowed_next_measurements": list(allowed_next_measurements or []),
            },
        }
    attachment = build_delta_context_packet(delta, bundle=bundle, allowed_next_measurements=allowed_next_measurements)
    return {**dict(packet), **attachment}
