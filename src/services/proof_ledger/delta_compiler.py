"""Cross-run delta compiler for parent-child and run-run transitions."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from .core import (
    _cid,
    _digest,
    _lineage_dir,
    _read,
    _write,
    audit_parent_child_loss,
    lineage_key_from_run,
    load_proof_ledger_bundle,
    load_protected_spans,
    preservation_metrics,
    span_identity,
)


def _run_file(run_path: Path) -> Path:
    path = run_path.resolve()
    return path / "run.json" if path.is_dir() else path


def _run_root(run_path: Path) -> Path:
    run_file = _run_file(run_path)
    return run_file.parent


def _candidate_manifest(run_path: Path, run: Mapping[str, Any]) -> Dict[str, Any]:
    selected = run.get("selected_candidate_id")
    if not selected:
        return {}
    manifest_path = _run_root(run_path) / "candidates" / str(selected) / "manifest.json"
    return _read(manifest_path) if manifest_path.is_file() else {}


def _candidate_bytes(run_path: Path, run: Mapping[str, Any]) -> bytes:
    selected = run.get("selected_candidate_id")
    if not selected:
        return b""
    candidate_path = _run_root(run_path) / "candidates" / str(selected) / "candidate.bin"
    return candidate_path.read_bytes() if candidate_path.is_file() else b""


def _parent_bytes(run: Mapping[str, Any]) -> bytes:
    parent = run.get("parent") or {}
    path = parent.get("path")
    if path and Path(path).is_file():
        return Path(path).read_bytes()
    return b""


def _gate_map(run_path: Path, run: Mapping[str, Any]) -> Dict[str, str]:
    selected = run.get("selected_candidate_id")
    if not selected:
        return {}
    gates_path = _run_root(run_path) / "candidates" / str(selected) / "gates.json"
    if not gates_path.is_file():
        validation_path = _run_root(run_path) / "candidates" / str(selected) / "validation.json"
        if validation_path.is_file():
            gates_path = validation_path
    if not gates_path.is_file():
        return {}
    payload = _read(gates_path)
    return dict(payload.get("gates") or {})


def _coverage_summary(run_path: Path) -> Dict[str, Any]:
    coverage_path = _run_root(run_path) / "coverage" / "complete.json"
    if coverage_path.is_file():
        return dict(_read(coverage_path).get("summary") or {})
    handoff_path = _run_root(run_path) / "coverage" / "handoff.json"
    if handoff_path.is_file():
        return dict(_read(handoff_path).get("summary") or {})
    return {}


def _plaintext_summary(run_path: Path) -> Dict[str, Any]:
    corpus_path = _run_root(run_path) / "exports" / "plaintext_corpus.index.json"
    if corpus_path.is_file():
        payload = _read(corpus_path)
        return {"verified_plaintext_bytes": int(payload.get("verified_plaintext_bytes") or 0), "record_count": int(payload.get("record_count") or 0)}
    return {"verified_plaintext_bytes": 0, "record_count": 0}


def _span_set(records: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(item["proof_span_id"]): item for item in records}


def compile_cross_run_delta(
    from_run_path: str | Path,
    to_run_path: str | Path,
    delta_kind: str,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    from_path = Path(from_run_path).resolve()
    to_path = Path(to_run_path).resolve()
    from_run_file = _run_file(from_path)
    to_run_file = _run_file(to_path)
    from_run = _read(from_run_file)
    to_run = _read(to_run_file)
    lineage_key = lineage_key_from_run(to_run, bundle=bundle)
    from_manifest = _candidate_manifest(from_path, from_run)
    to_manifest = _candidate_manifest(to_path, to_run)
    from_bytes = _candidate_bytes(from_path, from_run) or _parent_bytes(from_run)
    to_bytes = _candidate_bytes(to_path, to_run) or _parent_bytes(to_run)
    protected = load_protected_spans(lineage_key, bundle=bundle)
    preservation = preservation_metrics(from_bytes, to_bytes, protected)
    audit = audit_parent_child_loss(from_bytes, to_bytes, protected)
    from_plain = _plaintext_summary(from_path)
    to_plain = _plaintext_summary(to_path)
    from_coverage = _coverage_summary(from_path)
    to_coverage = _coverage_summary(to_path)
    from_gates = _gate_map(from_path, from_run)
    to_gates = _gate_map(to_path, to_run)
    gate_added = sorted(set(to_gates) - set(from_gates))
    gate_removed = sorted(set(from_gates) - set(to_gates))
    gate_changed = sorted(key for key in set(from_gates) & set(to_gates) if from_gates[key] != to_gates[key])
    gained_spans, lost_spans = [], []
    for record in protected:
        span_id = str(record["proof_span_id"])
        if span_id in preservation["preserved_proof_owned_span_ids"]:
            gained_spans.append(record)
        if span_id in preservation["lost_proof_owned_span_ids"]:
            lost_spans.append(record)
    delta_base = {
        "schema_version": 1,
        "delta_kind": delta_kind,
        "from": {
            "run_id": str(from_run.get("run_id") or ""),
            "candidate_id": str(from_run.get("selected_candidate_id") or ""),
            "manifest": from_manifest,
        },
        "to": {
            "run_id": str(to_run.get("run_id") or ""),
            "candidate_id": str(to_run.get("selected_candidate_id") or ""),
            "manifest": to_manifest,
        },
        "lineage_key": lineage_key,
        "summary": {
            "changed_bytes": sum(1 for left, right in zip(from_bytes, to_bytes) if left != right),
            "lost_proof_owned_span_count": int(preservation["lost_proof_owned_span_count"]),
            "preserved_proof_owned_span_count": int(preservation["preserved_proof_owned_span_count"]),
            "verified_plaintext_byte_delta": int(to_plain["verified_plaintext_bytes"]) - int(from_plain["verified_plaintext_bytes"]),
            "unresolved_byte_delta": int(to_coverage.get("unresolved", 0)) - int(from_coverage.get("unresolved", 0)),
        },
        "spans": {
            "lost_proof_owned_spans": [{"proof_span_id": item["proof_span_id"], "span": item["span"], "truth_state": item.get("truth_state")} for item in lost_spans],
            "gained_proof_owned_spans": [{"proof_span_id": item["proof_span_id"], "span": item["span"], "truth_state": item.get("truth_state")} for item in gained_spans],
            "hypothetical_losses": audit["hypothetical_losses"],
        },
        "plaintext": {"from": from_plain, "to": to_plain},
        "parser_semantic": {"from_gate_count": len(from_gates), "to_gate_count": len(to_gates)},
        "gates": {"added": gate_added, "removed": gate_removed, "changed": gate_changed},
        "transform_regime": {"from_rail_id": str(from_run.get("rail_id") or ""), "to_rail_id": str(to_run.get("rail_id") or "")},
        "lineage": {"lineage_key": lineage_key},
    }
    delta = {**delta_base, "delta_id": _cid("cross-run-delta", delta_base)}
    lineage_dir = _lineage_dir(bundle, lineage_key)
    delta_path = lineage_dir / "deltas" / f"{delta['delta_id']}.json"
    _write(delta_path, delta)
    return {"ok": True, "delta": delta, "delta_path": str(delta_path)}


def compile_parent_to_child_delta(parent_bytes: bytes, candidate_bytes: bytes, protected_spans: Sequence[Mapping[str, Any]], *, metadata: Mapping[str, Any], bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    preservation = preservation_metrics(parent_bytes, candidate_bytes, protected_spans)
    audit = audit_parent_child_loss(parent_bytes, candidate_bytes, protected_spans)
    delta_base = {
        "schema_version": 1,
        "delta_kind": "parent_to_child",
        "from": dict(metadata.get("from") or {}),
        "to": dict(metadata.get("to") or {}),
        "lineage_key": str(metadata.get("lineage_key") or ""),
        "summary": {
            "changed_bytes": sum(1 for left, right in zip(parent_bytes, candidate_bytes) if left != right),
            "lost_proof_owned_span_count": int(preservation["lost_proof_owned_span_count"]),
            "preserved_proof_owned_span_count": int(preservation["preserved_proof_owned_span_count"]),
            "verified_plaintext_byte_delta": int(metadata.get("verified_plaintext_byte_delta") or 0),
            "unresolved_byte_delta": int(metadata.get("unresolved_byte_delta") or 0),
        },
        "spans": {
            "lost_proof_owned_spans": audit["hypothetical_losses"],
            "gained_proof_owned_spans": [],
            "hypothetical_losses": audit["hypothetical_losses"],
        },
        "plaintext": dict(metadata.get("plaintext") or {}),
        "parser_semantic": dict(metadata.get("parser_semantic") or {}),
        "gates": dict(metadata.get("gates") or {}),
        "transform_regime": dict(metadata.get("transform_regime") or {}),
        "lineage": {"lineage_key": str(metadata.get("lineage_key") or "")},
    }
    delta = {**delta_base, "delta_id": _cid("cross-run-delta", delta_base)}
    key = str(metadata.get("lineage_key") or "")
    if key:
        delta_path = _lineage_dir(bundle, key) / "deltas" / f"{delta['delta_id']}.json"
        _write(delta_path, delta)
    return delta
