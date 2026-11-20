"""Rail adapters that normalize proof spans and axis values from run artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from .core import _cid, _digest, _read, _root, lineage_key_from_run, span_identity


def _run_root(run_path: Path) -> Path:
    path = run_path.resolve()
    return path.parent if path.name == "run.json" else path


def _base_record(
    *,
    run: Mapping[str, Any],
    lineage_key: str,
    span: Mapping[str, Any],
    coverage_class: str,
    truth_state: str,
    producer: Mapping[str, Any],
    gate_refs: Sequence[str],
    evidence_refs: Sequence[str],
    candidate_sha256: str | None = None,
) -> Dict[str, Any]:
    source_sha = str(run["source"]["sha256"])
    parent_sha = str(run["parent"]["sha256"])
    base = {
        "schema_version": 1,
        "lineage_key": lineage_key,
        "source_sha256": source_sha,
        "parent_sha256": parent_sha,
        "candidate_sha256": candidate_sha256,
        "span": {"offset": int(span["offset"]), "length": int(span["length"])},
        "coverage_class": coverage_class,
        "producer": dict(producer),
        "truth_state": truth_state,
        "gate_refs": sorted(set(gate_refs)),
        "evidence_refs": sorted(set(evidence_refs)),
        "supersedes": [],
        "counterexample_refs": [],
        "authority": {"rail_id": producer.get("rail_id"), "run_id": producer.get("run_id")},
    }
    return {**base, "proof_span_id": _cid("proof-span", base)}


def _truth_from_gates(gates: Mapping[str, Any]) -> str:
    if bool(gates.get("passed")):
        return "proof_owned"
    return "observed"


def _proven_digest(data: bytes, span: Mapping[str, Any]) -> str:
    offset, length = int(span["offset"]), int(span["length"])
    return hashlib.sha256(data[offset : offset + length]).hexdigest()


def normalize_full_decode_run(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    lineage_key = lineage_key_from_run(run, bundle=bundle)
    records: List[Dict[str, Any]] = []
    candidate_manifests: List[Dict[str, Any]] = []
    selected = run.get("selected_candidate_id")
    if selected:
        manifest_path = root / "candidates" / str(selected) / "manifest.json"
        if manifest_path.is_file():
            candidate_manifests.append(_read(manifest_path))
    coverage_path = root / "coverage" / "complete.json"
    coverage = _read(coverage_path) if coverage_path.is_file() else {"segments": [], "summary": {}}
    gates_path = root / "candidates" / str(selected) / "gates.json" if selected else None
    gates = _read(gates_path) if gates_path and gates_path.is_file() else {"passed": False, "gates": {}}
    proof_spans_path = root / "candidates" / str(selected) / "proof_spans.json" if selected else None
    proof_spans = _read(proof_spans_path) if proof_spans_path and proof_spans_path.is_file() else []
    candidate_bytes = b""
    candidate_path = root / "candidates" / str(selected) / "candidate.bin" if selected else None
    if candidate_path and candidate_path.is_file():
        candidate_bytes = candidate_path.read_bytes()
    producer = {"rail_id": "full_decode", "run_id": str(run.get("run_id") or ""), "candidate_id": str(selected or "")}
    gate_refs = [key for key, value in dict(gates.get("gates") or {}).items() if value == "passed"]
    evidence_refs = [str(root / "coverage" / "complete.json")]
    if proof_spans_path and proof_spans_path.is_file():
        evidence_refs.append(str(proof_spans_path))
    for span in proof_spans:
        offset, length = span_identity(span)
        segment_class = "verified_plaintext"
        for segment in coverage.get("segments") or []:
            seg_offset, seg_length = span_identity(segment)
            if seg_offset <= offset and offset + length <= seg_offset + seg_length:
                segment_class = str(segment.get("class") or segment_class)
                break
        records.append(
            _base_record(
                run=run,
                lineage_key=lineage_key,
                span=span,
                coverage_class=segment_class,
                truth_state=_truth_from_gates(gates) if segment_class in {"verified_plaintext", "verified_decoded_binary"} else "observed",
                producer={**producer, "scope_id": str(span.get("scope_id") or "")},
                gate_refs=gate_refs,
                evidence_refs=evidence_refs,
                candidate_sha256=str(candidate_manifests[0].get("output_sha256")) if candidate_manifests else None,
            )
            | ({"proven_bytes_digest": _proven_digest(candidate_bytes, span)} if candidate_bytes else {})
        )
    axis_values = extract_full_decode_axes(run_path, bundle=bundle)
    return {
        "lineage_key": lineage_key,
        "proof_span_records": records,
        "candidate_manifests": candidate_manifests,
        "axis_values": axis_values,
    }


def extract_full_decode_axes(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    selected = run.get("selected_candidate_id")
    manifest: Dict[str, Any] = {}
    if selected:
        manifest_path = root / "candidates" / str(selected) / "manifest.json"
        if manifest_path.is_file():
            manifest = _read(manifest_path)
    coverage_path = root / "coverage" / "complete.json"
    coverage = _read(coverage_path) if coverage_path.is_file() else {"summary": {}}
    corpus_path = root / "exports" / "plaintext_corpus.index.json"
    corpus = _read(corpus_path) if corpus_path.is_file() else {"verified_plaintext_bytes": 0}
    from .core import load_protected_spans

    protected = load_protected_spans(lineage_key_from_run(run, bundle=bundle), bundle=bundle)
    return {
        "supported_plaintext_bytes": int(corpus.get("verified_plaintext_bytes") or coverage.get("summary", {}).get("verified_plaintext", 0)),
        "unresolved_bytes": int(manifest.get("unresolved_bytes") or coverage.get("summary", {}).get("unresolved", 0)),
        "changed_bytes": int(manifest.get("changed_bytes") or 0),
        "reference_diff_bytes": int((manifest.get("reference_metrics") or {}).get("reference_diff_bytes") or 0),
        "proof_owned_span_count": len(protected),
    }


def normalize_local_transform_run(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    lineage_key = lineage_key_from_run(run, bundle=bundle)
    records: List[Dict[str, Any]] = []
    candidate_manifests: List[Dict[str, Any]] = []
    selected = run.get("selected_candidate_id")
    if selected:
        manifest_path = root / "candidates" / str(selected) / "manifest.json"
        if manifest_path.is_file():
            candidate_manifests.append(_read(manifest_path))
    descriptor_path = root / "candidates" / str(selected) / "descriptor.json" if selected else None
    descriptor = _read(descriptor_path) if descriptor_path and descriptor_path.is_file() else {"scopes": []}
    validation_path = root / "candidates" / str(selected) / "validation.json" if selected else None
    validation = _read(validation_path) if validation_path and validation_path.is_file() else {"passed": False, "gates": {}}
    producer = {"rail_id": "local_transform", "run_id": str(run.get("run_id") or ""), "candidate_id": str(selected or "")}
    gate_refs = [key for key, value in dict(validation.get("gates") or {}).items() if value == "passed"]
    evidence_refs = [str(descriptor_path)] if descriptor_path else []
    for scope in descriptor.get("scopes") or []:
        span = scope.get("span") or scope
        records.append(
            _base_record(
                run=run,
                lineage_key=lineage_key,
                span=span,
                coverage_class="verified_decoded_binary",
                truth_state=_truth_from_gates(validation),
                producer={**producer, "scope_id": str(scope.get("scope_id") or "")},
                gate_refs=gate_refs,
                evidence_refs=[ref for ref in evidence_refs if ref],
                candidate_sha256=str(candidate_manifests[0].get("output_sha256")) if candidate_manifests else None,
            )
        )
    return {
        "lineage_key": lineage_key,
        "proof_span_records": records,
        "candidate_manifests": candidate_manifests,
        "axis_values": extract_local_transform_axes(run_path, bundle=bundle),
    }


def extract_local_transform_axes(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    selected = run.get("selected_candidate_id")
    manifest: Dict[str, Any] = {}
    if selected:
        manifest_path = root / "candidates" / str(selected) / "manifest.json"
        if manifest_path.is_file():
            manifest = _read(manifest_path)
    from .core import load_protected_spans

    protected = load_protected_spans(lineage_key_from_run(run, bundle=bundle), bundle=bundle)
    return {
        "supported_plaintext_bytes": 0,
        "unresolved_bytes": int(manifest.get("unresolved_bytes") or 0),
        "changed_bytes": int(manifest.get("changed_bytes") or 0),
        "reference_diff_bytes": 0,
        "proof_owned_span_count": len(protected),
    }


def normalize_record_family_run(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    lineage_key = lineage_key_from_run(run, bundle=bundle)
    records: List[Dict[str, Any]] = []
    candidate_manifests: List[Dict[str, Any]] = []
    frontier_path = root / "final" / "pareto_frontier.json"
    if frontier_path.is_file():
        candidate_manifests.extend(_read(frontier_path))
    proofs_dir = root / "proofs"
    producer = {"rail_id": "record_family", "run_id": str(run.get("run_id") or "")}
    for proof_path in sorted(proofs_dir.glob("*.json")) if proofs_dir.is_dir() else []:
        proof = _read(proof_path)
        if str(proof.get("state")) != "holdout_passed":
            continue
        boundary = proof.get("boundary") or {}
        span = {"offset": int(boundary.get("offset", 0)), "length": int(boundary.get("length", 0))}
        if int(span["length"]) <= 0:
            continue
        records.append(
            _base_record(
                run=run,
                lineage_key=lineage_key,
                span=span,
                coverage_class="verified_decoded_binary",
                truth_state="proof_owned",
                producer={**producer, "proof_id": str(proof.get("proof_id") or "")},
                gate_refs=["holdout_passed"],
                evidence_refs=[str(proof_path)],
                candidate_sha256=None,
            )
        )
    findings_dir = root / "records"
    if findings_dir.is_dir():
        for finding_path in sorted(findings_dir.glob("*/*.json")):
            finding = _read(finding_path)
            span = finding.get("span") or {}
            if not span:
                continue
            record = _base_record(
                run=run,
                lineage_key=lineage_key,
                span=span,
                coverage_class=str(finding.get("coverage_class") or "verified_decoded_binary"),
                truth_state=str(finding.get("state") or "observed"),
                producer={**producer, "finding_id": str(finding.get("finding_id") or "")},
                gate_refs=list(finding.get("gate_refs") or []),
                evidence_refs=[str(finding_path)],
                candidate_sha256=str(finding.get("candidate_sha256") or "") or None,
            )
            record["supersedes"] = list(finding.get("supersedes") or [])
            record["counterexample_refs"] = list(finding.get("counterexample_refs") or [])
            records.append(record)
    return {
        "lineage_key": lineage_key,
        "proof_span_records": records,
        "candidate_manifests": candidate_manifests,
        "axis_values": extract_record_family_axes(run_path, bundle=bundle),
    }


def extract_record_family_axes(run_path: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    root = _run_root(run_path)
    frontier_path = root / "final" / "pareto_frontier.json"
    frontier = _read(frontier_path) if frontier_path.is_file() else []
    changed = sum(int(item.get("changed_bytes") or 0) for item in frontier)
    from .core import load_protected_spans

    protected = load_protected_spans(lineage_key_from_run(run, bundle=bundle), bundle=bundle)
    return {
        "supported_plaintext_bytes": 0,
        "unresolved_bytes": 0,
        "changed_bytes": changed,
        "reference_diff_bytes": 0,
        "proof_owned_span_count": len(protected),
    }
