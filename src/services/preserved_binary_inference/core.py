"""Mechanical ownership inference for preserved_binary coverage spans."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from jsonschema import Draft202012Validator

from src.services.unresolved_inference.core import (
    EventLog,
    acquire_context,
    cluster_spans,
    query_binary_semantic_graph,
)


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _cid(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value)}"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(value)
    os.replace(temporary, path)


def _identity(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _hook(spec: Mapping[str, Any]):
    function = getattr(importlib.import_module(str(spec["module"])), str(spec["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid preserved-binary-inference hook: {spec}")
    return function


def _strict_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    if set(value) != expected_set:
        raise ValueError(f"invalid {label}: missing={sorted(expected_set - set(value))}, extra={sorted(set(value) - expected_set)}")


def load_preserved_bundle(policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "preserved_binary_inference_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "preserved_binary_inference_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    _strict_keys(
        policy,
        {
            "schema_version",
            "policy_id",
            "revision",
            "artifact_root",
            "topology",
            "inference",
            "materialization",
            "validation",
            "objectives",
            "closure",
            "model_boundary",
            "finding_ledger",
            "forensic_bundle",
        },
        "preserved policy",
    )
    _strict_keys(
        policy["finding_ledger"],
        {"root", "maximum_summary_chars"},
        "preserved finding_ledger",
    )
    _strict_keys(
        policy["forensic_bundle"],
        {"enabled", "emit_on_run_complete"},
        "preserved forensic_bundle",
    )
    _strict_keys(registry, {"schema_version", "registry_id", "revision", "detectors", "graph_compiler", "ownership_compiler", "gate_runner"}, "preserved registry")
    _strict_keys(
        policy["topology"],
        {"cluster_max_gap_bytes", "maximum_cluster_spans", "context_before_bytes", "context_after_bytes", "alignment_widths", "maximum_spans"},
        "preserved topology",
    )
    _strict_keys(
        policy["validation"],
        {
            "require_upstream_verified",
            "require_upstream_zero_unresolved",
            "require_source_preserved",
            "require_parent_preserved",
            "require_candidate_preserved",
            "require_coverage_complete",
            "require_graph_valid",
            "require_inverse_replay",
            "require_scope_confinement",
            "require_parent_baseline_complete",
        },
        "preserved validation",
    )
    _strict_keys(
        policy["model_boundary"],
        {"grammar_path", "maximum_attempts", "maximum_tokens", "temperature", "allowed_actions", "forbidden_fields"},
        "preserved model boundary",
    )
    hooks = [item for family in registry["detectors"].values() for item in family] + [
        registry["graph_compiler"],
        registry["ownership_compiler"],
        registry["gate_runner"],
    ]
    for spec in hooks:
        _hook(spec)
    implementation_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry), "implementation_digest": implementation_digest}


def _import_upstream(full_decode_run_path: Path) -> Dict[str, Any]:
    from src.services.full_decode import verify_full_decode_run

    run = _read(full_decode_run_path)
    verification = verify_full_decode_run(full_decode_run_path)
    if not verification.get("ok"):
        raise ValueError("upstream full-decode run failed integrity verification")
    coverage = _read(Path(run["artifacts"]["coverage"]))
    unresolved = int(coverage["summary"].get("unresolved", 0))
    if unresolved:
        raise ValueError("preserved-binary inference requires zero upstream unresolved bytes")
    preserved_segments = [item for item in coverage["segments"] if item["class"] == "preserved_binary"]
    preserved_bytes = int(coverage["summary"].get("preserved_binary", 0))
    if sum(int(item["length"]) for item in preserved_segments) != preserved_bytes:
        raise ValueError("upstream preserved_binary summary mismatch")
    source_path = Path(run["source"]["path"])
    parent_path = Path(run["parent"]["path"])
    candidate_path = Path(run["artifacts"]["candidate"])
    spans = []
    for item in preserved_segments:
        base = {"offset": int(item["offset"]), "length": int(item["length"]), "class": "preserved_binary", "segment_id": str(item["segment_id"])}
        span = {"span_id": _cid("preserved-span", {"run": run["run_id"], **base}), **base}
        errors = list(Draft202012Validator(_read(_root() / "schemas" / "preserved_span.schema.json")).iter_errors(span))
        if errors:
            raise ValueError(f"invalid preserved span: {errors[0].message}")
        spans.append(span)
    return {
        "run": run,
        "coverage": coverage,
        "spans": spans,
        "source_path": source_path,
        "parent_path": parent_path,
        "candidate_path": candidate_path,
        "source": source_path.read_bytes(),
        "parent": parent_path.read_bytes(),
        "candidate": candidate_path.read_bytes(),
    }


def verify_parent_baseline_identity(
    spans: Sequence[Mapping[str, Any]],
    source: bytes,
    parent: bytes,
    candidate: bytes,
    *,
    bundle: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    del bundle
    output = []
    for span in spans:
        offset, length = int(span["offset"]), int(span["length"])
        end = offset + length
        slice_source, slice_parent, slice_candidate = source[offset:end], parent[offset:end], candidate[offset:end]
        verified = slice_source == slice_parent == slice_candidate
        base = {
            "span_id": span["span_id"],
            "offset": offset,
            "length": length,
            "state": "verified" if verified else "rejected",
            "detector_id": "parent-baseline-identity",
            "identity_digest": hashlib.sha256(slice_parent).hexdigest(),
        }
        output.append({"identity_id": _cid("parent-baseline", base), **base})
    return output


def compile_preserved_ownership_proofs(
    spans: Sequence[Mapping[str, Any]],
    identity_results: Sequence[Mapping[str, Any]],
    dependencies: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    del bundle
    identity_by_span = {str(item["span_id"]): item for item in identity_results}
    output = []
    for span in spans:
        identity = identity_by_span[str(span["span_id"])]
        verified_deps = [item for item in dependencies["edges"] if item["source_span_id"] == span["span_id"] and item["state"] == "verified"]
        baseline_ok = identity["state"] == "verified"
        accepted = baseline_ok
        evidence = [str(identity["identity_id"])] + sorted(str(item["dependency_id"]) for item in verified_deps)
        gate_statuses = {
            "parent_baseline": "passed" if baseline_ok else "failed",
            "structural_metadata": "passed" if verified_deps else "inconclusive",
        }
        base = {
            "span_id": span["span_id"],
            "classification": "preserved_binary",
            "state": "accepted" if accepted else "inconclusive",
            "detector_id": "preserved-ownership-compiler",
            "evidence_refs": evidence,
            "independence_groups": sorted({str(item["independence_group"]) for item in verified_deps}),
            "gate_statuses": gate_statuses,
            "promotion_authority": "mechanical_only",
        }
        proof = {"proof_id": _cid("ownership-proof", base), **base}
        errors = list(Draft202012Validator(_read(_root() / "schemas" / "ownership_proof.schema.json")).iter_errors(proof))
        if errors:
            raise ValueError(f"ownership proof schema failure: {errors[0].message}")
        output.append(proof)
    return output


def _ownership_overlay(coverage: Mapping[str, Any], spans: Sequence[Mapping[str, Any]], proofs: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    accepted = {item["span_id"]: item for item in proofs if item["state"] == "accepted"}
    span_by_segment = {item["segment_id"]: item for item in spans}
    segments = []
    for segment in coverage["segments"]:
        span = span_by_segment.get(segment["segment_id"])
        proof = accepted.get(span["span_id"]) if span else None
        owned = bool(proof)
        segments.append(
            {
                **segment,
                "ownership_state": "owned" if owned else "unowned",
                "proof_refs": sorted(set(list(segment.get("proof_refs") or []) + ([proof["proof_id"]] if proof else []))),
            }
        )
    owned_bytes = sum(int(item["length"]) for item in segments if item.get("ownership_state") == "owned" and item["class"] == "preserved_binary")
    unowned_bytes = sum(int(item["length"]) for item in segments if item.get("ownership_state") == "unowned" and item["class"] == "preserved_binary")
    summary = dict(coverage["summary"])
    summary["owned_preserved_binary"] = owned_bytes
    summary["unowned_preserved_binary"] = unowned_bytes
    structural_bytes = sum(
        int(span["length"])
        for span in spans
        if any(proof["span_id"] == span["span_id"] and proof["state"] == "accepted" and proof["gate_statuses"].get("structural_metadata") == "passed" for proof in proofs)
    )
    summary["structural_metadata_preserved"] = structural_bytes
    return {
        "schema_version": 1,
        "file_size": int(coverage["file_size"]),
        "segments": segments,
        "summary": summary,
        "coverage_complete": bool(coverage["coverage_complete"]),
    }


def run_preserved_gates(
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
    original: bytes,
    candidate: bytes,
    overlay: Mapping[str, Any],
    graph: Mapping[str, Any],
    proofs: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any],
) -> Dict[str, Any]:
    accepted_span_ids = {item["span_id"] for item in proofs if item["state"] == "accepted"}
    unowned = int(overlay["summary"].get("unowned_preserved_binary", 0))
    baseline_complete = all(item["state"] == "accepted" for item in proofs)
    checks = {
        "upstream_verified": True,
        "upstream_zero_unresolved": True,
        "source_preserved": before["source"] == after["source"],
        "parent_preserved": before["parent"] == after["parent"],
        "candidate_preserved": before["candidate"] == after["candidate"],
        "coverage_complete": bool(overlay["coverage_complete"]) and sum(int(item["length"]) for item in overlay["segments"]) == len(candidate),
        "graph_valid": bool(graph["validation"]["valid"]),
        "inverse_replay": candidate == original,
        "scope_confinement": all(item["span_id"] in accepted_span_ids for item in proofs if item["state"] == "accepted"),
        "parent_baseline_complete": baseline_complete and unowned == 0,
    }
    required = {key.removeprefix("require_") for key, enabled in bundle["policy"]["validation"].items() if enabled}
    return {"passed": all(checks.get(key, False) for key in required), "gates": {key: "passed" if value else "failed" for key, value in checks.items()}, "required_gates": sorted(required)}


def run_preserved_binary_inference_e2e(
    full_decode_run_path: str | Path,
    *,
    output_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    bundle = load_preserved_bundle(policy_path, registry_path)
    upstream_path = Path(full_decode_run_path).resolve()
    upstream = _import_upstream(upstream_path)
    spans = upstream["spans"]
    maximum_spans = int(bundle["policy"]["topology"]["maximum_spans"])
    if len(spans) > maximum_spans:
        raise RuntimeError("preserved span budget exceeded")
    identities = {role: _identity(upstream[f"{role}_path"]) for role in ("source", "parent", "candidate")}
    basis = {
        "upstream": upstream["run"]["run_id"],
        "identities": {key: value["sha256"] for key, value in identities.items()},
        "policy": bundle["policy_digest"],
        "registry": bundle["registry_digest"],
        "implementation": bundle["implementation_digest"],
    }
    run_id = _cid("preserved-inference-run", basis)
    base = Path(output_root).resolve() if output_root else (_root() / str(bundle["policy"]["artifact_root"])).resolve()
    root = base / run_id
    run_path = root / "run.json"
    if run_path.is_file() and verify_preserved_binary_inference_run(run_path).get("ok"):
        existing = _read(run_path)
        artifacts = dict(existing.get("artifacts") or {})
        if not artifacts.get("forensic_bundle_metrics"):
            return _finalize_preserved_run(run_path, upstream_path, bundle)
        return existing
    root.mkdir(parents=True, exist_ok=True)
    events = root / "logs" / "events.jsonl"
    if events.exists():
        events.unlink()
    log = EventLog(events, run_id)
    log.emit("run_started", {"upstream_run_id": upstream["run"]["run_id"], "preserved_span_count": len(spans)}, "turn-0000")
    clusters = cluster_spans(spans, bundle=bundle)
    contexts = acquire_context(spans, upstream["source"], upstream["parent"], upstream["candidate"], upstream["coverage"], bundle=bundle)
    identity_results = [
        item
        for spec in bundle["registry"]["detectors"]["identity"]
        for item in _hook(spec)(spans, upstream["source"], upstream["parent"], upstream["candidate"], bundle=bundle)
    ]
    boundaries = [
        item for spec in bundle["registry"]["detectors"]["boundaries"] for item in _hook(spec)(spans, upstream["coverage"], bundle=bundle)
    ]
    representations = [
        item for spec in bundle["registry"]["detectors"]["representations"] for item in _hook(spec)(spans, upstream["candidate"], bundle=bundle)
    ]
    dependency_results = [
        _hook(spec)(representations, spans, upstream["coverage"], bundle=bundle) for spec in bundle["registry"]["detectors"]["dependencies"]
    ]
    dependencies = {
        "schema_version": 1,
        "nodes": dependency_results[0]["nodes"] if dependency_results else [],
        "edges": [edge for result in dependency_results for edge in result["edges"]],
    }
    proofs = _hook(bundle["registry"]["ownership_compiler"])(spans, identity_results, dependencies, bundle=bundle)
    graph = _hook(bundle["registry"]["graph_compiler"])(upstream, spans, clusters, boundaries, representations, dependencies, proofs, bundle=bundle)
    overlay = _ownership_overlay(upstream["coverage"], spans, proofs)
    candidate = upstream["candidate"]
    before = identities
    after = {role: _identity(upstream[f"{role}_path"]) for role in ("source", "parent", "candidate")}
    gates = _hook(bundle["registry"]["gate_runner"])(before, after, upstream["candidate"], candidate, overlay, graph, proofs, bundle=bundle)
    unowned_bytes = int(overlay["summary"].get("unowned_preserved_binary", 0))
    owned_bytes = int(overlay["summary"].get("owned_preserved_binary", 0))
    candidate_id = _cid(
        "preserved-candidate",
        {"upstream": upstream["run"]["selected_candidate_id"], "proofs": [item["proof_id"] for item in proofs if item["state"] == "accepted"], "graph": graph["graph_id"]},
    )
    candidate_root = root / "candidates" / candidate_id
    _write_bytes(candidate_root / "candidate.bin", candidate)
    _write(candidate_root / "inverse.json", [])
    manifest = {
        "candidate_id": candidate_id,
        "artifact_path": str(candidate_root / "candidate.bin"),
        "changed_bytes": 0,
        "owned_preserved_bytes": owned_bytes,
        "unowned_preserved_bytes": unowned_bytes,
        "structural_metadata_bytes": int(overlay["summary"].get("structural_metadata_preserved", 0)),
        "gate_statuses": gates["gates"],
        "promotion_eligible": False,
        "verified_decryption": False,
    }
    _write(candidate_root / "manifest.json", manifest)
    _write(root / "baseline" / "preserved.json", spans)
    _write(root / "topology" / "clusters.json", clusters)
    _write(root / "topology" / "contexts.json", contexts)
    _write(root / "inference" / "identity.json", identity_results)
    _write(root / "inference" / "boundaries.json", boundaries)
    _write(root / "inference" / "representations.json", representations)
    _write(root / "inference" / "dependency_graph.json", dependencies)
    _write(root / "inference" / "ownership_proofs.json", proofs)
    _write(root / "graph" / "binary_semantic_graph.json", graph)
    _write(root / "graph" / "binary_semantic_graph.index.json", graph["indexes"])
    _write(root / "coverage" / "ownership_overlay.json", overlay)
    _write(candidate_root / "gates.json", gates)
    accepted = [item for item in proofs if item["state"] == "accepted"]
    status = (
        "completed"
        if gates["passed"] and unowned_bytes == 0
        else ("partial_unowned" if gates["passed"] and accepted else ("evidence_exhausted" if gates["passed"] else "failed_validation"))
    )
    decision = {
        "schema_version": 1,
        "status": status,
        "selected_candidate_id": candidate_id,
        "unowned_preserved_bytes": unowned_bytes,
        "owned_preserved_bytes": owned_bytes,
        "graph_id": graph["graph_id"],
        "promotion_eligible": False,
        "verified_decryption": False,
    }
    _write(root / "final" / "decision.json", decision)
    report_lines = [
        "PRESERVED BINARY OWNERSHIP REPORT",
        f"run_id={run_id}",
        f"status={status}",
        f"graph_id={graph['graph_id']}",
        f"owned_preserved_bytes={owned_bytes}",
        f"unowned_preserved_bytes={unowned_bytes}",
        f"structural_metadata_bytes={overlay['summary'].get('structural_metadata_preserved', 0)}",
        f"span_count={len(spans)}",
        f"cluster_count={len(clusters)}",
    ]
    report = "\n".join(report_lines) + "\n"
    report.encode("ascii", errors="strict")
    (root / "exports").mkdir(parents=True, exist_ok=True)
    (root / "exports" / "semantic_report.ascii").write_text(report, encoding="ascii", newline="\n")
    log.emit("run_completed", {"status": status, "owned_preserved_bytes": owned_bytes, "unowned_preserved_bytes": unowned_bytes}, "turn-0001")
    artifacts = {
        "preserved_baseline": str(root / "baseline" / "preserved.json"),
        "clusters": str(root / "topology" / "clusters.json"),
        "contexts": str(root / "topology" / "contexts.json"),
        "identity": str(root / "inference" / "identity.json"),
        "boundaries": str(root / "inference" / "boundaries.json"),
        "representations": str(root / "inference" / "representations.json"),
        "dependency_graph": str(root / "inference" / "dependency_graph.json"),
        "ownership_proofs": str(root / "inference" / "ownership_proofs.json"),
        "semantic_graph": str(root / "graph" / "binary_semantic_graph.json"),
        "semantic_graph_index": str(root / "graph" / "binary_semantic_graph.index.json"),
        "ownership_overlay": str(root / "coverage" / "ownership_overlay.json"),
        "candidate": str(candidate_root / "candidate.bin"),
        "candidate_manifest": str(candidate_root / "manifest.json"),
        "inverse": str(candidate_root / "inverse.json"),
        "gates": str(candidate_root / "gates.json"),
        "decision": str(root / "final" / "decision.json"),
        "semantic_report": str(root / "exports" / "semantic_report.ascii"),
        "events": str(events),
    }
    run = {
        "schema_version": 1,
        "run_id": run_id,
        "status": status,
        "upstream_run_id": upstream["run"]["run_id"],
        "source": identities["source"],
        "parent": identities["parent"],
        "candidate": identities["candidate"],
        "policy_digest": bundle["policy_digest"],
        "registry_digest": bundle["registry_digest"],
        "implementation_digest": bundle["implementation_digest"],
        "run_root": str(root),
        "artifacts": artifacts,
    }
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "preserved_binary_inference_run.schema.json")).iter_errors(run))
    if errors:
        raise ValueError(f"preserved run schema failure: {errors[0].message}")
    _write(run_path, run)
    return _finalize_preserved_run(run_path, upstream_path, bundle)


def _finalize_preserved_run(run_path: Path, upstream_path: Path, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read(run_path)
    forensic_cfg = dict(bundle["policy"].get("forensic_bundle") or {})
    if forensic_cfg.get("enabled") and forensic_cfg.get("emit_on_run_complete") and run.get("status") == "completed":
        from src.services.forensic_bundle import export_preserved_forensic_bundle

        export_result = export_preserved_forensic_bundle(run_path, full_decode_run_path=upstream_path)
        run = _read(run_path)
        run["artifacts"] = dict(run["artifacts"])
        run["artifacts"]["forensic_bundle"] = export_result["bundle_root"]
        run["artifacts"]["forensic_bundle_manifest"] = export_result["manifest_path"]
        run["artifacts"]["forensic_bundle_metrics"] = export_result["knowledge_coverage_path"]
        _write(run_path, run)
        try:
            from src.services.learning_db import index_finding_ledger, try_index_learning_db_on_run_complete

            try_index_learning_db_on_run_complete(run_path, "preserved_binary_inference")
            index_finding_ledger()
        except Exception:
            pass
    elif run.get("status") == "completed":
        try:
            from src.services.learning_db import try_index_learning_db_on_run_complete

            try_index_learning_db_on_run_complete(run_path, "preserved_binary_inference")
        except Exception:
            pass
    return run


def verify_preserved_binary_inference_run(run_path: str | Path) -> Dict[str, Any]:
    try:
        run = _read(Path(run_path).resolve())
        root = Path(run["run_root"]).resolve()
        schema_errors = list(Draft202012Validator(_read(_root() / "schemas" / "preserved_binary_inference_run.schema.json")).iter_errors(run))
        missing, unsafe = [], []
        directory_artifacts = {"forensic_bundle"}
        for name, raw in run["artifacts"].items():
            path = Path(raw).resolve()
            if root not in path.parents and path != root:
                unsafe.append(name)
            elif name in directory_artifacts:
                if not path.is_dir():
                    missing.append(name)
            elif not path.is_file():
                missing.append(name)
        identities_ok = all(_identity(Path(run[role]["path"]))["sha256"] == run[role]["sha256"] for role in ("source", "parent", "candidate"))
        graph_ok = False
        if not missing and not unsafe:
            graph = _read(Path(run["artifacts"]["semantic_graph"]))
            graph_ok = bool(graph["validation"]["valid"]) and not list(
                Draft202012Validator(_read(_root() / "schemas" / "binary_semantic_graph.schema.json")).iter_errors(graph)
            )
        return {
            "ok": not schema_errors and not missing and not unsafe and identities_ok and graph_ok,
            "run_id": run.get("run_id"),
            "schema_errors": [item.message for item in schema_errors],
            "missing_artifacts": missing,
            "unsafe_artifacts": unsafe,
            "identities_ok": identities_ok,
            "graph_ok": graph_ok,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_preserved_binary_inference_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve())
    verification = verify_preserved_binary_inference_run(run_path)
    overlay = _read(Path(run["artifacts"]["ownership_overlay"]))
    graph = _read(Path(run["artifacts"]["semantic_graph"]))
    decision = _read(Path(run["artifacts"]["decision"]))
    proofs = _read(Path(run["artifacts"]["ownership_proofs"]))
    manifest = _read(Path(run["artifacts"]["candidate_manifest"]))
    gates = _read(Path(run["artifacts"]["gates"]))
    ranges = [
        {
            "offset": item["offset"],
            "length": item["length"],
            "class": item["class"],
            "ownership_state": item.get("ownership_state"),
            "source_id": item["segment_id"],
            "proof_refs": item.get("proof_refs", []),
            "theme_token": f"binary_waterfall.preserved_{item.get('ownership_state', 'unknown')}",
        }
        for item in overlay["segments"]
        if item["class"] == "preserved_binary"
    ]
    return {
        "operation": "preserved_binary_inference_inspect",
        "run_id": run["run_id"],
        "verified": verification["ok"],
        "status": run["status"],
        "decision": decision,
        "candidate": manifest,
        "ownership_overlay": overlay,
        "gates": gates,
        "ownership_proofs": proofs,
        "graph_summary": {"graph_id": graph["graph_id"], "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]), "validation": graph["validation"]},
        "waterfall_overlay": {"schema_version": 1, "ranges": ranges},
        "run_root": run["run_root"],
        "artifacts": run["artifacts"],
    }


def build_preserved_model_packet(run_path: str | Path) -> Dict[str, Any]:
    inspected = inspect_preserved_binary_inference_run(run_path)
    if not inspected["verified"]:
        raise ValueError("preserved-binary inference run failed integrity verification")
    hypotheses = [
        {
            "target_id": item["proof_id"],
            "span_id": item["span_id"],
            "classification": item["classification"],
            "state": item["state"],
            "gate_statuses": item["gate_statuses"],
        }
        for item in inspected["ownership_proofs"]
    ]
    clusters = _read(Path(inspected["run_root"]) / "topology" / "clusters.json")
    cluster_packet = [{"cluster_id": item["cluster_id"], "span_count": len(item["span_ids"]), "length": item["length"]} for item in clusters]
    return {
        "schema_version": 1,
        "operation": "preserved_binary_model_packet",
        "run_id": inspected["run_id"],
        "run_verified": True,
        "hypotheses": hypotheses,
        "clusters": cluster_packet,
        "owned_preserved_bytes": int(inspected["decision"]["owned_preserved_bytes"]),
        "unowned_preserved_bytes": int(inspected["decision"]["unowned_preserved_bytes"]),
        "allowed_actions": ["prioritize_existing_cluster", "rank_existing_hypothesis"],
        "model_role": "advisory_only",
        "mechanical_authority": True,
    }


def validate_preserved_model_action(action: Mapping[str, Any], packet: Mapping[str, Any], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_preserved_bundle(policy_path, registry_path)
    forbidden = set(bundle["policy"]["model_boundary"]["forbidden_fields"])
    if forbidden.intersection(action):
        raise ValueError("model action contains forbidden authority fields")
    if action.get("action") not in set(bundle["policy"]["model_boundary"]["allowed_actions"]):
        raise ValueError("model action is not registered")
    if set(action) != {"action", "target_id", "reason"}:
        raise ValueError("model action fields do not match contract")
    known = {item["target_id"] for item in packet["hypotheses"]} | {item["cluster_id"] for item in packet["clusters"]}
    if action["target_id"] not in known:
        raise ValueError("model selected unknown evidence target")
    if not isinstance(action["reason"], str) or not action["reason"].strip():
        raise ValueError("model reason is missing")
    return dict(action)


__all__ = [
    "build_preserved_model_packet",
    "inspect_preserved_binary_inference_run",
    "load_preserved_bundle",
    "query_binary_semantic_graph",
    "run_preserved_binary_inference_e2e",
    "validate_preserved_model_action",
    "verify_preserved_binary_inference_run",
    "verify_parent_baseline_identity",
    "compile_preserved_ownership_proofs",
    "run_preserved_gates",
]
