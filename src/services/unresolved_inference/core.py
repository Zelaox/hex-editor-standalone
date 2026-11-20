"""Evidence-driven unresolved-byte ownership and Binary Semantic Graph rail."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from jsonschema import Draft202012Validator


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
        raise ValueError(f"invalid unresolved-inference hook: {spec}")
    return function


def _strict_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    if set(value) != expected_set:
        raise ValueError(f"invalid {label}: missing={sorted(expected_set - set(value))}, extra={sorted(set(value) - expected_set)}")


def load_unresolved_bundle(policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "unresolved_inference_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "unresolved_inference_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    _strict_keys(policy, {"schema_version", "policy_id", "revision", "artifact_root", "topology", "inference", "materialization", "validation", "objectives", "model_boundary"}, "unresolved policy")
    _strict_keys(registry, {"schema_version", "registry_id", "revision", "detectors", "graph_compiler", "ownership_compiler", "gate_runner"}, "unresolved registry")
    if int(policy["schema_version"]) != 1 or int(registry["schema_version"]) != 1:
        raise ValueError("unsupported unresolved-inference schema version")
    hooks = [item for family in registry["detectors"].values() for item in family] + [registry["graph_compiler"], registry["ownership_compiler"], registry["gate_runner"]]
    for spec in hooks:
        _hook(spec)
    implementation_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry), "implementation_digest": implementation_digest}


class EventLog:
    def __init__(self, path: Path, run_id: str):
        self.path, self.run_id, self.sequence, self.previous = path, run_id, 0, ""

    def emit(self, event_type: str, payload: Mapping[str, Any], turn_id: str) -> None:
        base = {"schema_version": 1, "run_id": self.run_id, "turn_id": turn_id, "sequence": self.sequence, "timestamp_utc": datetime.now(timezone.utc).isoformat(), "component_id": "unresolved-inference", "event_type": event_type, "payload": dict(payload), "previous_event_digest": self.previous}
        event = {**base, "event_id": _cid("unresolved-event", base)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            handle.flush()
        self.previous = hashlib.sha256(_canonical(event)).hexdigest()
        self.sequence += 1


def _import_upstream(run_path: Path) -> Dict[str, Any]:
    from src.services.full_decode import verify_full_decode_run

    run = _read(run_path)
    verification = verify_full_decode_run(run_path)
    if not verification.get("ok"):
        raise ValueError("upstream full-decode run failed integrity verification")
    coverage = _read(Path(run["artifacts"]["coverage"]))
    unresolved_index = _read(Path(run["artifacts"]["unresolved"]))
    unresolved_segments = [item for item in coverage["segments"] if item["class"] == "unresolved"]
    if unresolved_index != unresolved_segments:
        raise ValueError("upstream unresolved index does not match coverage")
    if sum(int(item["length"]) for item in unresolved_segments) != int(coverage["summary"].get("unresolved", 0)):
        raise ValueError("upstream unresolved summary mismatch")
    source, parent, candidate = Path(run["source"]["path"]), Path(run["parent"]["path"]), Path(run["artifacts"]["candidate"])
    spans = []
    for item in unresolved_segments:
        base = {"offset": int(item["offset"]), "length": int(item["length"]), "class": "unresolved", "segment_id": str(item["segment_id"])}
        span = {"span_id": _cid("unresolved-span", {"run": run["run_id"], **base}), **base}
        errors = list(Draft202012Validator(_read(_root() / "schemas" / "unresolved_span.schema.json")).iter_errors(span))
        if errors:
            raise ValueError(f"invalid unresolved span: {errors[0].message}")
        spans.append(span)
    return {"run": run, "coverage": coverage, "spans": spans, "source_path": source, "parent_path": parent, "candidate_path": candidate, "source": source.read_bytes(), "parent": parent.read_bytes(), "candidate": candidate.read_bytes()}


def cluster_spans(spans: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    maximum_gap = int(bundle["policy"]["topology"]["cluster_max_gap_bytes"])
    maximum_spans = int(bundle["policy"]["topology"]["maximum_cluster_spans"])
    groups: List[List[Mapping[str, Any]]] = []
    for span in sorted(spans, key=lambda item: (int(item["offset"]), int(item["length"]))):
        if not groups or int(span["offset"]) - (int(groups[-1][-1]["offset"]) + int(groups[-1][-1]["length"])) > maximum_gap or len(groups[-1]) >= maximum_spans:
            groups.append([])
        groups[-1].append(span)
    output = []
    alignments = [int(item) for item in bundle["policy"]["topology"]["alignment_widths"]]
    for group in groups:
        start = min(int(item["offset"]) for item in group)
        end = max(int(item["offset"]) + int(item["length"]) for item in group)
        base = {"offset": start, "length": end - start, "span_ids": [str(item["span_id"]) for item in group], "alignment": {str(width): start % width for width in alignments}}
        output.append({"cluster_id": _cid("span-cluster", base), **base})
    return output


def acquire_context(spans: Sequence[Mapping[str, Any]], source: bytes, parent: bytes, candidate: bytes, coverage: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    before = int(bundle["policy"]["topology"]["context_before_bytes"])
    after = int(bundle["policy"]["topology"]["context_after_bytes"])
    output = []
    for span in spans:
        offset, length = int(span["offset"]), int(span["length"])
        start, end = max(0, offset - before), min(len(candidate), offset + length + after)
        neighbors = [str(item["segment_id"]) for item in coverage["segments"] if int(item["offset"]) < end and int(item["offset"]) + int(item["length"]) > start]
        base = {"span_id": span["span_id"], "offset": start, "length": end - start, "source_digest": hashlib.sha256(source[start:end]).hexdigest(), "parent_digest": hashlib.sha256(parent[start:end]).hexdigest(), "candidate_digest": hashlib.sha256(candidate[start:end]).hexdigest(), "neighbor_segment_ids": neighbors, "preview": {"source_hex": source[start:end].hex(), "parent_hex": parent[start:end].hex(), "candidate_hex": candidate[start:end].hex()}}
        output.append({"context_id": _cid("span-context", {key: value for key, value in base.items() if key != "preview"}), **base})
    return output


def infer_boundaries(spans: Sequence[Mapping[str, Any]], coverage: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del bundle
    segments = sorted(coverage["segments"], key=lambda item: int(item["offset"]))
    output = []
    for span in spans:
        index = next(index for index, item in enumerate(segments) if item["segment_id"] == span["segment_id"])
        left = segments[index - 1]["segment_id"] if index else None
        right = segments[index + 1]["segment_id"] if index + 1 < len(segments) else None
        base = {"span_id": span["span_id"], "start": int(span["offset"]), "end": int(span["offset"]) + int(span["length"]), "left_segment_id": left, "right_segment_id": right, "state": "observed", "detector_id": "coverage-neighbor-boundaries"}
        output.append({"boundary_id": _cid("boundary", base), **base})
    return output


def infer_representations(spans: Sequence[Mapping[str, Any]], candidate: bytes, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    widths = [int(item) for item in bundle["policy"]["inference"]["integer_widths"]]
    modes = [str(item) for item in bundle["policy"]["inference"]["endian_modes"]]
    maximum = int(bundle["policy"]["inference"]["maximum_hypotheses_per_span"])
    output = []
    for span in spans:
        offset, length = int(span["offset"]), int(span["length"])
        for width in widths:
            if width > length:
                continue
            for endian in modes:
                raw = candidate[offset:offset + width]
                base = {"span_id": span["span_id"], "offset": offset, "width": width, "representation": "unsigned_integer", "endian": endian, "value": int.from_bytes(raw, endian, signed=False), "state": "tested", "detector_id": "fixed-width-integers"}
                output.append({"representation_id": _cid("representation", base), **base})
                if sum(1 for item in output if item["span_id"] == span["span_id"]) >= maximum:
                    break
            if sum(1 for item in output if item["span_id"] == span["span_id"]) >= maximum:
                break
    return output


def infer_dependencies(representations: Sequence[Mapping[str, Any]], spans: Sequence[Mapping[str, Any]], coverage: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    minimum = int(bundle["policy"]["inference"]["minimum_independent_occurrences"])
    segments = sorted(coverage["segments"], key=lambda item: int(item["offset"]))
    candidates = []
    for representation in representations:
        span = next(item for item in spans if item["span_id"] == representation["span_id"])
        span_end = int(span["offset"]) + int(span["length"])
        following = next((item for item in segments if int(item["offset"]) == span_end), None)
        if following and int(representation["value"]) == int(following["length"]):
            base = {"source_span_id": span["span_id"], "target_segment_id": following["segment_id"], "edge_type": "length_of", "representation_id": representation["representation_id"], "detector_id": "adjacent-length-count"}
            candidates.append({"dependency_id": _cid("dependency", base), **base})
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for item in candidates:
        representation = next(value for value in representations if value["representation_id"] == item["representation_id"])
        groups.setdefault((item["edge_type"], representation["width"], representation["endian"]), []).append(item)
    edges = []
    for key, items in sorted(groups.items()):
        state = "verified" if len(items) >= minimum else "inconclusive"
        for item in items:
            edges.append({**item, "state": state, "independence_group": str(item["source_span_id"])})
    return {"schema_version": 1, "nodes": [{"node_id": item["span_id"], "node_type": "ByteSpan"} for item in spans], "edges": edges}


def _node(node_type: str, truth_state: str, attributes: Mapping[str, Any]) -> Dict[str, Any]:
    base = {"node_type": node_type, "truth_state": truth_state, "attributes": dict(attributes)}
    return {"node_id": _cid("graph-node", base), **base}


def _edge(edge_type: str, source_id: str, target_id: str, truth_state: str, evidence_refs: Sequence[str]) -> Dict[str, Any]:
    base = {"edge_type": edge_type, "source_id": source_id, "target_id": target_id, "truth_state": truth_state, "evidence_refs": sorted(set(str(item) for item in evidence_refs))}
    return {"edge_id": _cid("graph-edge", base), **base}


def compile_binary_semantic_graph(upstream: Mapping[str, Any], spans: Sequence[Mapping[str, Any]], clusters: Sequence[Mapping[str, Any]], boundaries: Sequence[Mapping[str, Any]], representations: Sequence[Mapping[str, Any]], dependencies: Mapping[str, Any], proofs: Sequence[Mapping[str, Any]] | None = None, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    nodes, edges = [], []
    artifact_nodes = {}
    for role in ("source", "parent", "candidate"):
        identity = _identity(Path(upstream[f"{role}_path"]))
        node = _node("FileArtifact", "observed", {"role": role, "sha256": identity["sha256"], "size": identity["size"], "path": identity["path"]})
        nodes.append(node); artifact_nodes[role] = node
    span_nodes = {}
    for span in spans:
        node = _node("ByteSpan", "observed", {"span_id": span["span_id"], "offset": span["offset"], "length": span["length"], "artifact_role": "candidate"})
        nodes.append(node); span_nodes[span["span_id"]] = node
        edges.append(_edge("contained_by", node["node_id"], artifact_nodes["candidate"]["node_id"], "verified", [span["segment_id"]]))
    coverage_nodes = {}
    class_nodes = {}
    for segment in upstream["coverage"]["segments"]:
        klass = str(segment["class"])
        if klass not in class_nodes:
            class_nodes[klass] = _node("CoverageClass", "verified", {"class": klass}); nodes.append(class_nodes[klass])
        node = _node("CoverageSegment", "verified", {"segment_id": segment["segment_id"], "offset": segment["offset"], "length": segment["length"], "class": klass})
        nodes.append(node); coverage_nodes[segment["segment_id"]] = node
        edges.append(_edge("classified_as", node["node_id"], class_nodes[klass]["node_id"], "verified", list(segment.get("proof_refs") or [])))
    cluster_nodes = {}
    for cluster in clusters:
        node = _node("SpanCluster", "observed", dict(cluster)); nodes.append(node); cluster_nodes[cluster["cluster_id"]] = node
        for span_id in cluster["span_ids"]:
            edges.append(_edge("belongs_to", span_nodes[span_id]["node_id"], node["node_id"], "observed", [cluster["cluster_id"]]))
    for boundary in boundaries:
        node = _node("RecordOccurrence", "hypothesized", dict(boundary)); nodes.append(node)
        edges.append(_edge("belongs_to", span_nodes[boundary["span_id"]]["node_id"], node["node_id"], "hypothesized", [boundary["boundary_id"]]))
    representation_nodes = {}
    for representation in representations:
        node = _node("Representation", "tested", dict(representation)); nodes.append(node); representation_nodes[representation["representation_id"]] = node
        edges.append(_edge("interpreted_as", span_nodes[representation["span_id"]]["node_id"], node["node_id"], "tested", [representation["representation_id"]]))
    for dependency in dependencies["edges"]:
        node = _node("DependencyRule", dependency["state"], dict(dependency)); nodes.append(node)
        target = coverage_nodes[dependency["target_segment_id"]]
        edges.append(_edge("governed_by", span_nodes[dependency["source_span_id"]]["node_id"], node["node_id"], dependency["state"], [dependency["dependency_id"]]))
        edges.append(_edge(dependency["edge_type"], node["node_id"], target["node_id"], dependency["state"], [dependency["dependency_id"]]))
    for proof in proofs or []:
        node = _node("OwnershipProof", "verified" if proof["state"] == "accepted" else proof["state"], dict(proof)); nodes.append(node)
        if proof["span_id"] in span_nodes:
            edges.append(_edge("supported_by", span_nodes[proof["span_id"]]["node_id"], node["node_id"], node["truth_state"], proof["evidence_refs"]))
    indexes: Dict[str, Any] = {"by_node_type": {}, "by_truth_state": {}, "by_edge_type": {}, "by_span_id": {}, "by_offset": []}
    for node in nodes:
        indexes["by_node_type"].setdefault(node["node_type"], []).append(node["node_id"])
        indexes["by_truth_state"].setdefault(node["truth_state"], []).append(node["node_id"])
        attributes = node["attributes"]
        if attributes.get("span_id"):
            indexes["by_span_id"].setdefault(str(attributes["span_id"]), []).append(node["node_id"])
        if node["node_type"] in {"ByteSpan", "CoverageSegment"}:
            indexes["by_offset"].append({"node_id": node["node_id"], "offset": int(attributes["offset"]), "length": int(attributes["length"]), "artifact_role": str(attributes.get("artifact_role") or "candidate")})
    for edge in edges:
        indexes["by_edge_type"].setdefault(edge["edge_type"], []).append(edge["edge_id"])
    for mapping in (indexes["by_node_type"], indexes["by_truth_state"], indexes["by_edge_type"], indexes["by_span_id"]):
        for values in mapping.values(): values.sort()
    indexes["by_offset"].sort(key=lambda item: (item["artifact_role"], item["offset"], item["length"], item["node_id"]))
    node_ids = {item["node_id"] for item in nodes}
    errors = []
    if len(node_ids) != len(nodes): errors.append("duplicate node id")
    if len({item["edge_id"] for item in edges}) != len(edges): errors.append("duplicate edge id")
    for edge in edges:
        if edge["source_id"] not in node_ids or edge["target_id"] not in node_ids: errors.append(f"missing edge endpoint: {edge['edge_id']}")
    base = {"schema_version": 1, "revision": 1, "nodes": sorted(nodes, key=lambda item: item["node_id"]), "edges": sorted(edges, key=lambda item: item["edge_id"]), "indexes": indexes}
    graph_id = _cid("binary-semantic-graph", base)
    graph = {"schema_version": 1, "graph_id": graph_id, "revision": 1, "nodes": base["nodes"], "edges": base["edges"], "indexes": indexes, "validation": {"valid": not errors, "errors": errors}}
    schema_errors = list(Draft202012Validator(_read(_root() / "schemas" / "binary_semantic_graph.schema.json")).iter_errors(graph))
    if schema_errors: raise ValueError(f"binary semantic graph schema failure: {schema_errors[0].message}")
    return graph


def compile_ownership_proofs(spans: Sequence[Mapping[str, Any]], dependencies: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del bundle
    output = []
    for span in spans:
        verified = [item for item in dependencies["edges"] if item["source_span_id"] == span["span_id"] and item["state"] == "verified"]
        groups = sorted({str(item["independence_group"]) for item in verified})
        # A dependency reaches ``verified`` only after infer_dependencies has
        # observed the configured number of independent occurrences for its
        # rule family. Requiring that count again inside one source span makes
        # acceptance impossible because a span is itself one independence
        # group.
        accepted = bool(verified)
        base = {"span_id": span["span_id"], "classification": "preserved_binary" if accepted else "unresolved", "state": "accepted" if accepted else "inconclusive", "detector_id": "dependency-ownership-compiler", "evidence_refs": sorted(item["dependency_id"] for item in verified), "independence_groups": groups, "gate_statuses": {"verified_dependency": "passed" if verified else "inconclusive", "independent_occurrences": "passed" if verified else "inconclusive"}, "promotion_authority": "mechanical_only"}
        proof = {"proof_id": _cid("ownership-proof", base), **base}
        errors = list(Draft202012Validator(_read(_root() / "schemas" / "ownership_proof.schema.json")).iter_errors(proof))
        if errors: raise ValueError(f"ownership proof schema failure: {errors[0].message}")
        output.append(proof)
    return output


def _coverage_after(coverage: Mapping[str, Any], spans: Sequence[Mapping[str, Any]], proofs: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    accepted = {item["span_id"]: item for item in proofs if item["state"] == "accepted"}
    span_by_segment = {item["segment_id"]: item for item in spans}
    segments = []
    for segment in coverage["segments"]:
        span = span_by_segment.get(segment["segment_id"])
        proof = accepted.get(span["span_id"]) if span else None
        segments.append({**segment, "class": proof["classification"] if proof else segment["class"], "proof_refs": sorted(set(list(segment.get("proof_refs") or []) + ([proof["proof_id"]] if proof else [])))})
    summary: Dict[str, int] = {}
    for segment in segments: summary[segment["class"]] = summary.get(segment["class"], 0) + int(segment["length"])
    return {"schema_version": 1, "file_size": int(coverage["file_size"]), "segments": segments, "summary": summary, "coverage_complete": bool(coverage["coverage_complete"])}


def run_unresolved_gates(before: Mapping[str, Mapping[str, Any]], after: Mapping[str, Mapping[str, Any]], original: bytes, candidate: bytes, coverage: Mapping[str, Any], graph: Mapping[str, Any], proofs: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    accepted_span_ids = {item["span_id"] for item in proofs if item["state"] == "accepted"}
    checks = {"upstream_verified": True, "source_preserved": before["source"] == after["source"], "parent_preserved": before["parent"] == after["parent"], "candidate_preserved": before["candidate"] == after["candidate"], "coverage_complete": bool(coverage["coverage_complete"]) and sum(int(item["length"]) for item in coverage["segments"]) == len(candidate), "graph_valid": bool(graph["validation"]["valid"]), "inverse_replay": candidate == original, "scope_confinement": all(item["span_id"] in accepted_span_ids for item in proofs if item["state"] == "accepted"), "ascii_roundtrip": True}
    required = {key.removeprefix("require_") for key, enabled in bundle["policy"]["validation"].items() if enabled}
    return {"passed": all(checks.get(key, False) for key in required), "gates": {key: "passed" if value else "failed" for key, value in checks.items()}, "required_gates": sorted(required)}


def query_binary_semantic_graph(graph_path: str | Path, operation: str, *, node_id: str | None = None, offset: int | None = None, maximum_depth: int = 1, maximum_results: int = 4096) -> Dict[str, Any]:
    graph = _read(Path(graph_path).resolve())
    nodes = {item["node_id"]: item for item in graph["nodes"]}
    results: List[Any] = []
    if operation == "nodes_at_offset":
        if offset is None or int(offset) < 0: raise ValueError("nodes_at_offset requires a non-negative offset")
        ids = [item["node_id"] for item in graph["indexes"]["by_offset"] if int(item["offset"]) <= int(offset) < int(item["offset"]) + int(item["length"])]
        results = [nodes[item] for item in ids]
    elif operation in {"references_from", "references_to", "neighbors", "proof_path"}:
        if node_id not in nodes: raise ValueError("query node is not present in graph")
        frontier, seen = [str(node_id)], {str(node_id)}
        for _ in range(max(1, int(maximum_depth))):
            following = []
            for edge in graph["edges"]:
                match_from = edge["source_id"] in frontier and operation != "references_to"
                match_to = edge["target_id"] in frontier and operation != "references_from"
                if operation == "proof_path" and edge["truth_state"] != "verified": continue
                if match_from or match_to:
                    results.append(edge)
                    other = edge["target_id"] if match_from else edge["source_id"]
                    if other not in seen: seen.add(other); following.append(other)
            frontier = following
            if not frontier: break
    else:
        raise ValueError("unregistered graph query operation")
    truncated = len(results) > int(maximum_results)
    result = {"operation": operation, "graph_id": graph["graph_id"], "results": results[:int(maximum_results)], "truncated": truncated}
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "binary_semantic_graph_query.schema.json")).iter_errors(result))
    if errors: raise ValueError(f"graph query schema failure: {errors[0].message}")
    return result


def run_unresolved_inference_e2e(full_decode_run_path: str | Path, *, output_root: str | Path | None = None, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_unresolved_bundle(policy_path, registry_path)
    upstream_path = Path(full_decode_run_path).resolve()
    upstream = _import_upstream(upstream_path)
    identities = {role: _identity(upstream[f"{role}_path"]) for role in ("source", "parent", "candidate")}
    basis = {"upstream": upstream["run"]["run_id"], "identities": {key: value["sha256"] for key, value in identities.items()}, "policy": bundle["policy_digest"], "registry": bundle["registry_digest"], "implementation": bundle["implementation_digest"]}
    run_id = _cid("unresolved-inference-run", basis)
    base = Path(output_root).resolve() if output_root else (_root() / str(bundle["policy"]["artifact_root"])).resolve()
    root = base / run_id
    run_path = root / "run.json"
    if run_path.is_file() and verify_unresolved_inference_run(run_path).get("ok"):
        return _read(run_path)
    root.mkdir(parents=True, exist_ok=True)
    events = root / "logs" / "events.jsonl"
    if events.exists(): events.unlink()
    log = EventLog(events, run_id); log.emit("run_started", {"upstream_run_id": upstream["run"]["run_id"]}, "turn-0000")
    spans = upstream["spans"]
    clusters = cluster_spans(spans, bundle=bundle)
    contexts = acquire_context(spans, upstream["source"], upstream["parent"], upstream["candidate"], upstream["coverage"], bundle=bundle)
    boundaries = [item for spec in bundle["registry"]["detectors"]["boundaries"] for item in _hook(spec)(spans, upstream["coverage"], bundle=bundle)]
    representations = [item for spec in bundle["registry"]["detectors"]["representations"] for item in _hook(spec)(spans, upstream["candidate"], bundle=bundle)]
    dependency_results = [_hook(spec)(representations, spans, upstream["coverage"], bundle=bundle) for spec in bundle["registry"]["detectors"]["dependencies"]]
    dependencies = {"schema_version": 1, "nodes": dependency_results[0]["nodes"] if dependency_results else [], "edges": [edge for result in dependency_results for edge in result["edges"]]}
    proofs = _hook(bundle["registry"]["ownership_compiler"])(spans, dependencies, bundle=bundle)
    graph = _hook(bundle["registry"]["graph_compiler"])(upstream, spans, clusters, boundaries, representations, dependencies, proofs, bundle=bundle)
    coverage_after = _coverage_after(upstream["coverage"], spans, proofs)
    candidate = upstream["candidate"]
    before = identities
    after = {role: _identity(upstream[f"{role}_path"]) for role in ("source", "parent", "candidate")}
    gates = _hook(bundle["registry"]["gate_runner"])(before, after, upstream["candidate"], candidate, coverage_after, graph, proofs, bundle=bundle)
    unresolved_bytes = int(coverage_after["summary"].get("unresolved", 0))
    verified_ownership_bytes = sum(int(span["length"]) for span in spans if any(proof["span_id"] == span["span_id"] and proof["state"] == "accepted" for proof in proofs))
    candidate_id = _cid("unresolved-candidate", {"upstream": upstream["run"]["selected_candidate_id"], "proofs": [item["proof_id"] for item in proofs if item["state"] == "accepted"], "graph": graph["graph_id"]})
    candidate_root = root / "candidates" / candidate_id
    _write_bytes(candidate_root / "candidate.bin", candidate)
    _write(candidate_root / "inverse.json", [])
    manifest = {"candidate_id": candidate_id, "artifact_path": str(candidate_root / "candidate.bin"), "changed_bytes": 0, "verified_ownership_bytes": verified_ownership_bytes, "unresolved_bytes": unresolved_bytes, "gate_statuses": gates["gates"], "promotion_eligible": False, "verified_decryption": False}
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "unresolved_candidate.schema.json")).iter_errors(manifest))
    if errors: raise ValueError(f"unresolved candidate schema failure: {errors[0].message}")
    _write(candidate_root / "manifest.json", manifest)
    _write(root / "baseline" / "unresolved.json", spans); _write(root / "topology" / "clusters.json", clusters); _write(root / "topology" / "contexts.json", contexts)
    _write(root / "inference" / "boundaries.json", boundaries); _write(root / "inference" / "representations.json", representations); _write(root / "inference" / "dependency_graph.json", dependencies); _write(root / "inference" / "ownership_proofs.json", proofs)
    _write(root / "graph" / "binary_semantic_graph.json", graph); _write(root / "graph" / "binary_semantic_graph.index.json", graph["indexes"]); _write(root / "graph" / "revision_diff.json", {"schema_version": 1, "parent_graph_id": None, "graph_id": graph["graph_id"], "nodes_added": [item["node_id"] for item in graph["nodes"]], "edges_added": [item["edge_id"] for item in graph["edges"]], "coverage_transitions": [{"span_id": item["span_id"], "to": item["classification"], "proof_id": item["proof_id"]} for item in proofs if item["state"] == "accepted"]})
    _write(root / "coverage" / "after.json", coverage_after); _write(candidate_root / "gates.json", gates)
    frontier = [manifest] if gates["passed"] else []
    _write(root / "final" / "pareto_frontier.json", frontier)
    accepted = [item for item in proofs if item["state"] == "accepted"]
    status = "completed" if gates["passed"] and unresolved_bytes == 0 else ("partial_unresolved" if gates["passed"] and accepted else ("evidence_exhausted" if gates["passed"] else "failed_validation"))
    decision = {"schema_version": 1, "status": status, "selected_candidate_id": candidate_id if frontier else None, "unresolved_bytes": unresolved_bytes, "verified_ownership_bytes": verified_ownership_bytes, "graph_id": graph["graph_id"], "promotion_eligible": False, "verified_decryption": False}
    _write(root / "final" / "decision.json", decision)
    handoff = {"schema_version": 1, "run_id": run_id, "graph_id": graph["graph_id"], "verified_rule_candidates": [item for item in dependencies["edges"] if item["state"] == "verified"], "ownership_proof_ids": [item["proof_id"] for item in accepted], "promotion_allowed": False}
    _write(root / "handoff" / "parser_learning.json", handoff); _write(root / "handoff" / "converter_projection.json", {"schema_version": 1, "graph_id": graph["graph_id"], "nodes": [item for item in graph["nodes"] if item["truth_state"] == "verified"], "edges": [item for item in graph["edges"] if item["truth_state"] == "verified"]})
    report_lines = ["UNRESOLVED OWNERSHIP REPORT", f"run_id={run_id}", f"status={status}", f"graph_id={graph['graph_id']}", f"unresolved_bytes={unresolved_bytes}", f"verified_ownership_bytes={verified_ownership_bytes}", f"span_count={len(spans)}", f"cluster_count={len(clusters)}"]
    report = "\n".join(report_lines) + "\n"; report.encode("ascii", errors="strict")
    (root / "exports").mkdir(parents=True, exist_ok=True); (root / "exports" / "semantic_report.ascii").write_text(report, encoding="ascii", newline="\n")
    _write(root / "checkpoints" / "latest.json", {"schema_version": 1, "run_id": run_id, "status": status, "completed_stage": "semantic_graph_and_gates", "decision_digest": _digest(decision)})
    log.emit("run_completed", {"status": status, "unresolved_bytes": unresolved_bytes, "verified_ownership_bytes": verified_ownership_bytes, "graph_id": graph["graph_id"]}, "turn-0012")
    artifacts = {"unresolved_baseline": str(root / "baseline" / "unresolved.json"), "clusters": str(root / "topology" / "clusters.json"), "contexts": str(root / "topology" / "contexts.json"), "boundaries": str(root / "inference" / "boundaries.json"), "representations": str(root / "inference" / "representations.json"), "dependency_graph": str(root / "inference" / "dependency_graph.json"), "ownership_proofs": str(root / "inference" / "ownership_proofs.json"), "semantic_graph": str(root / "graph" / "binary_semantic_graph.json"), "semantic_graph_index": str(root / "graph" / "binary_semantic_graph.index.json"), "graph_diff": str(root / "graph" / "revision_diff.json"), "candidate": str(candidate_root / "candidate.bin"), "candidate_manifest": str(candidate_root / "manifest.json"), "inverse": str(candidate_root / "inverse.json"), "coverage": str(root / "coverage" / "after.json"), "gates": str(candidate_root / "gates.json"), "frontier": str(root / "final" / "pareto_frontier.json"), "decision": str(root / "final" / "decision.json"), "parser_handoff": str(root / "handoff" / "parser_learning.json"), "converter_projection": str(root / "handoff" / "converter_projection.json"), "semantic_report": str(root / "exports" / "semantic_report.ascii"), "checkpoint": str(root / "checkpoints" / "latest.json"), "events": str(events)}
    run = {"schema_version": 1, "run_id": run_id, "status": status, "upstream_run_id": upstream["run"]["run_id"], "source": identities["source"], "parent": identities["parent"], "candidate": identities["candidate"], "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "implementation_digest": bundle["implementation_digest"], "run_root": str(root), "artifacts": artifacts}
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "unresolved_inference_run.schema.json")).iter_errors(run))
    if errors: raise ValueError(f"unresolved run schema failure: {errors[0].message}")
    _write(run_path, run)
    return run


def verify_unresolved_inference_run(run_path: str | Path) -> Dict[str, Any]:
    try:
        run = _read(Path(run_path).resolve()); root = Path(run["run_root"]).resolve()
        schema_errors = list(Draft202012Validator(_read(_root() / "schemas" / "unresolved_inference_run.schema.json")).iter_errors(run))
        missing, unsafe = [], []
        for name, raw in run["artifacts"].items():
            path = Path(raw).resolve()
            if root not in path.parents: unsafe.append(name)
            elif not path.is_file(): missing.append(name)
        sequence, previous, chain_ok = 0, "", True
        if not missing and not unsafe:
            for line in Path(run["artifacts"]["events"]).read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous: chain_ok = False
                previous = hashlib.sha256(_canonical(event)).hexdigest(); sequence += 1
        identities_ok = all(_identity(Path(run[role]["path"]))["sha256"] == run[role]["sha256"] for role in ("source", "parent", "candidate"))
        graph_ok = False
        if not missing and not unsafe:
            graph = _read(Path(run["artifacts"]["semantic_graph"])); graph_ok = bool(graph["validation"]["valid"]) and not list(Draft202012Validator(_read(_root() / "schemas" / "binary_semantic_graph.schema.json")).iter_errors(graph))
        return {"ok": not schema_errors and not missing and not unsafe and chain_ok and identities_ok and graph_ok, "run_id": run.get("run_id"), "schema_errors": [item.message for item in schema_errors], "missing_artifacts": missing, "unsafe_artifacts": unsafe, "event_chain_ok": chain_ok, "identities_ok": identities_ok, "graph_ok": graph_ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_unresolved_inference_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve()); verification = verify_unresolved_inference_run(run_path)
    coverage = _read(Path(run["artifacts"]["coverage"])); graph = _read(Path(run["artifacts"]["semantic_graph"])); decision = _read(Path(run["artifacts"]["decision"])); proofs = _read(Path(run["artifacts"]["ownership_proofs"])); clusters = _read(Path(run["artifacts"]["clusters"])); manifest = _read(Path(run["artifacts"]["candidate_manifest"])); gates = _read(Path(run["artifacts"]["gates"]))
    ranges = [{"offset": item["offset"], "length": item["length"], "class": item["class"], "source_id": item["segment_id"], "proof_refs": item.get("proof_refs", []), "theme_token": f"binary_waterfall.{item['class']}"} for item in coverage["segments"]]
    return {"operation": "unresolved_inference_inspect", "run_id": run["run_id"], "verified": verification["ok"], "status": run["status"], "decision": decision, "candidate": manifest, "coverage": coverage, "gates": gates, "clusters": clusters, "ownership_proofs": proofs, "graph_summary": {"graph_id": graph["graph_id"], "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]), "validation": graph["validation"]}, "waterfall_overlay": {"schema_version": 1, "ranges": ranges}, "run_root": run["run_root"], "artifacts": run["artifacts"]}


def resume_unresolved_inference_run(run_path: str | Path) -> Dict[str, Any]:
    path = Path(run_path).resolve(); path = path / "run.json" if path.is_dir() else path
    verification = verify_unresolved_inference_run(path)
    if not verification["ok"]: raise ValueError("cannot resume invalid unresolved-inference run")
    run = _read(path)
    return {"operation": "unresolved_inference_resume", "run_id": run["run_id"], "status": run["status"], "executed_new_work": False, "reason": "terminal_verified_checkpoint"}


def build_unresolved_model_packet(run_path: str | Path) -> Dict[str, Any]:
    inspected = inspect_unresolved_inference_run(run_path)
    if not inspected["verified"]: raise ValueError("unresolved-inference run failed integrity verification")
    hypotheses = [{"target_id": item["proof_id"], "span_id": item["span_id"], "classification": item["classification"], "state": item["state"], "gate_statuses": item["gate_statuses"]} for item in inspected["ownership_proofs"]]
    clusters = [{"cluster_id": item["cluster_id"], "span_count": len(item["span_ids"]), "length": item["length"]} for item in inspected["clusters"]]
    return {"schema_version": 1, "operation": "unresolved_inference_model_packet", "run_id": inspected["run_id"], "run_verified": True, "hypotheses": hypotheses, "clusters": clusters, "allowed_actions": ["rank_existing_hypothesis", "request_registered_measurement", "prioritize_existing_cluster"], "model_role": "advisory_only", "mechanical_authority": True}


def validate_unresolved_model_action(action: Mapping[str, Any], packet: Mapping[str, Any], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_unresolved_bundle(policy_path, registry_path)
    forbidden = set(bundle["policy"]["model_boundary"]["forbidden_fields"])
    if forbidden.intersection(action): raise ValueError("model action contains forbidden authority fields")
    if action.get("action") not in set(bundle["policy"]["model_boundary"]["allowed_actions"]): raise ValueError("model action is not registered")
    if set(action) != {"action", "target_id", "reason"}: raise ValueError("model action fields do not match contract")
    known = {item["target_id"] for item in packet["hypotheses"]} | {item["cluster_id"] for item in packet["clusters"]}
    if action["target_id"] not in known: raise ValueError("model selected unknown evidence target")
    if not isinstance(action["reason"], str) or not action["reason"].strip(): raise ValueError("model reason is missing")
    return dict(action)
