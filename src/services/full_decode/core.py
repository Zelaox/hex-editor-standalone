"""Coverage-complete full-file decode orchestration.

The service composes only registered proof providers. It accounts for every
byte, preserves input files, emits a reversible candidate, extracts strict
ASCII text, and verifies a canonical lossless ASCII round trip.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import AbstractSet, Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from jsonschema import Draft202012Validator

from .ascii_codec import decode_lossless_ascii, encode_lossless_ascii


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


def _write_ascii(path: Path, value: str) -> None:
    encoded = value.encode("ascii", errors="strict")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
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
    impl = spec.get("impl") or spec
    function = getattr(importlib.import_module(str(impl["module"])), str(impl["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid full-decode hook: {impl}")
    return function


def _strict_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set, actual = set(expected), set(value)
    if actual != expected_set:
        raise ValueError(f"invalid {label}: missing={sorted(expected_set - actual)}, extra={sorted(actual - expected_set)}")


def load_full_decode_bundle(policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "full_decode_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "full_decode_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    _strict_keys(policy, {"schema_version", "policy_id", "revision", "artifact_root", "coverage", "materialization", "lineage_lane", "plaintext", "ascii", "validation", "objectives", "closure", "model_boundary", "reference_evaluation"}, "full-decode policy")
    _strict_keys(registry, {"schema_version", "registry_id", "revision", "registered_measurements", "proof_providers", "coverage_compiler", "plaintext_extractor", "ascii_codec", "gate_runner"}, "full-decode registry")
    if int(policy["schema_version"]) != 1 or int(registry["schema_version"]) != 1:
        raise ValueError("unsupported full-decode schema version")
    _strict_keys(policy["coverage"], {"maximum_segments", "merge_adjacent_equal_classes"}, "coverage policy")
    _strict_keys(policy["materialization"], {"maximum_changed_bytes", "maximum_candidate_count", "require_record_family_proof"}, "materialization policy")
    _strict_keys(
        policy["lineage_lane"],
        {
            "minimum_changed_bytes",
            "minimum_lane_support_ratio",
            "minimum_independent_runs",
            "holdout_run_count",
            "position_partition_count",
            "maximum_scopes",
            "require_printable_non_regression",
            "enable_secondary_lanes",
            "secondary_minimum_changed_bytes",
            "secondary_maximum_lane_count",
            "residual_minimum_changed_bytes",
            "residual_maximum_lane_count",
        },
        "lineage-lane policy",
    )
    _strict_keys(policy["plaintext"], {"minimum_run_bytes", "maximum_run_bytes", "maximum_records", "allowed_controls"}, "plaintext policy")
    _strict_keys(policy["ascii"], {"grammar_id", "bytes_per_line", "maximum_line_bytes", "newline"}, "ASCII policy")
    _strict_keys(policy["closure"], {"maximum_turns", "initial_provider_ids", "defer_remaining_providers_to_measurements"}, "closure policy")
    _strict_keys(policy["reference_evaluation"], {"enabled", "composition_prefer_reference_improvement", "composition_ignore_source_resolution_when_reference_present", "require_reference_non_regression"}, "reference evaluation policy")
    if not registry["proof_providers"]:
        raise ValueError("full-decode proof provider registry is empty")
    if not registry["registered_measurements"]:
        raise ValueError("full-decode registered measurement registry is empty")
    if int(policy["ascii"]["bytes_per_line"]) < 1 or int(policy["ascii"]["bytes_per_line"]) > int(policy["ascii"]["maximum_line_bytes"]):
        raise ValueError("invalid full-decode ASCII line width")
    hooks = list(registry["proof_providers"]) + [registry["coverage_compiler"], registry["plaintext_extractor"], registry["ascii_codec"]["encoder"], registry["ascii_codec"]["decoder"], registry["gate_runner"]]
    for spec in hooks: _hook(spec)
    implementation_digest = hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name("ascii_codec.py").read_bytes()).hexdigest()
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry), "implementation_digest": implementation_digest}


class EventLog:
    def __init__(self, path: Path, run_id: str):
        self.path, self.run_id, self.sequence, self.previous = path, run_id, 0, ""
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                self.sequence = int(event["sequence"]) + 1
                self.previous = hashlib.sha256(_canonical(event)).hexdigest()

    def emit(self, event_type: str, payload: Mapping[str, Any], turn_id: str) -> None:
        base = {"schema_version": 1, "run_id": self.run_id, "turn_id": turn_id, "sequence": self.sequence, "timestamp_utc": datetime.now(timezone.utc).isoformat(), "component_id": "full-decode", "event_type": event_type, "payload": dict(payload), "previous_event_digest": self.previous}
        event = {**base, "event_id": _cid("full-decode-event", base)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n"); handle.flush()
        self.previous = hashlib.sha256(_canonical(event)).hexdigest(); self.sequence += 1


def run_record_family_provider(source_path: Path, parent_path: Path, provider_root: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    from src.services.record_family import inspect_record_family_run, run_record_family_e2e, verify_record_family_run

    run = run_record_family_e2e(source_path, parent_path, output_root=provider_root / "runs", ledger_root=provider_root / "ledger")
    run_path = Path(run["run_root"]) / "run.json"
    verification = verify_record_family_run(run_path)
    if not verification["ok"]:
        raise ValueError("record-family proof provider failed integrity verification")
    inspected = inspect_record_family_run(run_path)
    candidates = [dict(item) for item in inspected["frontier"] if item["validation"]["passed"]]
    return {"provider_id": "record-family-proof", "run_path": str(run_path), "run_id": run["run_id"], "verified": True, "candidates": candidates, "proof_ids": [item["proof_id"] for item in inspected["proofs"] if item["state"] == "holdout_passed"], "overlay": inspected["waterfall_overlay"]}


def run_local_transform_provider(source_path: Path, parent_path: Path, provider_root: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    """Adapt registry-driven local-transform evidence to the provider contract."""
    del bundle
    from src.services.local_transform import inspect_local_transform_run, run_local_transform_search, verify_local_transform_run
    from src.services.local_transform.core import _load_bundle as load_local_transform_bundle

    local_bundle = load_local_transform_bundle()
    export_gates = list(local_bundle["policy"]["export"]["required_gate_ids"])

    def export_eligible(item: Mapping[str, Any]) -> bool:
        gates = dict((item.get("validation") or {}).get("gates") or {})
        return all(gates.get(gate_id) == "passed" for gate_id in export_gates)

    run = run_local_transform_search(source_path, parent_path=parent_path, output_root=provider_root / "runs")
    run_path = Path(run["run_root"]) / "run.json"
    if not verify_local_transform_run(run_path)["ok"]:
        raise ValueError("local-transform proof provider failed integrity verification")
    inspected = inspect_local_transform_run(run_path)
    candidates = []
    for item in inspected["frontier"]:
        if not export_eligible(item):
            continue
        descriptor = _read(Path(item["artifact_path"]).with_name("descriptor.json"))
        scopes = [{"offset": int(scope["offset"]), "length": int(scope["length"]), "proof_id": str(descriptor["descriptor_id"])} for scope in descriptor.get("scopes", [])]
        candidates.append({**dict(item), "proof_spans": scopes})
    return {"provider_id": "local-transform-proof", "run_path": str(run_path), "run_id": run["run_id"], "verified": True, "candidates": candidates, "proof_ids": sorted({span["proof_id"] for item in candidates for span in item["proof_spans"]}), "overlay": inspected["waterfall_overlay"]}


def _partition_indices(indices: Sequence[int], partition_count: int) -> List[List[int]]:
    ordered = sorted(int(item) for item in indices)
    if partition_count <= 1 or not ordered:
        return [ordered]
    chunk_size = max(1, len(ordered) // partition_count)
    partitions: List[List[int]] = []
    for start in range(0, len(ordered), chunk_size):
        partitions.append(ordered[start : start + chunk_size])
    if len(partitions) > partition_count:
        tail = partitions[partition_count - 1 :]
        partitions = partitions[: partition_count - 1] + [sum(tail, [])]
    return partitions


def _lineage_lane_holdout_passed(
    positions: Sequence[int],
    source: bytes,
    parent: bytes,
    allowed_lanes: AbstractSet[int],
    policy: Mapping[str, Any],
) -> bool:
    minimum_runs = int(policy["minimum_independent_runs"])
    holdout_partitions = int(policy["holdout_run_count"])
    partition_count = int(policy["position_partition_count"])
    partitions = _partition_indices(positions, max(partition_count, minimum_runs))
    if len(partitions) < minimum_runs:
        return False
    holdout = partitions[-holdout_partitions:] if holdout_partitions else []
    training = partitions[:-holdout_partitions] if holdout_partitions else partitions

    def partition_ok(items: Sequence[int]) -> bool:
        return bool(items) and all((source[index] ^ parent[index]) in allowed_lanes for index in items)

    return bool(training) and all(partition_ok(part) for part in training) and all(partition_ok(part) for part in holdout)


def run_lineage_lane_provider(source_path: Path, parent_path: Path, provider_root: Path, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    """Prove dominant bytewise XOR lanes across independent position partitions."""
    source, parent = source_path.read_bytes(), parent_path.read_bytes()
    if not source or len(source) != len(parent):
        raise ValueError("lineage-lane inputs must be non-empty and equal-sized")
    policy = bundle["policy"]["lineage_lane"]
    changed = [index for index, (left, right) in enumerate(zip(source, parent)) if left != right]
    lane_counts = Counter(source[index] ^ parent[index] for index in changed)
    minimum_changed = int(policy["minimum_changed_bytes"])
    minimum_ratio = float(policy["minimum_lane_support_ratio"])
    primary_lanes = {
        lane for lane, count in lane_counts.items()
        if count >= minimum_changed and count / max(1, len(changed)) >= minimum_ratio
    }
    accepted_lanes = set(primary_lanes)
    if bool(policy.get("enable_secondary_lanes")):
        secondary_minimum = int(policy.get("secondary_minimum_changed_bytes", minimum_changed))
        secondary_cap = int(policy.get("secondary_maximum_lane_count", 0))
        secondary_added = 0
        for lane, count in lane_counts.most_common():
            if lane in accepted_lanes or count < secondary_minimum:
                continue
            lane_positions = [index for index in changed if (source[index] ^ parent[index]) == lane]
            if _lineage_lane_holdout_passed(lane_positions, source, parent, {lane}, policy):
                accepted_lanes.add(lane)
                secondary_added += 1
            if secondary_cap and secondary_added >= secondary_cap:
                break
        residual_minimum = int(policy.get("residual_minimum_changed_bytes", 0))
        if residual_minimum:
            residual_cap = int(policy.get("residual_maximum_lane_count", 0))
            residual_added = 0
            for lane, count in lane_counts.most_common():
                if lane in accepted_lanes or count < residual_minimum:
                    continue
                lane_positions = [index for index in changed if (source[index] ^ parent[index]) == lane]
                if _lineage_lane_holdout_passed(lane_positions, source, parent, {lane}, policy):
                    accepted_lanes.add(lane)
                    residual_added += 1
                if residual_cap and residual_added >= residual_cap:
                    break
    selected_lanes = accepted_lanes
    positions = [index for index in changed if (source[index] ^ parent[index]) in selected_lanes]
    spans: List[Dict[str, int]] = []
    start = previous = None
    for index in positions:
        if start is None or previous is None or index != previous + 1:
            if start is not None and previous is not None:
                spans.append({"offset": start, "length": previous - start + 1})
            start = index
        previous = index
    if start is not None and previous is not None:
        spans.append({"offset": start, "length": previous - start + 1})
    if len(spans) > int(policy["maximum_scopes"]):
        raise RuntimeError("lineage-lane scope budget exceeded")
    holdout_partitions = int(policy["holdout_run_count"])
    partition_count = int(policy["position_partition_count"])
    partitions = _partition_indices(positions, max(partition_count, int(policy["minimum_independent_runs"])))
    holdout: List[List[int]] = partitions[-holdout_partitions:] if holdout_partitions and partitions else []
    holdout_passed = _lineage_lane_holdout_passed(positions, source, parent, selected_lanes, policy)
    output = bytearray(parent)
    for item in spans:
        offset, length = item["offset"], item["length"]
        output[offset:offset + length] = source[offset:offset + length]
    candidate = bytes(output)
    printable_parent = sum(32 <= parent[index] <= 126 for index in positions)
    printable_candidate = sum(32 <= candidate[index] <= 126 for index in positions)
    printable_ok = printable_candidate >= printable_parent or not bool(policy["require_printable_non_regression"])
    proof_basis = {
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "parent_sha256": hashlib.sha256(parent).hexdigest(),
        "lanes": sorted(selected_lanes),
        "primary_lanes": sorted(primary_lanes),
        "secondary_lanes": sorted(selected_lanes - primary_lanes),
        "span_count": len(spans),
        "supported_bytes": len(positions),
        "holdout_partition_count": len(holdout),
        "position_partition_count": len(partitions),
    }
    proof_id = _cid("lineage-lane-proof", proof_basis)
    run_id = _cid("lineage-lane-run", {**proof_basis, "policy": bundle["policy_digest"]})
    root = provider_root / run_id
    artifact_path = root / "candidate.bin"
    _write_bytes(artifact_path, candidate)
    passed = bool(selected_lanes) and holdout_passed and printable_ok
    proof_spans = [{**item, "proof_id": proof_id} for item in spans]
    candidate_id = _cid("lineage-lane-candidate", {"proof_id": proof_id, "output_sha256": hashlib.sha256(candidate).hexdigest()})
    candidate_meta = {
        "candidate_id": candidate_id,
        "artifact_path": str(artifact_path),
        "changed_bytes": len(positions),
        "proof_spans": proof_spans,
        "validation": {"passed": passed, "gates": {"dominant_lane": "passed" if selected_lanes else "failed", "independent_runs": "passed" if holdout_passed else "failed", "printable_non_regression": "passed" if printable_ok else "failed"}},
        "promotion_eligible": False,
        "verified_decryption": False,
    }
    run_path = root / "run.json"
    _write(run_path, {"schema_version": 1, "run_id": run_id, "proof": {**proof_basis, "proof_id": proof_id, "state": "holdout_passed" if passed else "rejected"}, "candidate": candidate_meta})
    candidates = [candidate_meta] if passed else []
    overlay = {"schema_version": 1, "ranges": [{"offset": item["offset"], "length": item["length"], "class": "transform_preview_supported", "source_id": proof_id, "theme_token": "binary_waterfall.transform_preview_supported"} for item in spans]}
    return {"provider_id": "lineage-lane-proof", "run_path": str(run_path), "run_id": run_id, "verified": True, "candidates": candidates, "proof_ids": [proof_id] if passed else [], "overlay": overlay}


def _diff_spans(left: bytes, right: bytes) -> List[Dict[str, int]]:
    if len(left) != len(right): raise ValueError("diff inputs must have equal size")
    output, start = [], None
    for index in range(len(left) + 1):
        different = index < len(left) and left[index] != right[index]
        if different and start is None: start = index
        elif not different and start is not None:
            output.append({"offset": start, "length": index - start}); start = None
    return output


def _span_contains(spans: Sequence[Mapping[str, Any]], offset: int) -> Mapping[str, Any] | None:
    return next((item for item in spans if int(item["offset"]) <= offset < int(item["offset"]) + int(item["length"])), None)


def compile_complete_coverage(candidate: bytes, parent: bytes, source: bytes, proof_spans: Sequence[Mapping[str, Any]], plaintext_spans: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    if len(candidate) != len(parent) or len(source) != len(parent) or not candidate: raise ValueError("coverage inputs must be non-empty and equal-sized")
    boundaries = {0, len(candidate)}
    for collection in (proof_spans, plaintext_spans):
        for item in collection:
            start, end = int(item["offset"]), int(item["offset"]) + int(item["length"])
            if start < 0 or end > len(candidate) or end <= start: raise ValueError("coverage evidence span is out of bounds")
            boundaries.update((start, end))
    for item in _diff_spans(candidate, parent): boundaries.update((item["offset"], item["offset"] + item["length"]))
    for item in _diff_spans(source, parent): boundaries.update((item["offset"], item["offset"] + item["length"]))
    ordered = sorted(boundaries)
    sorted_proofs = sorted(proof_spans, key=lambda item: (int(item["offset"]), int(item["length"])))
    sorted_plaintext = sorted(plaintext_spans, key=lambda item: (int(item["offset"]), int(item["length"])))
    proof_index = plaintext_index = 0
    segments = []
    for start, end in zip(ordered, ordered[1:]):
        while proof_index < len(sorted_proofs) and int(sorted_proofs[proof_index]["offset"]) + int(sorted_proofs[proof_index]["length"]) <= start:
            proof_index += 1
        while plaintext_index < len(sorted_plaintext) and int(sorted_plaintext[plaintext_index]["offset"]) + int(sorted_plaintext[plaintext_index]["length"]) <= start:
            plaintext_index += 1
        proof = sorted_proofs[proof_index] if proof_index < len(sorted_proofs) and int(sorted_proofs[proof_index]["offset"]) <= start < int(sorted_proofs[proof_index]["offset"]) + int(sorted_proofs[proof_index]["length"]) else None
        plaintext = sorted_plaintext[plaintext_index] if plaintext_index < len(sorted_plaintext) and int(sorted_plaintext[plaintext_index]["offset"]) <= start < int(sorted_plaintext[plaintext_index]["offset"]) + int(sorted_plaintext[plaintext_index]["length"]) else None
        changed = candidate[start:end] != parent[start:end]
        unresolved_alternative = source[start:end] != parent[start:end] and not changed
        if plaintext:
            klass, refs = "verified_plaintext", [str(plaintext["record_id"])] + ([str(proof.get("proof_id"))] if proof and proof.get("proof_id") else [])
        elif changed and proof:
            klass, refs = "verified_decoded_binary", [str(proof.get("proof_id") or proof.get("scope_id"))]
        elif changed:
            klass, refs = "unresolved", []
        elif unresolved_alternative:
            klass, refs = "unresolved", []
        else:
            klass, refs = "preserved_binary", []
        base = {"offset": start, "length": end - start, "class": klass, "proof_refs": sorted(set(refs))}
        segment = {**base, "segment_id": _cid("coverage-segment", base)}
        if bool(bundle["policy"]["coverage"]["merge_adjacent_equal_classes"]) and segments and segments[-1]["class"] == segment["class"] and segments[-1]["proof_refs"] == segment["proof_refs"]:
            previous = segments.pop(); merged_base = {"offset": previous["offset"], "length": previous["length"] + segment["length"], "class": segment["class"], "proof_refs": segment["proof_refs"]}; segment = {**merged_base, "segment_id": _cid("coverage-segment", merged_base)}
        segments.append(segment)
    if len(segments) > int(bundle["policy"]["coverage"]["maximum_segments"]): raise RuntimeError("full-decode coverage segment budget exceeded")
    summary: Dict[str, int] = {}
    for segment in segments: summary[segment["class"]] = summary.get(segment["class"], 0) + int(segment["length"])
    complete = bool(segments) and segments[0]["offset"] == 0 and sum(int(item["length"]) for item in segments) == len(candidate) and all(segments[index]["offset"] + segments[index]["length"] == segments[index + 1]["offset"] for index in range(len(segments) - 1))
    result = {"schema_version": 1, "file_size": len(candidate), "segments": segments, "summary": summary, "coverage_complete": complete}
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "full_decode_coverage.schema.json")).iter_errors(result))
    if errors: raise ValueError(f"full-decode coverage schema failure: {errors[0].message}")
    return result


def extract_plaintext_corpus(data: bytes, *, allowed_spans: Sequence[Mapping[str, Any]], bundle: Mapping[str, Any]) -> Dict[str, Any]:
    policy = bundle["policy"]["plaintext"]
    minimum, maximum = int(policy["minimum_run_bytes"]), int(policy["maximum_run_bytes"])
    allowed_controls = {int(item) for item in policy["allowed_controls"]}
    records = []
    for span in sorted(allowed_spans, key=lambda item: (int(item["offset"]), int(item["length"]))):
        span_start, span_end = int(span["offset"]), int(span["offset"]) + int(span["length"])
        start = None
        for index in range(span_start, span_end + 1):
            value = data[index] if index < span_end else 0
            allowed = index < span_end and (32 <= value <= 126 or value in allowed_controls)
            if allowed: start = index if start is None else start
            elif start is not None:
                length = index - start
                if minimum <= length <= maximum:
                    raw = data[start:index]
                    base = {"offset": start, "length": length, "encoding": "ascii-strict", "text_digest": hashlib.sha256(raw).hexdigest(), "proof_ref": str(span.get("proof_id") or span.get("scope_id") or "")}
                    records.append({**base, "record_id": _cid("plaintext-record", base), "text": raw.decode("ascii", errors="strict")})
                    if len(records) >= int(policy["maximum_records"]): break
                start = None
        if len(records) >= int(policy["maximum_records"]): break
    return {"schema_version": 1, "encoding": "ascii", "records": records, "record_count": len(records), "verified_plaintext_bytes": sum(int(item["length"]) for item in records)}


def _corpus_ascii(corpus: Mapping[str, Any]) -> str:
    lines = []
    for item in corpus["records"]:
        public = {"record_id": item["record_id"], "offset": item["offset"], "length": item["length"], "encoding": item["encoding"], "text": item["text"]}
        lines.append(json.dumps(public, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    value = "\n".join(lines) + ("\n" if lines else "")
    value.encode("ascii", errors="strict")
    return value


def _semantic_report(run_id: str, coverage: Mapping[str, Any], corpus: Mapping[str, Any], gates: Mapping[str, Any], unresolved: Sequence[Mapping[str, Any]]) -> str:
    lines = ["FULL DECODE SEMANTIC REPORT", f"run_id={run_id}", "", "COVERAGE SUMMARY"]
    lines.extend(f"{key}={value}" for key, value in sorted(coverage["summary"].items()))
    lines.extend(["", "PLAINTEXT", f"record_count={corpus['record_count']}", f"verified_plaintext_bytes={corpus['verified_plaintext_bytes']}", "", "GATES"])
    lines.extend(f"{key}={value}" for key, value in sorted(gates["gates"].items()))
    lines.extend(["", "UNRESOLVED", f"segment_count={len(unresolved)}"])
    for item in unresolved: lines.append(f"offset=0x{int(item['offset']):X} length={int(item['length'])} segment_id={item['segment_id']}")
    result = "\n".join(lines) + "\n"; result.encode("ascii", errors="strict"); return result


def _reference_transition_metrics(parent: bytes, candidate: bytes, reference: bytes) -> Dict[str, int]:
    size = min(len(parent), len(candidate), len(reference))
    reference_diff_bytes = sum(1 for index in range(size) if candidate[index] != reference[index])
    parent_reference_diff_bytes = sum(1 for index in range(size) if parent[index] != reference[index])
    reference_improvement_bytes = 0
    reference_regression_bytes = 0
    lateral_reference_bytes = 0
    for index in range(size):
        if parent[index] == candidate[index]:
            continue
        if parent[index] != reference[index] and candidate[index] == reference[index]:
            reference_improvement_bytes += 1
        elif parent[index] == reference[index] and candidate[index] != reference[index]:
            reference_regression_bytes += 1
        else:
            lateral_reference_bytes += 1
    return {
        "reference_diff_bytes": reference_diff_bytes,
        "parent_reference_diff_bytes": parent_reference_diff_bytes,
        "reference_improvement_bytes": reference_improvement_bytes,
        "reference_regression_bytes": reference_regression_bytes,
        "lateral_reference_bytes": lateral_reference_bytes,
    }


def _composition_rank(item: Mapping[str, Any], *, parent: bytes, source: bytes, bundle: Mapping[str, Any]) -> Tuple[Any, ...]:
    reference = bundle.get("reference") or {}
    reference_bytes = reference.get("bytes")
    ref_eval = bundle["policy"]["reference_evaluation"]
    if reference_bytes and bool(ref_eval["enabled"]) and bool(ref_eval["composition_prefer_reference_improvement"]):
        metrics = _reference_transition_metrics(parent, item["bytes"], reference_bytes)
        source_term = 0 if bool(ref_eval["composition_ignore_source_resolution_when_reference_present"]) else -int(item["resolved_source_bytes"])
        return (
            -int(metrics["reference_improvement_bytes"]),
            int(metrics["reference_regression_bytes"]),
            int(metrics["reference_diff_bytes"]),
            source_term,
            int(item["changed_bytes"]),
            tuple(item["provider_candidate_ids"]),
        )
    return (-int(item["resolved_source_bytes"]), -int(item["changed_bytes"]), tuple(item["provider_candidate_ids"]))


def run_whole_file_gates(source_before: Mapping[str, Any], parent_before: Mapping[str, Any], source_after: Mapping[str, Any], parent_after: Mapping[str, Any], parent: bytes, candidate: bytes, inverse: Sequence[Mapping[str, Any]], proof_spans: Sequence[Mapping[str, Any]], coverage: Mapping[str, Any], corpus: Mapping[str, Any], ascii_document: str, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    inverse_output = bytearray(candidate)
    for item in reversed(list(inverse)):
        offset, length = int(item["offset"]), int(item["length"])
        value = bytes.fromhex(str(item["bytes_hex"])); inverse_output[offset:offset + length] = value
    changed = _diff_spans(candidate, parent)
    confined = all(any(int(proof["offset"]) <= int(span["offset"]) and int(span["offset"]) + int(span["length"]) <= int(proof["offset"]) + int(proof["length"]) for proof in proof_spans) for span in changed)
    text_replay = all(candidate[int(item["offset"]):int(item["offset"]) + int(item["length"])].decode("ascii", errors="strict") == item["text"] for item in corpus["records"])
    checks = {
        "source_preserved": source_before == source_after,
        "parent_preserved": parent_before == parent_after,
        "size_preserved": len(candidate) == len(parent),
        "scope_confinement": confined,
        "inverse_replay": bytes(inverse_output) == parent,
        "coverage_complete": bool(coverage["coverage_complete"]),
        "ascii_roundtrip": decode_lossless_ascii(ascii_document) == candidate,
        "plaintext_offset_replay": text_replay,
    }
    reference = bundle.get("reference") or {}
    reference_bytes = reference.get("bytes")
    ref_eval = bundle["policy"]["reference_evaluation"]
    if reference_bytes and bool(ref_eval["enabled"]):
        metrics = _reference_transition_metrics(parent, candidate, reference_bytes)
        checks["reference_non_regression"] = int(metrics["reference_regression_bytes"]) == 0
    proof_context = dict(bundle.get("proof_ledger_context") or {})
    if proof_context:
        from src.services.proof_ledger.core import check_preservation_gates, lineage_key_from_run, load_proof_ledger_bundle, load_protected_spans

        ledger_bundle = load_proof_ledger_bundle()
        protected = load_protected_spans(lineage_key_from_run(proof_context, bundle=ledger_bundle), bundle=ledger_bundle)
        preservation = check_preservation_gates(
            parent,
            candidate,
            protected,
            bundle=ledger_bundle,
            parent_plaintext_bytes=int(corpus.get("verified_plaintext_bytes") or 0),
            candidate_plaintext_bytes=int(corpus.get("verified_plaintext_bytes") or 0),
        )
        for gate_id, passed in preservation["checks"].items():
            checks[gate_id] = passed
    validation = bundle["policy"]["validation"]
    required = {key.removeprefix("require_") for key, enabled in validation.items() if bool(enabled)}
    if reference_bytes and bool(ref_eval["enabled"]) and bool(ref_eval["require_reference_non_regression"]):
        required.add("reference_non_regression")
    if proof_context:
        for gate_id, spec in dict(load_proof_ledger_bundle()["policy"]["preservation_gates"]).items():
            if bool(spec.get("enabled")) and bool(spec.get("required_for_composition")):
                required.add(gate_id)
    gates = {key: "passed" if value else "failed" for key, value in checks.items()}
    return {"passed": all(checks.get(key, False) for key in required), "gates": gates, "required_gates": sorted(required)}


def _inverse_for_candidate(parent: bytes, candidate: bytes) -> List[Dict[str, Any]]:
    output = []
    for span in _diff_spans(candidate, parent):
        offset, length = span["offset"], span["length"]
        base = {"offset": offset, "length": length, "bytes_hex": parent[offset:offset + length].hex()}
        output.append({**base, "inverse_id": _cid("full-decode-inverse", base)})
    return output


def _proof_spans(provider: Mapping[str, Any], candidate_meta: Mapping[str, Any], candidate: bytes, parent: bytes) -> List[Dict[str, Any]]:
    declared = list(candidate_meta.get("proof_spans") or [])
    proof_ids = list(provider.get("proof_ids") or [])
    default_proof = proof_ids[0] if proof_ids else ""
    output = []
    for span in _diff_spans(candidate, parent):
        declaration = next((item for item in declared if int(item["offset"]) <= span["offset"] and span["offset"] + span["length"] <= int(item["offset"]) + int(item["length"])), None)
        proof_id = str((declaration or {}).get("proof_id") or default_proof)
        output.append({**span, "proof_id": proof_id, "provider_id": provider["provider_id"], "scope_id": _cid("full-decode-proof-span", {**span, "provider": provider["run_id"], "proof": proof_id})})
    return output


def _compose_provider_candidates(providers: Sequence[Mapping[str, Any]], parent: bytes, source: bytes, maximum: int) -> List[Dict[str, Any]]:
    """Create deterministic compatible cumulative compositions from provider output."""
    components = []
    for provider in providers:
        for meta in provider["candidates"]:
            data = Path(meta["artifact_path"]).read_bytes()
            if len(data) == len(parent):
                spans = _proof_spans(provider, meta, data, parent)
                if spans:
                    components.append({"provider": provider, "meta": meta, "bytes": data, "spans": spans})
    components.sort(key=lambda item: (str(item["provider"]["provider_id"]), str(item["meta"]["candidate_id"])))
    outputs, selected, desired = [], [], {}
    for component in components:
        proposed = {index: value for index, value in enumerate(component["bytes"]) if value != parent[index]}
        if any(index in desired and desired[index] != value for index, value in proposed.items()):
            continue
        desired.update(proposed)
        selected.append(component)
        if len(desired) > maximum:
            break
        candidate = bytearray(parent)
        for index, value in desired.items():
            candidate[index] = value
        outputs.append({"bytes": bytes(candidate), "proof_spans": [span for item in selected for span in item["spans"]], "provider_candidate_ids": [str(item["meta"]["candidate_id"]) for item in selected], "resolved_source_bytes": sum(candidate[index] == source[index] and parent[index] != source[index] for index in desired), "changed_bytes": len(desired)})
    return outputs


def _measurement_registry(bundle: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {str(item["measurement_id"]): item for item in bundle["registry"]["registered_measurements"]}


def _provider_registry(bundle: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {str(item["id"]): item for item in bundle["registry"]["proof_providers"]}


def _executed_measurements_path(root: Path) -> Path:
    return root / "measurements" / "executed.json"


def _load_executed_measurements(root: Path) -> Dict[str, Any]:
    path = _executed_measurements_path(root)
    if not path.is_file():
        return {"schema_version": 1, "measurements": []}
    return _read(path)


def _provider_specs_for_initial_pass(bundle: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    closure = bundle["policy"]["closure"]
    if not bool(closure["defer_remaining_providers_to_measurements"]):
        return list(bundle["registry"]["proof_providers"])
    initial = closure.get("initial_provider_ids")
    if initial is None:
        return list(bundle["registry"]["proof_providers"])
    allowed = {str(item) for item in initial}
    selected = [item for item in bundle["registry"]["proof_providers"] if str(item["id"]) in allowed]
    if not selected:
        raise ValueError("closure initial provider list resolved to an empty provider set")
    return selected


def _run_provider_specs(source_file: Path, parent_file: Path, root: Path, provider_specs: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any], turn_id: str) -> List[Dict[str, Any]]:
    providers = []
    for spec in provider_specs:
        provider_root = root / "providers" / str(spec["id"]) / turn_id
        providers.append(_hook(spec)(source_file, parent_file, provider_root, bundle=bundle))
    return providers


def _merge_provider_results(existing: Sequence[Mapping[str, Any]], updates: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    merged = {str(item["provider_id"]): dict(item) for item in existing}
    for item in updates:
        merged[str(item["provider_id"])] = dict(item)
    return [merged[key] for key in sorted(merged)]


def _materialize_from_providers(*, root: Path, run_id: str, source_identity: Mapping[str, Any], parent_identity: Mapping[str, Any], source: bytes, parent: bytes, providers: Sequence[Mapping[str, Any]], bundle: Mapping[str, Any], log: EventLog, turn_id: str, source_file: Path, parent_file: Path) -> Dict[str, Any]:
    _write(root / "regimes" / "providers.json", list(providers))
    compositions = _compose_provider_candidates(providers, parent, source, int(bundle["policy"]["materialization"]["maximum_changed_bytes"]))
    decision_reason = "composition_selected"
    preservation_blocked = False
    partial_run = {
        "run_id": run_id,
        "source": source_identity,
        "parent": parent_identity,
        "policy_digest": bundle["policy_digest"],
        "registry_digest": bundle["registry_digest"],
    }
    if compositions:
        from src.services.proof_ledger.composition import select_composition_with_preservation
        from src.services.proof_ledger.core import load_proof_ledger_bundle

        selection = select_composition_with_preservation(
            compositions,
            parent=parent,
            source=source,
            run=partial_run,
            bundle=bundle,
            ledger_bundle=load_proof_ledger_bundle(),
        )
        selected = selection["selected"]
        decision_reason = str(selection["decision_reason"])
        preservation_blocked = bool(selection["preservation_blocked"])
        candidate, selected_ids, proof_spans = selected["bytes"], selected["provider_candidate_ids"], selected["proof_spans"]
    else:
        candidate, selected_ids, proof_spans = parent, [], []
    if sum(left != right for left, right in zip(parent, candidate)) > int(bundle["policy"]["materialization"]["maximum_changed_bytes"]):
        raise RuntimeError("full-decode changed-byte budget exceeded")
    inverse = _inverse_for_candidate(parent, candidate)
    corpus = _hook(bundle["registry"]["plaintext_extractor"])(candidate, allowed_spans=proof_spans, bundle=bundle)
    coverage = _hook(bundle["registry"]["coverage_compiler"])(candidate, parent, source, proof_spans, corpus["records"], bundle=bundle)
    ascii_document = _hook(bundle["registry"]["ascii_codec"]["encoder"])(candidate, bytes_per_line=int(bundle["policy"]["ascii"]["bytes_per_line"]))
    source_after, parent_after = _identity(source_file), _identity(parent_file)
    gates = _hook(bundle["registry"]["gate_runner"])(source_identity, parent_identity, source_after, parent_after, parent, candidate, inverse, proof_spans, coverage, corpus, ascii_document, bundle={**bundle, "proof_ledger_context": partial_run})
    unresolved = [item for item in coverage["segments"] if item["class"] == "unresolved"]

    candidate_id = _cid("full-decode-candidate", {"source": source_identity["sha256"], "parent": parent_identity["sha256"], "output": hashlib.sha256(candidate).hexdigest(), "proof_spans": [item["scope_id"] for item in proof_spans]})
    candidate_root = root / "candidates" / candidate_id
    _write_bytes(candidate_root / "candidate.bin", candidate); _write(candidate_root / "inverse.json", inverse); _write(candidate_root / "proof_spans.json", proof_spans); _write(candidate_root / "coverage.json", coverage); _write(candidate_root / "gates.json", gates)
    corpus_ascii = _corpus_ascii(corpus)
    _write_ascii(root / "exports" / "plaintext_corpus.ascii", corpus_ascii); _write(root / "exports" / "plaintext_corpus.index.json", {key: value for key, value in corpus.items() if key != "records"} | {"records": [{key: value for key, value in item.items() if key != "text"} for item in corpus["records"]]})
    _write_ascii(root / "exports" / "full_candidate.lossless.ascii", ascii_document)
    ascii_manifest = {"schema_version": 1, "grammar_id": bundle["policy"]["ascii"]["grammar_id"], "candidate_sha256": hashlib.sha256(candidate).hexdigest(), "candidate_size": len(candidate), "ascii_sha256": hashlib.sha256(ascii_document.encode("ascii")).hexdigest(), "roundtrip_verified": decode_lossless_ascii(ascii_document) == candidate}
    _write(root / "exports" / "full_candidate.lossless.manifest.json", ascii_manifest)
    _write_ascii(root / "exports" / "semantic_report.ascii", _semantic_report(run_id, coverage, corpus, gates, unresolved)); _write(root / "exports" / "unresolved.index.json", unresolved)
    _write(root / "coverage" / "complete.json", coverage)
    manifest = {"schema_version": 1, "candidate_id": candidate_id, "selected_provider_candidate_id": selected_ids[0] if len(selected_ids) == 1 else None, "selected_provider_candidate_ids": selected_ids, "source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"], "output_sha256": hashlib.sha256(candidate).hexdigest(), "changed_bytes": sum(left != right for left, right in zip(parent, candidate)), "proof_owned_changed_bytes": sum(int(item["length"]) for item in proof_spans), "coverage_complete": coverage["coverage_complete"], "unresolved_bytes": int(coverage["summary"].get("unresolved", 0)), "gate_statuses": gates["gates"], "promotion_eligible": False, "verified_decryption": False, "artifact_path": str(candidate_root / "candidate.bin")}
    reference = bundle.get("reference") or {}
    if reference.get("bytes") is not None and bool(bundle["policy"]["reference_evaluation"]["enabled"]):
        manifest["reference_metrics"] = _reference_transition_metrics(parent, candidate, reference["bytes"])
        manifest["reference_sha256"] = str(reference.get("sha256") or "")
    _write(candidate_root / "manifest.json", manifest)
    frontier = [manifest] if gates["passed"] else []
    _write(root / "final" / "pareto_frontier.json", frontier)
    status = "completed" if gates["passed"] and not unresolved and selected_ids else ("partial_unresolved" if gates["passed"] and selected_ids else "evidence_exhausted")
    decision = {"schema_version": 1, "status": status, "selected_candidate_id": candidate_id if frontier else None, "provider_candidate_id": selected_ids[0] if len(selected_ids) == 1 else None, "provider_candidate_ids": selected_ids, "unresolved_bytes": manifest["unresolved_bytes"], "coverage_complete": coverage["coverage_complete"], "ascii_roundtrip_verified": ascii_manifest["roundtrip_verified"], "promotion_eligible": False, "verified_decryption": False, "reason": decision_reason, "preservation_blocked": preservation_blocked}
    _write(root / "final" / "decision.json", decision)
    _write(root / "checkpoints" / "latest.json", {"schema_version": 1, "run_id": run_id, "status": status, "completed_stage": "ascii_roundtrip_verified", "decision_digest": _digest(decision), "turn_id": turn_id})
    log.emit("run_recomposed", {"status": status, "candidate_id": decision["selected_candidate_id"], "changed_bytes": manifest["changed_bytes"], "unresolved_bytes": manifest["unresolved_bytes"], "turn_id": turn_id}, turn_id)
    executed_path = _executed_measurements_path(root)
    if not executed_path.is_file():
        _write(executed_path, {"schema_version": 1, "measurements": []})
    artifacts = {"providers": str(root / "regimes" / "providers.json"), "coverage": str(root / "coverage" / "complete.json"), "candidate": str(candidate_root / "candidate.bin"), "candidate_manifest": str(candidate_root / "manifest.json"), "inverse": str(candidate_root / "inverse.json"), "gates": str(candidate_root / "gates.json"), "plaintext_corpus": str(root / "exports" / "plaintext_corpus.ascii"), "plaintext_index": str(root / "exports" / "plaintext_corpus.index.json"), "lossless_ascii": str(root / "exports" / "full_candidate.lossless.ascii"), "lossless_ascii_manifest": str(root / "exports" / "full_candidate.lossless.manifest.json"), "semantic_report": str(root / "exports" / "semantic_report.ascii"), "unresolved": str(root / "exports" / "unresolved.index.json"), "frontier": str(root / "final" / "pareto_frontier.json"), "decision": str(root / "final" / "decision.json"), "checkpoint": str(root / "checkpoints" / "latest.json"), "events": str(root / "logs" / "events.jsonl"), "executed_measurements": str(executed_path)}
    run = {"schema_version": 1, "run_id": run_id, "status": status, "source": source_identity, "parent": parent_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "implementation_digest": bundle["implementation_digest"], "run_root": str(root), "selected_candidate_id": decision["selected_candidate_id"], "artifacts": artifacts}
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "full_decode_run.schema.json")).iter_errors(run))
    if errors: raise ValueError(f"full-decode run schema failure: {errors[0].message}")
    _write(root / "run.json", run)
    from src.services.learning_db import try_index_learning_db_on_run_complete

    try_index_learning_db_on_run_complete(root / "run.json", "full_decode")
    from src.services.proof_ledger import try_compile_proof_ledger_on_run_complete

    ledger_result = try_compile_proof_ledger_on_run_complete(root / "run.json", "full_decode")
    if ledger_result.get("ok"):
        from src.services.proof_ledger.delta_compiler import compile_parent_to_child_delta
        from src.services.proof_ledger.core import lineage_key_from_run, load_protected_spans, load_proof_ledger_bundle

        ledger_bundle = load_proof_ledger_bundle()
        key = lineage_key_from_run(partial_run, bundle=ledger_bundle)
        protected = load_protected_spans(key, bundle=ledger_bundle)
        compile_parent_to_child_delta(
            parent,
            candidate,
            protected,
            metadata={
                "from": {"run_id": run_id, "candidate_id": None},
                "to": {"run_id": run_id, "candidate_id": candidate_id},
                "lineage_key": key,
                "verified_plaintext_byte_delta": int(corpus.get("verified_plaintext_bytes") or 0),
                "unresolved_byte_delta": int(manifest["unresolved_bytes"]),
                "plaintext": {"verified_plaintext_bytes": int(corpus.get("verified_plaintext_bytes") or 0)},
                "parser_semantic": {},
                "gates": gates["gates"],
                "transform_regime": {"rail_id": "full_decode"},
            },
            bundle=ledger_bundle,
        )
    return run


def execute_registered_measurements(run_path: str | Path, measurement_ids: Sequence[str], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_full_decode_bundle(policy_path, registry_path)
    path = Path(run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    if not verify_full_decode_run(run_file)["ok"]:
        raise ValueError("cannot execute measurements on an invalid full-decode run")
    run = _read(run_file)
    root = Path(run["run_root"]).resolve()
    registry = _measurement_registry(bundle)
    provider_registry = _provider_registry(bundle)
    executed = _load_executed_measurements(root)
    already = {str(item["measurement_id"]) for item in executed["measurements"]}
    source_file, parent_file = Path(run["source"]["path"]).resolve(), Path(run["parent"]["path"]).resolve()
    providers = _read(root / "regimes" / "providers.json") if (root / "regimes" / "providers.json").is_file() else []
    updates = []
    newly_executed = []
    for measurement_id in measurement_ids:
        measurement_key = str(measurement_id)
        if measurement_key in already:
            continue
        if measurement_key not in registry:
            raise ValueError(f"unknown registered measurement: {measurement_key}")
        spec = registry[measurement_key]
        provider_id = str(spec["provider_id"])
        if provider_id not in provider_registry:
            raise ValueError(f"registered measurement references unknown provider: {provider_id}")
        turn_index = len(executed["measurements"]) + 1
        turn_id = f"turn-{turn_index:04d}"
        result = _run_provider_specs(source_file, parent_file, root, [provider_registry[provider_id]], bundle=bundle, turn_id=turn_id)[0]
        updates.append(result)
        executed["measurements"].append({"measurement_id": measurement_key, "provider_id": provider_id, "turn_id": turn_id, "provider_run_id": result["run_id"], "candidate_count": len(result.get("candidates") or [])})
        newly_executed.append(measurement_key)
        already.add(measurement_key)
    if updates:
        providers = _merge_provider_results(providers, updates)
        _write(root / "regimes" / "providers.json", providers)
        _write(_executed_measurements_path(root), executed)
    return {"operation": "full_decode_execute_registered_measurements", "run_id": run["run_id"], "executed_measurement_ids": [str(item) for item in measurement_ids], "newly_executed": newly_executed, "provider_count": len(providers)}


def apply_full_decode_advisory_action(run_path: str | Path, action: Mapping[str, Any], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    packet = build_full_decode_model_packet(run_file, policy_path=policy_path, registry_path=registry_path)
    validated = validate_full_decode_model_action(action, packet, policy_path=policy_path, registry_path=registry_path)
    if validated["action"] == "request_registered_measurement":
        execution = execute_registered_measurements(run_file, validated["measurement_ids"], policy_path=policy_path, registry_path=registry_path)
        return resume_full_decode_run(run_file, policy_path=policy_path, registry_path=registry_path) | {"accepted_action": validated, "measurement_execution": execution}
    _write(Path(_read(run_file)["run_root"]).resolve() / "advisory" / "latest_rank.json", validated)
    return {"operation": "full_decode_advisory_rank", "run_id": packet["run_id"], "executed_new_work": False, "accepted_action": validated}


def _build_measurement_catalog(run: Mapping[str, Any], providers: Sequence[Mapping[str, Any]], bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    executed = {str(item["measurement_id"]) for item in _load_executed_measurements(Path(run["run_root"]))["measurements"]}
    active_provider_ids = {str(item["provider_id"]) for item in providers}
    catalog = []
    for item in bundle["registry"]["registered_measurements"]:
        measurement_id = str(item["measurement_id"])
        provider_id = str(item["provider_id"])
        provider = next((entry for entry in providers if str(entry["provider_id"]) == provider_id), None)
        frontier_count = len(provider.get("candidates") or []) if provider else 0
        status = "executed" if measurement_id in executed else ("frontier_ready" if frontier_count else "pending")
        catalog.append({"measurement_id": measurement_id, "provider_id": provider_id, "description": str(item["description"]), "status": status, "frontier_count": frontier_count, "provider_active": provider_id in active_provider_ids})
    return catalog


def run_full_decode_e2e(source_path: str | Path, parent_path: str | Path, *, output_root: str | Path | None = None, policy_path: str | Path | None = None, registry_path: str | Path | None = None, reference_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_full_decode_bundle(policy_path, registry_path)
    if reference_path is not None:
        reference_file = Path(reference_path).resolve()
        reference_bytes = reference_file.read_bytes()
        bundle["reference"] = {**_identity(reference_file), "bytes": reference_bytes}
    source_file, parent_file = Path(source_path).resolve(), Path(parent_path).resolve()
    source_identity, parent_identity = _identity(source_file), _identity(parent_file)
    if source_identity["size"] != parent_identity["size"]: raise ValueError("full-decode source and parent must have equal size")
    run_basis = {"source": source_identity["sha256"], "parent": parent_identity["sha256"], "policy": bundle["policy_digest"], "registry": bundle["registry_digest"], "implementation": bundle["implementation_digest"]}
    run_id = _cid("full-decode-run", run_basis)
    base = Path(output_root).resolve() if output_root else (_root() / str(bundle["policy"]["artifact_root"])).resolve()
    root = base / run_id; existing = root / "run.json"
    if existing.is_file() and verify_full_decode_run(existing).get("ok"):
        return _read(existing)
    root.mkdir(parents=True, exist_ok=True)
    event_path = root / "logs" / "events.jsonl"
    if event_path.exists(): event_path.unlink()
    log = EventLog(event_path, run_id); log.emit("run_started", {"source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"]}, "turn-0000")
    source, parent = source_file.read_bytes(), parent_file.read_bytes()
    provider_specs = _provider_specs_for_initial_pass(bundle)
    providers = _run_provider_specs(source_file, parent_file, root, provider_specs, bundle=bundle, turn_id="turn-0000")
    run = _materialize_from_providers(root=root, run_id=run_id, source_identity=source_identity, parent_identity=parent_identity, source=source, parent=parent, providers=providers, bundle=bundle, log=log, turn_id="turn-0000", source_file=source_file, parent_file=parent_file)
    log.emit("run_completed", {"status": run["status"], "candidate_id": run["selected_candidate_id"], "provider_count": len(providers)}, "turn-0000")
    return run


def verify_full_decode_run(run_path: str | Path) -> Dict[str, Any]:
    try:
        run = _read(Path(run_path).resolve()); root = Path(run["run_root"]).resolve()
        errors = list(Draft202012Validator(_read(_root() / "schemas" / "full_decode_run.schema.json")).iter_errors(run))
        missing, unsafe = [], []
        for name, raw in run["artifacts"].items():
            path = Path(raw).resolve()
            if root not in path.parents: unsafe.append(name)
            elif not path.is_file(): missing.append(name)
        sequence, previous, chain_ok = 0, "", True
        event_path = Path(run["artifacts"]["events"])
        if event_path.is_file():
            for line in event_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous: chain_ok = False
                previous = hashlib.sha256(_canonical(event)).hexdigest(); sequence += 1
        source_ok = _identity(Path(run["source"]["path"]))["sha256"] == run["source"]["sha256"]
        parent_ok = _identity(Path(run["parent"]["path"]))["sha256"] == run["parent"]["sha256"]
        ascii_ok = False
        if not missing and not unsafe:
            candidate = Path(run["artifacts"]["candidate"]).read_bytes(); document = Path(run["artifacts"]["lossless_ascii"]).read_text(encoding="ascii"); ascii_ok = decode_lossless_ascii(document) == candidate
        return {"ok": not errors and not missing and not unsafe and chain_ok and source_ok and parent_ok and ascii_ok, "run_id": run.get("run_id"), "schema_errors": [item.message for item in errors], "missing_artifacts": missing, "unsafe_artifacts": unsafe, "event_chain_ok": chain_ok, "source_identity_ok": source_ok, "parent_identity_ok": parent_ok, "ascii_roundtrip_ok": ascii_ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_full_decode_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve()); verified = verify_full_decode_run(run_path); coverage = _read(Path(run["artifacts"]["coverage"])); manifest = _read(Path(run["artifacts"]["candidate_manifest"])); gates = _read(Path(run["artifacts"]["gates"])); decision = _read(Path(run["artifacts"]["decision"])); providers = _read(Path(run["artifacts"]["providers"]))
    ranges = [{"offset": item["offset"], "length": item["length"], "class": item["class"], "source_id": item["segment_id"], "proof_refs": item["proof_refs"], "theme_token": f"binary_waterfall.{item['class']}"} for item in coverage["segments"]]
    return {"operation": "full_decode_run_inspect", "run_id": run["run_id"], "verified": verified["ok"], "status": run["status"], "decision": decision, "candidate": manifest, "coverage": coverage, "gates": gates, "providers": providers, "waterfall_overlay": {"schema_version": 1, "ranges": ranges}, "exports": {key: run["artifacts"][key] for key in ("plaintext_corpus", "lossless_ascii", "semantic_report", "unresolved")}, "run_root": run["run_root"]}


def resume_full_decode_run(run_path: str | Path, *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    root = Path(run_path).resolve(); path = root / "run.json" if root.is_dir() else root
    verification = verify_full_decode_run(path)
    if not verification["ok"]: raise ValueError("cannot resume an invalid full-decode run")
    bundle = load_full_decode_bundle(policy_path, registry_path)
    run = _read(path)
    if run["status"] == "completed":
        return {"operation": "full_decode_resume", "run_id": run["run_id"], "status": run["status"], "executed_new_work": False, "reason": "terminal_completed"}
    run_root = Path(run["run_root"]).resolve()
    providers_path = run_root / "regimes" / "providers.json"
    if not providers_path.is_file():
        raise ValueError("full-decode run is missing provider artifacts required for resume")
    providers = _read(providers_path)
    source_file, parent_file = Path(run["source"]["path"]).resolve(), Path(run["parent"]["path"]).resolve()
    source, parent = source_file.read_bytes(), parent_file.read_bytes()
    event_path = Path(run["artifacts"]["events"])
    log = EventLog(event_path, run["run_id"])
    checkpoint = _read(Path(run["artifacts"]["checkpoint"])) if Path(run["artifacts"]["checkpoint"]).is_file() else {}
    turn_id = str(checkpoint.get("turn_id") or "turn-0000")
    if turn_id.startswith("turn-"):
        turn_index = int(turn_id.split("-", 1)[1]) + 1
    else:
        turn_index = 1
    next_turn = f"turn-{turn_index:04d}"
    updated = _materialize_from_providers(root=run_root, run_id=run["run_id"], source_identity=run["source"], parent_identity=run["parent"], source=source, parent=parent, providers=providers, bundle=bundle, log=log, turn_id=next_turn, source_file=source_file, parent_file=parent_file)
    return {"operation": "full_decode_resume", "run_id": updated["run_id"], "status": updated["status"], "executed_new_work": True, "reason": "providers_recomposed"}


def build_full_decode_model_packet(run_path: str | Path, *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_full_decode_bundle(policy_path, registry_path)
    inspected = inspect_full_decode_run(run_path)
    if not inspected["verified"]: raise ValueError("full-decode run failed integrity verification")
    run = _read(Path(run_path).resolve() if Path(run_path).is_file() else Path(run_path).resolve() / "run.json")
    candidate = inspected["candidate"]
    measurements = _build_measurement_catalog(run, inspected["providers"], bundle)
    packet = {"schema_version": 1, "operation": "full_decode_model_packet", "run_id": inspected["run_id"], "run_verified": True, "status": inspected["status"], "candidates": [{"candidate_id": candidate["candidate_id"], "changed_bytes": candidate["changed_bytes"], "unresolved_bytes": candidate["unresolved_bytes"], "gate_statuses": candidate["gate_statuses"], "promotion_authority": False}], "measurements": measurements, "allowed_actions": list(bundle["policy"]["model_boundary"]["allowed_actions"]), "model_role": "advisory_only", "mechanical_authority": True}
    from src.services.proof_ledger.delta_packet import attach_advisory_delta_context

    return attach_advisory_delta_context(packet, run_path, "full_decode", allowed_next_measurements=[str(item["measurement_id"]) for item in measurements])


def validate_full_decode_model_action(action: Mapping[str, Any], packet: Mapping[str, Any], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_full_decode_bundle(policy_path, registry_path)
    policy = bundle["policy"]["model_boundary"]
    forbidden = set(policy["forbidden_fields"])
    allowed = set(policy["allowed_actions"])
    contracts = dict(policy["action_contracts"])

    def all_keys(value: Any) -> set[str]:
        if isinstance(value, Mapping):
            return set(map(str, value)) | set().union(*(all_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(all_keys(item) for item in value)) if value else set()
        return set()

    action_id = str(action.get("action") or "")
    if action_id not in allowed or action_id not in contracts:
        raise ValueError("model action is not registered")
    present = forbidden.intersection(all_keys(action))
    if present:
        raise ValueError("model action contains forbidden authority fields")
    contract = contracts[action_id]
    fields = set(action) - {"action"}
    missing = set(contract["required_fields"]) - fields
    unknown = fields - set(contract["allowed_fields"])
    if missing or unknown:
        raise ValueError(f"model action contract mismatch: missing={sorted(missing)}, unknown={sorted(unknown)}")
    reference_field = contract.get("reference_field")
    if reference_field:
        references = action.get(reference_field)
        if isinstance(references, str):
            reference_values = [references]
        elif isinstance(references, list):
            reference_values = references
        else:
            raise ValueError("model reference field must be a string or list")
        collection = packet.get(contract["packet_collection"]) or []
        valid_ids = {str(item[contract["packet_id_field"]]) for item in collection}
        invalid = [str(item) for item in reference_values if str(item) not in valid_ids]
        if invalid:
            raise ValueError(f"model action contains unknown evidence references: {invalid}")
        if action_id == "request_registered_measurement":
            pending = {str(item["measurement_id"]) for item in collection if str(item.get("status")) == "pending"}
            requested = {str(item) for item in reference_values}
            if not requested.issubset(pending):
                raise ValueError("model requested measurements that are not pending")
    reason = action.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("model reason is missing")
    return dict(action)
