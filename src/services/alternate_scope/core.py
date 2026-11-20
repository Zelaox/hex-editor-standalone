"""Mechanical alternate-scope inference with bounded probes and fail-closed gates."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value)}"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _validate(schema_name: str, value: Any) -> None:
    schema = _read(_root() / "schemas" / schema_name)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        location = ".".join(str(item) for item in errors[0].path)
        raise ValueError(f"{schema_name} at {location or '<root>'}: {errors[0].message}")


def _hook(spec: Mapping[str, Any]):
    impl = dict(spec["impl"])
    function = getattr(importlib.import_module(str(impl["module"])), str(impl["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid alternate-scope hook: {impl['module']}.{impl['callable']}")
    return function


def load_alternate_scope_bundle(registry_path: str | Path | None = None, policy_path: str | Path | None = None) -> Dict[str, Any]:
    registry = _read(Path(registry_path).resolve() if registry_path else _root() / "config" / "alternate_scope_registry.json")
    policy = _read(Path(policy_path).resolve() if policy_path else _root() / "config" / "alternate_scope_policy.json")
    _validate("alternate_scope_registry.schema.json", registry)
    _validate("alternate_scope_policy.schema.json", policy)
    profile_id = str(policy["default_validation_profile_id"])
    if profile_id not in policy["validation_profiles"]:
        raise ValueError("default alternate-scope validation profile is missing")
    registered = {str(item["id"]) for item in registry["gates"]}
    unknown = set(policy["validation_profiles"][profile_id]["required_gate_ids"]) - registered
    if unknown:
        raise ValueError(f"validation profile references unknown gates: {sorted(unknown)}")
    for section in ("budgets", "artifact_layout", "coverage", "boundary", "model_boundary", "logging"):
        if not policy.get(section):
            raise ValueError(f"alternate-scope policy section is empty: {section}")
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry)}


class SegmentedEventLog:
    def __init__(self, root: Path, run_id: str, bundle: Mapping[str, Any]):
        self.root, self.run_id, self.bundle = root, run_id, bundle
        self.sequence, self.segment, self.previous_digest = 0, 1, ""
        self.logs = root / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)

    def _segment_path(self) -> Path:
        return self.logs / f"events-{self.segment:06d}.jsonl"

    def emit(self, event_type: str, payload: Mapping[str, Any], severity: str = "info") -> Dict[str, Any]:
        policy = self.bundle["policy"]
        if severity not in policy["logging"]["levels"]:
            raise ValueError(f"unknown log severity: {severity}")
        if self.sequence >= int(policy["budgets"]["maximum_log_events"]):
            raise ValueError("alternate-scope log event budget exceeded")
        forbidden = set(policy["logging"]["redacted_payload_fields"])
        clean = {key: value for key, value in payload.items() if key not in forbidden}
        event_base = {
            "schema_version": 1,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "event_type": event_type,
            "component_id": "alternate-scope",
            "payload": clean,
            "policy_digest": self.bundle["policy_digest"],
            "registry_digest": self.bundle["registry_digest"],
            "previous_event_digest": self.previous_digest,
        }
        event = {**event_base, "event_id": _content_id("alternate-scope-event", event_base)}
        _validate("alternate_scope_log_event.schema.json", event)
        encoded = json.dumps(event, sort_keys=True, default=str) + "\n"
        maximum_segment = int(policy["budgets"]["maximum_log_segment_bytes"])
        current = self._segment_path()
        if current.exists() and current.stat().st_size + len(encoded.encode("utf-8")) > maximum_segment:
            if self.segment >= int(policy["budgets"]["maximum_log_segments"]):
                raise ValueError("alternate-scope log segment budget exceeded")
            self.segment += 1
            current = self._segment_path()
        with current.open("a", encoding="utf-8") as handle:
            handle.write(encoded)
            if policy["logging"]["flush_after_event"]:
                handle.flush()
        with (self.logs / "rolling.log").open("a", encoding="utf-8") as handle:
            handle.write(f"{event['timestamp_utc']} | {self.sequence} | {severity} | {event_type} | {json.dumps(clean, sort_keys=True, default=str)}\n")
        self.previous_digest = hashlib.sha256(_canonical(event)).hexdigest()
        self.sequence += 1
        return event


def _printable(data: bytes) -> float:
    return sum(value in (9, 10, 13) or 32 <= value <= 126 for value in data) / max(1, len(data))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def _merge_intervals(spans: Sequence[Mapping[str, Any]]) -> List[Dict[str, int]]:
    ordered = sorted((int(item["offset"]), int(item["offset"]) + int(item["length"])) for item in spans if int(item.get("length") or 0) > 0)
    merged: List[List[int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [{"offset": start, "length": end - start} for start, end in merged]


def _subtract(offset: int, length: int, protected: Sequence[Mapping[str, Any]]) -> List[Dict[str, int]]:
    fragments = [(offset, offset + length)]
    for item in protected:
        left, right = int(item["offset"]), int(item["offset"]) + int(item["length"])
        revised = []
        for start, end in fragments:
            if right <= start or left >= end:
                revised.append((start, end))
            else:
                if start < left:
                    revised.append((start, left))
                if right < end:
                    revised.append((right, end))
        fragments = revised
    return [{"offset": start, "length": end - start} for start, end in fragments if end > start]


def _overlaps(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return max(int(left["offset"]), int(right["offset"])) < min(int(left["offset"]) + int(left["length"]), int(right["offset"]) + int(right["length"]))


def classify_window_roles(snapshot: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    policy, size = bundle["policy"], int(snapshot["source"]["size"])
    preserve_classes = set(policy["coverage"]["preserve_classes"])
    preserve_raw = [
        {"offset": max(0, int(item.get("offset") or 0)), "length": min(size - max(0, int(item.get("offset") or 0)), int(item.get("length") or 0))}
        for item in snapshot.get("coverage") or [] if str(item.get("class") or "") in preserve_classes
    ]
    preserve = _merge_intervals(preserve_raw)
    for item in preserve:
        item.update({"role": "preserve_header", "window_id": _content_id("preserve-window", item), "rule_id": "coverage-and-observation-roles"})
    hints = [item for item in observations if item.get("kind") == "boundary_hint"]
    candidates = []
    for hint in hints:
        candidates.append({"hint": int(hint["value"]), "evidence_refs": [hint["observation_id"]]})
    return {"preserve": preserve, "candidate_seeds": candidates, "validation": [], "conflicts": [], "rule_id": "coverage-and-observation-roles"}


def build_boundary_probe_plan(snapshot: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], roles: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del observations
    budget, size = bundle["policy"]["budgets"], int(snapshot["source"]["size"])
    count, span, step = int(budget["maximum_probe_windows"]), int(budget["probe_span_bytes"]), int(budget["probe_step_bytes"])
    span = min(span, int(budget["maximum_probe_bytes"]))
    span = max(span, int(budget["minimum_probe_bytes"]))
    probes = []
    for seed in roles["candidate_seeds"]:
        for index in range(count):
            center_delta = index - count // 2
            start = max(0, min(size - 1, int(seed["hint"]) + center_delta * step - span // 2))
            end = min(size, start + span)
            role = "before" if center_delta < 0 else ("after" if center_delta > 0 else "crossing")
            descriptor = {"offset": start, "length": end - start, "role": role, "evidence_refs": list(seed["evidence_refs"]), "rule_id": "symmetric-evidence-neighborhood"}
            probes.append({"probe_id": _content_id("boundary-probe", descriptor), **descriptor})
    unique = {(item["offset"], item["length"]): item for item in probes}
    return sorted(unique.values(), key=lambda item: (item["offset"], item["length"]))[:count]


def _apply(data: bytes, material: bytes) -> bytes:
    return bytes(value ^ material[index % len(material)] for index, value in enumerate(data))


def measure_boundary_probes(source: bytes, plan: Sequence[Mapping[str, Any]], roles: Mapping[str, Any], material: bytes, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del bundle
    protected = roles["preserve"]
    measurements = []
    for probe in plan:
        fragments = _subtract(int(probe["offset"]), int(probe["length"]), protected)
        before = b"".join(source[item["offset"]:item["offset"] + item["length"]] for item in fragments)
        after = _apply(before, material) if before else b""
        printable_gain = _printable(after) - _printable(before)
        null_gain = (before.count(0) - after.count(0)) / max(1, len(before))
        entropy_delta = _entropy(after) - _entropy(before)
        score = printable_gain + max(0.0, null_gain) - abs(entropy_delta) * 0.01
        payload = {
            "probe_id": probe["probe_id"], "offset": probe["offset"], "length": probe["length"], "role": probe["role"],
            "eligible_fragments": fragments, "eligible_bytes": len(before), "printable_before": _printable(before),
            "printable_after": _printable(after), "printable_gain": printable_gain, "null_reduction": null_gain,
            "entropy_before": _entropy(before), "entropy_after": _entropy(after), "entropy_delta": entropy_delta,
            "representation_score": score, "evidence_refs": probe["evidence_refs"], "rule_id": "registered-representation-delta",
        }
        payload["measurement_id"] = _content_id("boundary-measurement", payload)
        measurements.append(payload)
    return measurements


def infer_change_points(measurements: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    threshold = float(bundle["policy"]["boundary"]["change_score_delta"])
    uncertainty = int(bundle["policy"]["boundary"]["uncertainty_bytes"])
    output = []
    ordered = sorted(measurements, key=lambda item: int(item["offset"]))
    for left, right in zip(ordered, ordered[1:]):
        delta = float(right["representation_score"]) - float(left["representation_score"])
        if abs(delta) < threshold:
            continue
        position = (int(left["offset"]) + int(left["length"]) + int(right["offset"])) // 2
        candidate = {"position": position, "uncertainty_start": max(0, position - uncertainty), "uncertainty_end": position + uncertainty, "score_delta": delta, "left_measurement_id": left["measurement_id"], "right_measurement_id": right["measurement_id"], "rule_id": "adjacent-score-change", "promotion_authority": False}
        output.append({"change_point_id": _content_id("change-point", candidate), **candidate})
    return output[: int(bundle["policy"]["budgets"]["maximum_boundary_refinements"])]


def _scope_from_measurement(item: Mapping[str, Any], roles: Mapping[str, Any], material_ref: str, strategy: str) -> Dict[str, Any] | None:
    fragments = [{**fragment, "independence_group_id": item["probe_id"]} for fragment in item["eligible_fragments"]]
    if not fragments:
        return None
    value = {"strategy_id": strategy, "scopes": fragments, "measurement_refs": [item["measurement_id"]], "candidate_material_ref": material_ref, "preserve_spans": roles["preserve"], "promotion_authority": False}
    return {"scope_hypothesis_id": _content_id("alternate-scope", value), **value}


def generate_ranked_single_scopes(measurements: Sequence[Mapping[str, Any]], roles: Mapping[str, Any], material_ref: str, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    maximum = int(bundle["policy"]["budgets"]["maximum_scope_hypotheses"])
    ranked = sorted(measurements, key=lambda item: (-float(item["representation_score"]), int(item["offset"])))
    return [scope for item in ranked[:maximum] if (scope := _scope_from_measurement(item, roles, material_ref, "ranked-single-spans"))]


def generate_independent_union_scopes(measurements: Sequence[Mapping[str, Any]], roles: Mapping[str, Any], material_ref: str, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    required = int(bundle["policy"]["validation_profiles"][bundle["policy"]["default_validation_profile_id"]]["minimum_independent_windows"])
    ranked = sorted((item for item in measurements if item["eligible_fragments"]), key=lambda item: -float(item["representation_score"]))
    selected = []
    for item in ranked:
        span = {"offset": item["offset"], "length": item["length"]}
        if any(_overlaps(span, {"offset": other["offset"], "length": other["length"]}) for other in selected):
            continue
        selected.append(item)
        if len(selected) >= required:
            break
    if len(selected) < required:
        return []
    value = {"strategy_id": "independent-compatible-union", "scopes": [{**fragment, "independence_group_id": item["probe_id"]} for item in selected for fragment in item["eligible_fragments"]], "measurement_refs": [item["measurement_id"] for item in selected], "candidate_material_ref": material_ref, "preserve_spans": roles["preserve"], "promotion_authority": False}
    return [{"scope_hypothesis_id": _content_id("alternate-scope", value), **value}]


def _unique_byte_count(scopes: Sequence[Mapping[str, Any]]) -> int:
    return sum(item["length"] for item in _merge_intervals(scopes))


def execute_scope_descriptors(source: bytes, hypotheses: Sequence[Mapping[str, Any]], material: bytes, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    budget = bundle["policy"]["budgets"]
    maximum_count, maximum_bytes = int(budget["maximum_descriptor_executions"]), int(budget["maximum_transformed_bytes"])
    total, output = 0, []
    for hypothesis in hypotheses[:maximum_count]:
        raw_scopes = list(hypothesis["scopes"])
        merged = _merge_intervals(raw_scopes)
        debit = _unique_byte_count(merged)
        if total + debit > maximum_bytes:
            break
        artifact = bytearray(source)
        results = []
        for scope in merged:
            start, length = int(scope["offset"]), int(scope["length"])
            before = source[start:start + length]
            after = _apply(before, material)
            artifact[start:start + length] = after
        groups: Dict[str, List[Mapping[str, Any]]] = {}
        for scope in raw_scopes:
            groups.setdefault(str(scope["independence_group_id"]), []).append(scope)
        for group_id, scopes in groups.items():
            before = b"".join(source[int(scope["offset"]):int(scope["offset"]) + int(scope["length"])] for scope in scopes)
            after = b"".join(bytes(artifact[int(scope["offset"]):int(scope["offset"]) + int(scope["length"])]) for scope in scopes)
            printable_gain = _printable(after) - _printable(before)
            null_reduction = (before.count(0) - after.count(0)) / max(1, len(before))
            entropy_delta = _entropy(after) - _entropy(before)
            results.append({"independence_group_id": group_id, "offset": min(int(scope["offset"]) for scope in scopes), "length": sum(int(scope["length"]) for scope in scopes), "changed_bytes": sum(left != right for left, right in zip(before, after)), "printable_gain": printable_gain, "null_reduction": null_reduction, "entropy_delta": entropy_delta, "representation_score": printable_gain + max(0.0, null_reduction) - abs(entropy_delta) * 0.01})
        total += debit
        descriptor = {"scope_hypothesis_id": hypothesis["scope_hypothesis_id"], "candidate_material_ref": hypothesis["candidate_material_ref"], "scopes": raw_scopes, "preserve_spans": hypothesis["preserve_spans"], "strategy_id": hypothesis["strategy_id"]}
        descriptor["descriptor_id"] = _content_id("alternate-scope-descriptor", descriptor)
        output.append({"descriptor": descriptor, "artifact_bytes": bytes(artifact), "artifact_sha256": hashlib.sha256(artifact).hexdigest(), "window_results": results, "transformed_bytes_debited": debit})
    return output


def _parser_unknown(data: bytes) -> Dict[str, Any]:
    from src.plugins.ptx.runtime_analysis import build_ptx_snapshot
    from src.runtime.byte_source import ByteSource
    snapshot = build_ptx_snapshot(ByteSource.from_bytes(data)).to_dict()
    return {"unknown_bytes": int((snapshot.get("coverage_summary") or {}).get("bytes_by_class", {}).get("unknown", 0)), "snapshot_id": snapshot["snapshot_id"], "coverage_summary": snapshot.get("coverage_summary") or {}}


def _gate(gate_id: str, passed: bool | None, measurements: Mapping[str, Any], failure_code: str, request: str) -> Dict[str, Any]:
    status = "passed" if passed is True else ("failed" if passed is False else "inconclusive")
    return {"gate_id": gate_id, "status": status, "measurements": dict(measurements), "failure_codes": [] if passed is True else [failure_code], "next_evidence_requests": [] if passed is True else [request]}


def gate_non_identity(context: Mapping[str, Any]) -> Dict[str, Any]:
    changed = sum(int(item["changed_bytes"]) for item in context["result"]["window_results"])
    return _gate("non-identity", changed > 0, {"changed_bytes": changed}, "identity_transform", "request_non_identity_candidate")


def gate_preserve_integrity(context: Mapping[str, Any]) -> Dict[str, Any]:
    mutations = 0
    for span in context["result"]["descriptor"]["preserve_spans"]:
        start, length = int(span["offset"]), int(span["length"])
        mutations += context["source"][start:start + length] != context["result"]["artifact_bytes"][start:start + length]
    maximum = int(context["profile"]["maximum_preserve_mutations"])
    return _gate("preserve-integrity", mutations <= maximum, {"mutated_preserve_spans": mutations, "maximum": maximum}, "preserve_mutation", "request_scope_split")


def gate_representation_improvement(context: Mapping[str, Any]) -> Dict[str, Any]:
    gains = [float(item["representation_score"]) for item in context["result"]["window_results"]]
    best = max(gains, default=0.0)
    required = float(context["profile"]["minimum_representation_gain"])
    return _gate("representation-improvement", best >= required, {"best_representation_gain": best, "required": required, "window_gains": gains}, "representation_not_improved", "request_alternate_scope")


def gate_parser_non_regression(context: Mapping[str, Any]) -> Dict[str, Any]:
    metrics = context.get("parser_metrics")
    if not metrics:
        return _gate("parser-non-regression", None, {"evaluated": False}, "parser_budget_deferred", "request_parser_evaluation")
    regression = int(metrics["unknown_after"]) - int(metrics["unknown_before"])
    maximum = int(context["profile"]["maximum_parser_unknown_regression"])
    return _gate("parser-non-regression", regression <= maximum, {**metrics, "unknown_regression": regression, "maximum": maximum}, "parser_coverage_regression", "request_alternate_scope")


def gate_boundary_localization(context: Mapping[str, Any]) -> Dict[str, Any]:
    refs = set(context["result"]["descriptor"].get("measurement_refs") or context["hypothesis"].get("measurement_refs") or [])
    supported = [item for item in context["change_points"] if item["left_measurement_id"] in refs or item["right_measurement_id"] in refs]
    return _gate("boundary-localization", bool(supported), {"supporting_change_points": len(supported)}, "boundary_not_localized", "request_boundary_refinement")


def gate_cross_window_reproduction(context: Mapping[str, Any]) -> Dict[str, Any]:
    threshold = float(context["profile"]["minimum_representation_gain"])
    improved = [item for item in context["result"]["window_results"] if float(item["representation_score"]) >= threshold]
    independent = {str(item["independence_group_id"]) for item in improved}
    required = int(context["profile"]["minimum_independent_windows"])
    return _gate("cross-window-reproduction", len(independent) >= required, {"independent_improved_windows": len(independent), "required": required, "independence_group_ids": sorted(independent)}, "insufficient_independent_support", "request_independent_windows")


def gate_structural_compatibility(context: Mapping[str, Any]) -> Dict[str, Any]:
    windows = context["result"]["window_results"]
    if len(windows) < 2:
        return _gate("structural-compatibility", None, {"comparable_windows": len(windows)}, "independent_window_missing", "request_compatible_windows")
    lengths = [int(item["length"]) for item in windows]
    compatible = max(lengths) <= max(1, min(lengths)) * 2
    return _gate("structural-compatibility", compatible, {"window_lengths": lengths, "ratio_limit": 2}, "structural_layout_incompatible", "request_compatible_windows")


def gate_header_compatibility(context: Mapping[str, Any]) -> Dict[str, Any]:
    classes = set(context["bundle"]["policy"]["coverage"]["header_classes"])
    headers = [item for item in context["snapshot"].get("coverage") or [] if int(item.get("offset") or 0) == 0 and str(item.get("class") or "") in classes]
    if not headers:
        return _gate("header-compatibility", None, {"header_ranges": 0}, "header_evidence_missing", "request_header_validation")
    compatible = all(context["source"][:int(item["length"])] == context["result"]["artifact_bytes"][:int(item["length"])] for item in headers)
    return _gate("header-compatibility", compatible, {"header_ranges": len(headers)}, "header_mutated", "request_scope_split")


def build_alternate_scope_model_packet(run_path: str | Path, *, policy_path: str | Path | None = None) -> Dict[str, Any]:
    run_file = Path(run_path).resolve()
    run = _read(run_file)
    verified = verify_alternate_scope_run(run_file)
    if not verified["ok"]:
        raise ValueError("cannot build model packet from an unverified alternate-scope run")
    bundle = load_alternate_scope_bundle(policy_path=policy_path)
    hypotheses = _read(Path(run["artifacts"]["hypotheses"]))
    measurements = _read(Path(run["artifacts"]["measurements"]))
    breakdowns = {item["descriptor_id"]: item for item in _read(Path(run["artifacts"]["gate_breakdowns"]))}
    descriptors = _read(Path(run["artifacts"]["descriptors"]))
    descriptor_by_hypothesis = {item["scope_hypothesis_id"]: item for item in descriptors}
    maximum = int(bundle["policy"]["budgets"]["maximum_model_hypotheses"])
    packet_hypotheses = []
    for item in hypotheses[:maximum]:
        descriptor = descriptor_by_hypothesis.get(item["scope_hypothesis_id"])
        breakdown = breakdowns.get((descriptor or {}).get("descriptor_id"), {})
        packet_hypotheses.append({"hypothesis_id": item["scope_hypothesis_id"], "strategy_id": item["strategy_id"], "measurement_refs": list(item["measurement_refs"]), "independence_group_count": len({str(scope.get("independence_group_id") or "") for scope in item["scopes"]}), "gate_statuses": {gate["gate_id"]: gate["status"] for gate in breakdown.get("gates") or []}, "promotion_authority": False})
    packet_measurements = [{"measurement_id": item["measurement_id"], "role": item["role"], "eligible_bytes": item["eligible_bytes"], "representation_score": item["representation_score"]} for item in measurements]
    model_policy = bundle["policy"]["model_boundary"]
    return {"schema_version": 1, "operation": "alternate_scope_model_packet", "run_id": run["run_id"], "terminal_state": run["terminal_state"], "hypotheses": packet_hypotheses, "measurements": packet_measurements, "allowed_actions": list(model_policy["allowed_actions"]), "forbidden_authority_fields": list(model_policy["forbidden_fields"]), "model_role": "advisory_only", "mechanical_authority": True}


def validate_model_actions(actions: Sequence[Mapping[str, Any]], packet: Mapping[str, Any] | None = None, *, policy_path: str | Path | None = None) -> List[Dict[str, Any]]:
    policy = load_alternate_scope_bundle(policy_path=policy_path)["policy"]["model_boundary"]
    allowed, forbidden = set(policy["allowed_actions"]), set(policy["forbidden_fields"])
    contracts = dict(policy["action_contracts"])

    def all_keys(value: Any) -> set[str]:
        if isinstance(value, Mapping):
            return set(map(str, value)) | set().union(*(all_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(all_keys(item) for item in value)) if value else set()
        return set()

    validated = []
    for action in actions:
        action_id = str(action.get("action") or "")
        if action_id not in allowed or action_id not in contracts:
            raise ValueError("model action is not registered")
        present = forbidden.intersection(all_keys(action))
        if present:
            raise ValueError(f"model action contains authority fields: {sorted(present)}")
        contract = contracts[action_id]
        fields = set(action) - {"action"}
        missing = set(contract["required_fields"]) - fields
        unknown = fields - set(contract["allowed_fields"])
        if missing or unknown:
            raise ValueError(f"model action contract mismatch: missing={sorted(missing)}, unknown={sorted(unknown)}")
        reference_field = contract.get("reference_field")
        if reference_field:
            if packet is None:
                raise ValueError("model reference validation requires a mechanical packet")
            references = action.get(reference_field)
            if not isinstance(references, list):
                raise ValueError("model reference field must be a list")
            collection = packet.get(contract["packet_collection"]) or []
            valid_ids = {str(item[contract["packet_id_field"]]) for item in collection}
            invalid = [str(item) for item in references if str(item) not in valid_ids]
            if invalid:
                raise ValueError(f"model action contains unknown evidence references: {invalid}")
            gate_status_field = contract.get("gate_status_field")
            if gate_status_field:
                selected = [item for item in collection if str(item[contract["packet_id_field"]]) in {str(ref) for ref in references}]
                expected = sorted({gate_id for item in selected for gate_id, status in (item.get("gate_statuses") or {}).items() if status != "passed"})
                observed = sorted(str(item) for item in action.get(gate_status_field) or [])
                if observed != expected:
                    raise ValueError(f"model action gate grounding mismatch: expected={expected}, observed={observed}")
        validated.append(dict(action))
    return validated


def _admit_previous(previous_run: str | Path | None, source_sha256: str) -> Dict[str, Any]:
    if previous_run is None:
        return {"admitted": False, "reason": "no_previous_run_supplied", "feedback": []}
    from src.services.transform_scope import verify_scope_run
    path = Path(previous_run).resolve()
    verified = verify_scope_run(path)
    if not verified["ok"]:
        raise ValueError("previous transform-scope run failed integrity verification")
    run = _read(path)
    if str(run["source"]["sha256"]) != source_sha256:
        raise ValueError("previous transform-scope run belongs to a different source")
    feedback = _read(Path(run["artifacts"]["feedback"]))
    return {"admitted": True, "run_id": run["run_id"], "run_path": str(path), "run_digest": hashlib.sha256(path.read_bytes()).hexdigest(), "feedback": feedback}


def _safe_artifact_paths(root: Path, layout: Mapping[str, str]) -> Dict[str, str]:
    paths = {}
    for name, relative in layout.items():
        target = (root / relative).resolve()
        if root.resolve() not in target.parents:
            raise ValueError("artifact layout escapes the run root")
        paths[name] = str(target)
    return paths


def run_alternate_scope_proof(source_path: str | Path, *, output_root: str | Path, candidate_hex: str, boundary_hint: int, previous_run: str | Path | None = None, registry_path: str | Path | None = None, policy_path: str | Path | None = None) -> Dict[str, Any]:
    source_file, output = Path(source_path).resolve(), Path(output_root).resolve()
    source = source_file.read_bytes()
    material = bytes.fromhex(candidate_hex)
    if not material:
        raise ValueError("candidate observation is empty")
    bundle = load_alternate_scope_bundle(registry_path, policy_path)
    from src.services.binary_runtime import analyze_binary_snapshot
    snapshot = analyze_binary_snapshot(source_file)["snapshot"]
    source_identity = {"sha256": hashlib.sha256(source).hexdigest(), "size": len(source), "snapshot_id": snapshot["snapshot_id"], "format_plugin": snapshot["format_plugin"]}
    observations = [
        {"observation_id": _content_id("observation", {"kind": "transform_candidate", "value": candidate_hex, "source": source_identity["sha256"]}), "kind": "transform_candidate", "value_hex": candidate_hex.lower(), "promotion_authority": False},
        {"observation_id": _content_id("observation", {"kind": "boundary_hint", "value": int(boundary_hint), "source": source_identity["sha256"]}), "kind": "boundary_hint", "value": int(boundary_hint), "promotion_authority": False},
    ]
    admission = _admit_previous(previous_run, source_identity["sha256"])
    prior_feedback = admission.pop("feedback")
    run_id = _content_id("alternate-scope-run", {"source": source_identity, "observations": observations, "policy": bundle["policy_digest"], "registry": bundle["registry_digest"], "previous_run_digest": admission.get("run_digest", "")})
    final_root = output / run_id
    if (final_root / "run.json").is_file():
        existing = _read(final_root / "run.json")
        if verify_alternate_scope_run(final_root / "run.json")["ok"]:
            return existing
        raise ValueError("existing content-addressed run failed integrity verification")
    staging = output / ".staging" / run_id
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=False)
    log = SegmentedEventLog(staging, run_id, bundle)
    log.emit("admission_started", {"source_sha256": source_identity["sha256"], "source_size": len(source)})
    registered_priorities = list(bundle["registry"]["feedback_priorities"])
    observed_requests = {str(item.get("request") or "") for item in prior_feedback}
    consumed_priorities = [item for item in registered_priorities if item in observed_requests]
    admission["consumed_feedback_requests"] = consumed_priorities
    log.emit("admission_completed", {"previous_run_admitted": admission["admitted"], "feedback_count": len(prior_feedback), "consumed_feedback_requests": consumed_priorities})
    roles = _hook(bundle["registry"]["window_role_classifier"])(snapshot, observations, bundle=bundle)
    log.emit("window_roles_classified", {key: len(value) for key, value in roles.items() if isinstance(value, list)})
    plan = _hook(bundle["registry"]["boundary_planner"])(snapshot, observations, roles, bundle=bundle)
    roles["candidate_body"] = [{**item, "role": "candidate_body"} for item in plan]
    independent_validation = []
    for item in plan:
        if not any(_overlaps(item, existing) for existing in independent_validation):
            independent_validation.append({**item, "role": "independent_validation"})
    roles["validation"] = independent_validation
    log.emit("boundary_probe_scheduled", {"probe_count": len(plan)})
    measurements = _hook(bundle["registry"]["measurement_engine"])(source, plan, roles, material, bundle=bundle)
    for item in measurements:
        log.emit("boundary_probe_completed", {"measurement_id": item["measurement_id"], "eligible_bytes": item["eligible_bytes"], "representation_score": item["representation_score"]})
    change_points = _hook(bundle["registry"]["change_point_inference"])(measurements, bundle=bundle)
    log.emit("change_points_derived", {"change_point_count": len(change_points)})
    material_ref = observations[0]["observation_id"]
    hypotheses = []
    for strategy in bundle["registry"]["scope_strategies"]:
        hypotheses.extend(_hook(strategy)(measurements, roles, material_ref, bundle=bundle))
    hypotheses = list({_digest({key: value for key, value in item.items() if key != "scope_hypothesis_id"}): item for item in hypotheses}.values())
    budgets = bundle["policy"]["budgets"]
    hypotheses = hypotheses[: int(budgets["maximum_scope_hypotheses"])]
    log.emit("scopes_compiled", {"hypothesis_count": len(hypotheses)})
    results = _hook(bundle["registry"]["executor"])(source, hypotheses, material, bundle=bundle)
    baseline_parser = _parser_unknown(source)
    parser_metrics, breakdowns, feedback = [], [], []
    profile_id = bundle["policy"]["default_validation_profile_id"]
    profile = bundle["policy"]["validation_profiles"][profile_id]
    parser_limit = int(budgets["maximum_parser_evaluations"])
    for index, result in enumerate(results):
        hypothesis = next(item for item in hypotheses if item["scope_hypothesis_id"] == result["descriptor"]["scope_hypothesis_id"])
        result["descriptor"]["measurement_refs"] = hypothesis["measurement_refs"]
        parser = None
        if index < parser_limit:
            try:
                after = _parser_unknown(result["artifact_bytes"])
                parser = {"descriptor_id": result["descriptor"]["descriptor_id"], "unknown_before": baseline_parser["unknown_bytes"], "unknown_after": after["unknown_bytes"], "before_snapshot_id": baseline_parser["snapshot_id"], "after_snapshot_id": after["snapshot_id"]}
            except Exception as exc:
                parser = {"descriptor_id": result["descriptor"]["descriptor_id"], "error_class": type(exc).__name__}
            parser_metrics.append(parser)
        context = {"source": source, "snapshot": snapshot, "hypothesis": hypothesis, "result": result, "parser_metrics": parser if parser and "unknown_before" in parser else None, "change_points": change_points, "profile": profile, "bundle": bundle}
        gates = []
        for gate_spec in bundle["registry"]["gates"]:
            if gate_spec["id"] not in profile["required_gate_ids"]:
                continue
            gate = _hook(gate_spec)(context)
            gates.append(gate)
            log.emit("gate_evaluated", {"descriptor_id": result["descriptor"]["descriptor_id"], "gate_id": gate["gate_id"], "status": gate["status"]}, "info" if gate["status"] == "passed" else "warning")
            feedback.extend({"descriptor_id": result["descriptor"]["descriptor_id"], "gate_id": gate["gate_id"], "request": request, "promotion_authority": False} for request in gate["next_evidence_requests"])
        eligible = all(item["status"] == "passed" for item in gates) if profile["require_all_gates_pass_for_promotion"] else any(item["status"] == "passed" for item in gates)
        breakdowns.append({"descriptor_id": result["descriptor"]["descriptor_id"], "validation_profile_id": profile_id, "gates": gates, "promotion_eligible": eligible, "terminal_reason": "all_required_gates_passed" if eligible else "mechanical_gates_not_satisfied"})
    promotion = any(item["promotion_eligible"] for item in breakdowns)
    terminal = "promotion_eligible" if promotion else ("rejected" if breakdowns else "exhausted")
    representation_metrics = [{"descriptor_id": item["descriptor"]["descriptor_id"], "window_results": item["window_results"]} for item in results]
    preserve_metrics = [{"descriptor_id": item["descriptor"]["descriptor_id"], "protected_span_count": len(item["descriptor"]["preserve_spans"])} for item in results]
    compatibility = [{"probe_id": item["probe_id"], "layout_signature": _digest({"length": item["length"]})[:16]} for item in plan]
    independent_sets = [{"set_id": _content_id("independent-set", [item["probe_id"]]), "probe_ids": [item["probe_id"]], "independent": True} for item in plan]
    gate_counts = dict(Counter(gate["status"] for item in breakdowns for gate in item["gates"]))
    gate_summary = {"counts": gate_counts, "descriptor_count": len(breakdowns), "promotion_eligible_count": sum(item["promotion_eligible"] for item in breakdowns)}
    checkpoint = {"run_id": run_id, "terminal_state": terminal, "completed_descriptor_ids": [item["descriptor"]["descriptor_id"] for item in results], "queued_descriptor_ids": [], "budget": {"descriptor_executions": len(results), "parser_evaluations": len(parser_metrics), "transformed_bytes": sum(item["transformed_bytes_debited"] for item in results), "log_events": log.sequence}, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "event_cursor": log.sequence - 1, "event_digest": log.previous_digest}
    progress = {"run_id": run_id, "phase": "terminal", "terminal_state": terminal, "promotion_eligible": promotion, "gate_counts": gate_counts, "checkpoint": bundle["policy"]["artifact_layout"]["checkpoint"], "budget": checkpoint["budget"]}
    serial_results = [{key: value for key, value in item.items() if key != "artifact_bytes"} for item in results]
    layout = bundle["policy"]["artifact_layout"]
    payloads = {
        "admission": admission, "observations": observations, "prior_feedback": prior_feedback, "roles": roles,
        "compatibility": compatibility, "independent_sets": independent_sets, "probe_plan": plan,
        "measurements": measurements, "change_points": change_points, "hypotheses": hypotheses,
        "descriptors": [item["descriptor"] for item in results], "results": serial_results,
        "representation_metrics": representation_metrics, "parser_metrics": parser_metrics,
        "preserve_metrics": preserve_metrics, "gate_breakdowns": breakdowns, "gate_summary": gate_summary,
        "feedback": feedback, "checkpoint": checkpoint, "progress": progress,
    }
    for name, value in payloads.items():
        _write(staging / layout[name], value)
    log.emit("checkpoint_committed", {"terminal_state": terminal, "completed_descriptors": len(results), "transformed_bytes": checkpoint["budget"]["transformed_bytes"]})
    log.emit("run_terminal", {"terminal_state": terminal, "promotion_eligible": promotion, "gate_counts": gate_counts})
    checkpoint["budget"]["log_events"] = log.sequence
    checkpoint["event_cursor"] = log.sequence - 1
    checkpoint["event_digest"] = log.previous_digest
    _write(staging / layout["checkpoint"], checkpoint)
    progress["budget"] = checkpoint["budget"]
    _write(staging / layout["progress"], progress)
    if hashlib.sha256(source_file.read_bytes()).hexdigest() != source_identity["sha256"]:
        raise RuntimeError("source changed during alternate-scope proof")
    final_paths = _safe_artifact_paths(final_root, layout)
    artifact_names = [name for name in layout if name not in {"run", "rolling_log"}]
    artifact_digests = {name: hashlib.sha256((staging / layout[name]).read_bytes()).hexdigest() for name in artifact_names}
    event_segments = sorted((staging / "logs").glob("events-*.jsonl"))
    for segment in event_segments:
        name = segment.stem
        final_paths[name] = str((final_root / "logs" / segment.name).resolve())
        artifact_digests[name] = hashlib.sha256(segment.read_bytes()).hexdigest()
    final_paths["rolling_log"] = str((final_root / layout["rolling_log"]).resolve())
    artifact_digests["rolling_log"] = hashlib.sha256((staging / layout["rolling_log"]).read_bytes()).hexdigest()
    run = {"schema_version": 1, "run_id": run_id, "source": source_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "terminal_state": terminal, "promotion_eligible": promotion, "source_preserved": True, "artifacts": {name: path for name, path in final_paths.items() if name != "run"}, "artifact_digests": artifact_digests, "run_root": str(final_root)}
    _validate("alternate_scope_run.schema.json", run)
    _write(staging / layout["run"], run)
    final_root.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, final_root)
    return run


def verify_alternate_scope_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve())
    _validate("alternate_scope_run.schema.json", run)
    root = Path(run["run_root"]).resolve()
    missing, mismatches, unsafe = [], [], []
    for name, raw in run["artifacts"].items():
        path = Path(raw).resolve()
        if root not in path.parents:
            unsafe.append(name)
        elif not path.is_file():
            missing.append(name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != run["artifact_digests"].get(name):
            mismatches.append(name)
    chain_ok, sequence, previous = True, 0, ""
    event_paths = sorted(Path(path) for name, path in run["artifacts"].items() if name.startswith("events-"))
    for path in event_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous:
                chain_ok = False
            previous = hashlib.sha256(_canonical(event)).hexdigest()
            sequence += 1
    return {"ok": not missing and not mismatches and not unsafe and chain_ok, "operation": "alternate_scope_run_verify", "run_id": run["run_id"], "missing_artifacts": missing, "digest_mismatches": mismatches, "unsafe_artifacts": unsafe, "event_chain_ok": chain_ok, "event_count": sequence, "terminal_state": run["terminal_state"], "promotion_eligible": run["promotion_eligible"], "source_preserved": run["source_preserved"]}


def inspect_alternate_scope_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve())
    verified = verify_alternate_scope_run(run_path)
    progress = _read(Path(run["artifacts"]["progress"]))
    summary = _read(Path(run["artifacts"]["gate_summary"]))
    roles = _read(Path(run["artifacts"]["roles"]))
    change_points = _read(Path(run["artifacts"]["change_points"]))
    overlay_ranges = []
    for role_name in ("preserve", "candidate_body", "validation"):
        overlay_ranges.extend({"offset": int(item["offset"]), "length": int(item["length"]), "class": role_name, "source_id": item.get("window_id") or item.get("probe_id"), "theme_token": f"binary_waterfall.{role_name}"} for item in roles.get(role_name) or [])
    waterfall_overlay = {"schema_version": 1, "run_id": run["run_id"], "ranges": overlay_ranges, "boundaries": [{"position": int(item["position"]), "uncertainty_start": int(item["uncertainty_start"]), "uncertainty_end": int(item["uncertainty_end"]), "source_id": item["change_point_id"], "theme_token": "binary_waterfall.boundary"} for item in change_points], "selection_contract": {"fields": ["run_id", "offset", "length", "source_id"]}}
    return {"operation": "alternate_scope_run_inspect", "run_id": run["run_id"], "verified": verified["ok"], "progress": progress, "gate_summary": summary, "waterfall_overlay": waterfall_overlay, "run_root": run["run_root"]}


def resume_alternate_scope_run(run_path: str | Path) -> Dict[str, Any]:
    verified = verify_alternate_scope_run(run_path)
    if not verified["ok"]:
        raise ValueError("cannot resume alternate-scope run with failed integrity")
    run = _read(Path(run_path).resolve())
    if run["terminal_state"] not in {"promotion_eligible", "rejected", "exhausted", "budget_exhausted", "blocked_by_policy", "failed_integrity"}:
        raise ValueError("non-terminal alternate-scope resume requires a registered continuation")
    return {**run, "resumed": True, "new_descriptor_executions": 0, "resume_reason": "terminal_checkpoint_reused"}
