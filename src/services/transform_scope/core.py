"""Config-driven transform scope derivation, bounded execution, gates and logs."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
from collections import Counter
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


def _id(prefix: str, value: Any) -> str:
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
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise ValueError(f"{schema_name}: {errors[0].message}")


def load_scope_bundle(registry_path: str | Path | None = None, policy_path: str | Path | None = None) -> Dict[str, Any]:
    registry = _read(Path(registry_path).resolve() if registry_path else _root() / "config" / "transform_scope_registry.json")
    policy = _read(Path(policy_path).resolve() if policy_path else _root() / "config" / "transform_scope_policy.json")
    _validate("transform_scope_registry.schema.json", registry)
    _validate("transform_scope_policy.schema.json", policy)
    if int(registry["schema_version"]) != 1 or int(policy["schema_version"]) != 1:
        raise ValueError("unsupported transform scope schema version")
    profile_id = policy["default_validation_profile_id"]
    if profile_id not in policy["validation_profiles"]:
        raise ValueError("default transform validation profile missing")
    registered_gates = {item["id"] for item in registry["gates"]}
    unknown = set(policy["validation_profiles"][profile_id]["required_gate_ids"]) - registered_gates
    if unknown:
        raise ValueError(f"validation profile references unknown gates: {sorted(unknown)}")
    return {"registry": registry, "policy": policy, "registry_digest": _digest(registry), "policy_digest": _digest(policy)}


def _hook(spec: Mapping[str, Any]):
    impl = dict(spec.get("impl") or spec)
    module, name = str(impl.get("module") or ""), str(impl.get("callable") or "")
    function = getattr(importlib.import_module(module), name, None) if module and name else None
    if not callable(function):
        raise ValueError(f"invalid transform scope hook: {module}.{name}")
    return function


class EventLog:
    def __init__(self, root: Path, run_id: str, bundle: Mapping[str, Any]):
        self.root, self.run_id, self.bundle, self.sequence = root, run_id, bundle, 0
        layout = bundle["policy"]["artifact_layout"]
        self.jsonl, self.rolling = root / layout["events"], root / layout["rolling_log"]
        self.jsonl.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, payload: Mapping[str, Any], severity: str = "info", component_id: str = "transform-scope") -> Dict[str, Any]:
        allowed = set(self.bundle["policy"]["logging"]["levels"])
        if severity not in allowed:
            raise ValueError(f"unknown log severity: {severity}")
        maximum = int(self.bundle["policy"]["budgets"]["maximum_log_events"])
        if self.sequence >= maximum:
            raise ValueError("transform scope log event budget exceeded")
        forbidden = set(self.bundle["policy"]["logging"]["redacted_payload_fields"])
        clean = {key: value for key, value in payload.items() if key not in forbidden}
        event = {"schema_version": 1, "event_id": _id("event", {"run": self.run_id, "sequence": self.sequence, "type": event_type, "payload": clean}), "run_id": self.run_id, "sequence": self.sequence, "timestamp_utc": datetime.now(timezone.utc).isoformat(), "severity": severity, "event_type": event_type, "component_id": component_id, "payload": clean, "policy_digest": self.bundle["policy_digest"], "registry_digest": self.bundle["registry_digest"]}
        _validate("transform_scope_log_event.schema.json", event)
        with self.jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            if self.bundle["policy"]["logging"]["flush_after_event"]:
                handle.flush()
        with self.rolling.open("a", encoding="utf-8") as handle:
            handle.write(f"{event['timestamp_utc']} | {self.sequence} | {severity} | {event_type} | {json.dumps(clean, sort_keys=True, default=str)}\n")
        self.sequence += 1
        return event


def _printable(data: bytes) -> float:
    return sum(value in (9, 10, 13) or 32 <= value <= 126 for value in data) / max(1, len(data))


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()) if data else 0.0


def _bounded_window(offset: int, length: int, size: int, role: str, rule_id: str, evidence_refs: Sequence[str], maximum: int, minimum: int) -> Dict[str, Any] | None:
    start = max(0, min(int(offset), size))
    end = min(size, start + min(maximum, max(minimum, int(length))))
    if end <= start:
        return None
    descriptor = {"offset": start, "length": end - start, "role": role, "rule_id": rule_id, "evidence_refs": sorted(str(item) for item in evidence_refs)}
    return {"window_id": _id("probe-window", descriptor), **descriptor}


def derive_hint_windows(snapshot: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    budget = bundle["policy"]["budgets"]
    size = int(snapshot["source"]["size"])
    windows = []
    for item in observations:
        if item.get("kind") != "boundary_hint":
            continue
        radius = int(budget["hint_neighborhood_bytes"])
        window = _bounded_window(int(item["value"]) - radius // 2, radius, size, "case_hint", "case-hint-neighborhood", [item["observation_id"]], int(budget["maximum_window_bytes"]), int(budget["minimum_window_bytes"]))
        if window:
            windows.append(window)
    return windows


def derive_unknown_windows(snapshot: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del observations
    budget = bundle["policy"]["budgets"]
    size = int(snapshot["source"]["size"])
    output = []
    for region in snapshot.get("unknown_regions") or []:
        span = region.get("span") or {}
        window = _bounded_window(span.get("offset", 0), span.get("length", 0), size, "unknown_region", "unknown-region-boundaries", [str(region.get("region_id") or "")], int(budget["maximum_window_bytes"]), int(budget["minimum_window_bytes"]))
        if window:
            output.append(window)
    return output


def derive_preserve_windows(snapshot: Mapping[str, Any], observations: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del observations
    budget = bundle["policy"]["budgets"]
    size = int(snapshot["source"]["size"])
    output = []
    for span in snapshot.get("coverage") or []:
        if str(span.get("class") or "") not in {"verified", "known"}:
            continue
        window = _bounded_window(span.get("offset", 0), span.get("length", 0), size, "verified_known_coverage", "verified-known-coverage", list(span.get("node_ids") or []), int(budget["maximum_window_bytes"]), int(budget["minimum_window_bytes"]))
        if window:
            output.append(window)
    return output


def derive_boundaries(snapshot: Mapping[str, Any], windows: Sequence[Mapping[str, Any]], preserve: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    maximum = int(bundle["policy"]["budgets"]["maximum_boundaries"])
    values: Dict[int, List[str]] = {}
    for item in [*windows, *preserve]:
        values.setdefault(int(item["offset"]), []).append(item["window_id"])
        values.setdefault(int(item["offset"]) + int(item["length"]), []).append(item["window_id"])
    output = []
    for position, refs in sorted(values.items())[:maximum]:
        descriptor = {"position": position, "window_refs": sorted(refs), "rule_id": "window-and-coverage-boundaries", "promotion_allowed": False}
        output.append({"boundary_id": _id("boundary", descriptor), **descriptor})
    return output


def compile_scope_descriptors(source: bytes, observations: Sequence[Mapping[str, Any]], windows: Sequence[Mapping[str, Any]], preserve: Sequence[Mapping[str, Any]], boundaries: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del boundaries
    materials = [item for item in observations if item.get("kind") == "transform_candidate"]
    maximum = int(bundle["policy"]["budgets"]["maximum_descriptors"])
    descriptors = []
    preserve_spans = [{"offset": item["offset"], "length": item["length"], "window_id": item["window_id"]} for item in preserve]

    def subtract_preserve(offset: int, length: int) -> List[Dict[str, int]]:
        fragments = [(offset, offset + length)]
        for protected in preserve_spans:
            protected_start = int(protected["offset"])
            protected_end = protected_start + int(protected["length"])
            revised = []
            for start, end in fragments:
                if protected_end <= start or protected_start >= end:
                    revised.append((start, end))
                    continue
                if start < protected_start:
                    revised.append((start, protected_start))
                if protected_end < end:
                    revised.append((protected_end, end))
            fragments = revised
            if not fragments:
                break
        return [{"offset": start, "length": end - start} for start, end in fragments if end > start]

    for material in materials:
        key = bytes.fromhex(str(material["value_hex"]))
        if not key:
            raise ValueError("transform candidate material is empty")
        scopes = []
        evidence_refs = {material["observation_id"]}
        for window in windows:
            evidence_refs.update(window["evidence_refs"])
            for fragment in subtract_preserve(int(window["offset"]), int(window["length"])):
                scopes.append({**fragment, "window_id": window["window_id"]})
        unique_scopes = list({(item["offset"], item["length"], item["window_id"]): item for item in scopes}.values())
        if not unique_scopes:
            continue
        descriptor = {"family_id": "xor_repeating", "candidate_material_ref": material["observation_id"], "key_hex": key.hex(), "scopes": unique_scopes, "preserve_spans": preserve_spans, "evidence_refs": sorted(evidence_refs), "promotion_allowed": False}
        descriptor["descriptor_id"] = _id("compiled-transform", descriptor)
        descriptors.append(descriptor)
        if len(descriptors) >= maximum:
            return descriptors
    return descriptors


def execute_descriptors(source: bytes, descriptors: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    maximum_bytes = int(bundle["policy"]["budgets"]["maximum_transformed_bytes"])
    debited = 0
    output = []
    for descriptor in descriptors:
        artifact = bytearray(source)
        key = bytes.fromhex(str(descriptor["key_hex"]))
        window_results = []
        descriptor_debit = 0
        for scope in descriptor["scopes"]:
            start, length = int(scope["offset"]), int(scope["length"])
            debited += length
            if debited > maximum_bytes:
                return output
            descriptor_debit += length
            before = source[start:start + length]
            after = bytes(value ^ key[index % len(key)] for index, value in enumerate(before))
            artifact[start:start + length] = after
            window_results.append({"window_id": scope["window_id"], "offset": start, "length": length, "changed_byte_count": sum(left != right for left, right in zip(before, after)), "printable_ratio_before": _printable(before), "printable_ratio_after": _printable(after), "printable_gain": _printable(after) - _printable(before), "entropy_before": _entropy(before), "entropy_after": _entropy(after)})
        output.append({"descriptor_id": descriptor["descriptor_id"], "artifact_sha256": hashlib.sha256(artifact).hexdigest(), "artifact_bytes": bytes(artifact), "window_results": window_results, "transformed_bytes_debited": descriptor_debit})
    return output


def _gate(gate_id: str, passed: bool | None, measurements: Mapping[str, Any], failure_code: str, next_request: str) -> Dict[str, Any]:
    status = "passed" if passed is True else ("failed" if passed is False else "inconclusive")
    return {"gate_id": gate_id, "status": status, "measurements": dict(measurements), "failure_codes": [] if passed else [failure_code], "next_evidence_requests": [] if passed else [next_request]}


def gate_non_identity(context: Mapping[str, Any]) -> Dict[str, Any]:
    changed = sum(int(item["changed_byte_count"]) for item in context["result"]["window_results"])
    return _gate("non-identity", changed > 0, {"changed_byte_count": changed}, "identity_transform", "request_non_identity_candidate")


def gate_cross_window(context: Mapping[str, Any]) -> Dict[str, Any]:
    profile = context["profile"]
    improved = sum(float(item["printable_gain"]) >= float(profile["minimum_printable_gain"]) for item in context["result"]["window_results"])
    required = int(profile["minimum_independent_improved_windows"])
    return _gate("cross-window", improved >= required, {"improved_windows": improved, "required": required}, "insufficient_cross_window_agreement", "request_independent_windows")


def gate_preserve(context: Mapping[str, Any]) -> Dict[str, Any]:
    source, artifact = context["source"], context["result"]["artifact_bytes"]
    mutations = 0
    for span in context["descriptor"]["preserve_spans"]:
        start, length = int(span["offset"]), int(span["length"])
        mutations += source[start:start + length] != artifact[start:start + length]
    allowed = int(context["profile"]["maximum_preserve_mutations"])
    return _gate("preserve-regions", mutations <= allowed, {"mutated_preserve_regions": mutations, "maximum": allowed}, "preserve_region_mutated", "request_scope_split")


def gate_header(context: Mapping[str, Any]) -> Dict[str, Any]:
    source, artifact = context["source"], context["result"]["artifact_bytes"]
    snapshot = context["snapshot"]
    header_ranges = [item for item in snapshot.get("coverage") or [] if int(item.get("offset") or 0) == 0 and str(item.get("class") or "") in {"verified", "known"}]
    if not header_ranges:
        return _gate("header-compatible", None, {"header_ranges": 0}, "header_evidence_missing", "request_header_validation")
    compatible = all(source[: int(item["length"])] == artifact[: int(item["length"])] for item in header_ranges)
    return _gate("header-compatible", compatible, {"header_ranges": len(header_ranges)}, "header_mutated", "request_scope_split")


def gate_parser_coverage(context: Mapping[str, Any]) -> Dict[str, Any]:
    from src.plugins.ptx.runtime_analysis import build_ptx_snapshot
    from src.runtime.byte_source import ByteSource
    try:
        candidate = build_ptx_snapshot(ByteSource.from_bytes(context["result"]["artifact_bytes"])).to_dict()
    except Exception as exc:
        return _gate("parser-coverage", False, {"error_class": type(exc).__name__}, "parser_failed", "request_alternate_scope")
    before = int((context["snapshot"].get("coverage_summary") or {}).get("bytes_by_class", {}).get("unknown", 0))
    after = int((candidate.get("coverage_summary") or {}).get("bytes_by_class", {}).get("unknown", 0))
    gain = before - after
    required = int(context["profile"]["minimum_coverage_gain"])
    return _gate("parser-coverage", gain >= required, {"unknown_bytes_before": before, "unknown_bytes_after": after, "coverage_gain": gain, "required": required}, "coverage_regression", "request_alternate_scope")


def run_transform_scope_proof(source_path: str | Path, *, output_root: str | Path, candidate_hex: str, boundary_hint: int, registry_path: str | Path | None = None, policy_path: str | Path | None = None) -> Dict[str, Any]:
    source_file, output = Path(source_path).resolve(), Path(output_root).resolve()
    source = source_file.read_bytes()
    bundle = load_scope_bundle(registry_path, policy_path)
    from src.services.binary_runtime import analyze_binary_snapshot
    snapshot = analyze_binary_snapshot(source_file)["snapshot"]
    source_identity = {"sha256": hashlib.sha256(source).hexdigest(), "size": len(source), "snapshot_id": snapshot["snapshot_id"], "format_plugin": snapshot["format_plugin"]}
    observations = [{"observation_id": _id("observation", {"kind": "transform_candidate", "value_hex": candidate_hex, "source": source_identity["sha256"]}), "kind": "transform_candidate", "value_hex": candidate_hex, "promotion_authority": False}, {"observation_id": _id("observation", {"kind": "boundary_hint", "value": int(boundary_hint), "source": source_identity["sha256"]}), "kind": "boundary_hint", "value": int(boundary_hint), "promotion_authority": False}]
    run_id = _id("transform-scope-run", {"source": source_identity, "observations": observations, "policy": bundle["policy_digest"], "registry": bundle["registry_digest"]})
    run_root = output / run_id
    log = EventLog(run_root, run_id, bundle)
    log.emit("run_started", {"source_sha256": source_identity["sha256"], "source_size": len(source)})
    windows = []
    for rule in bundle["registry"]["window_derivers"]:
        windows.extend(_hook(rule)(snapshot, observations, bundle=bundle))
    unique = {item["window_id"]: item for item in windows}
    windows = list(unique.values())[: int(bundle["policy"]["budgets"]["maximum_windows"])]
    preserve = []
    for rule in bundle["registry"]["preserve_derivers"]:
        preserve.extend(_hook(rule)(snapshot, observations, bundle=bundle))
    log.emit("windows_derived", {"window_count": len(windows), "preserve_count": len(preserve)})
    boundaries = []
    for rule in bundle["registry"]["boundary_derivers"]:
        boundaries.extend(_hook(rule)(snapshot, windows, preserve, bundle=bundle))
    descriptors = _hook(bundle["registry"]["scope_compiler"])(source, observations, windows, preserve, boundaries, bundle=bundle)
    results = _hook(bundle["registry"]["executor"])(source, descriptors, bundle=bundle)
    profile_id = bundle["policy"]["default_validation_profile_id"]
    profile = bundle["policy"]["validation_profiles"][profile_id]
    result_by_id = {item["descriptor_id"]: item for item in results}
    breakdowns, feedback = [], []
    for descriptor in descriptors:
        result = result_by_id.get(descriptor["descriptor_id"])
        if not result:
            continue
        context = {"source": source, "snapshot": snapshot, "descriptor": descriptor, "result": result, "profile": profile}
        gates = []
        for gate in bundle["registry"]["gates"]:
            if gate["id"] in profile["required_gate_ids"]:
                gate_result = _hook(gate)(context)
                gates.append(gate_result)
                log.emit("gate_evaluated", {"descriptor_id": descriptor["descriptor_id"], "gate_id": gate["id"], "status": gate_result["status"]}, "warning" if gate_result["status"] != "passed" else "info")
        allowed = all(item["status"] == "passed" for item in gates) if profile["require_all_gates_pass_for_promotion"] else any(item["status"] == "passed" for item in gates)
        breakdown = {"descriptor_id": descriptor["descriptor_id"], "validation_profile_id": profile_id, "gates": gates, "promotion_allowed": allowed, "terminal_reason": "all_required_gates_passed" if allowed else "mechanical_gates_not_satisfied", "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"]}
        breakdowns.append(breakdown)
        feedback.extend({"descriptor_id": descriptor["descriptor_id"], "gate_id": item["gate_id"], "request": request} for item in gates for request in item["next_evidence_requests"])
    promoted = any(item["promotion_allowed"] for item in breakdowns)
    terminal = "promoted" if promoted else ("rejected" if breakdowns else "exhausted")
    layout = bundle["policy"]["artifact_layout"]
    artifacts = {layout["observations"]: observations, layout["windows"]: windows, layout["preserve"]: preserve, layout["boundaries"]: boundaries, layout["scopes"]: [{"scope_hypothesis_id": item["descriptor_id"], "scopes": item["scopes"], "preserve_spans": item["preserve_spans"], "promotion_allowed": False} for item in descriptors], layout["descriptors"]: descriptors, layout["window_results"]: [{key: value for key, value in item.items() if key != "artifact_bytes"} for item in results], layout["gate_breakdowns"]: breakdowns, layout["feedback"]: feedback}
    for relative, value in artifacts.items():
        _write(run_root / relative, value)
    checkpoint = {"run_id": run_id, "terminal_state": terminal, "completed_descriptor_ids": [item["descriptor_id"] for item in results], "budget": {"transformed_bytes": sum(item["transformed_bytes_debited"] for item in results)}, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"]}
    _write(run_root / layout["checkpoint"], checkpoint)
    log.emit("run_terminal", {"terminal_state": terminal, "descriptor_count": len(descriptors), "promotion_allowed": promoted})
    if hashlib.sha256(source_file.read_bytes()).hexdigest() != source_identity["sha256"]:
        raise RuntimeError("source changed during transform scope proof")
    artifact_paths = {name: str(run_root / relative) for name, relative in layout.items() if name not in {"events", "rolling_log", "run"}}
    artifact_digests = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in artifact_paths.items()}
    run = {"schema_version": 1, "run_id": run_id, "source": source_identity, "source_preserved": True, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "terminal_state": terminal, "promotion_allowed": promoted, "artifacts": artifact_paths, "artifact_digests": artifact_digests, "run_root": str(run_root)}
    _validate("transform_scope_run.schema.json", run)
    _write(run_root / layout["run"], run)
    return run


def verify_scope_run(run_path: str | Path) -> Dict[str, Any]:
    run_file = Path(run_path).resolve()
    run = _read(run_file)
    _validate("transform_scope_run.schema.json", run)
    missing = [name for name, path in run["artifacts"].items() if not Path(path).is_file()]
    mismatch = [name for name, path in run["artifacts"].items() if Path(path).is_file() and hashlib.sha256(Path(path).read_bytes()).hexdigest() != str((run.get("artifact_digests") or {}).get(name) or "")]
    return {"ok": not missing and not mismatch, "operation": "transform_scope_run_verify", "run_id": run["run_id"], "missing_artifacts": missing, "digest_mismatches": mismatch, "terminal_state": run["terminal_state"], "promotion_allowed": run["promotion_allowed"], "source_preserved": bool(run.get("source_preserved"))}


def resume_transform_scope_proof(run_path: str | Path) -> Dict[str, Any]:
    verified = verify_scope_run(run_path)
    if not verified["ok"]:
        raise ValueError("cannot resume transform scope run with failed artifact integrity")
    run = _read(Path(run_path).resolve())
    if run["terminal_state"] in {"promoted", "rejected", "exhausted", "budget_exhausted", "blocked_by_policy", "failed_integrity"}:
        return {**run, "resumed": True, "new_descriptor_executions": 0, "resume_reason": "terminal_checkpoint_reused"}
    raise ValueError("non-terminal resume requires a registered continuation state")
