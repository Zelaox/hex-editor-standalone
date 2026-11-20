"""Evidence-driven local transform regimes with lineage-safe materialization."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

import numpy as np
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


def _load_bundle(policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    policy = _read(Path(policy_path).resolve() if policy_path else _root() / "config" / "local_transform_policy.json")
    registry = _read(Path(registry_path).resolve() if registry_path else _root() / "config" / "local_transform_registry.json")
    required_policy = {"schema_version", "policy_id", "revision", "artifact_root", "scan", "parent_diff", "record_family", "materialization", "validation", "export", "objectives", "logging", "model_boundary", "export_promotion"}
    required_registry = {"schema_version", "registry_id", "revision", "transform_families", "aggregator", "materializer", "validator", "semantic_analyzers"}
    if set(policy) != required_policy or int(policy["schema_version"]) != 1:
        raise ValueError("invalid local transform policy")
    if set(registry) != required_registry or int(registry["schema_version"]) != 1:
        raise ValueError("invalid local transform registry")
    if not registry["transform_families"] or not registry["semantic_analyzers"]:
        raise ValueError("local transform registry is empty")
    scan = policy["scan"]
    if not 0 <= int(scan["transform_parameter_min"]) <= int(scan["transform_parameter_max"]) <= 255:
        raise ValueError("invalid transform parameter domain")
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry)}


def _hook(spec: Mapping[str, Any]):
    implementation = spec.get("impl") or spec
    function = getattr(importlib.import_module(str(implementation["module"])), str(implementation["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid local transform hook: {implementation}")
    return function


class EventLog:
    def __init__(self, path: Path, run_id: str, bundle: Mapping[str, Any]):
        self.path, self.run_id, self.bundle = path, run_id, bundle
        self.sequence, self.previous = 0, ""

    def emit(self, event_type: str, payload: Mapping[str, Any], turn_id: str) -> None:
        forbidden = set(self.bundle["policy"]["logging"]["redacted_fields"])
        clean = {key: value for key, value in payload.items() if key not in forbidden}
        base = {"schema_version": 1, "run_id": self.run_id, "turn_id": turn_id, "sequence": self.sequence, "timestamp_utc": datetime.now(timezone.utc).isoformat(), "component_id": "local-transform", "event_type": event_type, "payload": clean, "previous_event_digest": self.previous}
        event = {**base, "event_id": _cid("local-transform-event", base)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            if self.bundle["policy"]["logging"]["flush_after_event"]:
                handle.flush()
        self.previous = hashlib.sha256(_canonical(event)).hexdigest()
        self.sequence += 1


def apply_xor(data: bytes, parameter: int) -> bytes:
    return bytes(value ^ int(parameter) for value in data)


def compose_xor(left: int, right: int) -> int:
    return int(left) ^ int(right)


def invert_xor(parameter: int) -> int:
    return int(parameter)


def _printable_runs(data: bytes, minimum: int) -> List[Tuple[int, bytes]]:
    output, start = [], None
    for index, value in enumerate(data + b"\x00"):
        if index < len(data) and 32 <= value <= 126:
            start = index if start is None else start
        else:
            if start is not None and index - start >= minimum:
                output.append((start, data[start:index]))
            start = None
    return output


def _diff_spans(left: bytes, right: bytes) -> List[Dict[str, int]]:
    if len(left) != len(right):
        raise ValueError("diff inputs must have equal size")
    output, start = [], None
    for index in range(len(left) + 1):
        different = index < len(left) and left[index] != right[index]
        if different and start is None:
            start = index
        elif not different and start is not None:
            output.append({"offset": start, "length": index - start})
            start = None
    return output


def discover_parent_diff_xor(source: bytes, *, parent: bytes | None = None, family_id: str, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    if parent is None or len(parent) != len(source):
        return []
    diff_policy = bundle["policy"]["parent_diff"]
    scan = bundle["policy"]["scan"]
    minimum_span = int(diff_policy["minimum_span_bytes"])
    minimum_support = float(diff_policy["minimum_support_ratio"])
    maximum_spans = int(diff_policy["maximum_spans"])
    observations: List[Dict[str, Any]] = []
    for span in _diff_spans(source, parent)[:maximum_spans]:
        offset, length = int(span["offset"]), int(span["length"])
        if length < minimum_span:
            continue
        relation = _span_relation(source, parent, offset, length)
        if float(relation["support_ratio"]) < minimum_support:
            continue
        parameter = int(relation["parameter"])
        preview = apply_xor(parent[offset:offset + length], parameter)
        if preview != source[offset:offset + length]:
            continue
        raw_ratio = sum(32 <= value <= 126 for value in parent[offset:offset + length]) / max(1, length)
        decoded_ratio = sum(32 <= value <= 126 for value in preview) / max(1, length)
        structural_ratio = sum(32 <= value <= 126 or value == 0 for value in preview) / max(1, length)
        zero_ratio = sum(value == 0 for value in preview) / max(1, length)
        value = {
            "family_id": family_id,
            "parameter_hex": f"{parameter:02x}",
            "offset": offset,
            "length": length,
            "decoded_digest": hashlib.sha256(preview).hexdigest(),
            "bounded_preview": preview[: int(scan["maximum_preview_bytes"])].decode("ascii", errors="replace"),
            "printable_before": raw_ratio,
            "printable_after": decoded_ratio,
            "printable_gain": decoded_ratio - raw_ratio,
            "window_offset": offset,
            "structural_ratio": structural_ratio,
            "zero_ratio": zero_ratio,
            "window_length": length,
            "parent_diff_support_ratio": float(relation["support_ratio"]),
            "discovery_mode": "parent_diff_xor",
            "promotion_authority": False,
        }
        value["observation_id"] = _cid("local-transform-observation", value)
        observations.append(value)
    return sorted(observations, key=lambda item: (int(item["offset"]), -int(item["length"]), item["parameter_hex"]))


def discover_xor_windows(source: bytes, *, parent: bytes | None = None, family_id: str, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    del parent
    data = source
    scan = bundle["policy"]["scan"]
    window, step = int(scan["window_bytes"]), int(scan["step_bytes"])
    limit = min(len(data), int(scan["maximum_scan_bytes"]))
    minimum_run = int(scan["minimum_text_run_bytes"])
    keys = np.arange(int(scan["transform_parameter_min"]), int(scan["transform_parameter_max"]) + 1, dtype=np.uint8)
    printable_lookup = np.zeros(256, dtype=np.uint8); printable_lookup[32:127] = 1
    structural_lookup = printable_lookup.copy(); structural_lookup[0] = 1
    observations: Dict[Tuple[int, int, int], Dict[str, Any]] = {}
    for offset in range(0, max(1, limit - window + 1), step):
        raw = np.frombuffer(data[offset:offset + window], dtype=np.uint8)
        if not raw.size:
            continue
        raw_ratio = float(np.mean(printable_lookup[raw]))
        transformed = np.bitwise_xor(keys[:, None], raw[None, :])
        ratios = np.mean(printable_lookup[transformed], axis=1)
        structural_ratios = np.mean(structural_lookup[transformed], axis=1)
        zero_ratios = np.mean(transformed == 0, axis=1)
        ranking_scores = structural_ratios + zero_ratios * float(scan["zero_score_weight"])
        top_count = min(int(scan["top_parameters_per_window"]), ratios.size)
        indexes = np.argpartition(ranking_scores, -top_count)[-top_count:]
        for index in indexes[np.argsort(ranking_scores[indexes])[::-1]]:
            ratio = float(ratios[index])
            structural_ratio = float(structural_ratios[index])
            zero_ratio = float(zero_ratios[index])
            if ratio < float(scan["minimum_printable_ratio"]) or structural_ratio < float(scan["minimum_structural_ratio"]) or zero_ratio < float(scan["minimum_zero_ratio"]) or ratio - raw_ratio < float(scan["minimum_printable_gain"]):
                continue
            parameter = int(keys[index])
            preview = transformed[index].tobytes()
            for relative, decoded in _printable_runs(preview, minimum_run):
                absolute = offset + relative
                span_key = (absolute, len(decoded), parameter)
                value = {
                    "family_id": family_id, "parameter_hex": f"{parameter:02x}",
                    "offset": absolute, "length": len(decoded),
                    "decoded_digest": hashlib.sha256(decoded).hexdigest(),
                    "bounded_preview": decoded[: int(scan["maximum_preview_bytes"])].decode("ascii", errors="replace"),
                    "printable_before": raw_ratio, "printable_after": ratio,
                    "printable_gain": ratio - raw_ratio, "window_offset": offset,
                    "structural_ratio": structural_ratio, "zero_ratio": zero_ratio, "window_length": int(raw.size), "promotion_authority": False,
                }
                value["observation_id"] = _cid("local-transform-observation", value)
                current = observations.get(span_key)
                if current is None or float(value["printable_gain"]) > float(current["printable_gain"]):
                    observations[span_key] = value
    return sorted(observations.values(), key=lambda item: (int(item["offset"]), -int(item["length"]), item["parameter_hex"]))


def aggregate_record_families(observations: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    policy = bundle["policy"]["record_family"]
    fields = [str(item) for item in policy["group_fields"]]
    groups: Dict[Tuple[Any, ...], List[Mapping[str, Any]]] = {}
    for item in observations:
        groups.setdefault(tuple(item[field] for field in fields), []).append(item)
    output = []
    required = int(policy["minimum_independent_occurrences"])
    distance = int(policy["minimum_occurrence_distance_bytes"])
    maximum = int(policy["maximum_occurrences_per_family"])
    for key, items in groups.items():
        selected = []
        for item in sorted(items, key=lambda value: int(value["offset"])):
            if not selected or int(item["offset"]) - int(selected[-1]["offset"]) >= distance:
                selected.append(item)
            if len(selected) >= maximum:
                break
        if len(selected) < required:
            continue
        value = {"group_fields": dict(zip(fields, key)), "occurrence_ids": [item["observation_id"] for item in selected], "occurrences": [{"offset": int(item["offset"]), "length": int(item["length"]), "observation_id": item["observation_id"]} for item in selected], "independent_occurrence_count": len(selected), "promotion_authority": False}
        output.append({**value, "record_family_id": _cid("local-record-family", value)})
    if bool(policy.get("allow_singleton_parent_diff")):
        minimum_support = float(policy.get("singleton_parent_diff_minimum_support_ratio") or bundle["policy"]["parent_diff"]["minimum_support_ratio"])
        assigned = {occurrence_id for family in output for occurrence_id in family["occurrence_ids"]}
        singletons: Dict[Tuple[Any, ...], Mapping[str, Any]] = {}
        for item in observations:
            if str(item.get("observation_id") or "") in assigned:
                continue
            if str(item.get("discovery_mode") or "") != "parent_diff_xor":
                continue
            if float(item.get("parent_diff_support_ratio") or 0.0) < minimum_support:
                continue
            key = tuple(item[field] for field in fields)
            current = singletons.get(key)
            if current is None or int(item["offset"]) < int(current["offset"]):
                singletons[key] = item
        for key, item in sorted(singletons.items(), key=lambda entry: int(entry[1]["offset"])):
            value = {"group_fields": dict(zip(fields, key)), "occurrence_ids": [str(item["observation_id"])], "occurrences": [{"offset": int(item["offset"]), "length": int(item["length"]), "observation_id": str(item["observation_id"])}], "independent_occurrence_count": 1, "singleton_parent_diff": True, "promotion_authority": False}
            output.append({**value, "record_family_id": _cid("local-record-family", value)})
    return sorted(output, key=lambda item: (-int(item["independent_occurrence_count"]), item["record_family_id"]))


def _span_relation(source: bytes, parent: bytes, offset: int, length: int) -> Dict[str, Any]:
    relations = Counter(left ^ right for left, right in zip(source[offset:offset + length], parent[offset:offset + length]))
    parameter, count = relations.most_common(1)[0]
    return {"parameter": int(parameter), "support_ratio": count / max(1, length), "support_count": count}


def materialize_record_families(source: bytes, parent: bytes, families: Sequence[Mapping[str, Any]], observations: Mapping[str, Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    policy = bundle["policy"]["materialization"]
    output = bytearray(parent)
    scopes, changed = [], 0
    maximum_scopes = int(policy["maximum_scopes"])
    for family in families[: int(policy["maximum_families"])]:
        source_parameter = int(family["group_fields"]["parameter_hex"], 16)
        for occurrence in family["occurrences"]:
            if len(scopes) >= maximum_scopes:
                break
            offset, length = int(occurrence["offset"]), int(occurrence["length"])
            observation = observations[occurrence["observation_id"]]
            relation = _span_relation(source, parent, offset, length)
            before = bytes(output[offset:offset + length])
            if str(observation.get("discovery_mode") or "") == "parent_diff_xor":
                effective = int(relation["parameter"])
                after = apply_xor(before, effective)
                expected = source[offset:offset + length]
            else:
                source_parameter = int(family["group_fields"]["parameter_hex"], 16)
                effective = compose_xor(source_parameter, relation["parameter"])
                after = apply_xor(before, effective)
                expected = apply_xor(source[offset:offset + length], source_parameter)
            if after != expected:
                continue
            output[offset:offset + length] = after
            delta = sum(left != right for left, right in zip(before, after))
            changed += delta
            scopes.append({"offset": offset, "length": length, "record_family_id": family["record_family_id"], "observation_id": occurrence["observation_id"], "source_parameter_ref": observation["observation_id"], "parent_relation_hex": f"{relation['parameter']:02x}", "parent_relation_support": relation["support_ratio"], "effective_parameter_hex": f"{effective:02x}", "changed_bytes": delta, "discovery_mode": observation.get("discovery_mode") or "xor_window"})
    if changed > int(policy["maximum_changed_bytes"]):
        raise ValueError("local transform materialization changed-byte budget exceeded")
    descriptor = {"family_id": "local-record-family-composition", "parent_sha256": hashlib.sha256(parent).hexdigest(), "source_sha256": hashlib.sha256(source).hexdigest(), "scopes": scopes, "promotion_authority": False}
    descriptor["descriptor_id"] = _cid("local-materialization-descriptor", descriptor)
    return {"bytes": bytes(output), "descriptor": descriptor, "changed_bytes": changed}


def analyze_legacy_ptx(data: bytes, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    import tempfile
    from ptx_analyzer import PTXAnalyzer
    with tempfile.NamedTemporaryFile(suffix=".ptx", delete=False) as handle:
        handle.write(data); temporary = Path(handle.name)
    try:
        analyzer = PTXAnalyzer(str(temporary)); analyzer.analyze_header(); analyzer.find_sections(); analyzer.extract_strings(4); analyzer.analyze_key_offsets()
        return {"parser_sections": len(analyzer.sections), "timecode_count": len(analyzer.timecodes), "legacy_string_count": len(analyzer.strings)}
    finally:
        try: temporary.unlink()
        except OSError: pass


def analyze_runtime_snapshot(data: bytes, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    from src.plugins.ptx.runtime_analysis import build_ptx_snapshot
    from src.runtime.byte_source import ByteSource
    snapshot = build_ptx_snapshot(ByteSource.from_bytes(data)).to_dict()
    coverage = (snapshot.get("coverage_summary") or {}).get("bytes_by_class") or {}
    return {"runtime_nodes": len(snapshot.get("nodes") or []), "runtime_anchors": len(snapshot.get("anchors") or []), "unknown_bytes": int(coverage.get("unknown", 0)), "snapshot_id": snapshot["snapshot_id"]}


def _semantic_analysis(data: bytes, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    output = {}
    for analyzer in bundle["registry"]["semantic_analyzers"]:
        output[str(analyzer["id"])] = _hook(analyzer)(data, bundle=bundle)
    return output


def _independent_occurrences_passed(descriptor: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> bool:
    policy = bundle["policy"]["validation"]
    if not policy["require_independent_occurrences"]:
        return True
    scopes = list(descriptor.get("scopes") or [])
    if len(scopes) > 1:
        return True
    if len(scopes) == 1 and bool(bundle["policy"]["record_family"].get("allow_singleton_parent_diff")):
        scope = scopes[0]
        minimum_support = float(bundle["policy"]["record_family"].get("singleton_parent_diff_minimum_support_ratio") or bundle["policy"]["parent_diff"]["minimum_support_ratio"])
        return str(scope.get("discovery_mode") or "") == "parent_diff_xor" and float(scope.get("parent_relation_support") or 0.0) >= minimum_support
    return False


def validate_materialized_candidate(source: bytes, parent: bytes, candidate: bytes, descriptor: Mapping[str, Any], baseline: Mapping[str, Any], analysis: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    policy = bundle["policy"]["validation"]
    legacy_id = str(bundle["registry"]["semantic_analyzers"][0]["id"])
    base_legacy, candidate_legacy = baseline[legacy_id], analysis[legacy_id]
    gates = {
        "non_identity": (candidate != parent) if policy["require_non_identity"] else True,
        "source_preserved": hashlib.sha256(source).hexdigest() == descriptor["source_sha256"] if policy["require_source_preserved"] else True,
        "timecode_non_regression": int(candidate_legacy["timecode_count"]) >= int(base_legacy["timecode_count"]) if policy["require_timecode_non_regression"] else True,
        "parser_section_non_regression": int(candidate_legacy["parser_sections"]) >= int(base_legacy["parser_sections"]) if policy["require_parser_section_non_regression"] else True,
        "independent_occurrences": _independent_occurrences_passed(descriptor, bundle=bundle),
    }
    return {"gates": {key: "passed" if value else "failed" for key, value in gates.items()}, "passed": all(gates.values()), "promotion_eligible": False, "verified_decryption": False}


def _attach_export_promotion(source: bytes, candidate: bytes, validation: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    from src.services.export_promotion import resolve_export_promotion
    promotion = resolve_export_promotion(source, candidate, policy=bundle["policy"])
    merged = dict(validation)
    merged["promotion_eligible"] = bool(promotion["promotion_eligible"])
    merged["verified_decryption"] = bool(promotion["verified_decryption"])
    merged["promotion_reason"] = str(promotion.get("promotion_reason") or "")
    merged["reject_reasons"] = list(promotion.get("reject_reasons") or [])
    return merged


def run_local_transform_search(source_path: str | Path, *, parent_path: str | Path | None = None, output_root: str | Path | None = None, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = _load_bundle(policy_path, registry_path)
    source_file = Path(source_path).resolve(); parent_file = Path(parent_path).resolve() if parent_path else None
    source_identity = _identity(source_file); parent_identity = _identity(parent_file) if parent_file else None
    if parent_identity and parent_identity["size"] != source_identity["size"]:
        raise ValueError("local transform source and parent must have equal length")
    seed = {"source": source_identity, "parent": parent_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"]}
    run_id = _cid("local-transform-run", seed)
    default_root = _root().parent / str(bundle["policy"]["artifact_root"])
    root = (Path(output_root).resolve() if output_root else default_root) / run_id
    if root.exists():
        run_file = root / "run.json"
        if run_file.is_file() and verify_local_transform_run(run_file)["ok"]:
            return _read(run_file)
        raise ValueError(f"existing local transform run is invalid: {root}")
    root.mkdir(parents=True)
    log = EventLog(root / "logs" / "events.jsonl", run_id, bundle)
    source, parent = source_file.read_bytes(), parent_file.read_bytes() if parent_file else source_file.read_bytes()
    log.emit("discovery_started", {"source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"] if parent_identity else source_identity["sha256"]}, "turn-0001")
    observations = []
    for family in bundle["registry"]["transform_families"]:
        discover = _hook(family["discover"])
        kwargs: Dict[str, Any] = {"family_id": str(family["id"]), "bundle": bundle}
        if "parent" in inspect.signature(discover).parameters:
            kwargs["parent"] = parent
        observations.extend(discover(source, **kwargs))
    families = _hook(bundle["registry"]["aggregator"])(observations, bundle=bundle)
    _write(root / "turns" / "turn-0001" / "observations.json", observations)
    _write(root / "turns" / "turn-0001" / "record_families.json", families)
    log.emit("discovery_completed", {"observation_count": len(observations), "record_family_count": len(families)}, "turn-0001")
    selected_id, status = None, "evidence_exhausted"
    candidate_record = None
    if families:
        baseline = _semantic_analysis(parent, bundle=bundle)
        observation_map = {item["observation_id"]: item for item in observations}
        materialized = _hook(bundle["registry"]["materializer"])(source, parent, families, observation_map, bundle=bundle)
        candidate = materialized["bytes"]
        analysis = _semantic_analysis(candidate, bundle=bundle)
        validation = _hook(bundle["registry"]["validator"])(source, parent, candidate, materialized["descriptor"], baseline, analysis, bundle=bundle)
        validation = _attach_export_promotion(source, candidate, validation, bundle=bundle)
        candidate_id = _cid("local-transform-candidate", {"descriptor_id": materialized["descriptor"]["descriptor_id"], "sha256": hashlib.sha256(candidate).hexdigest()})
        candidate_root = root / "candidates" / candidate_id
        _write_bytes(candidate_root / "candidate.ptx", candidate)
        _write(candidate_root / "descriptor.json", materialized["descriptor"])
        _write(candidate_root / "analysis.json", analysis)
        _write(candidate_root / "validation.json", validation)
        manifest = {"schema_version": 1, "candidate_id": candidate_id, "status": "experimental_local_transform_candidate", "source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"] if parent_identity else source_identity["sha256"], "output_sha256": hashlib.sha256(candidate).hexdigest(), "changed_bytes": materialized["changed_bytes"], "descriptor_id": materialized["descriptor"]["descriptor_id"], "artifact_path": str(candidate_root / "candidate.ptx"), "verified_decryption": bool(validation["verified_decryption"]), "promotion_eligible": bool(validation["promotion_eligible"])}
        _write(candidate_root / "manifest.json", manifest)
        candidate_record = {**manifest, "analysis": analysis, "validation": validation, "supported_plaintext_bytes": sum(int(item["length"]) for item in materialized["descriptor"]["scopes"]), "record_family_count": len(families), "promotion_eligible": bool(validation["promotion_eligible"]), "verified_decryption": bool(validation["verified_decryption"])}
        _write(root / "turns" / "turn-0002" / "materialization.json", candidate_record)
        _write(root / "checkpoints" / "latest.json", {"turn_id": "turn-0002", "candidate_id": candidate_id, "descriptor_id": materialized["descriptor"]["descriptor_id"], "gate_statuses": validation["gates"]})
        log.emit("materialization_completed", {"candidate_id": candidate_id, "changed_bytes": materialized["changed_bytes"], "gate_statuses": validation["gates"]}, "turn-0002")
        if validation["passed"]:
            selected_id, status = candidate_id, "goal_satisfied"
    frontier = [candidate_record] if candidate_record else []
    _write(root / "final" / "frontier.json", frontier)
    _write(root / "final" / "decision.json", {
        "schema_version": 1,
        "status": status,
        "selected_candidate_id": selected_id,
        "promotion_eligible": bool(candidate_record.get("promotion_eligible")) if candidate_record else False,
        "verified_decryption": bool(candidate_record.get("verified_decryption")) if candidate_record else False,
        "reject_reasons": list((candidate_record or {}).get("validation", {}).get("reject_reasons") or []),
        "promotion_reason": str((candidate_record or {}).get("validation", {}).get("promotion_reason") or ""),
    })
    artifacts = {"observations": str(root / "turns" / "turn-0001" / "observations.json"), "record_families": str(root / "turns" / "turn-0001" / "record_families.json"), "frontier": str(root / "final" / "frontier.json"), "decision": str(root / "final" / "decision.json"), "checkpoint": str(root / "checkpoints" / "latest.json") if candidate_record else str(root / "final" / "decision.json"), "events": str(root / "logs" / "events.jsonl")}
    run = {"schema_version": 1, "run_id": run_id, "status": status, "source": source_identity, "parent": parent_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "run_root": str(root), "selected_candidate_id": selected_id, "artifacts": artifacts}
    schema = _read(_root() / "schemas" / "local_transform_run.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(run))
    if errors: raise ValueError(f"local transform run schema failure: {errors[0].message}")
    _write(root / "run.json", run)
    from src.services.learning_db import try_index_learning_db_on_run_complete

    try_index_learning_db_on_run_complete(root / "run.json", "local_transform")
    from src.services.proof_ledger import try_compile_proof_ledger_on_run_complete

    try_compile_proof_ledger_on_run_complete(root / "run.json", "local_transform")
    log.emit("run_completed", {"status": status, "selected_candidate_id": selected_id}, "turn-0002")
    return run


def verify_local_transform_run(run_path: str | Path) -> Dict[str, Any]:
    try:
        run = _read(Path(run_path).resolve())
        schema = _read(_root() / "schemas" / "local_transform_run.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(run))
        root = Path(run["run_root"]).resolve(); missing, unsafe = [], []
        for name, raw in run["artifacts"].items():
            path = Path(raw).resolve()
            if root not in path.parents: unsafe.append(name)
            elif not path.is_file(): missing.append(name)
        sequence, previous, chain_ok = 0, "", True
        for line in Path(run["artifacts"]["events"]).read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous: chain_ok = False
            previous = hashlib.sha256(_canonical(event)).hexdigest(); sequence += 1
        source_ok = _identity(Path(run["source"]["path"]))["sha256"] == run["source"]["sha256"]
        parent_ok = run["parent"] is None or _identity(Path(run["parent"]["path"]))["sha256"] == run["parent"]["sha256"]
        return {"ok": not errors and not missing and not unsafe and chain_ok and source_ok and parent_ok, "run_id": run.get("run_id"), "schema_errors": [item.message for item in errors], "missing_artifacts": missing, "unsafe_artifacts": unsafe, "event_chain_ok": chain_ok, "source_identity_ok": source_ok, "parent_identity_ok": parent_ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_local_transform_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve()); verified = verify_local_transform_run(run_path)
    observations = _read(Path(run["artifacts"]["observations"])); families = _read(Path(run["artifacts"]["record_families"])); frontier = _read(Path(run["artifacts"]["frontier"]))
    overlays = [{"offset": int(item["offset"]), "length": int(item["length"]), "class": "transform_preview_supported", "source_id": item["observation_id"], "record_family_id": next((family["record_family_id"] for family in families if item["observation_id"] in family["occurrence_ids"]), None), "theme_token": "binary_waterfall.transform_preview_supported"} for item in observations]
    return {"operation": "local_transform_run_inspect", "run_id": run["run_id"], "verified": verified["ok"], "status": run["status"], "frontier": frontier, "record_families": families, "waterfall_overlay": {"schema_version": 1, "ranges": overlays}, "run_root": run["run_root"]}


def build_local_transform_model_packet(run_path: str | Path) -> Dict[str, Any]:
    if not verify_local_transform_run(run_path)["ok"]: raise ValueError("local transform run failed integrity verification")
    run = _read(Path(run_path).resolve()); frontier = _read(Path(run["artifacts"]["frontier"]))
    candidates = [{"candidate_id": item["candidate_id"], "changed_bytes": item["changed_bytes"], "supported_plaintext_bytes": item["supported_plaintext_bytes"], "record_family_count": item["record_family_count"], "gate_statuses": item["validation"]["gates"], "promotion_authority": False} for item in frontier]
    eligible = [item["candidate_id"] for item in candidates if all(status == "passed" for status in item["gate_statuses"].values())]
    packet = {"schema_version": 1, "operation": "local_transform_model_packet", "run_id": run["run_id"], "run_verified": True, "candidates": candidates, "advisory_eligible_candidate_ids": eligible, "allowed_actions": ["rank_existing_candidate"], "model_role": "advisory_only", "mechanical_authority": True}
    from src.services.proof_ledger.delta_packet import attach_advisory_delta_context

    return attach_advisory_delta_context(packet, run_path, "local_transform")


def validate_local_transform_model_action(action: Mapping[str, Any], packet: Mapping[str, Any]) -> Dict[str, Any]:
    forbidden = {"offset", "start", "end", "key_hex", "candidate_hex", "promotion_eligible", "verified_decryption"}
    if forbidden.intersection(action): raise ValueError("model action contains forbidden authority fields")
    if set(action) != {"action", "candidate_id", "reason"} or action["action"] != "rank_existing_candidate": raise ValueError("model action is not registered")
    known = {item["candidate_id"] for item in packet["candidates"]}
    if action["candidate_id"] not in known: raise ValueError("model selected an unknown candidate")
    if action["candidate_id"] not in set(packet["advisory_eligible_candidate_ids"]): raise ValueError("model selected a mechanically ineligible candidate")
    if not isinstance(action["reason"], str) or not action["reason"].strip(): raise ValueError("model reason is missing")
    return dict(action)
