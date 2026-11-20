"""Mechanical multi-turn semantic scope search.

The engine composes byte ranges from declared inputs. Offsets are derived from
analyzer evidence and every materialized candidate carries a content-addressed
descriptor. Model output is deliberately absent from the authority path.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

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


def _write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(value)
    os.replace(temporary, path)


def _identity(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _load_bundle(policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "iterative_scope_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "iterative_scope_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    required_policy = {"schema_version", "policy_id", "revision", "artifact_root", "budgets", "text_analysis", "semantic_detectors", "scope_context", "objectives", "stop_policy", "model_boundary", "logging", "export_promotion"}
    required_registry = {"schema_version", "registry_id", "revision", "analyzers", "scope_strategies", "materializer", "frontier"}
    if set(policy) != required_policy or int(policy["schema_version"]) != 1:
        raise ValueError("invalid iterative scope policy")
    if set(registry) != required_registry or int(registry["schema_version"]) != 1:
        raise ValueError("invalid iterative scope registry")
    objective_ids = [str(item["id"]) for item in policy["objectives"]]
    if len(objective_ids) != len(set(objective_ids)) or not objective_ids:
        raise ValueError("iterative scope objectives must be non-empty and unique")
    if not policy["semantic_detectors"] or not registry["scope_strategies"]:
        raise ValueError("iterative scope detectors and strategies must be configured")
    return {"policy": policy, "registry": registry, "policy_digest": _digest(policy), "registry_digest": _digest(registry)}


def _hook(spec: Mapping[str, Any]):
    impl = spec["impl"]
    function = getattr(importlib.import_module(str(impl["module"])), str(impl["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid iterative scope hook: {impl}")
    return function


class EventLog:
    def __init__(self, path: Path, run_id: str, bundle: Mapping[str, Any]):
        self.path, self.run_id, self.bundle, self.sequence = path, run_id, bundle, 0
        self.previous_digest = ""

    def emit(self, event_type: str, payload: Mapping[str, Any], *, turn_id: str | None = None, level: str = "info") -> Dict[str, Any]:
        forbidden = set(self.bundle["policy"]["logging"]["redacted_fields"])
        clean = {key: value for key, value in payload.items() if key not in forbidden}
        base = {
            "schema_version": 1, "run_id": self.run_id, "turn_id": turn_id,
            "sequence": self.sequence, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "level": level, "event_type": event_type, "component_id": "iterative-scope",
            "payload": clean, "previous_event_digest": self.previous_digest,
        }
        event = {**base, "event_id": _content_id("iterative-event", base)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            if self.bundle["policy"]["logging"]["flush_after_event"]:
                handle.flush()
        self.previous_digest = hashlib.sha256(_canonical(event)).hexdigest()
        self.sequence += 1
        return event


def _accepted(value: int, text_policy: Mapping[str, Any]) -> bool:
    return value in set(int(item) for item in text_policy["accepted_control_bytes"]) or any(int(left) <= value <= int(right) for left, right in text_policy["accepted_byte_ranges"])


def _text_runs(data: bytes, text_policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    minimum = int(text_policy["minimum_run_bytes"])
    runs, start = [], None
    for index, value in enumerate(data + b"\x00"):
        if index < len(data) and _accepted(value, text_policy):
            start = index if start is None else start
            continue
        if start is not None and index - start >= minimum:
            raw = data[start:index]
            item = {"offset": start, "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            item["run_id"] = _content_id("text-run", item)
            runs.append(item)
        start = None
    return runs


def _semantic_spans(data: bytes, runs: Sequence[Mapping[str, Any]], detectors: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    matches = []
    for run in runs:
        start, length = int(run["offset"]), int(run["length"])
        text = data[start:start + length].decode("ascii", errors="ignore")
        for detector in detectors:
            flags = re.ASCII if "ASCII" in detector.get("flags", []) else 0
            for match in re.finditer(str(detector["pattern"]), text, flags):
                raw = match.group(0).encode("ascii", errors="ignore")
                value = {
                    "family": str(detector["family"]), "detector_id": str(detector["id"]),
                    "offset": start + match.start(), "length": len(raw),
                    "value_digest": hashlib.sha256(raw).hexdigest(), "text_run_id": run["run_id"],
                }
                matches.append({**value, "semantic_id": _content_id("semantic-span", value)})
    # Multiple registered detectors may describe the same bytes. Retain the
    # longest non-overlapping span per semantic family so metrics count evidence,
    # not detector implementations.
    selected: List[Dict[str, Any]] = []
    for item in sorted(matches, key=lambda value: (str(value["family"]), -int(value["length"]), int(value["offset"]))):
        start, end = int(item["offset"]), int(item["offset"]) + int(item["length"])
        overlaps = any(str(other["family"]) == str(item["family"]) and max(start, int(other["offset"])) < min(end, int(other["offset"]) + int(other["length"])) for other in selected)
        if not overlaps:
            selected.append(item)
    return sorted(selected, key=lambda value: (int(value["offset"]), str(value["family"])))


def _runtime_metrics(data: bytes) -> Dict[str, int]:
    try:
        from src.plugins.pe.runtime_analysis import build_pe_snapshot
        from src.runtime.byte_source import ByteSource
        snapshot = build_pe_snapshot(ByteSource.from_bytes(data)).to_dict()
        coverage = (snapshot.get("coverage_summary") or {}).get("bytes_by_class") or {}
        return {
            "parser_nodes": len(snapshot.get("nodes") or []),
            "parser_anchors": len(snapshot.get("anchors") or []),
            "unknown_bytes": int(coverage.get("unknown", 0)),
        }
    except Exception as exc:
        return {"parser_nodes": 0, "parser_anchors": 0, "unknown_bytes": len(data), "parser_error_digest": hashlib.sha256(str(exc).encode()).hexdigest()}


def analyze_candidate(data: bytes, *, bundle: Mapping[str, Any], include_runtime: bool = True) -> Dict[str, Any]:
    policy = bundle["policy"]
    runs = _text_runs(data, policy["text_analysis"])
    semantic = _semantic_spans(data, runs, policy["semantic_detectors"])
    families: Dict[str, int] = {}
    for item in semantic:
        families[item["family"]] = families.get(item["family"], 0) + 1
    runtime = _runtime_metrics(data) if include_runtime else {"parser_nodes": 0, "parser_anchors": 0, "unknown_bytes": len(data)}
    metrics = {
        "timecode_count": int(families.get("timecode", 0)),
        "text_bytes": sum(int(item["length"]) for item in runs),
        "text_run_count": len(runs),
        **runtime,
    }
    value = {"metrics": metrics, "text_runs": runs, "semantic_spans": semantic}
    return {**value, "analysis_id": _content_id("candidate-analysis", value)}


def _signal_key(item: Mapping[str, Any]) -> Tuple[str, str]:
    return str(item["family"]), str(item["value_digest"])


def _lost_gained(reference: Mapping[str, Any], alternative: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    def inventory(analysis: Mapping[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
        values = [dict(item) for item in analysis["semantic_spans"]]
        for run in analysis["text_runs"]:
            values.append({
                "family": "text", "detector_id": "mechanical-text-run",
                "offset": int(run["offset"]), "length": int(run["length"]),
                "value_digest": str(run["sha256"]), "text_run_id": str(run["run_id"]),
                "semantic_id": str(run["run_id"]),
            })
        return {_signal_key(item): item for item in values}

    left = inventory(reference)
    right = inventory(alternative)
    return {
        "lost": [dict(left[key]) for key in sorted(left.keys() - right.keys())],
        "gained": [dict(right[key]) for key in sorted(right.keys() - left.keys())],
        "retained": [dict(right[key]) for key in sorted(left.keys() & right.keys())],
    }


def _contextual_ranges(spans: Sequence[Mapping[str, Any]], size: int, policy: Mapping[str, Any]) -> List[List[Dict[str, Any]]]:
    context = policy["scope_context"]
    base = max(int(context["minimum_context_bytes"]), max((int(item["length"]) for item in spans), default=1))
    output = []
    for multiplier in context["multipliers"]:
        padding = min(int(context["maximum_context_bytes"]), base * int(multiplier))
        ranges = []
        for item in spans:
            start = max(0, int(item["offset"]) - padding)
            end = min(size, int(item["offset"]) + int(item["length"]) + padding)
            ranges.append({"offset": start, "length": end - start, "evidence_refs": [item["semantic_id"]]})
        output.append(_merge_ranges(ranges, int(context["merge_adjacent_gap_bytes"])))
    unique = {_digest(item): item for item in output if item}
    return list(unique.values())


def _merge_ranges(ranges: Sequence[Mapping[str, Any]], gap: int = 0) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    for item in sorted(ranges, key=lambda value: (int(value["offset"]), int(value["length"]))):
        start, end = int(item["offset"]), int(item["offset"]) + int(item["length"])
        refs = list(item.get("evidence_refs") or [])
        if not merged or start > int(merged[-1]["offset"]) + int(merged[-1]["length"]) + gap:
            merged.append({"offset": start, "length": end - start, "evidence_refs": refs})
        else:
            prior_end = int(merged[-1]["offset"]) + int(merged[-1]["length"])
            merged[-1]["length"] = max(prior_end, end) - int(merged[-1]["offset"])
            merged[-1]["evidence_refs"] = sorted(set(merged[-1]["evidence_refs"] + refs))
    return merged


def _descriptor(strategy_id: str, parent_id: str, donor_id: str, ranges: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    base = {"strategy_id": strategy_id, "parent_candidate_id": parent_id, "donor_candidate_id": donor_id, "ranges": list(ranges), "promotion_authority": False}
    return {**base, "descriptor_id": _content_id("iterative-descriptor", base)}


def derive_retain_descriptors(parent: Mapping[str, Any], donor: Mapping[str, Any], evidence: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    size = int(parent["size"])
    return [_descriptor("retain-lost-semantic-spans", parent["candidate_id"], donor["candidate_id"], ranges) for ranges in _contextual_ranges(evidence["lost"], size, bundle["policy"])]


def derive_adopt_descriptors(parent: Mapping[str, Any], donor: Mapping[str, Any], evidence: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    size = int(parent["size"])
    return [_descriptor("adopt-gained-semantic-spans", parent["candidate_id"], donor["candidate_id"], ranges) for ranges in _contextual_ranges(evidence["gained"], size, bundle["policy"])]


def materialize_descriptor(descriptor: Mapping[str, Any], candidates: Mapping[str, Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> bytes:
    del bundle
    parent = bytes(candidates[str(descriptor["parent_candidate_id"])] ["bytes"])
    donor = bytes(candidates[str(descriptor["donor_candidate_id"])] ["bytes"])
    if len(parent) != len(donor):
        raise ValueError("scope composition requires equal-length inputs")
    output = bytearray(parent)
    for item in descriptor["ranges"]:
        start, length = int(item["offset"]), int(item["length"])
        if start < 0 or length <= 0 or start + length > len(parent):
            raise ValueError("descriptor range is outside input bounds")
        output[start:start + length] = donor[start:start + length]
    return bytes(output)


def _objective_map(bundle: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {str(item["id"]): item for item in bundle["policy"]["objectives"]}


def _dominates(left: Mapping[str, Any], right: Mapping[str, Any], bundle: Mapping[str, Any]) -> bool:
    better = False
    for objective_id, objective in _objective_map(bundle).items():
        a, b = float(left["metrics"].get(objective_id, 0)), float(right["metrics"].get(objective_id, 0))
        if objective["direction"] == "maximize":
            if a < b:
                return False
            better = better or a > b
        else:
            if a > b:
                return False
            better = better or a < b
    return better


def pareto_frontier(candidates: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    output = []
    for candidate in candidates:
        if not any(other["candidate_id"] != candidate["candidate_id"] and _dominates(other, candidate, bundle) for other in candidates):
            output.append(dict(candidate))
    return sorted(output, key=lambda item: item["candidate_id"])


def _changed(source: bytes, candidate: bytes) -> int:
    return sum(left != right for left, right in zip(source, candidate)) + abs(len(source) - len(candidate))


def _candidate(candidate_id: str, data: bytes, analysis: Mapping[str, Any], source: bytes, *, parent_id: str | None, descriptor_id: str | None, reference_analysis: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    gained = len(_lost_gained(reference_analysis, analysis)["gained"]) if reference_analysis is not None else 0
    metrics = {**analysis["metrics"], "gained_semantic_count": gained, "changed_bytes": _changed(source, data)}
    return {"candidate_id": candidate_id, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "parent_candidate_id": parent_id, "descriptor_id": descriptor_id, "metrics": metrics, "analysis_id": analysis["analysis_id"], "bytes": data, "analysis": dict(analysis)}


def _public(candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in candidate.items() if key not in {"bytes", "analysis"}}


def _goal(frontier: Sequence[Mapping[str, Any]], source_metrics: Mapping[str, Any], alternative_metrics: Mapping[str, Any], bundle: Mapping[str, Any]) -> bool:
    stop = bundle["policy"]["stop_policy"]
    for item in frontier:
        metrics = item["metrics"]
        time_ok = not stop["require_timecode_recovery"] or int(metrics["timecode_count"]) >= int(source_metrics["timecode_count"])
        text_ok = not stop["require_plaintext_gain"] or int(metrics["gained_semantic_count"]) > 0
        parser_ok = not stop["require_parser_non_regression"] or int(metrics["parser_nodes"]) >= int(source_metrics["parser_nodes"])
        if time_ok and text_ok and parser_ok and item["candidate_id"] not in {"source", "alternative"}:
            return True
    return False


def run_iterative_scope_search(source_path: str | Path, alternative_path: str | Path, *, output_root: str | Path | None = None, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = _load_bundle(policy_path, registry_path)
    source_file, alternative_file = Path(source_path).resolve(), Path(alternative_path).resolve()
    source_identity, alternative_identity = _identity(source_file), _identity(alternative_file)
    if source_identity["size"] != alternative_identity["size"]:
        raise ValueError("iterative scope inputs must have equal length")
    run_seed = {"source": source_identity, "alternative": alternative_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"]}
    run_id = _content_id("iterative-scope-run", run_seed)
    configured_root = _root().parent / str(bundle["policy"]["artifact_root"])
    root = (Path(output_root).resolve() if output_root else configured_root) / run_id
    if root.exists():
        run_path = root / "run.json"
        if run_path.is_file() and verify_iterative_run(run_path)["ok"]:
            return _read(run_path)
        raise ValueError(f"existing iterative run is incomplete or invalid: {root}")
    root.mkdir(parents=True, exist_ok=False)
    log = EventLog(root / "logs" / "events.jsonl", run_id, bundle)
    source_data, alternative_data = source_file.read_bytes(), alternative_file.read_bytes()
    analyze = _hook(bundle["registry"]["analyzers"][0])
    log.emit("run_started", {"source_sha256": source_identity["sha256"], "alternative_sha256": alternative_identity["sha256"]})
    source_analysis = analyze(source_data, bundle=bundle, include_runtime=True)
    alternative_analysis = analyze(alternative_data, bundle=bundle, include_runtime=True)
    evidence = _lost_gained(source_analysis, alternative_analysis)
    _write(root / "baseline" / "source_analysis.json", source_analysis)
    _write(root / "baseline" / "alternative_analysis.json", alternative_analysis)
    _write(root / "evidence" / "semantic_delta.json", evidence)
    candidates: Dict[str, Dict[str, Any]] = {
        "source": _candidate("source", source_data, source_analysis, source_data, parent_id=None, descriptor_id=None, reference_analysis=source_analysis),
        "alternative": _candidate("alternative", alternative_data, alternative_analysis, source_data, parent_id=None, descriptor_id=None, reference_analysis=source_analysis),
    }
    frontier = pareto_frontier(list(candidates.values()), bundle=bundle)
    stable, total, status, turn_count = 0, 0, "evidence_exhausted", 0
    budgets = bundle["policy"]["budgets"]
    descriptors_seen = set()
    for turn_number in range(1, int(budgets["maximum_turns"]) + 1):
        turn_count, turn_id = turn_number, f"turn-{turn_number:04d}"
        turn_root = root / "turns" / turn_id
        descriptor_list = []
        source_record, alternative_record = candidates["source"], candidates["alternative"]
        for strategy in bundle["registry"]["scope_strategies"]:
            function = _hook(strategy)
            if str(strategy["id"]).startswith("retain"):
                descriptor_list.extend(function(alternative_record, source_record, evidence, bundle=bundle))
            else:
                descriptor_list.extend(function(source_record, alternative_record, evidence, bundle=bundle))
        descriptor_list = [item for item in descriptor_list if item["descriptor_id"] not in descriptors_seen]
        descriptor_list = descriptor_list[: int(budgets["maximum_candidates_per_turn"])]
        if not descriptor_list:
            status = "evidence_exhausted"
            break
        _write(turn_root / "hypothesis_descriptors.json", descriptor_list)
        created = []
        materialize = _hook(bundle["registry"]["materializer"])
        for descriptor in descriptor_list:
            if total >= int(budgets["maximum_total_candidates"]):
                status = "budget_exhausted"
                break
            descriptors_seen.add(descriptor["descriptor_id"])
            data = materialize(descriptor, candidates, bundle=bundle)
            candidate_id = _content_id("iterative-candidate", {"descriptor_id": descriptor["descriptor_id"], "sha256": hashlib.sha256(data).hexdigest()})
            if any(existing["sha256"] == hashlib.sha256(data).hexdigest() for existing in candidates.values()):
                continue
            analysis = analyze(data, bundle=bundle, include_runtime=False)
            candidate = _candidate(candidate_id, data, analysis, source_data, parent_id=descriptor["parent_candidate_id"], descriptor_id=descriptor["descriptor_id"], reference_analysis=source_analysis)
            if int(candidate["metrics"]["changed_bytes"]) > int(budgets["maximum_changed_bytes"]):
                continue
            candidates[candidate_id] = candidate
            created.append(candidate)
            total += 1
            candidate_root = root / "candidates" / candidate_id
            _write(candidate_root / "descriptor.json", descriptor)
            _write(candidate_root / "analysis.json", analysis)
            _write_bytes(candidate_root / "candidate.bin", data)
            manifest = {**_public(candidate), "source_sha256": source_identity["sha256"], "alternative_sha256": alternative_identity["sha256"], "status": "experimental_scope_candidate", "verified_decryption": False}
            _write(candidate_root / "manifest.json", manifest)
        prior_ids = {item["candidate_id"] for item in frontier}
        frontier = pareto_frontier(list(candidates.values()), bundle=bundle)
        frontier_ids = {item["candidate_id"] for item in frontier}
        stable = stable + 1 if frontier_ids == prior_ids else 0
        turn_summary = {"schema_version": 1, "turn_id": turn_id, "created_candidate_ids": [item["candidate_id"] for item in created], "frontier_candidate_ids": sorted(frontier_ids), "candidate_budget_used": total, "stable_frontier_turns": stable}
        _write(turn_root / "pareto_delta.json", turn_summary)
        _write(root / "checkpoints" / "latest.json", {**turn_summary, "descriptor_ids_seen": sorted(descriptors_seen)})
        log.emit("turn_completed", turn_summary, turn_id=turn_id)
        if _goal(frontier, source_analysis["metrics"], alternative_analysis["metrics"], bundle):
            status = "goal_satisfied"
            break
        if stable >= int(budgets["stable_frontier_turns"]):
            status = "frontier_stable"
            break
        if status == "budget_exhausted":
            break
    # Runtime-validate frontier candidates before final decision.
    for item in frontier:
        if item["candidate_id"] in {"source", "alternative"}:
            continue
        full = analyze(bytes(item["bytes"]), bundle=bundle, include_runtime=True)
        item["analysis"] = full
        item["analysis_id"] = full["analysis_id"]
        item["metrics"].update(full["metrics"])
        item["metrics"]["gained_semantic_count"] = len(_lost_gained(source_analysis, full)["gained"])
        item["metrics"]["changed_bytes"] = _changed(source_data, bytes(item["bytes"]))
        _write(root / "candidates" / item["candidate_id"] / "analysis.json", full)
    frontier = pareto_frontier(frontier, bundle=bundle)
    if status == "goal_satisfied" and not _goal(frontier, source_analysis["metrics"], alternative_analysis["metrics"], bundle):
        status = "frontier_stable"
    final_frontier = [{**_public(item), "artifact_path": str(root / "candidates" / item["candidate_id"] / "candidate.bin") if item["candidate_id"] not in {"source", "alternative"} else item["candidate_id"]} for item in frontier]
    _write(root / "final" / "frontier.json", final_frontier)
    promotion = {"promotion_eligible": False, "verified_decryption": False, "reject_reasons": ["no_export_candidate"]}
    for item in frontier:
        if item["candidate_id"] in {"source", "alternative"}:
            continue
        from src.services.export_promotion import resolve_export_promotion
        promotion = resolve_export_promotion(source_data, bytes(item["bytes"]), policy=bundle["policy"])
        break
    decision = {
        "schema_version": 1,
        "status": status,
        "promotion_eligible": bool(promotion["promotion_eligible"]),
        "verified_decryption": bool(promotion["verified_decryption"]),
        "frontier_candidate_ids": [item["candidate_id"] for item in frontier],
        "reason": "multi-objective mechanical search completed; cryptographic promotion requires independent proof",
        "reject_reasons": list(promotion.get("reject_reasons") or []),
        "promotion_reason": str(promotion.get("promotion_reason") or ""),
    }
    _write(root / "final" / "decision.json", decision)
    artifacts = {
        "source_analysis": str(root / "baseline" / "source_analysis.json"),
        "alternative_analysis": str(root / "baseline" / "alternative_analysis.json"),
        "semantic_delta": str(root / "evidence" / "semantic_delta.json"),
        "frontier": str(root / "final" / "frontier.json"),
        "decision": str(root / "final" / "decision.json"),
        "checkpoint": str(root / "checkpoints" / "latest.json"),
        "events": str(root / "logs" / "events.jsonl"),
    }
    run = {"schema_version": 1, "run_id": run_id, "status": status, "source": source_identity, "alternative": alternative_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "run_root": str(root), "frontier": [item["candidate_id"] for item in frontier], "turn_count": turn_count, "artifacts": artifacts}
    schema = _read(_root() / "schemas" / "iterative_scope_run.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(run))
    if errors:
        raise ValueError(f"iterative run schema failure: {errors[0].message}")
    _write(root / "run.json", run)
    log.emit("run_completed", {"status": status, "frontier": run["frontier"], "turn_count": turn_count})
    return run


def verify_iterative_run(run_path: str | Path) -> Dict[str, Any]:
    path = Path(run_path).resolve()
    try:
        run = _read(path)
        schema = _read(_root() / "schemas" / "iterative_scope_run.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(run))
        root = Path(run["run_root"]).resolve()
        unsafe, missing = [], []
        for name, raw in run["artifacts"].items():
            artifact = Path(raw).resolve()
            if root != artifact.parent and root not in artifact.parents:
                unsafe.append(name)
            elif not artifact.is_file():
                missing.append(name)
        chain_ok, sequence, previous = True, 0, ""
        event_path = Path(run["artifacts"]["events"])
        for line in event_path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous:
                chain_ok = False
            previous = hashlib.sha256(_canonical(event)).hexdigest()
            sequence += 1
        identities_ok = _identity(Path(run["source"]["path"]))["sha256"] == run["source"]["sha256"] and _identity(Path(run["alternative"]["path"]))["sha256"] == run["alternative"]["sha256"]
        return {"ok": not errors and not unsafe and not missing and chain_ok and identities_ok, "run_id": run.get("run_id"), "schema_errors": [item.message for item in errors], "unsafe_artifacts": unsafe, "missing_artifacts": missing, "event_chain_ok": chain_ok, "input_identities_ok": identities_ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def inspect_iterative_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve())
    verified = verify_iterative_run(run_path)
    frontier = _read(Path(run["artifacts"]["frontier"]))
    delta = _read(Path(run["artifacts"]["semantic_delta"]))
    ranges = []
    for state in ("lost", "gained", "retained"):
        ranges.extend({"offset": int(item["offset"]), "length": int(item["length"]), "class": f"semantic_{state}", "family": item["family"], "source_id": item["semantic_id"], "theme_token": f"binary_waterfall.semantic_{state}"} for item in delta[state])
    return {"operation": "iterative_scope_run_inspect", "run_id": run["run_id"], "verified": verified["ok"], "status": run["status"], "frontier": frontier, "waterfall_overlay": {"schema_version": 1, "ranges": ranges}, "run_root": run["run_root"]}


def build_iterative_model_packet(run_path: str | Path) -> Dict[str, Any]:
    run_file = Path(run_path).resolve()
    verified = verify_iterative_run(run_file)
    if not verified["ok"]:
        raise ValueError("iterative run failed integrity verification")
    run = _read(run_file)
    bundle = _load_bundle()
    if run["policy_digest"] != bundle["policy_digest"] or run["registry_digest"] != bundle["registry_digest"]:
        raise ValueError("iterative run policy or registry digest is not current")
    frontier = _read(Path(run["artifacts"]["frontier"]))
    options = [{"candidate_id": item["candidate_id"], "metrics": item["metrics"], "status": "experimental_scope_candidate", "promotion_authority": False} for item in frontier]
    objectives = list(bundle["policy"]["objectives"])
    def rank_key(item: Mapping[str, Any]):
        values = []
        for objective in objectives:
            value = float(item["metrics"].get(objective["id"], 0))
            values.append(-value if objective["direction"] == "maximize" else value)
        return tuple(values)
    eligible = [min(options, key=rank_key)["candidate_id"]] if options else []
    return {"schema_version": 1, "operation": "iterative_scope_model_packet", "run_id": run["run_id"], "run_verified": True, "terminal_status": run["status"], "allowed_actions": ["rank_frontier_candidate"], "candidates": options, "advisory_eligible_candidate_ids": eligible, "ranking_objective_ids": [item["id"] for item in objectives], "mechanical_authority": True, "model_role": "advisory_only"}


def validate_iterative_model_action(action: Mapping[str, Any], packet: Mapping[str, Any], *, policy_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = _load_bundle(policy_path)
    forbidden = set(bundle["policy"]["model_boundary"]["forbidden_fields"])
    if forbidden.intersection(action):
        raise ValueError("model action contains forbidden authority fields")
    if set(action) != {"action", "candidate_id", "reason"}:
        raise ValueError("model action fields do not match the registered contract")
    if action["action"] not in bundle["policy"]["model_boundary"]["allowed_actions"]:
        raise ValueError("model action is not registered")
    known = {str(item["candidate_id"]) for item in packet["candidates"]}
    if str(action["candidate_id"]) not in known:
        raise ValueError("model selected a candidate outside the mechanical packet")
    if str(action["candidate_id"]) not in set(packet["advisory_eligible_candidate_ids"]):
        raise ValueError("model selected a mechanically ineligible frontier candidate")
    if not isinstance(action["reason"], str) or not action["reason"].strip():
        raise ValueError("model action reason is missing")
    return dict(action)
