"""Generic, policy-driven record-family proof and compositional materialization.

Runtime behavior is derived from registered hooks, input evidence and validated
policy. This module intentionally contains no format-, filename-, offset-, key-
or plaintext-specific facts.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

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
    implementation = spec.get("impl") or spec
    function = getattr(importlib.import_module(str(implementation["module"])), str(implementation["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid record-family hook: {implementation}")
    return function


def _strict_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise ValueError(f"invalid {label}: missing={missing}, extra={extra}")


def load_record_family_bundle(
    policy_path: str | Path | None = None,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "record_family_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "record_family_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    _strict_keys(policy, {"schema_version", "policy_id", "revision", "artifact_root", "seed", "neighborhood", "boundary", "family", "materialization", "validation", "objectives", "finding_ledger", "model_boundary"}, "record-family policy")
    _strict_keys(registry, {"schema_version", "registry_id", "revision", "seed_detectors", "boundary_strategies", "materializer", "semantic_analyzers", "coverage_handoff", "parser_learning_handoff"}, "record-family registry")
    if int(policy["schema_version"]) != 1 or int(registry["schema_version"]) != 1:
        raise ValueError("unsupported record-family schema version")
    if not registry["seed_detectors"] or not registry["boundary_strategies"] or not registry["semantic_analyzers"]:
        raise ValueError("record-family registry contains an empty required hook set")
    _strict_keys(policy["seed"], {"minimum_printable_run_bytes", "minimum_occurrences", "maximum_seed_bytes", "maximum_seeds", "maximum_occurrences_per_seed"}, "seed policy")
    _strict_keys(policy["neighborhood"], {"radii_bytes", "maximum_total_measured_bytes"}, "neighborhood policy")
    _strict_keys(
        policy["boundary"],
        {
            "minimum_shared_prefix_bytes",
            "minimum_shared_suffix_bytes",
            "minimum_invariant_prefix_bytes",
            "minimum_invariant_suffix_bytes",
            "maximum_envelope_bytes",
            "maximum_context_extension_bytes",
            "maximum_framing_scan_bytes",
            "holdout_boundary_strategy_preference",
            "negative_control_samples",
            "strategies",
        },
        "boundary policy",
    )
    _strict_keys(policy["family"], {"minimum_training_occurrences", "minimum_holdout_occurrences", "minimum_occurrence_distance_bytes", "maximum_families", "cluster_features"}, "family policy")
    _strict_keys(policy["materialization"], {"maximum_scopes_per_family", "maximum_changed_bytes_per_candidate", "maximum_combination_size", "maximum_candidates"}, "materialization policy")
    for name in ("minimum_printable_run_bytes", "minimum_occurrences", "maximum_seed_bytes", "maximum_seeds", "maximum_occurrences_per_seed"):
        if int(policy["seed"][name]) < 1:
            raise ValueError(f"seed.{name} must be positive")
    radii = [int(item) for item in policy["neighborhood"]["radii_bytes"]]
    if not radii or any(item < 1 for item in radii) or radii != sorted(set(radii)):
        raise ValueError("neighborhood.radii_bytes must be sorted unique positive integers")
    registered_boundaries = {str(item["id"]) for item in registry["boundary_strategies"]}
    configured_boundaries = {str(item) for item in policy["boundary"]["strategies"]}
    if not configured_boundaries.issubset(registered_boundaries):
        raise ValueError("policy references an unregistered boundary strategy")
    for collection in (registry["seed_detectors"], registry["boundary_strategies"], registry["semantic_analyzers"]):
        for spec in collection:
            _hook(spec)
    implementation_files = [Path(__file__).resolve()]
    implementation_digest = hashlib.sha256(b"".join(path.read_bytes() for path in implementation_files)).hexdigest()
    return {
        "policy": policy,
        "registry": registry,
        "policy_digest": _digest(policy),
        "registry_digest": _digest(registry),
        "implementation_digest": implementation_digest,
    }


class EventLog:
    def __init__(self, path: Path, run_id: str, bundle: Mapping[str, Any]):
        self.path, self.run_id, self.bundle = path, run_id, bundle
        self.sequence, self.previous = 0, ""
        if path.exists():
            path.unlink()

    def emit(self, event_type: str, payload: Mapping[str, Any], turn_id: str) -> None:
        base = {
            "schema_version": 1,
            "run_id": self.run_id,
            "turn_id": turn_id,
            "sequence": self.sequence,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "component_id": "record-family",
            "event_type": event_type,
            "payload": dict(payload),
            "previous_event_digest": self.previous,
        }
        event = {**base, "event_id": _cid("record-family-event", base)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            handle.flush()
        self.previous = hashlib.sha256(_canonical(event)).hexdigest()
        self.sequence += 1


def _printable_runs(data: bytes, minimum: int, maximum: int) -> List[Tuple[int, bytes]]:
    output: List[Tuple[int, bytes]] = []
    start: int | None = None
    for index, value in enumerate(data + b"\x00"):
        if index < len(data) and 32 <= value <= 126:
            start = index if start is None else start
            continue
        if start is not None and index - start >= minimum:
            run = data[start:index]
            if len(run) <= maximum:
                output.append((start, run))
        start = None
    return output


def detect_repeated_printable_seeds(data: bytes, *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    policy = bundle["policy"]["seed"]
    minimum = int(policy["minimum_printable_run_bytes"])
    maximum = int(policy["maximum_seed_bytes"])
    groups: MutableMapping[Tuple[int, str], List[Tuple[int, bytes]]] = {}
    for offset, value in _printable_runs(data, minimum, maximum):
        groups.setdefault((len(value), hashlib.sha256(value).hexdigest()), []).append((offset, value))
    required = int(policy["minimum_occurrences"])
    occurrence_limit = int(policy["maximum_occurrences_per_seed"])
    output: List[Dict[str, Any]] = []
    for (length, decoded_digest), members in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])):
        if len(members) < required:
            continue
        selected = members[:occurrence_limit]
        value = {
            "detector_id": "repeated-printable-runs",
            "length": length,
            "decoded_digest": decoded_digest,
            "occurrences": [{"offset": offset, "length": length} for offset, _ in selected],
            "independent_occurrence_count": len(selected),
            "bounded_preview": selected[0][1][:maximum].decode("ascii", errors="replace"),
            "promotion_authority": False,
        }
        value["seed_id"] = _cid("plaintext-seed", {key: val for key, val in value.items() if key != "bounded_preview"})
        output.append(value)
        if len(output) >= int(policy["maximum_seeds"]):
            break
    return output


def _common_extension(data: bytes, offsets: Sequence[int], *, direction: int, limit: int) -> bytes:
    result = bytearray()
    for distance in range(1, limit + 1):
        positions = [offset - distance if direction < 0 else offset + distance - 1 for offset in offsets]
        if any(position < 0 or position >= len(data) for position in positions):
            break
        values = {data[position] for position in positions}
        if len(values) != 1:
            break
        if direction < 0:
            result.insert(0, values.pop())
        else:
            result.append(values.pop())
    return bytes(result)


def measure_neighborhoods(data: bytes, seed: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    radii = [int(item) for item in bundle["policy"]["neighborhood"]["radii_bytes"]]
    budget = int(bundle["policy"]["neighborhood"]["maximum_total_measured_bytes"])
    consumed, output = 0, []
    for occurrence in seed["occurrences"]:
        offset, length = int(occurrence["offset"]), int(occurrence["length"])
        measurements = []
        for radius in radii:
            start, end = max(0, offset - radius), min(len(data), offset + length + radius)
            consumed += end - start
            if consumed > budget:
                raise RuntimeError("record-family neighborhood measurement budget exceeded")
            block = data[start:end]
            measurements.append({
                "radius": radius,
                "span": {"offset": start, "length": len(block)},
                "digest": hashlib.sha256(block).hexdigest(),
                "printable_ratio": sum(32 <= value <= 126 for value in block) / max(1, len(block)),
                "zero_ratio": block.count(0) / max(1, len(block)),
            })
        value = {"seed_id": seed["seed_id"], "occurrence": dict(occurrence), "measurements": measurements}
        value["neighborhood_id"] = _cid("occurrence-neighborhood", value)
        output.append(value)
    return output


def infer_shared_context_boundaries(data: bytes, seed: Mapping[str, Any], training: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    policy = bundle["policy"]["boundary"]
    extension_limit = _context_extension_limit(seed, policy)
    starts = [int(item["offset"]) for item in training]
    ends = [int(item["offset"]) + int(item["length"]) for item in training]
    left = _common_extension(data, starts, direction=-1, limit=extension_limit)
    right = _common_extension(data, ends, direction=1, limit=extension_limit)
    required_left = int(policy["minimum_shared_prefix_bytes"])
    required_right = int(policy["minimum_shared_suffix_bytes"])
    supported = len(left) >= required_left and len(right) >= required_right
    # Compile the least-specific policy-sufficient replay pattern. Maximal
    # training context is retained as a measurement, but using it as the rule
    # would overfit variant record fields immediately outside the seed.
    selected_left = left[-required_left:] if required_left else b""
    selected_right = right[:required_right] if required_right else b""
    value = {
        "strategy_id": "shared-context",
        "left_bytes": len(selected_left),
        "right_bytes": len(selected_right),
        "measured_shared_left_bytes": len(left),
        "measured_shared_right_bytes": len(right),
        "left_digest": hashlib.sha256(selected_left).hexdigest(),
        "right_digest": hashlib.sha256(selected_right).hexdigest(),
        "left_pattern_hex": selected_left.hex(),
        "right_pattern_hex": selected_right.hex(),
        "supported": supported,
        "falsifiers": [] if supported else ["insufficient_shared_context"],
    }
    value["boundary_hypothesis_id"] = _cid("boundary-hypothesis", value)
    return value


def measure_zero_terminator(data: bytes, seed: Mapping[str, Any], training: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    ends = [int(item["offset"]) + int(seed["length"]) for item in training]
    supported = bool(ends) and all(end < len(data) and data[end] == 0 for end in ends)
    value = {"strategy_id": "zero-terminator", "supported": supported, "terminator_width": 1 if supported else 0, "falsifiers": [] if supported else ["terminator_mismatch"]}
    value["boundary_hypothesis_id"] = _cid("boundary-hypothesis", value)
    return value


def measure_alignment_padding(data: bytes, seed: Mapping[str, Any], training: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del data, bundle
    ends = [int(item["offset"]) + int(seed["length"]) for item in training]
    residues = {end % alignment for alignment in (2, 4, 8, 16) for end in ends}
    value = {"strategy_id": "alignment-padding", "supported": len(residues) < max(1, len(ends) * 4), "measurement_digest": _digest(sorted(residues)), "falsifiers": []}
    value["boundary_hypothesis_id"] = _cid("boundary-hypothesis", value)
    return value


def _context_extension_limit(seed: Mapping[str, Any], policy: Mapping[str, Any]) -> int:
    maximum_envelope = int(policy["maximum_envelope_bytes"])
    configured = int(policy["maximum_context_extension_bytes"])
    framing_scan = int(policy["maximum_framing_scan_bytes"])
    derived = max(0, (maximum_envelope - int(seed["length"])) // 2)
    return max(0, min(configured, derived, framing_scan))


def _collect_invariant_positions(
    data: bytes,
    *,
    starts: Sequence[int],
    ends: Sequence[int],
    seed_length: int,
    limit: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    left_invariants: List[Dict[str, Any]] = []
    right_invariants: List[Dict[str, Any]] = []
    for distance in range(1, limit + 1):
        left_positions = [start - distance for start in starts]
        if any(position < 0 for position in left_positions):
            break
        left_values = {data[position] for position in left_positions}
        if len(left_values) != 1:
            break
        left_invariants.append({"relative_offset": -distance, "value": left_values.pop()})
    for distance in range(1, limit + 1):
        right_positions = [end + distance - 1 for end in ends]
        if any(position >= len(data) for position in right_positions):
            break
        right_values = {data[position] for position in right_positions}
        if len(right_values) != 1:
            break
        right_invariants.append({"relative_offset": seed_length + distance - 1, "value": right_values.pop()})
    return left_invariants, right_invariants


def infer_masked_invariant_boundaries(
    data: bytes,
    seed: Mapping[str, Any],
    training: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any],
) -> Dict[str, Any]:
    policy = bundle["policy"]["boundary"]
    extension_limit = _context_extension_limit(seed, policy)
    starts = [int(item["offset"]) for item in training]
    ends = [int(item["offset"]) + int(seed["length"]) for item in training]
    seed_length = int(seed["length"])
    left_invariants, right_invariants = _collect_invariant_positions(
        data,
        starts=starts,
        ends=ends,
        seed_length=seed_length,
        limit=extension_limit,
    )
    required_left = int(policy["minimum_invariant_prefix_bytes"])
    required_right = int(policy["minimum_invariant_suffix_bytes"])
    supported = len(left_invariants) >= required_left and len(right_invariants) >= required_right
    left_extent = max((abs(int(item["relative_offset"])) for item in left_invariants), default=0)
    right_extent = max(
        (int(item["relative_offset"]) - seed_length + 1 for item in right_invariants),
        default=0,
    )
    value = {
        "strategy_id": "masked-invariant-context",
        "left_bytes": left_extent,
        "right_bytes": right_extent,
        "left_invariants": left_invariants,
        "right_invariants": right_invariants,
        "measured_invariant_prefix_count": len(left_invariants),
        "measured_invariant_suffix_count": len(right_invariants),
        "invariant_mask_digest": _digest({"left": left_invariants, "right": right_invariants}),
        "supported": supported,
        "falsifiers": [] if supported else ["insufficient_invariant_context"],
    }
    value["boundary_hypothesis_id"] = _cid("boundary-hypothesis", value)
    return value


def _boundary_envelope_extents(boundary: Mapping[str, Any], *, seed_length: int) -> Tuple[int, int]:
    if str(boundary.get("strategy_id") or "") == "masked-invariant-context":
        left = max((abs(int(item["relative_offset"])) for item in boundary.get("left_invariants") or []), default=0)
        right = max(
            (int(item["relative_offset"]) - seed_length + 1 for item in boundary.get("right_invariants") or []),
            default=0,
        )
        return left, right
    return int(boundary.get("left_bytes") or 0), int(boundary.get("right_bytes") or 0)


def _select_holdout_boundary(hypotheses: Sequence[Mapping[str, Any]], preference: Sequence[str]) -> Mapping[str, Any]:
    by_id = {str(item["strategy_id"]): item for item in hypotheses}
    for strategy_id in preference:
        candidate = by_id.get(str(strategy_id))
        if candidate is not None and candidate.get("supported"):
            return candidate
    for item in hypotheses:
        if item.get("supported"):
            return item
    if not hypotheses:
        raise ValueError("record-family boundary inference produced no hypotheses")
    return hypotheses[0]


def _validate_holdout_exact(data: bytes, seed: Mapping[str, Any], holdout: Sequence[Mapping[str, Any]], boundary: Mapping[str, Any]) -> Dict[str, Any]:
    left = bytes.fromhex(str(boundary.get("left_pattern_hex") or ""))
    right = bytes.fromhex(str(boundary.get("right_pattern_hex") or ""))
    checks = []
    for item in holdout:
        offset, length = int(item["offset"]), int(item["length"])
        start, end = offset - len(left), offset + length + len(right)
        in_bounds = start >= 0 and end <= len(data)
        left_ok = in_bounds and data[start:offset] == left
        right_ok = in_bounds and data[offset + length:end] == right
        seed_ok = hashlib.sha256(data[offset:offset + length]).hexdigest() == seed["decoded_digest"]
        checks.append(
            {
                "occurrence": dict(item),
                "in_bounds": in_bounds,
                "left_replay": left_ok,
                "right_replay": right_ok,
                "seed_replay": seed_ok,
                "passed": in_bounds and left_ok and right_ok and seed_ok,
            }
        )
    return {"checks": checks, "passed": bool(checks) and all(item["passed"] for item in checks)}


def _validate_holdout_masked(data: bytes, seed: Mapping[str, Any], holdout: Sequence[Mapping[str, Any]], boundary: Mapping[str, Any]) -> Dict[str, Any]:
    left_invariants = list(boundary.get("left_invariants") or [])
    right_invariants = list(boundary.get("right_invariants") or [])
    checks = []
    for item in holdout:
        offset, length = int(item["offset"]), int(item["length"])
        in_bounds = True
        invariant_ok = True
        for invariant in left_invariants + right_invariants:
            position = offset + int(invariant["relative_offset"])
            if position < 0 or position >= len(data):
                in_bounds = False
                invariant_ok = False
                continue
            if data[position] != int(invariant["value"]):
                invariant_ok = False
        seed_ok = hashlib.sha256(data[offset:offset + length]).hexdigest() == seed["decoded_digest"]
        checks.append(
            {
                "occurrence": dict(item),
                "in_bounds": in_bounds,
                "invariant_replay": invariant_ok,
                "seed_replay": seed_ok,
                "passed": in_bounds and invariant_ok and seed_ok,
            }
        )
    return {"checks": checks, "passed": bool(checks) and all(item["passed"] for item in checks)}


def _validate_holdout(data: bytes, seed: Mapping[str, Any], holdout: Sequence[Mapping[str, Any]], boundary: Mapping[str, Any]) -> Dict[str, Any]:
    if str(boundary.get("strategy_id") or "") == "masked-invariant-context":
        return _validate_holdout_masked(data, seed, holdout, boundary)
    return _validate_holdout_exact(data, seed, holdout, boundary)


def _negative_control_checks(
    data: bytes,
    seed: Mapping[str, Any],
    training: Sequence[Mapping[str, Any]],
    holdout: Sequence[Mapping[str, Any]],
    boundary: Mapping[str, Any],
    *,
    sample_count: int,
) -> Dict[str, Any]:
    if sample_count <= 0:
        return {"samples": [], "false_positives": 0}
    seed_length = int(seed["length"])
    left, right = _boundary_envelope_extents(boundary, seed_length=seed_length)
    protected = set()
    for item in list(training) + list(holdout):
        offset = int(item["offset"])
        for position in range(max(0, offset - left), min(len(data), offset + seed_length + right)):
            protected.add(position)
    candidates = [index for index in range(len(data)) if index not in protected]
    if not candidates:
        return {"samples": [], "false_positives": 0}
    stride = max(1, len(candidates) // sample_count)
    samples = []
    false_positives = 0
    for index in range(0, min(len(candidates), sample_count * stride), stride):
        offset = candidates[index]
        synthetic = {"offset": offset, "length": seed_length}
        result = _validate_holdout(data, seed, [synthetic], boundary)
        passed = bool(result["checks"]) and result["checks"][0]["passed"]
        if passed:
            false_positives += 1
        samples.append({"offset": offset, "passed": passed})
    return {"samples": samples, "false_positives": false_positives}


def measure_transform_lane_consistency(
    source: bytes,
    parent: bytes,
    scopes: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    lanes = set()
    lanes_by_family: Dict[str, set[int]] = {}
    for scope in scopes:
        family_id = str(scope.get("family_id") or "unassigned")
        family_lanes = lanes_by_family.setdefault(family_id, set())
        offset, length = int(scope["offset"]), int(scope["length"])
        for position in range(offset, offset + length):
            lane = int(source[position]) ^ int(parent[position])
            lanes.add(lane)
            family_lanes.add(lane)
    family_results = {
        family_id: {"lane_count": len(values), "lanes": sorted(values), "supported": len(values) <= 1}
        for family_id, values in sorted(lanes_by_family.items())
    }
    return {
        "supported": all(item["supported"] for item in family_results.values()),
        "lane_count": len(lanes),
        "lanes": sorted(lanes),
        "families": family_results,
    }


def build_family_proofs(data: bytes, seeds: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    policy = bundle["policy"]["family"]
    required_training = int(policy["minimum_training_occurrences"])
    required_holdout = int(policy["minimum_holdout_occurrences"])
    families, proofs, boundaries = [], [], []
    enabled = set(bundle["policy"]["boundary"]["strategies"])
    boundary_hooks = {str(spec["id"]): _hook(spec) for spec in bundle["registry"]["boundary_strategies"]}
    for seed in seeds[: int(policy["maximum_families"])]:
        occurrences = sorted(seed["occurrences"], key=lambda item: int(item["offset"]))
        if len(occurrences) < required_training + required_holdout:
            continue
        holdout = occurrences[-required_holdout:]
        training = occurrences[:-required_holdout]
        hypotheses = [boundary_hooks[strategy](data, seed, training, bundle=bundle) for strategy in sorted(enabled)]
        preference = list(bundle["policy"]["boundary"]["holdout_boundary_strategy_preference"])
        holdout_boundary = _select_holdout_boundary(hypotheses, preference)
        holdout_result = _validate_holdout(data, seed, holdout, holdout_boundary)
        negative = _negative_control_checks(
            data,
            seed,
            training,
            holdout,
            holdout_boundary,
            sample_count=int(bundle["policy"]["boundary"]["negative_control_samples"]),
        )
        left_extent, right_extent = _boundary_envelope_extents(holdout_boundary, seed_length=int(seed["length"]))
        occurrence_values = []
        for role, members in (("training", training), ("holdout", holdout)):
            for item in members:
                occurrence = {"seed_id": seed["seed_id"], "offset": int(item["offset"]), "length": int(item["length"]), "role": role}
                occurrence["occurrence_id"] = _cid("record-occurrence", occurrence)
                occurrence_values.append(occurrence)
        family_base = {
            "seed_id": seed["seed_id"],
            "normalized_layout": {
                "seed_relative_offset": left_extent,
                "seed_length": int(seed["length"]),
                "envelope_length": left_extent + int(seed["length"]) + right_extent,
                "boundary_strategy_id": holdout_boundary["strategy_id"],
                "invariant_mask_digest": holdout_boundary.get("invariant_mask_digest"),
            },
            "boundary_hypothesis_ids": [item["boundary_hypothesis_id"] for item in hypotheses],
            "occurrence_ids": [item["occurrence_id"] for item in occurrence_values],
            "counterexamples": [item for item in holdout_result["checks"] if not item["passed"]],
            "promotion_authority": False,
        }
        family_id = _cid("record-family", family_base)
        family = {**family_base, "family_id": family_id, "occurrences": occurrence_values}
        state = "holdout_passed" if holdout_boundary["supported"] and holdout_result["passed"] else "falsified"
        proof_base = {
            "schema_version": 1,
            "family_id": family_id,
            "state": state,
            "training_occurrence_ids": [item["occurrence_id"] for item in occurrence_values if item["role"] == "training"],
            "holdout_occurrence_ids": [item["occurrence_id"] for item in occurrence_values if item["role"] == "holdout"],
            "boundary": holdout_boundary,
            "validation": {
                "boundary_supported": holdout_boundary["supported"],
                "holdout": holdout_result,
                "negative_control": negative,
                "negative_control_false_positives": int(negative["false_positives"]),
            },
            "promotion_authority": False,
        }
        proof = {**proof_base, "proof_id": _cid("record-family-proof", proof_base)}
        families.append(family); proofs.append(proof); boundaries.extend(hypotheses)
    return families, proofs, boundaries


def _diff_runs(parent: bytes, source: bytes, start: int, end: int) -> List[Tuple[int, int]]:
    output: List[Tuple[int, int]] = []
    run_start: int | None = None
    for position in range(start, end + 1):
        different = position < end and parent[position] != source[position]
        if different and run_start is None:
            run_start = position
        elif not different and run_start is not None:
            output.append((run_start, position - run_start)); run_start = None
    return output


def compile_family_scopes(source: bytes, parent: bytes, family: Mapping[str, Any], proof: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    maximum = int(bundle["policy"]["materialization"]["maximum_scopes_per_family"])
    seed_length = int(family["normalized_layout"]["seed_length"])
    left, right = _boundary_envelope_extents(proof["boundary"], seed_length=seed_length)
    output = []
    for occurrence in family["occurrences"]:
        start = max(0, int(occurrence["offset"]) - left)
        end = min(len(source), int(occurrence["offset"]) + int(occurrence["length"]) + right)
        for offset, length in _diff_runs(parent, source, start, end):
            value = {"offset": offset, "length": length, "family_id": family["family_id"], "proof_id": proof["proof_id"], "source_bytes_digest": hashlib.sha256(source[offset:offset + length]).hexdigest(), "parent_bytes_digest": hashlib.sha256(parent[offset:offset + length]).hexdigest()}
            value["scope_id"] = _cid("family-scope", value)
            output.append(value)
            if len(output) > maximum:
                raise RuntimeError("record-family scope budget exceeded")
    return output


def materialize_family_set(source: bytes, parent: bytes, scopes: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    output = bytearray(parent)
    inverse = []
    changed = 0
    for scope in sorted(scopes, key=lambda item: (int(item["offset"]), int(item["length"]), str(item["scope_id"]))):
        offset, length = int(scope["offset"]), int(scope["length"])
        if offset < 0 or length < 1 or offset + length > len(source):
            raise ValueError("compiled family scope is outside the source")
        intended = source[offset:offset + length]
        existing = bytes(output[offset:offset + length])
        if hashlib.sha256(intended).hexdigest() != scope["source_bytes_digest"]:
            raise ValueError("source bytes no longer match family scope")
        overlap = [item for item in inverse if not (offset + length <= item["offset"] or item["offset"] + item["length"] <= offset)]
        if overlap and existing != intended:
            raise ValueError("incompatible record-family scope overlap")
        output[offset:offset + length] = intended
        delta = sum(left != right for left, right in zip(existing, intended))
        changed += delta
        inverse.append({"offset": offset, "length": length, "bytes_hex": existing.hex(), "scope_id": scope["scope_id"]})
    if changed > int(bundle["policy"]["materialization"]["maximum_changed_bytes_per_candidate"]):
        raise RuntimeError("record-family changed-byte budget exceeded")
    return {"bytes": bytes(output), "inverse": inverse, "changed_bytes": changed}


def _revert(candidate: bytes, inverse: Sequence[Mapping[str, Any]]) -> bytes:
    output = bytearray(candidate)
    for item in reversed(list(inverse)):
        offset, length = int(item["offset"]), int(item["length"])
        value = bytes.fromhex(str(item["bytes_hex"]))
        if len(value) != length:
            raise ValueError("invalid inverse descriptor")
        output[offset:offset + length] = value
    return bytes(output)


def analyze_generic_bytes(data: bytes, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del bundle
    runs = _printable_runs(data, 1, max(1, len(data)))
    printable_bytes = sum(32 <= value <= 126 for value in data)
    return {"size": len(data), "printable_bytes": printable_bytes, "printable_run_count": len(runs), "unknown_bytes": len(data)}


def _semantic_analysis(data: bytes, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    return {str(spec["id"]): _hook(spec)(data, bundle=bundle) for spec in bundle["registry"]["semantic_analyzers"]}


def _validate_candidate(source: bytes, parent: bytes, candidate: bytes, scopes: Sequence[Mapping[str, Any]], inverse: Sequence[Mapping[str, Any]], baseline: Mapping[str, Any], analysis: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    validation = bundle["policy"]["validation"]
    analyzer_id = str(bundle["registry"]["semantic_analyzers"][0]["id"])
    gates = {
        "source_preserved": True,
        "parent_preserved": True,
        "size_preserved": len(candidate) == len(parent) if validation["require_size_preserved"] else True,
        "inverse_replay": _revert(candidate, inverse) == parent if validation["require_inverse_replay"] else True,
        "scope_confinement": all(candidate[index] == parent[index] for index in range(len(parent)) if not any(int(scope["offset"]) <= index < int(scope["offset"]) + int(scope["length"]) for scope in scopes)),
        "printable_non_regression": int(analysis[analyzer_id]["printable_bytes"]) >= int(baseline[analyzer_id]["printable_bytes"]) if validation["require_printable_non_regression"] else True,
    }
    statuses = {key: "passed" if value else "failed" for key, value in gates.items()}
    return {"passed": all(gates.values()), "gates": statuses}


def _dominates(left: Mapping[str, Any], right: Mapping[str, Any], objectives: Sequence[Mapping[str, Any]]) -> bool:
    better = False
    for objective in objectives:
        key, direction = str(objective["id"]), str(objective["direction"])
        lv, rv = int(left["objectives"].get(key, 0)), int(right["objectives"].get(key, 0))
        if direction == "maximize":
            if lv < rv: return False
            better = better or lv > rv
        elif direction == "minimize":
            if lv > rv: return False
            better = better or lv < rv
        else:
            raise ValueError(f"unsupported objective direction: {direction}")
    return better


def pareto_frontier(candidates: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    objectives = bundle["policy"]["objectives"]
    return [dict(candidate) for candidate in candidates if not any(other["candidate_id"] != candidate["candidate_id"] and _dominates(other, candidate, objectives) for other in candidates)]


class FindingLedger:
    def __init__(self, root: Path, bundle: Mapping[str, Any]):
        self.root, self.bundle = root, bundle
        self.records: List[Dict[str, Any]] = []
        self.schema = _read(_root() / "schemas" / "finding_record.schema.json")

    def add(self, *, kind: str, state: str, source_sha256: str, span: Mapping[str, Any], producer: Mapping[str, Any], evidence_refs: Sequence[str], summary: str, counterexample_refs: Sequence[str] = (), supersedes: Sequence[str] = (), authority: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        maximum = int(self.bundle["policy"]["finding_ledger"]["maximum_summary_chars"])
        base = {"schema_version": 1, "kind": kind, "state": state, "source_sha256": source_sha256, "span": {"offset": int(span["offset"]), "length": int(span["length"])}, "producer": dict(producer), "evidence_refs": sorted(set(evidence_refs)), "counterexample_refs": sorted(set(counterexample_refs)), "supersedes": sorted(set(supersedes)), "summary": summary[:maximum], "authority": dict(authority or {"promotion": False})}
        record = {**base, "finding_id": _cid("finding", base)}
        errors = list(Draft202012Validator(self.schema).iter_errors(record))
        if errors: raise ValueError(f"finding schema failure: {errors[0].message}")
        path = self.root / "records" / record["finding_id"][:2] / f"{record['finding_id']}.json"
        if not path.exists(): _write(path, record)
        self.records.append(record)
        return record

    def rebuild_indexes(self) -> None:
        all_records = []
        for path in sorted((self.root / "records").glob("*/*.json")):
            all_records.append(_read(path))
        indexes: Dict[str, Dict[str, List[str]]] = {"by_source": {}, "by_state": {}, "by_kind": {}, "by_run": {}}
        for item in all_records:
            for index_name, key in (("by_source", item["source_sha256"]), ("by_state", item["state"]), ("by_kind", item["kind"]), ("by_run", str(item["producer"].get("run_id") or "unknown"))):
                indexes[index_name].setdefault(key, []).append(item["finding_id"])
        for name, value in indexes.items(): _write(self.root / "indexes" / f"{name}.json", value)
        _write(self.root / "checkpoints" / "latest.json", {"schema_version": 1, "record_count": len(all_records), "index_digest": _digest(indexes)})


def build_coverage_handoff(source: bytes, families: Sequence[Mapping[str, Any]], proofs: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del source, bundle
    passed = {item["family_id"]: item for item in proofs if item["state"] == "holdout_passed"}
    proposals = []
    for family in families:
        if family["family_id"] not in passed: continue
        spans = [{"offset": int(item["offset"]), "length": int(item["length"])} for item in family["occurrences"]]
        value = {"family_id": family["family_id"], "proof_id": passed[family["family_id"]]["proof_id"], "claimed_spans": spans, "proposed_class": "record_family_candidate", "coverage_mutated": False, "review_required": True}
        proposals.append({**value, "proposal_id": _cid("coverage-ownership-proposal", value)})
    return {"schema_version": 1, "operation": "coverage_handoff", "proposals": proposals, "coverage_mutated": False}


def build_parser_learning_handoff(source: bytes, families: Sequence[Mapping[str, Any]], proofs: Sequence[Mapping[str, Any]], *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    del source, bundle
    passed = {item["family_id"]: item for item in proofs if item["state"] == "holdout_passed"}
    candidates = []
    for family in families:
        proof = passed.get(family["family_id"])
        if not proof: continue
        declaration = {"layout": family["normalized_layout"], "boundary_strategy_id": proof["boundary"]["strategy_id"], "absolute_offsets_in_rule": False}
        value = {"rule_kind": "record_family", "family_id": family["family_id"], "proof_id": proof["proof_id"], "declaration": declaration, "state": "experimental", "promotion_allowed": False}
        candidates.append({**value, "candidate_id": _cid("parser-rule-candidate", value)})
    return {"schema_version": 1, "operation": "parser_learning_handoff", "candidates": candidates, "promotion_allowed": False}


def _candidate_record(source: bytes, parent: bytes, family_ids: Sequence[str], scopes: Sequence[Mapping[str, Any]], proofs: Mapping[str, Mapping[str, Any]], baseline: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> Dict[str, Any] | None:
    validation_policy = dict(bundle["policy"].get("validation") or {})
    if scopes and validation_policy.get("require_transform_lane_consistency", False):
        transform = measure_transform_lane_consistency(source, parent, scopes)
        if not transform["supported"]:
            return None
    result = _hook(bundle["registry"]["materializer"])(source, parent, scopes, bundle=bundle)
    candidate = result["bytes"]
    analysis = _semantic_analysis(candidate, bundle=bundle)
    validation = _validate_candidate(source, parent, candidate, scopes, result["inverse"], baseline, analysis, bundle=bundle)
    descriptor = {"family_ids": sorted(family_ids), "scope_ids": sorted(item["scope_id"] for item in scopes), "parent_sha256": hashlib.sha256(parent).hexdigest(), "source_sha256": hashlib.sha256(source).hexdigest()}
    candidate_id = _cid("record-family-candidate", {"descriptor": descriptor, "output_sha256": hashlib.sha256(candidate).hexdigest()})
    analyzer_id = str(bundle["registry"]["semantic_analyzers"][0]["id"])
    supported = sum(int(item["length"]) for item in scopes)
    heldout = sum(len(proofs[family_id]["holdout_occurrence_ids"]) for family_id in family_ids)
    objectives = {"verified_family_count": len(family_ids), "heldout_occurrence_count": heldout, "supported_plaintext_bytes": supported, "printable_bytes": int(analysis[analyzer_id]["printable_bytes"]), "unknown_bytes": int(analysis[analyzer_id].get("unknown_bytes", len(candidate))), "changed_bytes": int(result["changed_bytes"])}
    return {"candidate_id": candidate_id, "family_ids": sorted(family_ids), "descriptor": descriptor, "scopes": list(scopes), "inverse": result["inverse"], "bytes": candidate, "changed_bytes": result["changed_bytes"], "analysis": analysis, "validation": validation, "objectives": objectives, "promotion_eligible": False, "verified_decryption": False}


def run_record_family_e2e(
    source_path: str | Path,
    parent_path: str | Path,
    *,
    output_root: str | Path | None = None,
    ledger_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    bundle = load_record_family_bundle(policy_path, registry_path)
    source_file, parent_file = Path(source_path).resolve(), Path(parent_path).resolve()
    source, parent = source_file.read_bytes(), parent_file.read_bytes()
    if not source or len(source) != len(parent):
        raise ValueError("source and parent must be non-empty and equal-sized")
    source_identity, parent_identity = _identity(source_file), _identity(parent_file)
    run_basis = {"source": source_identity["sha256"], "parent": parent_identity["sha256"], "policy": bundle["policy_digest"], "registry": bundle["registry_digest"], "implementation": bundle["implementation_digest"]}
    run_id = _cid("record-family-run", run_basis)
    configured_root = Path(str(bundle["policy"]["artifact_root"]))
    base = Path(output_root).resolve() if output_root else (_root() / configured_root).resolve()
    run_root = base / run_id
    existing_run = run_root / "run.json"
    if existing_run.is_file() and verify_record_family_run(existing_run).get("ok"):
        return _read(existing_run)
    run_root.mkdir(parents=True, exist_ok=True)
    event_path = run_root / "logs" / "events.jsonl"
    if event_path.exists():
        event_path.unlink()
    log = EventLog(event_path, run_id, bundle)
    log.emit("run_started", {"source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"]}, "turn-0000")

    seeds: List[Dict[str, Any]] = []
    for spec in bundle["registry"]["seed_detectors"]:
        seeds.extend(_hook(spec)(source, bundle=bundle))
    deduped = {item["seed_id"]: item for item in seeds}
    seeds = [deduped[key] for key in sorted(deduped)]
    _write(run_root / "turns" / "turn-0001-seeds" / "index.json", seeds)
    log.emit("seeds_discovered", {"count": len(seeds)}, "turn-0001")

    neighborhoods = [item for seed in seeds for item in measure_neighborhoods(source, seed, bundle=bundle)]
    _write(run_root / "turns" / "turn-0002-neighborhoods" / "index.json", neighborhoods)
    families, proofs, boundaries = build_family_proofs(source, seeds, bundle=bundle)
    proof_schema = _read(_root() / "schemas" / "record_family_proof.schema.json")
    for proof in proofs:
        errors = list(Draft202012Validator(proof_schema).iter_errors(proof))
        if errors: raise ValueError(f"record-family proof schema failure: {errors[0].message}")
        _write(run_root / "proofs" / f"{proof['proof_id']}.json", proof)
    _write(run_root / "turns" / "turn-0003-boundaries" / "index.json", boundaries)
    _write(run_root / "turns" / "turn-0004-alignments" / "families.json", families)
    _write(run_root / "turns" / "turn-0005-holdouts" / "proofs.json", proofs)
    passed_proofs = {item["family_id"]: item for item in proofs if item["state"] == "holdout_passed"}
    passed_families = [item for item in families if item["family_id"] in passed_proofs]
    log.emit("family_proofs_completed", {"family_count": len(families), "passed_count": len(passed_families)}, "turn-0005")

    scopes_by_family = {family["family_id"]: compile_family_scopes(source, parent, family, passed_proofs[family["family_id"]], bundle=bundle) for family in passed_families}
    baseline = _semantic_analysis(parent, bundle=bundle)
    candidate_records: List[Dict[str, Any]] = []
    maximum_candidates = int(bundle["policy"]["materialization"]["maximum_candidates"])
    for family in passed_families:
        scopes = scopes_by_family[family["family_id"]]
        if scopes and len(candidate_records) < maximum_candidates:
            candidate = _candidate_record(source, parent, [family["family_id"]], scopes, passed_proofs, baseline, bundle=bundle)
            if candidate is not None:
                candidate_records.append(candidate)
    combination_limit = int(bundle["policy"]["materialization"]["maximum_combination_size"])
    combined_ids: List[str] = []
    combined_scopes: List[Mapping[str, Any]] = []
    for family in passed_families[:combination_limit]:
        if not scopes_by_family[family["family_id"]]: continue
        combined_ids.append(family["family_id"]); combined_scopes.extend(scopes_by_family[family["family_id"]])
        if len(combined_ids) > 1 and len(candidate_records) < maximum_candidates:
            candidate = _candidate_record(source, parent, combined_ids, combined_scopes, passed_proofs, baseline, bundle=bundle)
            if candidate is not None:
                candidate_records.append(candidate)

    public_candidates = []
    for candidate in candidate_records:
        candidate_root = run_root / "candidates" / candidate["candidate_id"]
        _write_bytes(candidate_root / "candidate.bin", candidate.pop("bytes"))
        _write(candidate_root / "descriptor.json", candidate["descriptor"])
        _write(candidate_root / "inverse.json", candidate["inverse"])
        _write(candidate_root / "analysis.json", candidate["analysis"])
        _write(candidate_root / "validation.json", candidate["validation"])
        manifest = {key: value for key, value in candidate.items() if key not in {"inverse", "analysis", "scopes"}}
        manifest["artifact_path"] = str(candidate_root / "candidate.bin")
        _write(candidate_root / "manifest.json", manifest)
        public_candidates.append({**manifest, "analysis": candidate["analysis"]})
    frontier = pareto_frontier(public_candidates, bundle=bundle)
    _write(run_root / "final" / "pareto_frontier.json", frontier)
    compatibility = {"schema_version": 1, "nodes": [item["family_id"] for item in passed_families], "edges": [{"left": left["family_id"], "right": right["family_id"], "compatible": True, "reason": "identical_source_target_for_overlap"} for index, left in enumerate(passed_families) for right in passed_families[index + 1:]]}
    _write(run_root / "final" / "compatibility_graph.json", compatibility)

    coverage = _hook(bundle["registry"]["coverage_handoff"])(source, families, proofs, bundle=bundle)
    parser_handoff = _hook(bundle["registry"]["parser_learning_handoff"])(source, families, proofs, bundle=bundle)
    _write(run_root / "coverage" / "handoff.json", coverage)
    _write(run_root / "parser_learning" / "handoff.json", parser_handoff)

    configured_ledger = Path(str(bundle["policy"]["finding_ledger"]["root"]))
    ledger = FindingLedger(Path(ledger_root).resolve() if ledger_root else (_root() / configured_ledger).resolve(), bundle)
    for seed in seeds:
        for occurrence in seed["occurrences"]:
            ledger.add(kind="plaintext_seed", state="observed", source_sha256=source_identity["sha256"], span=occurrence, producer={"run_id": run_id, "artifact": "seeds"}, evidence_refs=[seed["seed_id"]], summary=f"Repeated printable evidence ({seed['length']} bytes)")
    for proof in proofs:
        family = next(item for item in families if item["family_id"] == proof["family_id"])
        first = family["occurrences"][0]
        ledger.add(kind="record_family_proof", state="experimental_verified" if proof["state"] == "holdout_passed" else "falsified", source_sha256=source_identity["sha256"], span={"offset": first["offset"], "length": first["length"]}, producer={"run_id": run_id, "artifact": proof["proof_id"]}, evidence_refs=[proof["family_id"]] + proof["training_occurrence_ids"] + proof["holdout_occurrence_ids"], summary=f"Record family proof state: {proof['state']}", counterexample_refs=[_cid("counterexample", item) for item in proof["validation"]["holdout"]["checks"] if not item["passed"]])
    ledger.rebuild_indexes()

    status = "goal_satisfied" if frontier else ("family_proof_satisfied" if passed_families else ("insufficient_independence" if seeds else "evidence_exhausted"))
    decision = {"schema_version": 1, "status": status, "proof_ids": [item["proof_id"] for item in proofs], "candidate_ids": [item["candidate_id"] for item in public_candidates], "frontier_candidate_ids": [item["candidate_id"] for item in frontier], "promotion_eligible": False, "verified_decryption": False}
    _write(run_root / "final" / "decision.json", decision)
    artifacts = {
        "seeds": str(run_root / "turns" / "turn-0001-seeds" / "index.json"),
        "neighborhoods": str(run_root / "turns" / "turn-0002-neighborhoods" / "index.json"),
        "boundaries": str(run_root / "turns" / "turn-0003-boundaries" / "index.json"),
        "families": str(run_root / "turns" / "turn-0004-alignments" / "families.json"),
        "proofs": str(run_root / "turns" / "turn-0005-holdouts" / "proofs.json"),
        "frontier": str(run_root / "final" / "pareto_frontier.json"),
        "compatibility": str(run_root / "final" / "compatibility_graph.json"),
        "coverage_handoff": str(run_root / "coverage" / "handoff.json"),
        "parser_learning_handoff": str(run_root / "parser_learning" / "handoff.json"),
        "decision": str(run_root / "final" / "decision.json"),
        "events": str(run_root / "logs" / "events.jsonl"),
    }
    run = {"schema_version": 1, "run_id": run_id, "status": status, "source": source_identity, "parent": parent_identity, "policy_digest": bundle["policy_digest"], "registry_digest": bundle["registry_digest"], "implementation_digest": bundle["implementation_digest"], "run_root": str(run_root), "proof_ids": decision["proof_ids"], "candidate_ids": decision["candidate_ids"], "artifacts": artifacts}
    run_schema = _read(_root() / "schemas" / "record_family_run.schema.json")
    errors = list(Draft202012Validator(run_schema).iter_errors(run))
    if errors: raise ValueError(f"record-family run schema failure: {errors[0].message}")
    _write(run_root / "run.json", run)
    from src.services.learning_db import try_index_learning_db_on_run_complete

    try_index_learning_db_on_run_complete(run_root / "run.json", "record_family")
    from src.services.proof_ledger import try_compile_proof_ledger_on_run_complete

    try_compile_proof_ledger_on_run_complete(run_root / "run.json", "record_family")
    _write(run_root / "checkpoints" / "latest.json", {"schema_version": 1, "run_id": run_id, "status": status, "completed_turn": "turn-0008", "decision_digest": _digest(decision)})
    log.emit("run_completed", {"status": status, "proof_count": len(proofs), "candidate_count": len(public_candidates)}, "turn-0008")
    return run


def verify_record_family_run(run_path: str | Path) -> Dict[str, Any]:
    try:
        path = Path(run_path).resolve(); run = _read(path)
        schema = _read(_root() / "schemas" / "record_family_run.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(run))
        root = Path(run["run_root"]).resolve(); missing, unsafe = [], []
        for name, raw in run["artifacts"].items():
            artifact = Path(raw).resolve()
            if root not in artifact.parents: unsafe.append(name)
            elif not artifact.is_file(): missing.append(name)
        sequence, previous, chain_ok = 0, "", True
        event_path = Path(run["artifacts"]["events"])
        if event_path.is_file():
            for line in event_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if int(event["sequence"]) != sequence or event["previous_event_digest"] != previous: chain_ok = False
                previous = hashlib.sha256(_canonical(event)).hexdigest(); sequence += 1
        source_ok = _identity(Path(run["source"]["path"]))["sha256"] == run["source"]["sha256"]
        parent_ok = _identity(Path(run["parent"]["path"]))["sha256"] == run["parent"]["sha256"]
        return {"ok": not errors and not missing and not unsafe and chain_ok and source_ok and parent_ok, "run_id": run.get("run_id"), "schema_errors": [item.message for item in errors], "missing_artifacts": missing, "unsafe_artifacts": unsafe, "event_chain_ok": chain_ok, "source_identity_ok": source_ok, "parent_identity_ok": parent_ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def discover_record_family_run_for_source(
    file_path: str | Path,
    *,
    policy_path: str | Path | None = None,
) -> str | None:
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        return None
    bundle = load_record_family_bundle(policy_path)
    artifact_root = bundle["policy"].get("artifact_root")
    if not artifact_root:
        return None
    root = Path(str(artifact_root))
    if not root.is_absolute():
        root = (_root() / root).resolve()
    if not root.is_dir():
        return None
    file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    matches: List[tuple[float, str]] = []
    for run_dir in root.glob("record-family-run-*"):
        run_json = run_dir / "run.json"
        if not run_json.is_file():
            continue
        try:
            run = _read(run_json)
        except Exception:
            continue
        source_sha = str((run.get("source") or {}).get("sha256") or "")
        parent_sha = str((run.get("parent") or {}).get("sha256") or "")
        if file_sha not in {source_sha, parent_sha}:
            continue
        matches.append((run_json.stat().st_mtime, str(run_json.resolve())))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def inspect_record_family_run(run_path: str | Path) -> Dict[str, Any]:
    run = _read(Path(run_path).resolve()); verified = verify_record_family_run(run_path)
    families = _read(Path(run["artifacts"]["families"])); proofs = _read(Path(run["artifacts"]["proofs"])); frontier = _read(Path(run["artifacts"]["frontier"])); boundaries = _read(Path(run["artifacts"]["boundaries"]))
    proof_by_family = {item["family_id"]: item for item in proofs}
    ranges = []
    for family in families:
        proof = proof_by_family.get(family["family_id"])
        for occurrence in family["occurrences"]:
            ranges.append({"offset": occurrence["offset"], "length": occurrence["length"], "class": "record_family_holdout" if occurrence["role"] == "holdout" else "record_family_training", "source_id": occurrence["occurrence_id"], "record_family_id": family["family_id"], "proof_id": proof["proof_id"] if proof else None, "theme_token": "binary_waterfall.record_family_holdout" if occurrence["role"] == "holdout" else "binary_waterfall.record_family_training"})
    return {"operation": "record_family_run_inspect", "run_id": run["run_id"], "verified": verified["ok"], "status": run["status"], "families": families, "proofs": proofs, "boundaries": boundaries, "frontier": frontier, "waterfall_overlay": {"schema_version": 1, "ranges": ranges}, "run_root": run["run_root"]}


def build_record_family_model_packet(run_path: str | Path) -> Dict[str, Any]:
    if not verify_record_family_run(run_path)["ok"]: raise ValueError("record-family run failed integrity verification")
    inspected = inspect_record_family_run(run_path)
    families = [{"family_id": item["family_id"], "occurrence_count": len(item["occurrence_ids"]), "counterexample_count": len(item["counterexamples"]), "promotion_authority": False} for item in inspected["families"]]
    candidates = [{"candidate_id": item["candidate_id"], "family_ids": item["family_ids"], "objectives": item["objectives"], "gate_statuses": item["validation"]["gates"], "promotion_authority": False} for item in inspected["frontier"]]
    return {"schema_version": 1, "operation": "record_family_model_packet", "run_id": inspected["run_id"], "run_verified": True, "families": families, "candidates": candidates, "allowed_actions": ["rank_existing_family", "rank_existing_candidate", "request_registered_measurement"], "model_role": "advisory_only", "mechanical_authority": True}


def validate_record_family_model_action(action: Mapping[str, Any], packet: Mapping[str, Any], *, policy_path: str | Path | None = None, registry_path: str | Path | None = None) -> Dict[str, Any]:
    bundle = load_record_family_bundle(policy_path, registry_path)
    forbidden = set(bundle["policy"]["model_boundary"]["forbidden_fields"])
    if forbidden.intersection(action): raise ValueError("model action contains forbidden authority fields")
    allowed = set(bundle["policy"]["model_boundary"]["allowed_actions"])
    if action.get("action") not in allowed: raise ValueError("model action is not registered")
    if set(action) != {"action", "target_id", "reason"}: raise ValueError("model action has invalid fields")
    known = {item["family_id"] for item in packet.get("families", [])} | {item["candidate_id"] for item in packet.get("candidates", [])}
    if action["target_id"] not in known: raise ValueError("model selected an unknown target")
    if not isinstance(action["reason"], str) or not action["reason"].strip(): raise ValueError("model reason is missing")
    return dict(action)
