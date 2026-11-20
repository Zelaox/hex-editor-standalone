"""Config-driven structural compatibility gate for BinarySnapshot diffs."""

from __future__ import annotations

import json
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def load_binary_diff_policy(path: str | Path | None = None) -> Dict[str, Any]:
    policy_path = Path(path).expanduser().resolve() if path else _lab_root() / "config" / "binary_diff_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("binary diff policy schema_version unsupported")
    return policy


def _value_at(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in str(path).split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _effective_policy(policy: Mapping[str, Any], plugin: str) -> Dict[str, Any]:
    defaults = dict(policy.get("defaults") or {})
    plugin_policy = dict(((policy.get("plugins") or {}).get(plugin) or {}))
    required = list(defaults.get("required_equal_fields") or []) + list(plugin_policy.get("required_equal_fields") or [])
    optional = list(defaults.get("optional_equal_fields") or []) + list(plugin_policy.get("optional_equal_fields") or [])
    return {**defaults, **plugin_policy, "required_equal_fields": list(dict.fromkeys(map(str, required))), "optional_equal_fields": list(dict.fromkeys(map(str, optional)))}


def _sequence(snapshot: Mapping[str, Any], source: str, field: str = "") -> List[str]:
    items = list(snapshot.get(source) or [])
    values: List[str] = []
    for item in items:
        raw = item.get(field) if field and isinstance(item, Mapping) else item
        token = str(raw if raw is not None else "unknown")
        if not values or values[-1] != token:
            values.append(token)
    return values


def _similarity(left: Sequence[str], right: Sequence[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return float(SequenceMatcher(a=list(left), b=list(right), autojunk=False).ratio())


def _coverage_layout(snapshot: Mapping[str, Any], class_field: str) -> List[tuple[str, int, int]]:
    return [
        (str(item.get(class_field) or "unknown"), int(item.get("offset") or 0), int(item.get("length") or 0))
        for item in snapshot.get("coverage") or []
    ]


def _aligned_segments(left: Mapping[str, Any], right: Mapping[str, Any], class_field: str) -> List[Dict[str, Any]]:
    left_items = list(left.get("coverage") or [])
    right_items = list(right.get("coverage") or [])
    left_classes = [str(item.get(class_field) or "unknown") for item in left_items]
    right_classes = [str(item.get(class_field) or "unknown") for item in right_items]
    alignments: List[Dict[str, Any]] = []
    matcher = SequenceMatcher(a=left_classes, b=right_classes, autojunk=False)
    for block in matcher.get_matching_blocks():
        for delta in range(block.size):
            left_item, right_item = left_items[block.a + delta], right_items[block.b + delta]
            alignments.append({
                "class": str(left_item.get(class_field) or "unknown"),
                "left": {"offset": int(left_item.get("offset") or 0), "length": int(left_item.get("length") or 0)},
                "right": {"offset": int(right_item.get("offset") or 0), "length": int(right_item.get("length") or 0)},
            })
    return alignments


def assess_snapshot_compatibility(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    cfg = dict(policy or load_binary_diff_policy())
    left_plugin, right_plugin = str(left.get("format_plugin") or ""), str(right.get("format_plugin") or "")
    if not left_plugin or left_plugin != right_plugin:
        return {"classification": "incompatible", "automatic_diff_allowed": False, "reasons": ["format_plugin_mismatch"], "alignment": []}
    effective = _effective_policy(cfg, left_plugin)
    mismatches = []
    compared = []
    for field in effective["required_equal_fields"]:
        left_value, right_value = _value_at(left, field), _value_at(right, field)
        compared.append({"field": field, "left": left_value, "right": right_value, "equal": left_value == right_value})
        if left_value is None or right_value is None:
            mismatches.append(f"required_identity_missing:{field}")
        elif left_value != right_value:
            mismatches.append(f"required_identity_mismatch:{field}")
    for field in effective["optional_equal_fields"]:
        left_value, right_value = _value_at(left, field), _value_at(right, field)
        both_missing = left_value is None and right_value is None
        equal = both_missing or (left_value is not None and right_value is not None and left_value == right_value)
        compared.append({"field": field, "left": left_value, "right": right_value, "equal": equal, "optional": True})
        if not equal:
            mismatches.append(f"optional_identity_mismatch:{field}")
    if mismatches:
        return {"classification": "incompatible", "automatic_diff_allowed": False, "reasons": mismatches, "identity_fields": compared, "alignment": []}

    class_field = str(effective.get("coverage_class_field") or "class")
    left_coverage = _sequence(left, "coverage", class_field)
    right_coverage = _sequence(right, "coverage", class_field)
    left_kinds = _sequence(left, "nodes", "kind")
    right_kinds = _sequence(right, "nodes", "kind")
    coverage_similarity = _similarity(left_coverage, right_coverage)
    node_similarity = _similarity(left_kinds, right_kinds)
    coverage_ok = coverage_similarity >= float(effective.get("minimum_coverage_sequence_similarity", 1.0))
    nodes_ok = node_similarity >= float(effective.get("minimum_node_kind_sequence_similarity", 1.0))
    metrics = {"coverage_sequence_similarity": coverage_similarity, "node_kind_sequence_similarity": node_similarity}
    if not coverage_ok or not nodes_ok:
        reasons = []
        if not coverage_ok:
            reasons.append("coverage_layout_below_threshold")
        if not nodes_ok:
            reasons.append("node_layout_below_threshold")
        return {"classification": "incompatible", "automatic_diff_allowed": False, "reasons": reasons, "identity_fields": compared, "metrics": metrics, "alignment": []}

    exact_layout = _coverage_layout(left, class_field) == _coverage_layout(right, class_field)
    exact_nodes = left_kinds == right_kinds
    classification = "exact" if exact_layout and exact_nodes else "structural"
    return {
        "classification": classification,
        "automatic_diff_allowed": True,
        "reasons": ["matching_identity_and_exact_layout" if classification == "exact" else "matching_identity_and_alignable_layout"],
        "identity_fields": compared,
        "metrics": metrics,
        "alignment": _aligned_segments(left, right, class_field),
        "normalized_inputs": {
            "left": bool((left.get("source") or {}).get("candidate_descriptor")),
            "right": bool((right.get("source") or {}).get("candidate_descriptor")),
        },
    }
