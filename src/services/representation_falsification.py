"""Registry-driven mechanical falsification over RepresentationBrief artifacts."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence


def _config_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "representation_falsification_policy.json"


def load_falsification_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _config_path()
    policy = json.loads(target.read_text(encoding="utf-8"))
    required = {"schema_version", "policy_id", "revision", "budgets", "hypothesis_sources", "thresholds", "terminal_statuses", "promotion_authority"}
    if int(policy.get("schema_version") or 0) != 1 or required - set(policy):
        raise ValueError("invalid representation falsification policy")
    if not policy["hypothesis_sources"]:
        raise ValueError("representation falsification policy has no hypothesis sources")
    return policy


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _resolve_path(value: Mapping[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in str(dotted).split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _condition_value(condition: Mapping[str, Any], policy: Mapping[str, Any]) -> Any:
    if "value_ref" in condition:
        resolved = _resolve_path(policy, str(condition["value_ref"]))
        if resolved is None:
            raise ValueError(f"unresolved falsification policy ref: {condition['value_ref']}")
        return resolved
    if "value" not in condition:
        raise ValueError("falsification condition requires value or value_ref")
    return condition["value"]


def _matches(candidate: Mapping[str, Any], condition: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    actual = _resolve_path(candidate, str(condition.get("field") or ""))
    expected = _condition_value(condition, policy)
    operator = str(condition.get("operator") or "")
    operations = {
        "equals": lambda: actual == expected,
        "not_equals": lambda: actual != expected,
        "greater_or_equal": lambda: actual is not None and float(actual) >= float(expected),
        "less_or_equal": lambda: actual is not None and float(actual) <= float(expected),
        "nonempty": lambda: bool(actual) is bool(expected),
    }
    if operator not in operations:
        raise ValueError(f"unsupported falsification operator: {operator}")
    return bool(operations[operator]())


def _all_match(candidate: Mapping[str, Any], conditions: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> bool:
    return bool(conditions) and all(_matches(candidate, item, policy) for item in conditions)


def falsify_representation_brief(brief: Mapping[str, Any], *, policy: Mapping[str, Any] | None = None, region_id: str = "") -> Dict[str, Any]:
    active = dict(policy or load_falsification_policy())
    if str(brief.get("operation") or "") != "representation_brief":
        raise ValueError("mechanical falsification requires a RepresentationBrief")
    brief_digest = hashlib.sha256(_canonical(brief)).hexdigest()
    maximum = int((active.get("budgets") or {})["max_hypotheses_per_region"])
    hypotheses = []
    for rule in active["hypothesis_sources"]:
        collection = _resolve_path(brief, str(rule.get("collection_path") or ""))
        if not isinstance(collection, list):
            raise ValueError(f"hypothesis source is not a list: {rule.get('collection_path')}")
        for candidate in collection:
            if not isinstance(candidate, Mapping):
                continue
            falsified = _all_match(candidate, list(rule.get("falsify_conditions") or []), active)
            supported = _all_match(candidate, list(rule.get("support_conditions") or []), active)
            status = "falsified" if falsified else ("supported" if supported else "inconclusive")
            identity = {field: _resolve_path(candidate, str(field)) for field in rule.get("identity_fields") or []}
            descriptor = {"rule_id": rule["rule_id"], "identity": identity, "brief_digest": brief_digest, "region_id": str(region_id or "")}
            hypotheses.append({
                "hypothesis_id": "representation-hypothesis-" + hashlib.sha256(_canonical(descriptor)).hexdigest(),
                "rule_id": rule["rule_id"],
                "identity": identity,
                "status": status,
                "evidence_refs": [{"brief_digest": brief_digest, "collection": rule["collection_path"]}],
                "promotion_allowed": False,
                "promotion_authority": active["promotion_authority"],
            })
            if len(hypotheses) >= maximum:
                break
        if len(hypotheses) >= maximum:
            break
    counts = Counter(item["status"] for item in hypotheses)
    return {
        "schema_version": 1,
        "ok": True,
        "operation": "binary_representation_falsify",
        "region_id": str(region_id or ""),
        "brief_digest": brief_digest,
        "policy": {"policy_id": active["policy_id"], "revision": active["revision"]},
        "hypotheses": hypotheses,
        "summary": {"total": len(hypotheses), **{status: int(counts.get(status, 0)) for status in active["terminal_statuses"]}, "budget_exhausted": len(hypotheses) >= maximum},
        "mechanical_authority": True,
        "model_role": "advisory_only",
        "parser_promotion_unchanged": True,
    }
