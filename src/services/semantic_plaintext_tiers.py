"""Presentation-tier classification for decoded plaintext — policy-driven, no specimen literals."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_semantic_plaintext_tiers_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "semantic_plaintext_tiers_policy.json"
    policy = json.loads(target.read_text(encoding="utf-8"))
    schema = json.loads((_root() / "schemas" / "semantic_plaintext_tiers_policy.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"semantic plaintext tiers policy invalid: {errors[0].message}")
    return policy


def _field_value(document: Mapping[str, Any], field_path: str) -> Any:
    current: Any = document
    for part in str(field_path).split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise ValueError(f"structured pattern field missing: {field_path}")
        current = current[part]
    return current


def _load_config_field(source: Mapping[str, Any]) -> Any:
    config_path = Path(str(source.get("config_path") or ""))
    if not config_path.is_absolute():
        config_path = (_root() / config_path).resolve()
    document = json.loads(config_path.read_text(encoding="utf-8"))
    return _field_value(document, str(source.get("field_path") or ""))


def _pattern_list(policy: Mapping[str, Any], field_name: str) -> List[str]:
    classification = dict(policy.get("classification") or {})
    patterns: List[str] = []
    for source in classification.get(field_name) or []:
        values = _load_config_field(source)
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ValueError(f"{field_name} source must be a string array")
        patterns.extend(str(item) for item in values if str(item))
    return patterns


def _dominant_char_ratio(text: str) -> float:
    if not text:
        return 1.0
    counts = Counter(text)
    return max(counts.values()) / len(text)


def _unique_char_ratio(text: str) -> float:
    compact = [char for char in text if not char.isspace()]
    if not compact:
        return 0.0
    return len(set(compact)) / len(compact)


def _alphabetic_or_digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    allowed = sum(1 for char in text if char.isalpha() or char.isdigit())
    return allowed / len(text)


def _non_alphanumeric_ratio(text: str) -> float:
    if not text:
        return 1.0
    non_alnum = sum(1 for char in text if not char.isalnum() and not char.isspace())
    return non_alnum / len(text)


def _gates_pass(text: str, gates: Mapping[str, Any]) -> bool:
    return (
        _dominant_char_ratio(text) <= float(gates["maximum_dominant_char_ratio"])
        and _unique_char_ratio(text) >= float(gates["minimum_unique_char_ratio"])
        and _alphabetic_or_digit_ratio(text) >= float(gates["minimum_alphabetic_or_digit_ratio"])
        and _non_alphanumeric_ratio(text) <= float(gates["maximum_non_alphanumeric_ratio"])
    )


def _matches_semantic_label(text: str, *, policy: Mapping[str, Any]) -> bool:
    for pattern in _pattern_list(policy, "semantic_label_pattern_sources"):
        if re.fullmatch(pattern, text):
            return True
    return False


def classify_plaintext_tier(text: str, *, policy: Mapping[str, Any] | None = None) -> str:
    cfg = dict(policy or load_semantic_plaintext_tiers_policy())
    classification = dict(cfg.get("classification") or {})
    minimum_length = int(classification.get("minimum_length") or 1)
    if len(text) < minimum_length:
        return "verified_printable_bytes"

    disallowed = str(classification.get("disallowed_char_pattern") or "")
    if disallowed and re.search(disallowed, text):
        return "verified_printable_bytes"

    for pattern in _pattern_list(cfg, "structured_pattern_sources"):
        if re.search(pattern, text):
            return "semantic_plaintext"

    gates = dict(classification.get("gates") or {})
    require_gates = bool(classification.get("require_gates_for_semantic_labels"))
    if _matches_semantic_label(text, policy=cfg):
        if not require_gates or _gates_pass(text, gates):
            return "semantic_plaintext"
    return "verified_printable_bytes"


def classify_cluster_tier(preview: str, *, policy: Mapping[str, Any] | None = None) -> str:
    span_tier = classify_plaintext_tier(preview, policy=policy)
    if span_tier == "semantic_plaintext":
        return "repeated_semantic_cluster"
    return "repeated_printable_cluster"


def tier_presentation(tier_id: str, *, policy: Mapping[str, Any] | None = None) -> Dict[str, str]:
    cfg = dict(policy or load_semantic_plaintext_tiers_policy())
    tiers = dict(cfg.get("tiers") or {})
    tier = dict(tiers.get(str(tier_id)) or {})
    if not tier:
        raise ValueError(f"unknown plaintext tier: {tier_id}")
    return {
        "tier_id": str(tier_id),
        "presentation_label": str(tier["presentation_label"]),
        "truth_state": str(tier["truth_state"]),
    }


def verified_printable_bytes_comment(*, policy: Mapping[str, Any] | None = None) -> str:
    cfg = dict(policy or load_semantic_plaintext_tiers_policy())
    presentation = dict(cfg.get("presentation") or {})
    text = str(presentation.get("verified_printable_bytes_comment") or "").strip()
    if not text:
        raise ValueError("semantic plaintext tiers policy missing verified_printable_bytes_comment")
    return text
