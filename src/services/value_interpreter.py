"""Mechanical pattern detectors over decoder output (Layer B scoring)."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, Sequence

from src.services.representation_registry import load_value_interpreter_policy, resolve_interpreter_callable, resolve_policy_ref


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for value in data if 32 <= value <= 126 or value in (9, 10, 13))
    return printable / len(data)


def _utf16le_zero_run(data: bytes, threshold: float) -> Dict[str, Any] | None:
    if len(data) < 2:
        return None
    even_printable = 0
    odd_zero = 0
    pairs = min(len(data) // 2, len(data))
    for index in range(0, pairs * 2, 2):
        low = data[index]
        high = data[index + 1] if index + 1 < len(data) else 0
        if 32 <= low <= 126:
            even_printable += 1
        if high == 0:
            odd_zero += 1
    pair_count = max(1, pairs)
    score = (even_printable + odd_zero) / (2 * pair_count)
    if score < threshold:
        return None
    return {
        "score": round(score, 6),
        "evidence": "even indices printable ASCII, odd indices 0x00",
    }


def _monotonic_integer_sequence(
    integer_candidate: Mapping[str, Any],
    *,
    min_length: int,
) -> Dict[str, Any] | None:
    values = list(integer_candidate.get("values") or [])
    if len(values) < min_length:
        return None
    grouped: Dict[tuple[int, str, bool], List[int]] = {}
    for item in values:
        key = (int(item.get("width") or 0), str(item.get("byte_order") or ""), bool(item.get("signed")))
        grouped.setdefault(key, []).append(int(item.get("value") or 0))
    best: Dict[str, Any] | None = None
    for (width, byte_order, signed), numeric_values in grouped.items():
        if len(numeric_values) < min_length:
            continue
        sample = numeric_values[: min_length * 2]
        increasing = all(left <= right for left, right in zip(sample, sample[1:]))
        decreasing = all(left >= right for left, right in zip(sample, sample[1:]))
        if not increasing and not decreasing:
            continue
        direction = "increasing" if increasing else "decreasing"
        score = min(1.0, len(sample) / max(min_length, 1))
        candidate = {
            "score": round(score, 6),
            "evidence": f"monotonic {direction} {width}-byte {byte_order} integers (signed={signed})",
            "sample_values": sample[:min_length],
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate
    return best


def _repeated_stride(data: bytes, stride_lengths: Sequence[int]) -> Dict[str, Any] | None:
    best: Dict[str, Any] | None = None
    for stride in [int(value) for value in stride_lengths]:
        if stride < 1 or stride >= len(data):
            continue
        pattern = data[:stride]
        matches = 0
        for index in range(0, len(data) - stride + 1, stride):
            if data[index : index + stride] == pattern:
                matches += 1
            else:
                break
        if matches < 2:
            continue
        score = matches * stride / len(data)
        candidate = {
            "score": round(min(1.0, score), 6),
            "evidence": f"repeating byte pattern every {stride} bytes",
            "stride": stride,
            "repeat_count": matches,
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate
    return best


def _mostly_printable(data: bytes, threshold: float) -> Dict[str, Any] | None:
    ratio = _printable_ratio(data)
    if ratio < threshold:
        return None
    return {
        "score": round(ratio, 6),
        "evidence": f"printable ratio {ratio:.4f} above threshold {threshold}",
    }


def _float_plausible_range(float_candidate: Mapping[str, Any], policy: Mapping[str, Any]) -> Dict[str, Any] | None:
    plausibility = dict(policy.get("plausibility") or {})
    values = list(float_candidate.get("values") or [])
    plausible = [item for item in values if item.get("plausible")]
    if not plausible:
        return None
    sample = plausible[0]
    score = len(plausible) / max(1, len(values))
    return {
        "score": round(score, 6),
        "evidence": f"finite float{sample.get('width')} {sample.get('byte_order')} in plausible range",
        "sample_value": sample.get("value"),
    }


def evaluate_utf16_zero_run(data, candidates, policy, pattern):
    del candidates
    result = _utf16le_zero_run(data, float(resolve_policy_ref(policy, str(pattern["threshold_ref"]))))
    if result:
        result["id"] = str(pattern["id"])
    return result


def evaluate_monotonic_integer_sequence(data, candidates, policy, pattern):
    del data
    candidate_kind = str(pattern["candidate_kind"])
    candidate = next((item for item in candidates if item.get("kind") == candidate_kind), None)
    result = _monotonic_integer_sequence(candidate or {}, min_length=int(resolve_policy_ref(policy, str(pattern["min_length_ref"])))) if candidate else None
    if result:
        result["id"] = str(pattern["id"])
    return result


def evaluate_repeated_stride(data, candidates, policy, pattern):
    del candidates
    result = _repeated_stride(data, resolve_policy_ref(policy, str(pattern["stride_lengths_ref"])))
    if result:
        result["id"] = str(pattern["id"])
    return result


def evaluate_mostly_printable(data, candidates, policy, pattern):
    del candidates
    result = _mostly_printable(data, float(resolve_policy_ref(policy, str(pattern["threshold_ref"]))))
    if result:
        result["id"] = str(pattern["id"])
    return result


def evaluate_float_plausible_range(data, candidates, policy, pattern):
    del data
    candidate_kind = str(pattern["candidate_kind"])
    candidate = next((item for item in candidates if item.get("kind") == candidate_kind), None)
    result = _float_plausible_range(candidate or {}, policy) if candidate else None
    if result:
        result["id"] = str(pattern["id"])
    return result


def evaluate_integer_range(data, candidates, policy, pattern):
    del data
    candidate = next((item for item in candidates if item.get("kind") == str(pattern["candidate_kind"])), None)
    if not candidate:
        return None
    match = dict(pattern["candidate_match"])
    expected_width = int(resolve_policy_ref(policy, str(match["width_ref"])))
    expected_order = str(resolve_policy_ref(policy, str(match["byte_order_ref"])))
    expected_signed = bool(resolve_policy_ref(policy, str(match["signed_ref"])))
    range_min = int(resolve_policy_ref(policy, str(pattern["range_min_ref"])))
    range_max = int(resolve_policy_ref(policy, str(pattern["range_max_ref"])))
    for item in candidate.get("values") or []:
        if int(item.get("width") or 0) == expected_width and str(item.get("byte_order")) == expected_order and bool(item.get("signed")) == expected_signed:
            value = int(item.get("value") or 0)
            if range_min <= value <= range_max:
                return {"id": str(pattern["id"]), "score": float(resolve_policy_ref(policy, str(pattern["score_ref"]))), "evidence": str(pattern["evidence_template"]).format(value=value)}
    return None


def interpret_candidates(
    data: bytes,
    decoder_candidates: Sequence[Mapping[str, Any]],
    *,
    policy: Mapping[str, Any] | None = None,
    pattern_ids: Sequence[str] | None = None,
) -> List[Dict[str, Any]]:
    bundle = load_value_interpreter_policy(dict(policy) if policy else None)
    active_policy = dict(bundle["policy"])
    budgets = dict(active_policy.get("budgets") or {})
    max_signals = int(budgets["max_interpreter_signals"])
    allowed = {str(value) for value in pattern_ids} if pattern_ids else None
    signals: List[Dict[str, Any]] = []

    for pattern in bundle["patterns"]:
        if not pattern.get("enabled"):
            continue
        pattern_id = str(pattern.get("id") or "")
        if allowed is not None and pattern_id not in allowed:
            continue
        evaluator = resolve_interpreter_callable(pattern)
        result = evaluator(data, decoder_candidates, active_policy, pattern)
        if result is not None:
            signals.append(result)

    signals.sort(key=lambda item: float(item.get("score") or 0), reverse=True)
    return signals[:max_signals]
