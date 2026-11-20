"""Registry-driven window scoring — NO HARDCODE signal weights."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from src.services.ptx_crypto_primitives import is_identity_transform, printable_ratio, shannon_entropy
from src.services.transform_registry import load_markers_config, scoring_profile
from src.services.plaintext_profiles import score_plaintext_profiles


def marker_score(decrypted: bytes, *, markers: Sequence[bytes] | None = None) -> Tuple[int, List[str]]:
    marker_list = list(markers or load_markers_config())
    hits: List[str] = []
    score = 0
    plaintext_profile: Dict[str, Any] = {"available": False, "best": None, "matches": []}
    for marker in marker_list:
        count = decrypted.count(marker)
        if count:
            hits.append(f"{marker.decode('ascii', errors='replace')}:{count}")
            score += min(count, 4) * 2
    return score, hits


def score_window(
    cipher: bytes,
    transformed: bytes,
    *,
    region_name: str,
    profile_name: str = "xor",
    defaults: Mapping[str, Any] | None = None,
    markers: Sequence[bytes] | None = None,
) -> Dict[str, Any]:
    from src.services.transform_registry import merge_crypto_defaults

    base = dict(defaults or merge_crypto_defaults())
    profile = scoring_profile(base, profile_name)
    signals = list(profile.get("signals") or [])

    marker_hits_score, marker_hits = marker_score(transformed, markers=markers)
    ratio = printable_ratio(transformed)
    entropy_before = shannon_entropy(cipher)
    entropy_after = shannon_entropy(transformed)
    entropy_drop = round(max(0.0, entropy_before - entropy_after), 4)

    score = 0
    for signal in signals:
        signal_id = str(signal.get("id") or "")
        if signal_id == "marker_hits":
            weight = int(signal.get("weight") or 2)
            max_per = int(signal.get("max_per_marker") or 4)
            marker_list = list(markers or load_markers_config())
            for marker in marker_list:
                count = transformed.count(marker)
                if count:
                    score += min(count, max_per) * weight
        elif signal_id == "printable_ratio":
            for threshold in signal.get("thresholds") or []:
                if ratio >= float(threshold.get("min") or 0):
                    score += int(threshold.get("bonus") or 0)
        elif signal_id == "entropy_drop":
            down_weight = bool(signal.get("down_weight"))
            for threshold in signal.get("thresholds") or []:
                if entropy_drop >= float(threshold.get("min") or 0):
                    bonus = int(threshold.get("bonus") or 0)
                    score += bonus // 2 if down_weight else bonus
        elif signal_id == "zero_byte_structure":
            zero_runs = sum(1 for byte in transformed if byte == 0)
            if zero_runs >= max(1, len(transformed) // 32):
                score += int(signal.get("bonus") or 2)
        elif signal_id == "plaintext_profile_similarity":
            plaintext_profile = score_plaintext_profiles(transformed)
            best = plaintext_profile.get("best") or {}
            similarity = float(best.get("similarity") or 0.0)
            for threshold in signal.get("thresholds") or []:
                if similarity >= float(threshold.get("min") or 0.0):
                    score += int(threshold.get("bonus") or 0)

    if not signals:
        score = marker_hits_score
        if ratio > 0.45:
            score += 2
        if ratio > 0.65:
            score += 2
        min_drop = float(base.get("min_entropy_drop") or 0.35)
        if entropy_drop >= min_drop:
            score += 2
        if entropy_drop >= 0.75:
            score += 2

    return {
        "region": region_name,
        "score": score,
        "printable_ratio": ratio,
        "entropy_before": entropy_before,
        "entropy_after": entropy_after,
        "entropy_drop": entropy_drop,
        "marker_hits": marker_hits,
        "identity": is_identity_transform(cipher, transformed),
        "scoring_profile": profile_name,
        "plaintext_profile": plaintext_profile,
    }
