"""Load transform-evidence bounds from calibration fixture — no inline literals."""

from __future__ import annotations

from typing import Any, Dict, Mapping


class EvidencePolicyError(ValueError):
    pass


_REQUIRED_EVIDENCE_KEYS = (
    "max_window_bytes",
    "max_delta_entries",
    "max_diff_hunks",
    "min_printable_ratio_improvement",
)


def evidence_policy(crypto_defaults: Mapping[str, Any]) -> Dict[str, Any]:
    raw = dict(crypto_defaults.get("evidence_policy") or {})
    missing = [key for key in _REQUIRED_EVIDENCE_KEYS if key not in raw]
    if missing:
        raise EvidencePolicyError(
            "crypto_defaults.evidence_policy missing required keys: "
            + ", ".join(missing)
        )
    promotion = dict(crypto_defaults.get("promotion_policy") or {})
    return {
        "max_window_bytes": int(raw["max_window_bytes"]),
        "max_delta_entries": int(raw["max_delta_entries"]),
        "max_diff_hunks": int(raw["max_diff_hunks"]),
        "min_printable_ratio_improvement": float(raw["min_printable_ratio_improvement"]),
        "max_printable_preview_chars": int(raw.get("max_printable_preview_chars") or 120),
        "sha_match_requires_evidence_pass": bool(
            promotion.get("sha_match_requires_evidence_pass", True)
        ),
    }
