"""PE unpack hypothesis loop — structure promotion without decrypt key hunt."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from src.runtime.byte_source import ByteSource
from src.runtime.config import load_binary_dynamic_config


def run_unpack_hypothesis(source: ByteSource, baseline: Mapping[str, Any], *, descriptor: Mapping[str, Any]) -> Dict[str, Any]:
    """Mechanical placeholder: validates descriptor bounds; full transform registry integration is future work."""
    offset = int(descriptor.get("offset", -1))
    length = int(descriptor.get("length", -1))
    if offset < 0 or length <= 0 or offset + length > source.size:
        raise ValueError("unpack hypothesis out of bounds")
    return {
        "ok": True,
        "structure_improved": False,
        "baseline_coverage": (baseline.get("signals") or {}).get("coverage_ratio"),
        "descriptor": dict(descriptor),
        "status": "tested",
    }


def default_unpack_policy() -> Dict[str, Any]:
    cfg = load_binary_dynamic_config()
    return {
        "schema_version": 1,
        "budgets": {"max_hypotheses": int(cfg.get("max_records", 256))},
        "promotion_gate": {"minimum_coverage_gain": 0.05},
    }
