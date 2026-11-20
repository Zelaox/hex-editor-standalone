"""Investigation debug bundle tests."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEBUG_POLICY = ROOT / "config" / "investigation_debug_policy.json"


def _pair(tmp_path: Path):
    rng = random.Random(771)
    decoded = bytearray(rng.randrange(128, 256) for _ in range(2048))
    text = b"portable repeated ascii record"
    positions = (137, 509, 1301)
    for offset in positions:
        decoded[offset - 1] = 0
        decoded[offset:offset + len(text)] = text
        decoded[offset + len(text)] = 0
    parent = bytearray(decoded)
    for offset in positions:
        for index in range(offset, offset + len(text)):
            parent[index] ^= 0xD3
    start, end = 1800, 1850
    for index in range(start, end):
        parent[index] ^= rng.randrange(1, 256)
    source, base = tmp_path / "decoded.bin", tmp_path / "parent.bin"
    source.write_bytes(decoded)
    base.write_bytes(parent)
    return source, base


def test_classify_debug_bottleneck_partial_with_empty_local_frontier():
    from src.services.investigation_debug.core import classify_debug_bottleneck

    baseline = {
        "full_decode": {"verified": True},
        "metrics": {"unresolved_bytes": 50, "proof_owned_changed_bytes": 10},
        "provider_frontier": {"local-transform-proof": {"frontier_empty": True, "candidate_count": 0}, "record-family-proof": {"frontier_empty": False, "candidate_count": 1}},
        "provider_gap": {"overlap_coefficient": 0.0},
        "multi_turn_closure": {"class_g_resolved_for_full_decode": True},
        "unresolved_inference": {"status": "evidence_exhausted"},
    }
    result = classify_debug_bottleneck(baseline)
    assert result["primary_class"] == "A"
    assert result["hypothesis_map"]["H1"] == "confirmed"


def test_investigation_debug_e2e_emits_deliverables(tmp_path):
    from src.services.investigation_debug import run_investigation_debug_e2e

    source, parent = _pair(tmp_path)
    summary = run_investigation_debug_e2e(source, parent, output_root=tmp_path / "debug", policy_path=DEBUG_POLICY)
    root = Path(summary["artifact_root"])
    assert summary["verified"] is True
    assert summary["primary_class"] in {"A", "B", "C", "E"}
    for name in (
        "debug_baseline.json",
        "debug_classification.json",
        "provider_gap_report.json",
        "multi_turn_closure_report.json",
        "gemma_advisory_assessment.json",
        "recommendation.json",
        "summary.json",
    ):
        assert (root / name).is_file()
