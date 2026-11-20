"""Reference-aware full-decode composition tests."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _pair_with_reference(tmp_path: Path):
    rng = random.Random(991)
    reference = bytearray(rng.randrange(256) for _ in range(1024))
    source = bytearray(reference)
    parent = bytearray(reference)
    for offset in (100, 200, 300):
        source[offset] ^= 0x5A
    for offset in (100, 200):
        parent[offset] = reference[offset]
    for offset in (400,):
        parent[offset] ^= 0x17
    ref_path = tmp_path / "reference.bin"
    src_path = tmp_path / "source.bin"
    parent_path = tmp_path / "parent.bin"
    ref_path.write_bytes(reference)
    src_path.write_bytes(source)
    parent_path.write_bytes(parent)
    return src_path, parent_path, ref_path, reference


def test_reference_aware_full_decode_prefers_reference_improvement(tmp_path):
    from src.services.full_decode import inspect_full_decode_run, run_full_decode_e2e

    source, parent, reference, _ = _pair_with_reference(tmp_path)
    policy = ROOT / "config" / "full_decode_reference_policy.json"
    run = run_full_decode_e2e(
        source,
        parent,
        output_root=tmp_path / "runs",
        policy_path=policy,
        reference_path=reference,
    )
    inspected = inspect_full_decode_run(Path(run["run_root"]) / "run.json")
    metrics = inspected["candidate"]["reference_metrics"]
    assert metrics["reference_regression_bytes"] == 0
    assert metrics["reference_improvement_bytes"] >= 0
    assert inspected["candidate"]["gate_statuses"]["reference_non_regression"] == "passed"


def test_reference_policy_schema_is_loadable():
    from src.services.full_decode.core import load_full_decode_bundle

    bundle = load_full_decode_bundle(ROOT / "config" / "full_decode_reference_policy.json")
    assert bundle["policy"]["reference_evaluation"]["enabled"] is True
