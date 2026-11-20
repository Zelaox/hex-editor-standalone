from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.plugins.ptx.runtime_analysis import analyze_ptx_path, build_ptx_snapshot
from src.runtime.byte_source import ByteSource
from src.services.binary_runtime import binary_waterfall_payload
from src.services.binary_workspace import export_binary_workspace, load_binary_workspace
from src.services.ptx_experiment_ledger import structural_experiment_diff
from src.services.ptx_full_coverage import load_full_coverage_policy, partition_coverage


def test_full_coverage_is_exact_and_unknown_is_preserved():
    data = b"\x00\x01Alpha Track\x00" + bytes(range(128)) + b"Alpha Track\xff"
    snapshot = build_ptx_snapshot(ByteSource.from_bytes(data)).to_dict()

    coverage = snapshot["coverage"]
    assert sum(item["length"] for item in coverage) == len(data)
    assert coverage[0]["offset"] == 0
    assert all(left["offset"] + left["length"] == right["offset"] for left, right in zip(coverage, coverage[1:]))
    assert snapshot["coverage_summary"]["coverage_complete"] is True
    assert snapshot["unknown_regions"]
    assert snapshot["anchors"]
    assert snapshot["record_families"]


def test_partition_handles_overlapping_interpretations():
    policy = load_full_coverage_policy()
    coverage = partition_coverage(12, [{"offset": 2, "length": 6, "class": "verified", "node_ids": ["a"]}, {"offset": 6, "length": 4, "class": "inferred", "node_ids": ["b"]}], policy)
    assert sum(item["length"] for item in coverage) == 12
    assert any(item["class"] == "overlap" for item in coverage)


def test_full_workspace_roundtrip_preserves_unknown_bytes(tmp_path: Path):
    source = tmp_path / "fixture.ptx"
    source.write_bytes(b"Header\x00" + bytes(range(64)) + b"\x00Tail")
    snapshot = analyze_ptx_path(source)["snapshot"]
    exported = export_binary_workspace(source, snapshot, tmp_path / "artifacts")
    loaded = load_binary_workspace(exported["artifact_directory"])

    unknown_files = sorted((Path(exported["artifact_directory"]) / "unknown").glob("unknown-*.bin"))
    assert loaded["snapshot"] == snapshot
    assert unknown_files


def test_waterfall_uses_same_snapshot_and_full_coverage():
    snapshot = build_ptx_snapshot(ByteSource.from_bytes(b"Name One\x00" + bytes(range(32)))).to_dict()
    payload = binary_waterfall_payload(snapshot)
    assert payload["snapshot_id"] == snapshot["snapshot_id"]
    assert payload["coverage_summary"] == snapshot["coverage_summary"]
    assert payload["unknown_regions"] == snapshot["unknown_regions"]


def test_experiment_manifest_hashes_and_compatibility_gate():
    left = build_ptx_snapshot(ByteSource.from_bytes(b"Repeated Name\x00Repeated Name")).to_dict()
    right = build_ptx_snapshot(ByteSource.from_bytes(b"Repeated Name\x00Repeated Namo")).to_dict()
    manifest = {"schema_version": 1, "baseline_sha256": left["source"]["sha256"], "variant_sha256": right["source"]["sha256"], "operation": "single declared change", "expected_change": {"field": "user_declared"}}
    result = structural_experiment_diff(left, right, manifest)
    assert result["mechanical_authority"] is True
    assert result["model_role"] == "advisory_only"
    assert all(item["promotion_allowed"] is False for item in result["field_candidates"])

    bad = dict(manifest, baseline_sha256="0" * 64)
    with pytest.raises(ValueError, match="source hashes"):
        structural_experiment_diff(left, right, bad)


def test_policy_and_runtime_code_do_not_embed_reference_specimen_values():
    roots = [Path(__file__).resolve().parents[1] / "src" / "services" / "ptx_full_coverage.py", Path(__file__).resolve().parents[1] / "config" / "plaintext_profile_policy.json"]
    forbidden = ["ac240", "Gtr L", "Gtr R", "556029"]
    text = "\n".join(path.read_text(encoding="utf-8") for path in roots)
    assert not any(value in text for value in forbidden)
