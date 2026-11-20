from __future__ import annotations

from copy import deepcopy

from src.services.binary_compatibility import assess_snapshot_compatibility
from src.services.binary_runtime import binary_waterfall_payload
from src.services.binary_snapshot_diff import diff_binary_snapshots


def _snapshot() -> dict:
    return {
        "snapshot_id": "left",
        "format_plugin": "ptx",
        "registry_revision": "1",
        "registry_digest": "registry-a",
        "source": {"sha256": "a" * 64, "size": 30},
        "signals": {"profile_id": "generic-test"},
        "coverage": [
            {"offset": 0, "length": 10, "class": "header", "node_ids": ["h"]},
            {"offset": 10, "length": 20, "class": "records", "node_ids": ["r"]},
        ],
        "nodes": [{"id": "h", "kind": "header"}, {"id": "r", "kind": "record"}],
        "edges": [],
    }


def test_exact_layout_allows_direct_diff():
    left = _snapshot()
    right = deepcopy(left)
    right["snapshot_id"] = "right"
    right["source"]["sha256"] = "b" * 64
    result = diff_binary_snapshots(left, right)
    assert result["compatibility"]["classification"] == "exact"
    assert result["raw"]["performed"] is True
    assert result["raw"]["mode"] == "direct"


def test_structural_layout_aligns_sections_instead_of_offsets():
    left = _snapshot()
    right = deepcopy(left)
    right["coverage"][0].update({"offset": 0, "length": 14})
    right["coverage"][1].update({"offset": 14, "length": 24})
    result = diff_binary_snapshots(left, right)
    assert result["compatibility"]["classification"] == "structural"
    assert result["raw"]["mode"] == "aligned_segments"
    assert result["waterfall"]["comparison_status"] == "structural"
    assert result["raw"]["alignment"][1]["left"]["offset"] == 10
    assert result["raw"]["alignment"][1]["right"]["offset"] == 14


def test_incompatible_variant_blocks_all_automatic_diff_levels():
    left = _snapshot()
    right = deepcopy(left)
    right["signals"]["profile_id"] = "different-variant"
    result = diff_binary_snapshots(left, right)
    assert result["status"] == "incompatible"
    assert result["compatibility"]["automatic_diff_allowed"] is False
    assert all(result[level]["performed"] is False for level in ("raw", "parsed", "runtime"))
    assert result["waterfall"]["automatic_diff_allowed"] is False


def test_normalized_candidate_is_reported_without_filename_rules():
    left = _snapshot()
    right = deepcopy(left)
    right["source"]["candidate_descriptor"] = {"transform_family_id": "registry-transform"}
    result = assess_snapshot_compatibility(left, right)
    assert result["classification"] == "exact"
    assert result["normalized_inputs"] == {"left": False, "right": True}


def test_waterfall_advertises_compatibility_gate():
    payload = binary_waterfall_payload(_snapshot())
    assert payload["comparison_contract"]["classifications"] == ["exact", "structural", "incompatible"]
    assert payload["comparison_contract"]["incompatible_behavior"] == "block_automatic_diff"
    assert "learning_db_hints" in payload
