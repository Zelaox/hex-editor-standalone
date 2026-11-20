from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.transform_preview import (
    build_transform_preview_overlay_spans,
    export_full_file_preview,
    inspect_transform_preview,
    iter_full_file_preview,
    load_transform_preview_policy,
    map_output_offset_to_source,
)
from src.services.transform_preview.cache import cache_key, shared_preview_cache
from src.services.transform_preview.composite import assemble_composite_text
from src.services.transform_preview.registry import dispatch_preview_step, is_preview_safe, load_transform_preview_registry
from src.services.transform_preview.resolver import partition_range
from src.services.ui_policy import load_ui_policy
from src.transform_preview_controller import TransformPreviewController


def test_policy_revision_three_loads():
    policy = load_transform_preview_policy()
    assert policy["revision"] >= 4
    assert "truth_labels" in policy
    assert "cache" in policy


def test_registry_marks_preview_safe_families():
    registry = load_transform_preview_registry()
    assert is_preview_safe(registry, "sub_byte")
    assert not is_preview_safe(registry, "missing-family")


def test_dispatch_sub_byte_preview_step():
    registry = load_transform_preview_registry()
    data = bytes([0x05, 0x06, 0x07])
    output, meta = dispatch_preview_step(
        family_id="sub_byte",
        data=data,
        step={"offset": 0, "parameters": {"subtrahend": 1}},
        source_sha="abc",
        registry=registry,
    )
    assert output == bytes([0x06, 0x07, 0x08])
    assert meta["length_relation"] == "one_to_one"


def test_composite_assembler_labels_spans():
    policy = load_transform_preview_policy()
    text, rows, gaps = assemble_composite_text(
        raw=b"AAhelloBB",
        output=b"AAhelloBB",
        spans=[
            {"offset": 0, "length": 2, "presentation_class": "raw_plaintext"},
            {"offset": 2, "length": 5, "presentation_class": "preview_plaintext", "descriptor_id": "d1"},
            {"offset": 7, "length": 2, "presentation_class": "raw_plaintext"},
        ],
        conflicts=[],
        policy=policy,
        range_offset=0,
    )
    assert "RAW · SOURCE" in text
    assert "PREVIEW · VERIFIED" in text
    assert "hello" in text
    assert len(rows) == 3
    assert gaps == []


def test_cache_hit_returns_same_result(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"cached")
    policy = load_transform_preview_policy()
    cache = shared_preview_cache(policy)
    cache.clear()
    first = inspect_transform_preview(source, offset=0, length=6, mode="raw", policy=policy)
    second = inspect_transform_preview(source, offset=0, length=6, mode="raw", policy=policy)
    assert first["output_bytes"] == second["output_bytes"]
    key = cache_key(source_sha256=first["source_sha256"], mode="raw", offset=0, length=6, policy=policy)
    assert cache.get(key) is not None


def test_map_output_offset_one_to_one():
    mapping = {
        "output_offset": 0,
        "segments": [
            {
                "kind": "one_to_one",
                "source_offset": 100,
                "source_length": 4,
                "output_offset": 0,
                "output_length": 4,
                "exact": True,
            }
        ],
    }
    hit = map_output_offset_to_source(mapping, 2)
    assert hit["source_offset"] == 102
    assert hit["exact"] is True


def test_map_output_offset_block_is_not_exact():
    mapping = {
        "output_offset": 0,
        "segments": [
            {
                "kind": "block",
                "source_offset": 50,
                "source_length": 8,
                "output_offset": 0,
                "output_length": 8,
                "exact": False,
            }
        ],
    }
    hit = map_output_offset_to_source(mapping, 3)
    assert hit["source_offset"] == 50
    assert hit["exact"] is False


def test_overlay_spans_from_preview():
    ui_policy = load_ui_policy()
    ui_policy = {**ui_policy, "feature_flags": {**ui_policy.get("feature_flags", {}), "hex_forensic_overlays": True}}
    ui_policy = {**ui_policy, "hex_overlays": {**ui_policy.get("hex_overlays", {}), "show_transform_preview_scopes": True}}
    preview = {
        "composite_spans": [{"offset": 4, "length": 2, "presentation_class": "preview_plaintext", "descriptor_id": "d1"}],
        "conflicts": [{"offset": 10, "length": 1, "kind": "overlapping_proof_span"}],
    }
    spans = build_transform_preview_overlay_spans(preview, ui_policy=ui_policy)
    roles = {item["role"] for item in spans}
    assert "transform_preview_scope" in roles
    assert "transform_preview_conflict" in roles


def test_export_full_file_preview_report(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")
    policy = load_transform_preview_policy()
    policy = dict(policy)
    policy["full_file_export"] = {"page_bytes": 4, "max_total_bytes": 10}
    report = export_full_file_preview(source, mode="raw", policy=policy)
    assert report["page_count"] == 3
    assert report["output_length"] == 10
    assert report["complete"] is True


def test_controller_stale_generation():
    controller = TransformPreviewController()
    gen = controller.bump_generation()
    assert controller.is_stale(gen) is False
    controller.bump_generation()
    assert controller.is_stale(gen) is True


def test_registry_chain_on_descriptor(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x01\x02\x03\x04")
    candidate_dir = tmp_path / "candidate_root"
    candidate_dir.mkdir()
    candidate = candidate_dir / "candidate.bin"
    candidate.write_bytes(b"\x02\x03\x04\x05")
    proof_path = candidate_dir / "proof_spans.json"
    proof_path.write_text(
        json.dumps(
            [
                {
                    "offset": 0,
                    "length": 4,
                    "scope_id": "scope-a",
                    "proof_id": "proof-a",
                    "provider_id": "sub_byte",
                }
            ]
        ),
        encoding="utf-8",
    )
    (candidate_dir / "inverse.json").write_text("[]", encoding="utf-8")

    def fake_discovery(_rail, _sha, _limit):
        return {
            "verified": True,
            "matched_role": "parent",
            "run": {
                "parent": {"path": str(source), "sha256": "p"},
                "source": {"sha256": "s"},
                "artifacts": {"candidate": str(candidate), "inverse": str(candidate_dir / "inverse.json")},
            },
            "inspected": {"run_root": str(candidate_dir.parent), "candidate": {"artifact_path": str(candidate)}},
        }

    monkeypatch.setattr("src.services.transform_preview.inspect._discover_lineage", fake_discovery)
    partition = partition_range(
        inspected={"artifacts": {"candidate": str(candidate)}},
        source_sha256="s",
        parent_sha256="p",
        range_offset=0,
        range_length=4,
        scope_sources=["full_decode_proof_spans"],
    )
    partition["descriptors"][0]["steps"] = [
        {
            "step_id": "step-sub",
            "family_id": "sub_byte",
            "operation": "preview",
            "offset": 0,
            "length": 4,
            "parameters": {"subtrahend": 1},
        }
    ]
    monkeypatch.setattr(
        "src.services.transform_preview.inspect.partition_range",
        lambda **kwargs: partition,
    )
    result = inspect_transform_preview(source, offset=0, length=4, mode="transform_preview", use_cache=False)
    assert result["output_bytes"] == bytes([0x02, 0x03, 0x04, 0x05])
    assert result["state"] == "verified_preview"
    assert len(result["chain_steps"]) == 1


def test_source_hash_unchanged_after_preview(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"immutable")
    before = source.read_bytes()
    monkeypatch.setattr("src.services.transform_preview.inspect._discover_lineage", lambda *_args: {})
    inspect_transform_preview(source, offset=0, length=9, mode="transform_preview", use_cache=False)
    assert source.read_bytes() == before
