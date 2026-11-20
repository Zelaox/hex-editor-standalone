from __future__ import annotations

from pathlib import Path

import pytest

from src.services.region_routed_pseudocode import (
    build_region_map_document,
    load_region_routing_policy,
    offset_for_line,
    render_region_routed_bundle,
    render_region_routed_pseudocode_for_path,
    run_region_routed_pseudocode_job,
)
from src.services.region_routed_pseudocode.ledger_merge import apply_ledger_to_regions
from src.services.region_routed_pseudocode.coalesce import coalesce_regions
from src.services.region_routed_pseudocode.format_detect import detect_format
from src.services.region_routed_pseudocode.policies import load_format_detect_registry, load_merge_policy
from src.services.region_routed_pseudocode.region_map import RegionSpan, classify_raw_regions


def test_policies_load():
    routing = load_region_routing_policy()
    merge = load_merge_policy(routing=routing)
    assert routing["policy_id"] == "hex-editor-region-routing"
    assert merge["policy_id"] == "hex-editor-pseudocode-merge"


def test_html_uses_semantic_clusters(tmp_path: Path):
    sample = tmp_path / "page.html"
    phrase = b"Choose Your Plan"
    sample.write_bytes(b"<!DOCTYPE html><html><body>" + phrase + b" x " + phrase + b"</body></html>")
    document = build_region_map_document(sample)
    assert document["regions"][0]["format_plugin"] == "html"
    rendered = "\n".join(render_region_routed_pseudocode_for_path(sample))
    assert "semantic_fallback" in rendered
    assert "Semantic structure unavailable" in rendered
    assert "unresolved_region_0x" not in rendered


def test_rtf_format_detect(tmp_path: Path):
    sample = tmp_path / "sample.rtf"
    sample.write_bytes(b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}} hello}")
    registry = load_format_detect_registry()
    plugin, region_class, confidence = detect_format(sample, registry=registry, prefix_bytes=4096)
    assert plugin == "rtf"
    assert region_class == "structured_data"
    assert confidence >= 0.9


def test_rtf_region_map_and_render(tmp_path: Path):
    sample = tmp_path / "doc.rtf"
    payload = b"{\\rtf1\\ansi\\ansicpg1252\\deff0 {\\fonttbl {\\f0\\fcharset0 Arial;}} {\\colortbl;\\red0\\green0\\blue0;} body}"
    sample.write_bytes(payload)
    document = build_region_map_document(sample)
    assert document["region_count"] >= 1
    assert document["regions"][0]["format_plugin"] == "rtf"
    rendered = "\n".join(render_region_routed_pseudocode_for_path(sample))
    assert "RTFDocument" in rendered
    assert "fonttbl_group" in rendered or "header_rtf" in rendered
    assert "region_routed_document" in rendered


def test_coalesce_merges_adjacent_same_producer():
    merge = load_merge_policy()
    regions = [
        RegionSpan(0, 10, "unknown_data", "unknown", "unknown", 0.0),
        RegionSpan(10, 10, "unknown_data", "unknown", "unknown", 0.0),
    ]
    merged, audit = coalesce_regions(regions, merge_policy=merge, file_size=20)
    assert len(merged) == 1
    assert merged[0].length == 20
    assert audit["coalesced"] is True


def test_coalesce_fail_closed_on_region_cap():
    merge = load_merge_policy()
    cap = int(merge["coalescence"]["max_raw_regions_after_classify"])
    regions = [
        RegionSpan(index * 2, 1, "unknown_data", "unknown", "unknown", 0.0) for index in range(cap + 1)
    ]
    with pytest.raises(ValueError, match="region_map_truncated"):
        coalesce_regions(regions, merge_policy=merge, file_size=cap * 2 + 2)


def test_unknown_binary_whole_file(tmp_path: Path):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(b"\x00\x01\x02\x03")
    regions = classify_raw_regions(sample)
    assert sum(item.length for item in regions) == 4


def test_ir_document_and_source_map(tmp_path: Path):
    sample = tmp_path / "doc.rtf"
    sample.write_bytes(b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}} tail}")
    bundle = render_region_routed_bundle(sample)
    assert bundle["ir_document"]["kind"] == "pseudocode_ir_document"
    assert bundle["source_map"]
    assert any(entry.get("offset") == 0 for entry in bundle["source_map"])


def test_navigation_offset_for_line(tmp_path: Path):
    sample = tmp_path / "nav.rtf"
    sample.write_bytes(b"{\\rtf1\\ansi x}")
    bundle = render_region_routed_bundle(sample)
    entry = bundle["source_map"][0]
    offset = offset_for_line(bundle["source_map"], int(entry["line_start"]))
    assert offset == int(entry["offset"])


def test_ledger_marks_protected_regions():
    merge = load_merge_policy()
    regions = [
        __import__("src.services.region_routed_pseudocode.region_map", fromlist=["RegionSpan"]).RegionSpan(
            0, 100, "unknown_data", "unknown", "unknown", 0.0
        )
    ]
    proof_rows = [
        {"proof_span_id": "ps1", "span_offset": 10, "span_length": 8, "coverage_class": "verified_plaintext", "truth_state": "verified"}
    ]
    adjusted = apply_ledger_to_regions(regions, proof_rows, merge_policy=merge)
    assert adjusted[0].meta.get("ledger_protected") is True


def test_render_job_writes_artifacts(tmp_path: Path):
    sample = tmp_path / "mini.rtf"
    sample.write_bytes(b"{\\rtf1\\ansi test}")
    out = tmp_path / "artifacts"
    summary = run_region_routed_pseudocode_job(sample, output_root=out)
    assert summary["ok"] is True
    assert Path(summary["region_map_path"]).is_file()
    assert Path(summary["pseudocode_path"]).is_file()
    assert Path(summary["source_map_path"]).is_file()
    assert Path(summary["ir_document_path"]).is_file()
