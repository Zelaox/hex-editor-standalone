from __future__ import annotations

from pathlib import Path

from src.services.region_routed_pseudocode.cooperative_merge import audit_region_map
from src.services.region_routed_pseudocode.format_detect import detect_format
from src.services.region_routed_pseudocode.policies import load_format_detect_registry, load_merge_policy, load_region_routing_policy
from src.services.region_routed_pseudocode.region_map import RegionSpan


def test_mz_prefix_detects_pe(tmp_path: Path):
    sample = tmp_path / "binary.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    routing = load_region_routing_policy()
    registry = load_format_detect_registry(routing=routing)
    plugin, region_class, confidence = detect_format(sample, registry=registry, prefix_bytes=4096)
    assert plugin == "pe"
    assert confidence >= 0.9


def test_audit_flags_pe_whole_file_unknown_takeover():
    merge = load_merge_policy()
    regions = [
        RegionSpan(0, 1000, "unknown_data", "unknown", "pe", 0.0, meta={"strategy": "whole_file"}),
    ]
    violations = audit_region_map(regions, file_size=1000, format_plugin="pe", merge_policy=merge)
    codes = {item["code"] for item in violations}
    assert "generic_whole_file_takeover" in codes or "pe_collapsed_to_whole_unknown" in codes


def test_real_pe_render_uses_decompiler_not_whole_semantic():
    import os

    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "notepad.exe"
    if not candidate.is_file():
        import pytest

        pytest.skip("no system PE for cooperative merge E2E")
    from src.services.region_routed_pseudocode import render_region_routed_bundle

    lines = render_region_routed_bundle(candidate)["lines"]
    text = "\n".join(lines)
    assert "executable_code decompiler region" in text
    assert "Semantic structure unavailable" not in text


def test_real_pe_region_map_has_executable_and_no_whole_file_violation():
    import os

    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "notepad.exe"
    if not candidate.is_file():
        import pytest

        pytest.skip("no system PE for cooperative merge E2E")
    from src.services.region_routed_pseudocode import build_region_map_document

    doc = build_region_map_document(candidate)
    regions = doc.get("regions") or []
    classes = {str(r.get("region_class")) for r in regions}
    assert "executable_code" in classes
    violations = doc.get("merge_violations") or []
    takeover = {v.get("code") for v in violations}
    assert "generic_whole_file_takeover" not in takeover
    assert "pe_collapsed_to_whole_unknown" not in takeover


def test_audit_passes_when_executable_region_present():
    merge = load_merge_policy()
    regions = [
        RegionSpan(0, 512, "executable_code", "decompiler", "pe", 0.9, meta={"pe_section": ".text"}),
        RegionSpan(512, 488, "structured_data", "structural", "pe", 0.9, meta={"pe_section": ".data"}),
    ]
    violations = audit_region_map(regions, file_size=1000, format_plugin="pe", merge_policy=merge)
    assert not any(v.get("code") == "pe_collapsed_to_whole_unknown" for v in violations)
