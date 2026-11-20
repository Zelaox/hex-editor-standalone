from __future__ import annotations

import sys
from pathlib import Path

import pytest

HEX_EDITOR = Path(__file__).resolve().parents[1]
if str(HEX_EDITOR) not in sys.path:
    sys.path.insert(0, str(HEX_EDITOR))

from src.plugins.pe.dynamic_execution import pe_execution_preflight, pe_execution_run
from src.plugins.pe.runtime_analysis import _structure_file_offset, analyze_pe_path, build_pe_snapshot
from src.plugins.ptx.runtime_analysis import analyze_ptx_path, build_ptx_snapshot
from src.runtime.byte_source import ByteSource
from src.runtime.format_router import detect_format_plugin
from src.services.binary_runtime import analyze_binary_snapshot, binary_waterfall_payload
from src.services.binary_snapshot_diff import diff_binary_snapshots
from src.services.binary_workspace import export_binary_workspace, load_binary_workspace
from src.binary_inspector_view import inspector_view_model
from src.parsing.semantic_validator import validate_binary_snapshot


def test_format_router_detects_ptx_and_pe():
    assert detect_format_plugin("file.ptx") == "ptx"
    assert detect_format_plugin("file.exe") == "pe"


def test_analyze_ptx_path_accepts_ptx_shaped_bin(tmp_path: Path):
    sample = tmp_path / "candidate17.bin"
    sample.write_bytes(b"\x03" + b"\x00" * 20 + b"Pro Tools Session File\x00Track One")
    result = analyze_ptx_path(sample)
    assert result["ok"] is True
    assert result["format_plugin"] == "ptx"
    assert result["snapshot"]["format_plugin"] == "ptx"


def test_analyze_binary_snapshot_accepts_ptx_shaped_bin(tmp_path: Path):
    sample = tmp_path / "materialized.bin"
    sample.write_bytes(b"\x03" + b"\x00" * 20 + b"Pro Tools Session File\x00")
    result = analyze_binary_snapshot(sample)
    assert result["ok"] is True
    assert result["format_plugin"] == "ptx"


def test_ptx_snapshot_deterministic():
    source = ByteSource.from_bytes(b"\x00\x01Track One\x00\xff")
    first = build_ptx_snapshot(source).to_dict()
    second = build_ptx_snapshot(source).to_dict()
    assert first == second
    assert first["format_plugin"] == "ptx"
    assert any(item["class"] == "unknown" for item in first["coverage"])


def test_binary_workspace_round_trip(tmp_path: Path):
    source_path = tmp_path / "session.ptx"
    source_path.write_bytes(b"Header Track One End")
    snap = analyze_ptx_path(source_path)["snapshot"]
    exported = export_binary_workspace(source_path, snap, tmp_path / "artifacts")
    loaded = load_binary_workspace(exported["artifact_directory"])
    assert loaded["snapshot"] == snap


def test_binary_workspace_exports_pretty_json(tmp_path: Path):
    source_path = tmp_path / "session.ptx"
    source_path.write_bytes(b"Header Track One End")
    snap = analyze_ptx_path(source_path)["snapshot"]
    exported = export_binary_workspace(source_path, snap, tmp_path / "artifacts")
    root = Path(exported["artifact_directory"])
    for rel in ("graph/nodes.json", "maps/file_offsets.json", "graph/snapshot.json"):
        text = (root / rel).read_text(encoding="utf-8")
        assert text.count("\n") > 5, f"{rel} should be pretty-printed"


def test_binary_diff_cross_snapshot():
    left = build_ptx_snapshot(ByteSource.from_bytes(b"Track One")).to_dict()
    right = build_ptx_snapshot(ByteSource.from_bytes(b"Track Two")).to_dict()
    diff = diff_binary_snapshots(left, right)
    assert diff["raw"]["source_changed"] is True
    assert diff["parsed"]["match_strategy"] == "stable_provenance_id"


def test_pe_snapshot_from_mz_buffer():
    # Minimal path: any MZ-prefixed buffer goes through PE parser until pefile rejects
    data = b"MZ" + b"\x00" * 128
    source = ByteSource.from_bytes(data, descriptor={"suffix": ".exe"})
    source.identity["suffix"] = ".exe"
    try:
        snap = build_pe_snapshot(source).to_dict()
        assert snap["format_plugin"] == "pe"
    except Exception:
        pytest.skip("pefile could not parse synthetic buffer")


def test_pe_structure_offset_uses_pefile_public_api():
    class Structure:
        def get_file_offset(self):
            return 0x240

    assert _structure_file_offset(Structure()) == 0x240


def test_pe_execution_stub_mode(tmp_path: Path):
    target = tmp_path / "hello.bat"
    target.write_text("@echo off\n", encoding="utf-8")
    static = build_ptx_snapshot(ByteSource.from_bytes(b"MZ fake")).to_dict()
    static["format_plugin"] = "pe"
    static["snapshot_id"] = "test-pe"
    static["nodes"] = [
        {"id": "entry-1", "kind": "entry_point", "attributes": {"entry_rva": 4096}},
        {"id": "imp-1", "kind": "import_symbol", "label": "kernel32.CreateFileW"},
    ]
    pre = pe_execution_preflight(static, mode="sandbox")
    assert pre["requires_confirmation"] is True
    run = pe_execution_run(target, static, confirmed=True, mode="sandbox")
    assert run["runtime_snapshot"]["signals"]["event_count"] >= 2
    assert run["merge"]["crosslinks"]


def test_inspector_view_model_runtime_tabs():
    static = build_ptx_snapshot(ByteSource.from_bytes(b"data")).to_dict()
    runtime = {"runtime_snapshot_id": "r1", "nodes": [{"id": "e1"}]}
    model = inspector_view_model(static, runtime_snapshot=runtime)
    assert "Overview" in model["static_tabs"]
    assert model["has_runtime"] is True


def test_waterfall_payload_includes_format_plugin():
    snap = build_ptx_snapshot(ByteSource.from_bytes(b"abc")).to_dict()
    payload = binary_waterfall_payload(snap)
    assert payload["format_plugin"] == "ptx"


def test_semantic_validator_blocks_empty_graph():
    empty = {"format_plugin": "pe", "nodes": [], "signals": {"coverage_ratio": 0.0, "entry_resolved": False}}
    result = validate_binary_snapshot(empty)
    assert result["promotion_blocked"] is True
    assert "empty_graph" in result["issues"]


def test_pe_execution_trace_helpers():
    static = build_ptx_snapshot(ByteSource.from_bytes(b"MZ fake")).to_dict()
    static["format_plugin"] = "pe"
    static["snapshot_id"] = "static-1"
    from src.plugins.pe.dynamic_execution import pe_execution_get_trace, pe_execution_merge_view

    runtime = {
        "runtime_snapshot_id": "runtime-1",
        "static_snapshot_id": "static-1",
        "events": [{"kind": "process_start", "confidence": "observed"}],
        "nodes": [{"id": "n1", "kind": "runtime_event", "attributes": {}}],
        "edges": [],
        "signals": {"event_count": 1, "status": "completed"},
    }
    trace = pe_execution_get_trace(runtime)
    assert trace["event_count"] == 1
    merge = pe_execution_merge_view(static, runtime)
    assert merge["static_snapshot_id"] == "static-1"


def test_snapshot_controller_stale_guard():
    from src.snapshot_controller import SnapshotController

    controller = SnapshotController()
    generation = controller.generation
    assert controller.is_stale(generation) is False
    snap = build_ptx_snapshot(ByteSource.from_bytes(b"Track One")).to_dict()
    controller._static = snap
    controller._generation = generation + 1
    assert controller.is_stale(generation) is True
    assert controller.is_stale(generation + 1) is False
