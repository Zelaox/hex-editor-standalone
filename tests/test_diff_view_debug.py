"""Config-driven Diff View debug report tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _write_diff_config(tmp_path: Path) -> Path:
    cfg = {
        "schema_version": 1,
        "user_state_path": "config/diff_view.user.json",
        "analysis_chunk_bytes": 1024,
        "changed_range_limit": 64,
        "visualization_max_samples": 4096,
        "block_size": 256,
        "alignment_max_shift": 16,
        "alignment_probe_samples": 128,
        "alignment_min_improvement": 0.05,
        "default_mode": "changed_mask",
        "default_view": "diff_map",
        "default_blend_percent": 50,
        "default_threshold": 1,
        "default_zoom_percent": 100,
        "minimap_width": 512,
        "source_a_tint": [30, 190, 255],
        "source_b_tint": [255, 60, 170],
        "change_class_rgb": {
            "changed": [255, 40, 80],
            "deleted": [255, 150, 30],
            "inserted": [80, 255, 150],
        },
        "view_modes": [
            {"id": "diff_map", "title": "Diff Map", "layout": "single", "blend_behavior": "source_a_to_diff"},
        ],
        "modes": [
            {"id": "changed_mask", "title": "Changed / Unchanged", "low_rgb": [0, 0, 0], "high_rgb": [255, 40, 80]},
        ],
        "pair_policy": {
            "require_equal_length": False,
            "require_matching_suffix_group": False,
            "allow_unlisted_suffixes": True,
            "suffix_groups": [],
            "clear_missing_paths_on_load": True,
            "compare_on_startup": False,
            "summary_include_sha256": True,
        },
        "file_dialog": {"filter_label": "All files (*.*)", "filter_glob": "*"},
    }
    path = tmp_path / "configs" / "diff_view.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def test_debug_report_detects_path_b_manifest_mismatch(tmp_path):
    from scripts.diff_view_debug import build_report

    cfg_path = _write_diff_config(tmp_path)
    state_dir = tmp_path / "config"
    state_dir.mkdir()
    file_a = tmp_path / "a.bin"
    file_b_ui = tmp_path / "b_ui.bin"
    file_b_manifest = tmp_path / "b_manifest.bin"
    file_a.write_bytes(b"\x00" * 32)
    file_b_ui.write_bytes(b"\x01" * 32)
    file_b_manifest.write_bytes(b"\x00" * 32)
    state = {
        "schema_version": 1,
        "path_a": str(file_a),
        "path_b": str(file_b_ui),
        "mode_id": "changed_mask",
    }
    (state_dir / "diff_view.user.json").write_text(json.dumps(state), encoding="utf-8")
    manifest = {
        "source": {"path": str(file_a)},
        "artifact_path": str(file_b_manifest),
        "changed_bytes": 0,
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    policy = json.loads((ROOT / "config" / "diff_view_debug_policy.json").read_text(encoding="utf-8"))
    report = build_report(
        diff_config_path=cfg_path,
        workspace_root=tmp_path,
        policy=policy,
        manifest_path=manifest_path,
    )
    assert report["raw_byte_diff"]["changed_bytes"] == 32
    assert report["manifest_raw_byte_diff"]["changed_bytes"] == 0
    assert "ui_path_b_differs_from_manifest_file_b" in report["mismatch_classes"]
    assert report["ok"] is False


def test_debug_report_reads_user_state_paths(tmp_path):
    from scripts.diff_view_debug import build_report

    cfg_path = _write_diff_config(tmp_path)
    state_dir = tmp_path / "config"
    state_dir.mkdir()
    file_a = tmp_path / "left.bin"
    file_b = tmp_path / "right.bin"
    payload = bytearray(b"\x00" * 16)
    payload[4] = 0xFF
    file_a.write_bytes(bytes(payload))
    file_b.write_bytes(bytes(payload))
    state = {
        "schema_version": 1,
        "path_a": str(file_a),
        "path_b": str(file_b),
        "mode_id": "changed_mask",
    }
    (state_dir / "diff_view.user.json").write_text(json.dumps(state), encoding="utf-8")
    policy = json.loads((ROOT / "config" / "diff_view_debug_policy.json").read_text(encoding="utf-8"))
    report = build_report(diff_config_path=cfg_path, workspace_root=tmp_path, policy=policy)
    assert report["raw_byte_diff"]["changed_bytes"] == 0
    assert report["ok"] is True
