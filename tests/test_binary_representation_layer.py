"""Binary representation & decoding layer tests."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

HEX_ROOT = Path(__file__).resolve().parents[1]
if str(HEX_ROOT) not in sys.path:
    sys.path.insert(0, str(HEX_ROOT))


@pytest.fixture
def policy():
    from src.services.representation_registry import load_representation_policy

    return load_representation_policy()


def test_representation_registry_loads(policy):
    from src.services.representation_registry import load_decoder_registry, load_representation_bundle

    bundle = load_representation_bundle()
    decoders = load_decoder_registry(policy)
    assert int(policy["schema_version"]) == 1
    assert bundle["decoders"]["enabled_families"]
    enabled_ids = {item["id"] for item in decoders["enabled_families"]}
    assert "integer_fixed" in enabled_ids
    assert "float_fixed" in enabled_ids
    assert "varint_leb128" not in enabled_ids


def test_hex_round_trip(policy):
    from src.services.binary_representation import bytes_to_hex, convert_representation, hex_to_bytes

    data = b"\x03\x30\x30\x31\x30\x31"
    hex_view = bytes_to_hex(data, policy=policy)
    assert hex_view == "03 30 30 31 30 31"
    assert hex_to_bytes(hex_view, policy=policy) == data
    converted = convert_representation(direction="from_bytes", format_id="hex", payload=data, policy=policy)
    assert converted["result"] == hex_view
    back = convert_representation(direction="to_bytes", format_id="hex", payload=hex_view, policy=policy)
    assert bytes.fromhex(back["result_hex"].replace(" ", "")) == data


def test_binary_decimal_round_trip(policy):
    from src.services.binary_representation import binary_to_bytes, bytes_to_binary, bytes_to_decimal, decimal_to_bytes

    data = b"\x03\xff"
    binary = bytes_to_binary(data, policy=policy)
    assert binary_to_bytes(binary, policy=policy) == data
    decimal = bytes_to_decimal(data, policy=policy)
    assert decimal_to_bytes(decimal, policy=policy) == data


def test_float32_le_decoder(policy):
    from src.services.decoders.float_fixed import decode_float_candidates

    value = 1.234567
    chunk = struct.pack("<f", value)
    result = decode_float_candidates(chunk, policy=policy, family={"id": "float_fixed"}, offset=0)
    assert result["valid"]
    sample = result["values"][0]
    assert sample["width"] == 4
    assert sample["byte_order"] == "little"
    assert sample["finite"]
    assert abs(sample["value"] - value) < 1e-5


def test_representation_sweep_ascii_region(policy):
    from src.services.representation_sweep import sweep_region

    data = b"\x03\x30\x30\x31\x30\x31"
    brief = sweep_region(data, offset=16, policy=policy, include_binary_decimal=True)
    assert brief["operation"] == "representation_brief"
    assert brief["representation"]["hex"].startswith("03 30")
    assert brief["representation"]["decimal"].startswith("3 48")
    text = next(item for item in brief["text_candidates"] if item["encoding"] == "ascii")
    assert "00101" in text["escaped"]
    signal_ids = {item["id"] for item in brief["interpreter_signals"]}
    assert "mostly_printable" in signal_ids


def test_monotonic_integer_signal(policy):
    from src.services.representation_sweep import sweep_region

    data = b"".join(struct.pack("<I", value) for value in (100, 101, 102, 103))
    brief = sweep_region(data, policy=policy)
    signal_ids = {item["id"] for item in brief["interpreter_signals"]}
    assert "monotonic_integer_sequence" in signal_ids


def test_ptx_full_coverage_delegates_to_sweep(policy):
    from src.services.full_coverage_policy import load_full_coverage_policy, scan_region_features

    full_policy = load_full_coverage_policy()
    data = b"\x03\x30\x30\x31\x30\x31"
    features = scan_region_features(data, full_policy)
    assert "interpreter_signals" in features
    assert "representation_brief_digest" in features


def test_representation_brief_cache(tmp_path, policy):
    from src.services.representation_sweep import load_representation_brief_cache, sweep_region, write_representation_brief_cache

    brief = sweep_region(b"ABC", policy=policy)
    write_representation_brief_cache(tmp_path, "region-1", brief)
    loaded = load_representation_brief_cache(tmp_path, "region-1")
    assert loaded is not None
    assert loaded["operation"] == "representation_brief"


def test_snapshot_brief_attaches_cached_representation(tmp_path, policy):
    from src.services.representation_sweep import sweep_region, write_representation_brief_cache
    from src.services.snapshot_brief_compiler import compile_snapshot_brief

    workspace = tmp_path / "ws"
    workspace.mkdir()
    brief = sweep_region(b"test", policy=policy)
    write_representation_brief_cache(workspace, "unknown-1", brief)
    (workspace / "manifest.json").write_text(
        json.dumps({"details": {"snapshot_id": "snap-1", "snapshot_sha256": "abc", "format_plugin": "ptx"}}),
        encoding="utf-8",
    )
    (workspace / "coverage.json").write_text(json.dumps({}), encoding="utf-8")
    (workspace / "unknown").mkdir()
    (workspace / "unknown" / "regions.json").write_text(
        json.dumps(
            [
                {
                    "region_id": "unknown-1",
                    "span": {"offset": 0, "length": 4},
                    "classification": "unknown",
                    "confidence": "unknown",
                    "features": {"entropy": 1.0},
                    "neighbor_anchor_ids": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    for name in ("anchors.json", "records/families.json", "diagnostics/parser.json", "experiments/index.json"):
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps([] if name.endswith(".json") and "index" not in name else {}), encoding="utf-8")

    policy_override = dict(policy)
    gemma = dict(policy_override.get("gemma_packet") or {})
    gemma["include_representation_brief"] = True
    policy_override["gemma_packet"] = gemma

    from src.services import representation_registry

    representation_registry.load_representation_policy.cache_clear()
    original = representation_registry._config_path

    def _policy_path(_name: str) -> Path:
        if _name == "representation_policy.json":
            custom = tmp_path / "representation_policy.json"
            custom.write_text(json.dumps(policy_override), encoding="utf-8")
            return custom
        return original(_name)

    representation_registry._config_path = lambda name: _policy_path(name) if name == "representation_policy.json" else original(name)
    try:
        compiled = compile_snapshot_brief(workspace)
        region = compiled["top_unknown_regions"][0]
        assert "representation_brief" in region
    finally:
        representation_registry._config_path = original
        representation_registry.load_representation_policy.cache_clear()


def test_export_can_skip_representation_sweep(tmp_path):
    from src.services.representation_sweep import load_representation_brief_cache
    from src.services.representation_workspace import sweep_unknown_regions_in_workspace

    workspace = tmp_path / "ws"
    (workspace / "unknown").mkdir(parents=True)
    region_id = "unknown-skip"
    (workspace / "unknown" / f"{region_id}.bin").write_bytes(b"\x03\x30")
    (workspace / "unknown" / "regions.json").write_text(
        json.dumps(
            [
                {
                    "region_id": region_id,
                    "span": {"offset": 0, "length": 2},
                    "classification": "unknown",
                    "confidence": "unknown",
                    "features": {},
                    "neighbor_anchor_ids": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    skipped = sweep_unknown_regions_in_workspace(workspace, include_representation_sweep=False)
    assert skipped.get("skipped") is True
    assert load_representation_brief_cache(workspace, region_id) is None


def test_bcd_packed_decoder(policy):
    from src.services.decoders.bcd import decode_bcd_packed_candidates

    data = bytes([0x12, 0x34, 0x9A])
    result = decode_bcd_packed_candidates(data, policy=policy, family={"id": "bcd_packed"}, offset=0)
    assert result["valid"]
    assert result["values"][0]["decimal_string"] == "12"
    assert result["values"][1]["decimal_string"] == "34"


def test_bitfield_decoder(policy):
    from src.services.decoders.bitfield import decode_bitfield_candidates

    data = b"\x3A"
    result = decode_bitfield_candidates(data, policy=policy, family={"id": "bitfield_extract"}, offset=0)
    assert result["valid"]
    fields = {item["name"]: item["value"] for item in result["fields"]}
    assert fields["low_nibble"] == 0xA
    assert fields["high_nibble"] == 0x3


def test_workspace_export_runs_representation_sweep(tmp_path):
    from src.services.representation_workspace import sweep_unknown_regions_in_workspace
    from src.services.representation_sweep import load_representation_brief_cache

    workspace = tmp_path / "ws"
    (workspace / "unknown").mkdir(parents=True)
    region_id = "unknown-test"
    (workspace / "unknown" / f"{region_id}.bin").write_bytes(b"\x03\x30\x30\x31\x30\x31")
    (workspace / "unknown" / "regions.json").write_text(
        json.dumps(
            [
                {
                    "region_id": region_id,
                    "span": {"offset": 0, "length": 6},
                    "classification": "unknown",
                    "confidence": "unknown",
                    "features": {},
                    "neighbor_anchor_ids": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    result = sweep_unknown_regions_in_workspace(workspace, force=True)
    assert result["ok"] is True
    assert result["swept_count"] == 1
    cached = load_representation_brief_cache(workspace, region_id)
    assert cached is not None
    assert cached["operation"] == "representation_brief"


def test_mcp_representation_tools():
    lab_root = HEX_ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools import api as hex_editor_tools

    sample = HEX_ROOT / "tests" / "_representation_mcp_sample.bin"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_bytes(b"\x03\x30\x30\x31\x30\x31")
    path = str(sample)
    try:
        converted = hex_editor_tools.binary_representation_convert("from_bytes", "hex", "03 30 30 31")
        assert converted["format_id"] == "hex"
        brief = hex_editor_tools.binary_region_representation_sweep(path, offset=0, length=16)
        assert brief["operation"] == "representation_brief"
        candidates = hex_editor_tools.binary_decoder_candidates(path, offset=0, length=16)
        assert candidates["candidates"]
        signals = hex_editor_tools.binary_value_interpret(path, offset=0, length=16)
        assert "signals" in signals
    finally:
        sample.unlink(missing_ok=True)


def test_mechanical_representation_falsification(policy):
    from src.services.representation_falsification import falsify_representation_brief
    from src.services.representation_sweep import sweep_region

    brief = sweep_region(b"ABCD", policy=policy)
    result = falsify_representation_brief(brief, region_id="unknown-test")
    assert result["operation"] == "binary_representation_falsify"
    assert result["mechanical_authority"] is True
    assert result["model_role"] == "advisory_only"
    assert result["summary"]["total"] > 0
    assert all(item["status"] in {"supported", "falsified", "inconclusive"} for item in result["hypotheses"])
    assert all(item["promotion_allowed"] is False for item in result["hypotheses"])


def test_falsification_policy_drives_threshold(policy):
    from src.services.representation_falsification import falsify_representation_brief, load_falsification_policy
    from src.services.representation_sweep import sweep_region

    brief = sweep_region(b"ABCD", policy=policy)
    active = load_falsification_policy()
    active["thresholds"]["minimum_interpreter_score"] = 1.1
    result = falsify_representation_brief(brief, policy=active)
    signal_hypotheses = [item for item in result["hypotheses"] if item["rule_id"] == "interpreter-signal-threshold"]
    assert signal_hypotheses
    assert all(item["status"] == "inconclusive" for item in signal_hypotheses)


def test_falsification_rejects_non_brief():
    from src.services.representation_falsification import falsify_representation_brief

    with pytest.raises(ValueError, match="RepresentationBrief"):
        falsify_representation_brief({"operation": "model_claim"})
