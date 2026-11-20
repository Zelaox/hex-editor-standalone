"""Hex Editor transform engine unit tests."""

from __future__ import annotations

import gzip
import sys
from pathlib import Path

import pytest

HEX_ROOT = Path(__file__).resolve().parents[1]
if str(HEX_ROOT) not in sys.path:
    sys.path.insert(0, str(HEX_ROOT))


def test_transform_registry_loads():
    from src.services.transform_registry import load_transform_registry

    registry = load_transform_registry()
    assert registry.get("enabled_families")
    assert registry.get("chain_recipes") is not None
    ids = {f["id"] for f in registry["enabled_families"]}
    assert "xor_sweep" in ids
    assert "aes128_cbc" in ids


def test_markers_from_config():
    from src.services.transform_registry import load_markers_config

    markers = load_markers_config()
    assert b"Pro Tools" in markers
    assert b"TRAK" in markers


def test_stage2_cap_min_policy():
    from src.services.stage2_policy import select_stage2_survivors

    cheap = [{"score": index, "key_hex": f"{index:02x}"} for index in range(10)]
    pipeline = {"cheap_top_k": 8, "stage2_top_k": 4, "cheap_min_score": 1, "stage2_cap_policy": "min"}
    survivors = select_stage2_survivors(cheap, pipeline=pipeline, defaults={"stage2_policy": {"mode": "min"}})
    assert len(survivors) <= 4


def test_stage2_cap_not_max_bug():
    from src.services.stage2_policy import select_stage2_survivors

    cheap = [
        {"score": 5, "key_hex": "94"},
        {"score": 4, "key_hex": "55"},
        {"score": 3, "key_hex": "aa"},
        {"score": 2, "key_hex": "01"},
        {"score": 1, "key_hex": "02"},
        {"score": 0, "key_hex": "00"},
    ]
    pipeline = {"cheap_top_k": 8, "stage2_top_k": 4, "cheap_min_score": 1, "stage2_cap_policy": "min"}
    survivors = select_stage2_survivors(cheap, pipeline=pipeline, defaults={})
    assert len(survivors) == 4


def test_behavior_classifier_gzip():
    from src.services.behavior_classifier import classify_binary

    payload = gzip.compress(b"hello pro tools session")
    result = classify_binary(payload, transform_start=0)
    assert result.get("is_compressed") is True
    assert result.get("decompression_success") is True
    assert result.get("skip_crypto_lanes") is True


def test_xor_lane_recovery_single_byte():
    from src.services.ptx_crypto_primitives import xor_apply
    from src.services.transforms.xor_repeating import recover_repeating_key

    key = bytes([0x94])
    plain = (b"Pro Tools TRAK CLIP MEDI SESS Session Audio 00:00:00:01 0:00.100 " * 32)[:512]
    cipher = xor_apply(plain, key)
    recovered, lane_scores = recover_repeating_key(cipher, 1, sample_bytes=len(cipher))
    assert recovered == key
    assert len(lane_scores) == 1


def test_xor_inference_missing_period_policy_fails_loud():
    from src.services.transforms.xor_repeating import _infer_key_lengths

    with pytest.raises(ValueError, match="xor_period_inference"):
        _infer_key_lengths({}, b"sample")


def test_scheduler_requires_registry_metadata():
    from src.services.transform_scheduler import schedule_families

    with pytest.raises(ValueError, match="scheduler metadata"):
        schedule_families({"enabled_families": [{"id": "unregistered-behavior"}]})


def test_crib_refines_repeating_key():
    from src.services.ptx_crypto_primitives import xor_apply
    from src.services.transforms.xor_repeating import apply_crib_constraints

    key = bytes([0x12, 0x34, 0x56, 0x78])
    crib = b"Pro Tools"
    body = crib * 24
    cipher = xor_apply(body, key)
    refined = apply_crib_constraints(
        bytes(len(key)),
        cipher=cipher,
        crib_plain=crib,
        crib_offset=0,
        start_offset=0,
    )
    assert refined == key


def test_derive_iv_from_spec():
    from src.services.ptx_crypto_primitives import derive_iv_from_spec

    raw = b"\x03\x30\x30\x31" + bytes(range(60))
    iv_derived = derive_iv_from_spec(raw, "prefix_slice:0:16")
    assert len(iv_derived) == 16
    assert iv_derived[:4] == raw[:4]


def test_chain_recipe_rejects_unknown_in_registry():
    from src.services.transform_registry import TransformRegistryError, validate_chain_recipes

    families = {"xor_sweep": {"enabled": True}, "rol": {"enabled": True}}
    with pytest.raises(TransformRegistryError):
        validate_chain_recipes(
            {"chain_recipes": [{"id": "bad", "enabled": True, "steps": ["missing_family"]}], "max_chain_depth": 3},
            families,
        )


def test_crypto_defaults_merges_lab_fixture():
    from src.services.ptx_crypto_config import crypto_defaults

    defaults = crypto_defaults()
    assert int(defaults["probe_pipeline"]["stage2_top_k"]) == 4
    assert defaults.get("scoring_profiles")
