"""UI policy feature flag tests."""

from __future__ import annotations


def test_auto_disassemble_flags_default_off():
    from src.services.ui_policy import feature_enabled, load_ui_policy

    policy = load_ui_policy()
    assert feature_enabled(policy, "auto_disassemble_on_load") is False
    assert feature_enabled(policy, "auto_disassemble_on_dock_show") is False


def test_feature_enabled_missing_key_is_false():
    from src.services.ui_policy import feature_enabled

    assert feature_enabled({"feature_flags": {}}, "unknown_flag") is False
