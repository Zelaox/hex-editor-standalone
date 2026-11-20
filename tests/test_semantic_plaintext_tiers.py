from __future__ import annotations

import pytest

from src.services.semantic_plaintext_tiers import (
    classify_cluster_tier,
    classify_plaintext_tier,
    load_semantic_plaintext_tiers_policy,
)


def test_tiers_policy_is_schema_valid():
    policy = load_semantic_plaintext_tiers_policy()
    assert policy["policy_id"] == "semantic-plaintext-tiers"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Pro tools projekt", "semantic_plaintext"),
        ("d_Post Gain 2", "semantic_plaintext"),
        ("d_Control 38", "semantic_plaintext"),
        ("d_Flip Phase 6", "semantic_plaintext"),
        ("00:00:01:00.00", "semantic_plaintext"),
        ("Blue Cat's PatchWork Synth 1", "semantic_plaintext"),
        ("Abx`FLCZBLGgIgE", "verified_printable_bytes"),
        ("'9<=ixIIIIcIIIy", "verified_printable_bytes"),
        ("b{cGgjo[`zoW`z{", "verified_printable_bytes"),
        ("&&&&&&&&&&&&&&&&", "verified_printable_bytes"),
        ("wwwwwvwwwvswvw", "verified_printable_bytes"),
        ("+&/:b}$ninfkf", "verified_printable_bytes"),
        ("555555555555QjfZYZ", "verified_printable_bytes"),
        ("HOxOOOn_MOJOOO", "verified_printable_bytes"),
    ],
)
def test_plaintext_tier_classification(text: str, expected: str):
    assert classify_plaintext_tier(text) == expected


@pytest.mark.parametrize(
    ("preview", "expected"),
    [
        ("d_Control 24", "repeated_semantic_cluster"),
        ("Abx`FLCZBLGgIgE", "repeated_printable_cluster"),
    ],
)
def test_cluster_tier_classification(preview: str, expected: str):
    assert classify_cluster_tier(preview) == expected
