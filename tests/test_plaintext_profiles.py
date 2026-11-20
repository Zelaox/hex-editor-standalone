import json
from pathlib import Path

import pytest

from src.services.plaintext_profiles import (
    build_plaintext_profile,
    load_plaintext_profile_policy,
    score_plaintext_profiles,
)


def _policy(tmp_path: Path):
    policy = load_plaintext_profile_policy()
    policy["library_path"] = str((tmp_path / "library.json").resolve())
    return policy


def test_profile_uses_hashed_tokens_and_path_free_provenance(tmp_path):
    reference = tmp_path / "sample.py"
    reference.write_text("alpha_token = 1\nalpha_token += 2\n", encoding="utf-8")

    profile = build_plaintext_profile("suffix-py", [reference], policy=_policy(tmp_path))
    serialized = json.dumps(profile, sort_keys=True)

    assert "alpha_token" not in serialized
    assert str(reference) not in serialized
    assert profile["source_provenance"][0]["suffix"] == ".py"
    assert profile["features"]["token_hashes"]
    assert profile["features"]["sequence_hashes"]
    assert "alpha".encode("utf-8").hex() not in serialized


def test_profile_scores_related_plaintext_above_binary(tmp_path):
    reference = tmp_path / "sample.txt"
    reference.write_text("session timeline track region\n" * 20, encoding="utf-8")
    policy = _policy(tmp_path)
    profile = build_plaintext_profile("suffix-txt", [reference], policy=policy)
    library = {"profiles": {"suffix-txt": profile}}

    text_score = score_plaintext_profiles(reference.read_bytes(), policy=policy, library=library)
    binary_score = score_plaintext_profiles(bytes(range(256)) * 4, policy=policy, library=library)

    assert text_score["best"]["similarity"] > binary_score["best"]["similarity"]


def test_profile_rejects_suffix_not_declared_by_policy(tmp_path):
    reference = tmp_path / "sample.exe"
    reference.write_bytes(b"not a permitted reference")

    policy = _policy(tmp_path)
    policy["allowed_suffixes"] = [".txt"]
    with pytest.raises(ValueError, match="suffix is not allowed"):
        build_plaintext_profile("suffix-exe", [reference], policy=policy)
