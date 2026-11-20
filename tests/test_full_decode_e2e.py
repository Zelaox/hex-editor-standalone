"""Coverage, materialization and lossless ASCII E2E tests."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _pair(tmp_path: Path, positions=(137, 509, 1301), relation=0xD3):
    rng = random.Random(771)
    decoded = bytearray(rng.randrange(128, 256) for _ in range(2048))
    text = b"portable repeated ascii record"
    for offset in positions:
        decoded[offset - 1] = 0
        decoded[offset:offset + len(text)] = text
        decoded[offset + len(text)] = 0
    parent = bytearray(decoded)
    for offset in positions:
        for index in range(offset, offset + len(text)):
            parent[index] ^= relation
    source, base = tmp_path / "decoded.bin", tmp_path / "parent.bin"
    source.write_bytes(decoded); base.write_bytes(parent)
    return source, base, text, positions


def test_lossless_ascii_roundtrips_arbitrary_bytes():
    from src.services.full_decode import decode_lossless_ascii, encode_lossless_ascii

    for seed in range(20):
        rng = random.Random(seed)
        data = bytes(rng.randrange(256) for _ in range(seed * 19))
        document = encode_lossless_ascii(data, bytes_per_line=(seed % 13) + 1)
        assert document.isascii()
        assert decode_lossless_ascii(document) == data


def test_lossless_ascii_rejects_noncanonical_or_corrupt_documents():
    from src.services.full_decode import decode_lossless_ascii, encode_lossless_ascii

    document = encode_lossless_ascii(b"abc\x00\xff", bytes_per_line=3)
    with pytest.raises(ValueError):
        decode_lossless_ascii(document.replace("@0000000000000003", "@0000000000000004"))
    with pytest.raises(ValueError):
        decode_lossless_ascii(document.replace("61", "62", 1))
    with pytest.raises(UnicodeEncodeError):
        decode_lossless_ascii(document + "å")


def test_full_decode_e2e_produces_complete_coverage_and_ascii_exports(tmp_path):
    from src.services.full_decode import inspect_full_decode_run, run_full_decode_e2e, verify_full_decode_run

    source, parent, text, positions = _pair(tmp_path)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs")
    run_path = Path(run["run_root"]) / "run.json"
    verification = verify_full_decode_run(run_path)
    assert verification["ok"] is True
    inspected = inspect_full_decode_run(run_path)
    assert inspected["verified"] is True
    assert inspected["coverage"]["coverage_complete"] is True
    assert sum(item["length"] for item in inspected["coverage"]["segments"]) == source.stat().st_size
    candidate = Path(inspected["candidate"]["artifact_path"]).read_bytes()
    for offset in positions:
        assert candidate[offset:offset + len(text)] == text
    assert Path(inspected["exports"]["plaintext_corpus"]).read_text(encoding="ascii").isascii()
    assert Path(inspected["exports"]["lossless_ascii"]).read_text(encoding="ascii").isascii()
    assert all(status == "passed" for status in inspected["gates"]["gates"].values())


def test_full_decode_is_idempotent_and_terminal_resume_is_read_only(tmp_path):
    from src.services.full_decode import resume_full_decode_run, run_full_decode_e2e

    source, parent, _, _ = _pair(tmp_path)
    first = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs")
    second = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs")
    assert first == second
    resumed = resume_full_decode_run(Path(first["run_root"]))
    assert resumed["executed_new_work"] is False


def test_model_cannot_inject_decode_authority(tmp_path):
    from src.services.full_decode import build_full_decode_model_packet, run_full_decode_e2e, validate_full_decode_model_action

    source, parent, _, _ = _pair(tmp_path)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs")
    packet = build_full_decode_model_packet(Path(run["run_root"]) / "run.json")
    candidate_id = packet["candidates"][0]["candidate_id"]
    assert validate_full_decode_model_action({"action": "rank_existing_candidate", "candidate_id": candidate_id, "reason": "all required gates pass"}, packet)
    with pytest.raises(ValueError, match="authority"):
        validate_full_decode_model_action({"action": "rank_existing_candidate", "candidate_id": candidate_id, "reason": "guess", "key_hex": "00"}, packet)


def test_full_decode_runtime_has_no_case_facts():
    paths = [ROOT / "src" / "services" / "full_decode" / "core.py", ROOT / "src" / "services" / "full_decode" / "ascii_codec.py", ROOT / "config" / "full_decode_policy.json", ROOT / "config" / "full_decode_registry.json"]
    content = "\n".join(path.read_text(encoding="utf-8").casefold() for path in paths)
    forbidden = ("blue cat", "patchwork", "1candidate", "chillax", "nectar", "0x7aed", "0x7b18", "0x7b47")
    assert not any(item in content for item in forbidden)


def test_mcp_full_decode_tools_are_registered():
    import sys
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools.catalog import _definitions

    definitions = _definitions()
    assert definitions["binary_full_decode_run"]["effect"] == "reversible_mutation"
    assert definitions["binary_full_decode_inspect"]["effect"] == "evidence_read"
    assert definitions["binary_full_decode_verify"]["effect"] == "evidence_read"
    assert definitions["binary_full_decode_resume"]["effect"] == "reversible_mutation"


def test_mcp_full_decode_run_and_resume_require_confirmation():
    import sys
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools import api as hex_editor_tools

    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_full_decode_run("source", "parent", "output")
    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_full_decode_resume("run")
