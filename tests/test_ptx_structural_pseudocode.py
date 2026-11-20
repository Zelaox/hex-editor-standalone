from __future__ import annotations

from src.services.region_routed_pseudocode.ptx_structural import _render_finding


def test_ptx_finding_uses_value_not_payload():
    lines = _render_finding(
        {
            "kind": "header",
            "value": {"layout": "session_text", "magic": "PTX0", "body_encrypted": True},
            "provenance": "PTXHeader",
            "confidence": "inferred",
        },
        budgets={"max_session_strings": 4},
    )
    text = "\n".join(lines)
    assert "header_layout" in text
    assert "session_text" in text
    assert "None" not in text


def test_ptx_sections_and_timecodes_render_counts():
    section_lines = _render_finding(
        {"kind": "sections", "value": [{"offset": "0x10", "type_name": "Primary", "size": 100}], "confidence": "heuristic"},
        budgets={"max_sections": 8},
    )
    assert "section_count = 1U" in "\n".join(section_lines)
    timecode_lines = _render_finding(
        {"kind": "timecodes", "value": [{"offset": 48, "value": "00:00:00:01"}], "confidence": "heuristic"},
        budgets={"max_timecodes": 12},
    )
    assert "timecode_count = 1U" in "\n".join(timecode_lines)
    assert "00:00:00:01" in "\n".join(timecode_lines)
