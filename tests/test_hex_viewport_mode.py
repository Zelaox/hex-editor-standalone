"""Viewport mode selection and rendering helpers."""

from __future__ import annotations

import pytest

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


def test_viewport_mode_auto_threshold():
    from src.services.ui_policy import load_ui_policy

    policy = load_ui_policy()
    budgets = dict(policy.get("load_budgets") or {})
    threshold = int(budgets["hex_viewport_file_bytes"])
    mode = str(budgets["hex_view_mode"])
    assert mode == "auto"
    assert threshold > 0

    class _EditorStub:
        def __init__(self, size: int):
            self.file_size = size
            self._hex_view_mode = mode
            self._hex_viewport_file_bytes = threshold

        def _uses_viewport_mode(self):
            from src.hex_editor import HexEditor

            return HexEditor._uses_viewport_mode(self)

    assert _EditorStub(threshold - 1)._uses_viewport_mode() is False
    assert _EditorStub(threshold)._uses_viewport_mode() is True
    assert _EditorStub(threshold + 1)._uses_viewport_mode() is True


def test_viewport_render_is_bounded(tmp_path):
    from src.utils import bytes_to_hex_view
    from src.services.ui_policy import load_ui_policy

    payload = bytes(range(256)) * 4096
    sample = tmp_path / "large.bin"
    sample.write_bytes(payload)
    policy = load_ui_policy()
    line_budget = int(dict(policy.get("load_budgets") or {})["hex_viewport_document_lines"])
    top_line = 1000
    offset = top_line * 16
    length = min(line_budget * 16, len(payload) - offset)
    window = payload[offset : offset + length]
    rendered = bytes_to_hex_view(window, base_offset=offset)
    assert rendered.count("\n") + 1 <= line_budget
    assert f"{offset:08X}" in rendered
