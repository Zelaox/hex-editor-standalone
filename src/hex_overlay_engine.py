"""
Incremental hex forensic overlays on a stable QTextDocument.

Render invariants (R1–R6):
  R1  Full file loaded once per open/save-reload.
  R2  Native Qt scroll on stable document.
  R3  Forensic refresh must not replace the whole document.
  R4  Overlays applied via viewport highlighter only — never full-document rehighlight.
  R5  Scroll/cursor preserved by caller across apply().
  R6  Full document replace only on initial load / explicit reload / post-save.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from PyQt5.QtCore import QPoint, QTimer
from PyQt5.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat, QTextDocument
from PyQt5.QtWidgets import QPlainTextEdit, QTextEdit

from src.constants import BYTE_GROUP_SIZE


def _set_highlighter_suspended(highlighter: QSyntaxHighlighter, suspended: bool) -> None:
    setter = getattr(highlighter, "set_overlay_suspended", None)
    if callable(setter):
        setter(suspended)


def suspend_document_highlighters(highlighters: Sequence[QSyntaxHighlighter]) -> None:
    """Detach highlighters so bulk document replace does not invoke highlightBlock per line."""
    for highlighter in highlighters:
        if highlighter is None:
            continue
        _set_highlighter_suspended(highlighter, True)
        highlighter.setDocument(None)


def resume_document_highlighters(
    document: QTextDocument,
    highlighters: Sequence[QSyntaxHighlighter],
) -> None:
    """Reattach highlighters and repaint only the visible viewport."""
    for highlighter in highlighters:
        if highlighter is None:
            continue
        highlighter.setDocument(document)
        _set_highlighter_suspended(highlighter, False)
        if hasattr(highlighter, "rehighlight_viewport"):
            highlighter.rehighlight_viewport()
        elif hasattr(highlighter, "rehighlightBlock"):
            _rehighlight_viewport_blocks(highlighter, document)


def _rehighlight_viewport_blocks(highlighter: QSyntaxHighlighter, document: QTextDocument) -> None:
    text_edit = getattr(highlighter, "_text_edit", None)
    if text_edit is None:
        return
    cursor = text_edit.cursorForPosition(QPoint(1, 1))
    if cursor.isNull():
        return
    block = cursor.block()
    viewport_lines = max(1, text_edit.height() // max(1, text_edit.fontMetrics().height()))
    margin = max(0, int(getattr(highlighter, "_viewport_margin_lines", 0) or 0))
    limit = viewport_lines + margin
    count = 0
    while block.isValid() and count < limit:
        highlighter.rehighlightBlock(block)
        block = block.next()
        count += 1


class HexForensicHighlighter(QSyntaxHighlighter):
    """Paint forensic span colors on visible blocks only."""

    def __init__(self, document, *, text_edit: QPlainTextEdit, bytes_per_line: int = 16) -> None:
        super().__init__(document)
        self._text_edit = text_edit
        self._bytes_per_line = max(1, int(bytes_per_line))
        self._viewport_margin_lines = 0
        self._overlay_suspended = False
        self._file_top_line = 0
        self._spans: List[Dict[str, Any]] = []
        self._paint_spans: List[Dict[str, Any]] = []
        self._formats: Dict[str, QTextCharFormat] = {}
        self._enabled_layers: Dict[str, bool] = {}

    def set_overlay_suspended(self, suspended: bool) -> None:
        self._overlay_suspended = bool(suspended)

    def configure(self, *, policy: Mapping[str, Any]) -> None:
        from src.services.ui_policy import load_budget

        tokens = dict(policy.get("theme_tokens") or {})
        overlays = dict(policy.get("hex_overlays") or {})
        self._enabled_layers = {str(key): bool(value) for key, value in overlays.items()}
        self._viewport_margin_lines = load_budget(policy, "hex_overlay_viewport_margin_lines")
        self._formats = {}
        for token, color_value in tokens.items():
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(str(color_value)))
            fmt.setForeground(QColor("#000000"))
            self._formats[str(token)] = fmt
        self._refresh_paint_spans()

    def set_file_top_line(self, line: int) -> None:
        self._file_top_line = max(0, int(line))

    def set_spans(self, spans: Sequence[Mapping[str, Any]]) -> None:
        self._spans = [dict(item) for item in spans or []]
        self._refresh_paint_spans()
        self.rehighlight_viewport()

    def spans(self) -> List[Dict[str, Any]]:
        return list(self._spans)

    def _refresh_paint_spans(self) -> None:
        paintable = [span for span in self._spans if self._layer_enabled(span)]
        paintable.sort(
            key=lambda item: (-int(item.get("priority") or 0), int(item.get("offset") or 0)),
        )
        self._paint_spans = paintable

    def rehighlight_viewport(self) -> None:
        document = self.document()
        if document is None or self._text_edit is None:
            return
        _rehighlight_viewport_blocks(self, document)

    def _layer_enabled(self, span: Mapping[str, Any]) -> bool:
        role = str(span.get("role") or "")
        token = str(span.get("theme_token") or "")
        if token.startswith("timecode.") or role == "timecode":
            return bool(self._enabled_layers.get("show_timecodes", True))
        if role == "anchor" or token.startswith("anchor."):
            return bool(self._enabled_layers.get("show_anchors", True))
        if role == "probe_window" or token == "probe_window":
            return bool(self._enabled_layers.get("show_probe_windows", True))
        if role in {"preserve", "candidate_body", "validation"} or (
            token.startswith("binary_waterfall.") and "record_family" not in token
        ):
            if str(span.get("source_id") or "") == "pair_diff":
                return bool(self._enabled_layers.get("show_pair_diff", True))
            return bool(self._enabled_layers.get("show_alternate_scope_ranges", True))
        if role == "record_family_training" or token == "binary_waterfall.record_family_training":
            return bool(self._enabled_layers.get("show_record_family_training", True))
        if role == "record_family_holdout" or token == "binary_waterfall.record_family_holdout":
            return bool(self._enabled_layers.get("show_record_family_holdout", True))
        if role == "boundary" or token == "binary_waterfall.boundary":
            return bool(self._enabled_layers.get("show_scope_boundaries", True))
        return True

    def _format_for_span(self, span: Mapping[str, Any]) -> Optional[QTextCharFormat]:
        token = str(span.get("theme_token") or "")
        return self._formats.get(token)

    @staticmethod
    def _hex_byte_column(byte_index: int) -> int:
        prefix = 11
        groups_before = byte_index // BYTE_GROUP_SIZE
        index_in_group = byte_index % BYTE_GROUP_SIZE
        return prefix + groups_before * (BYTE_GROUP_SIZE * 3 - 1) + index_in_group * 3

    def highlightBlock(self, text: str) -> None:
        if self._overlay_suspended or not self._paint_spans or ":" not in text:
            return
        block_number = self.currentBlock().blockNumber()
        line_start = (self._file_top_line + block_number) * self._bytes_per_line
        line_end = line_start + self._bytes_per_line

        for span in self._paint_spans:
            fmt = self._format_for_span(span)
            if fmt is None:
                continue
            span_start = int(span.get("offset") or 0)
            span_end = span_start + max(1, int(span.get("length") or 0))
            if span_end <= line_start or span_start >= line_end:
                continue
            first_byte = max(span_start, line_start) - line_start
            last_byte = min(span_end, line_end) - line_start - 1
            for byte_index in range(first_byte, last_byte + 1):
                start_col = self._hex_byte_column(byte_index)
                end_col = start_col + 2
                if end_col <= len(text):
                    self.setFormat(start_col, end_col - start_col, fmt)


class HexOverlayEngine:
    """Attach incremental viewport overlays without document replacement."""

    def __init__(self, text_edit: QPlainTextEdit, *, bytes_per_line: int = 16) -> None:
        self.text_edit = text_edit
        self._highlighter = HexForensicHighlighter(
            text_edit.document(),
            text_edit=text_edit,
            bytes_per_line=bytes_per_line,
        )
        self._defer_ms = 0
        self._scroll_debounce_ms = 0
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._flush_pending)
        self._scroll_timer = QTimer()
        self._scroll_timer.setSingleShot(True)
        self._scroll_timer.timeout.connect(self._highlighter.rehighlight_viewport)
        self._pending_spans: Optional[List[Dict[str, Any]]] = None

    def configure(self, policy: Mapping[str, Any]) -> None:
        from src.services.ui_policy import load_budget

        self._highlighter.configure(policy=policy)
        self._defer_ms = load_budget(policy, "scroll_highlight_defer_ms")
        self._scroll_debounce_ms = load_budget(policy, "scroll_debounce_ms")

    @property
    def highlighter(self) -> HexForensicHighlighter:
        return self._highlighter

    def set_file_top_line(self, line: int) -> None:
        self._highlighter.set_file_top_line(line)

    def apply(self, spans: Sequence[Mapping[str, Any]], *, immediate: bool = False) -> None:
        self._pending_spans = [dict(item) for item in spans or []]
        if immediate:
            self._timer.stop()
            self._highlighter.set_spans(self._pending_spans)
            self._pending_spans = None
            return
        self._timer.start(max(1, int(self._defer_ms or 0)))

    def rehighlight_viewport(self) -> None:
        self._highlighter.rehighlight_viewport()

    def schedule_viewport_refresh(self) -> None:
        if self._pending_spans is not None:
            self._timer.start(max(1, int(self._defer_ms or 0)))
            return
        delay = max(0, int(self._scroll_debounce_ms or 0))
        if delay <= 0:
            self._highlighter.rehighlight_viewport()
            return
        self._scroll_timer.start(delay)

    def spans(self) -> List[Dict[str, Any]]:
        return self._highlighter.spans()

    def _flush_pending(self) -> None:
        if self._pending_spans is None:
            self._highlighter.rehighlight_viewport()
            return
        self._highlighter.set_spans(self._pending_spans)
        self._pending_spans = None
