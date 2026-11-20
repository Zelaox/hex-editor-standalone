"""
Hex editing functionality for the HexEditor application.
"""
import os
import shutil
import tempfile
import logging
import threading
from html import escape
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from pathlib import Path

from PyQt5.QtCore import QObject, QFileSystemWatcher, pyqtSignal, QThread, QTimer, Qt, QPoint, QEvent
from PyQt5.QtWidgets import QPlainTextEdit, QMessageBox, QApplication
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QColor, QBrush

from src.constants import CHUNK_SIZE, MAX_UNDO_STEPS, PTX_SECTION_HEADER_SIZE, MAX_CACHED_CHUNKS, VISIBLE_CHUNK_COUNT, HEX_TEXT_COLOR, OFFSET_COLOR, ASCII_COLOR, DEFAULT_FONT_FAMILY, DEFAULT_FONT_SIZE, BYTE_GROUP_SIZE
from src.services.path_utils import normalize_input_path
from src.utils import bytes_to_hex_view, hex_view_to_bytes_strict, FileCache
from src.hex_overlay_engine import resume_document_highlighters, suspend_document_highlighters


class HexEditor(QObject):
    """Class for handling hex editing operations."""
    
    # Signals
    file_loaded = pyqtSignal(str, int)  # file_path, file_size
    file_saved = pyqtSignal(str)  # file_path
    file_changed = pyqtSignal(str)  # file_path
    error_occurred = pyqtSignal(str)  # error_message
    timecodes_found = pyqtSignal(list)  # List of timecodes found
    loading_progress = pyqtSignal(int, int)  # current, total
    display_refresh_requested = pyqtSignal()
    _hex_load_ready = pyqtSignal(int, str, int, object, str)  # generation, path, size, data, text
    
    def __init__(self, text_edit: QPlainTextEdit):
        """
        Initialize the hex editor.
        
        Args:
            text_edit: The QPlainTextEdit widget to use for displaying the hex view
        """
        super().__init__()
        self.text_edit = text_edit
        self.file_path = None
        self.file_size = 0
        self.file_data = b''  # Entire loaded file content
        self.file_cache = None
        self.undo_stack = []
        self.redo_stack = []
        self.modifications = {}  # absolute file offset -> replacement byte
        self._display_refresh = False
        self._loaded_stat = None
        self.bookmarks = {}  # {offset: description}
        self.comments = {}  # {offset: comment}
        self.timecodes = []  # List of timecode offsets
        self.plaintext_runs: List[Dict[str, Union[str, int]]] = []
        self.forensic_overlay_spans: List[Dict[str, Union[str, int]]] = []
        self.ui_policy = None
        self._document_highlighters = []
        self._parse_generation = 0
        self._load_generation = 0
        self._document_content_epoch = 0
        self._document_mutation_active = False
        self._max_highlight_ops = 0
        self._highlight_color_map: Dict[int, str] = {}
        self._scroll_debounce_ms = 0
        self._scroll_highlight_defer_ms = 120
        self._pseudocode_navigation_spans: List[Tuple[int, int]] = []
        self._pseudocode_navigation_theme_token = ""
        self._hex_view_mode = "auto"
        self._hex_viewport_file_bytes = 0
        self._hex_viewport_document_lines = 0
        self._hex_viewport_overscan_lines = 0
        self._viewport_mode_active = False
        self._file_top_line = 0
        self._suppress_scroll = False
        self.file_watcher = QFileSystemWatcher()
        self.file_watcher.fileChanged.connect(self.handle_file_changed)
        self.is_modified = False
        self.show_hex = True
        self.show_ascii = True
        self.bytes_per_line = 16
        self.is_ptx_file = False
        self.ptx_handler = None
        self.highlight_formats = {
            "header": self._create_highlight_format(QColor(100, 149, 237, 180)),
            "section_header": self._create_highlight_format(QColor(255, 105, 180, 180)),
            "selection": self._create_highlight_format(QColor(255, 165, 0, 180)),
        }
        try:
            from src.services.ui_policy import load_ui_policy

            self.configure_ui_policy(load_ui_policy())
        except Exception:
            self._max_highlight_ops = 0
            self.highlight_formats.update(
                {
                    "timecode_reference": self._create_highlight_format(QColor(255, 215, 0, 180)),
                    "timecode": self._create_highlight_format(QColor(144, 238, 144, 180)),
                }
            )

        self.current_visible_start = 0
        self.current_visible_size = 0

        self.text_edit.verticalScrollBar().valueChanged.connect(self._on_scroll_bar_changed)
        self.text_edit.installEventFilter(self)

        # Legacy timer kept for policy compatibility; unused for scroll reload
        self.update_timer = QTimer()
        self.update_timer.setSingleShot(True)
        self.update_timer.timeout.connect(self.update_visible_range)

        # Track whether update is in progress
        self.update_in_progress = False

        # Logger
        self.logger = logging.getLogger("hex_editor")

        # Background parsing thread
        self.parsing_thread = None
        self.text_edit.textChanged.connect(self._handle_text_changed)
        self.display_refresh_requested.connect(self.update_display)
        self._hex_load_ready.connect(self._apply_hex_load, Qt.QueuedConnection)

    def _begin_document_mutation(self) -> None:
        self._document_mutation_active = True
        self._display_refresh = True
        self._suppress_scroll = True
        self.text_edit.blockSignals(True)
        bar = self.text_edit.verticalScrollBar()
        bar.blockSignals(True)
        self._suspend_document_highlights()

    def _end_document_mutation(self) -> None:
        bar = self.text_edit.verticalScrollBar()
        bar.blockSignals(False)
        self.text_edit.blockSignals(False)
        self._resume_document_highlights()
        self._display_refresh = False
        self._suppress_scroll = False
        self._document_mutation_active = False

    def _apply_hex_text(self, text: str, *, restore_scroll: bool = True) -> None:
        if not text:
            return
        anchor = self._document_top_line() if restore_scroll else 0
        self._begin_document_mutation()
        try:
            self.text_edit.setPlainText(text)
            self._document_content_epoch += 1
        finally:
            self._end_document_mutation()
        if restore_scroll and anchor > 0:
            self._set_document_scroll_line(anchor)

    def configure_ui_policy(self, policy: Dict) -> None:
        """Load highlight colors from ui_policy theme tokens."""
        self.ui_policy = dict(policy or {})
        tokens = dict(self.ui_policy.get("theme_tokens") or {})
        mapping = {
            "timecode_reference": "timecode.reference",
            "timecode": "timecode.standard",
            "anchor_verified": "anchor.verified",
            "anchor_candidate": "anchor.candidate",
            "preserve": "binary_waterfall.preserve",
            "candidate_body": "binary_waterfall.candidate_body",
            "validation": "binary_waterfall.validation",
            "probe_window": "probe_window",
            "boundary": "binary_waterfall.boundary",
            "record_family_training": "binary_waterfall.record_family_training",
            "record_family_holdout": "binary_waterfall.record_family_holdout",
            "plaintext_run": "plaintext.run",
        }
        for fmt_key, token in mapping.items():
            color_value = tokens.get(token)
            if color_value:
                self.highlight_formats[fmt_key] = self._create_highlight_format(QColor(str(color_value)))
        from src.services.ui_policy import load_budget

        self._max_highlight_ops = load_budget(self.ui_policy, "max_highlight_ops_per_visible_section")
        self._scroll_debounce_ms = load_budget(self.ui_policy, "scroll_debounce_ms")
        self._scroll_highlight_defer_ms = load_budget(self.ui_policy, "scroll_highlight_defer_ms")
        self._hex_view_mode = str(dict(self.ui_policy.get("load_budgets") or {}).get("hex_view_mode") or "auto")
        if self._hex_view_mode in {"viewport", "auto"}:
            self._hex_viewport_file_bytes = load_budget(self.ui_policy, "hex_viewport_file_bytes")
            self._hex_viewport_document_lines = load_budget(self.ui_policy, "hex_viewport_document_lines")
            self._hex_viewport_overscan_lines = load_budget(self.ui_policy, "hex_viewport_overscan_lines")
        else:
            self._hex_viewport_file_bytes = 0
            self._hex_viewport_document_lines = 0
            self._hex_viewport_overscan_lines = 0
        for highlighter in self._document_highlighters:
            configure = getattr(highlighter, "configure_viewport", None)
            if callable(configure):
                configure(policy=self.ui_policy)

    def _uses_viewport_mode(self) -> bool:
        if self.file_size <= 0:
            return False
        mode = str(self._hex_view_mode or "auto")
        if mode == "viewport":
            return True
        if mode == "full":
            return False
        threshold = int(self._hex_viewport_file_bytes or 0)
        if threshold <= 0:
            raise ValueError("hex viewport threshold is not configured")
        return self.file_size >= threshold

    def _viewport_render_line_count(self) -> int:
        viewport_lines = self._viewport_line_count()
        overscan = int(self._hex_viewport_overscan_lines or 0)
        if overscan < 0:
            raise ValueError("hex viewport overscan is not configured")
        budget = int(self._hex_viewport_document_lines or 0)
        if budget <= 0:
            raise ValueError("hex viewport document line budget is not configured")
        return min(budget, viewport_lines + (overscan * 2))

    def _sync_viewport_scrollbar_value(self) -> None:
        bar = self.text_edit.verticalScrollBar()
        bar.blockSignals(True)
        try:
            bar.setRange(0, self._max_file_top_line())
            bar.setPageStep(max(1, self._viewport_line_count()))
            bar.setValue(self._file_top_line)
        finally:
            bar.blockSignals(False)

    def _refresh_viewport_after_scroll(self) -> None:
        self._render_viewport(preserve_cursor=False)

    def _scroll_viewport_by_lines(self, lines: int) -> None:
        if lines == 0:
            return
        new_top = max(0, min(self._file_top_line + int(lines), self._max_file_top_line()))
        if new_top == self._file_top_line:
            return
        self._file_top_line = new_top
        self._refresh_viewport_after_scroll()

    def eventFilter(self, watched, event) -> bool:
        if watched is self.text_edit and self._uses_viewport_mode():
            if event.type() == QEvent.Wheel:
                delta = event.angleDelta().y()
                if delta:
                    steps = max(1, abs(delta) // 120) if abs(delta) >= 120 else 1
                    self._scroll_viewport_by_lines(-steps if delta > 0 else steps)
                    event.accept()
                    return True
            if event.type() == QEvent.Resize:
                if self.file_cache:
                    QTimer.singleShot(0, lambda: self._render_viewport(preserve_cursor=True))
        return super().eventFilter(watched, event)

    def _configure_viewport_scrollbar(self) -> None:
        self._sync_viewport_scrollbar_value()

    def _render_viewport(self, *, preserve_cursor: bool = False) -> None:
        if not self.file_cache or self.file_size <= 0:
            return
        line_count = self._viewport_render_line_count()
        byte_offset = self._file_top_line * self.bytes_per_line
        byte_length = min(line_count * self.bytes_per_line, max(0, self.file_size - byte_offset))
        if byte_length <= 0:
            self._apply_hex_text("", restore_scroll=False)
            self._sync_viewport_scrollbar_value()
            return
        window = self._read_with_modifications(byte_offset, byte_length)
        anchor_line = self._document_top_line() if preserve_cursor else 0
        self._apply_hex_text(
            bytes_to_hex_view(window, bytes_per_line=self.bytes_per_line, base_offset=byte_offset),
            restore_scroll=False,
        )
        self.current_visible_start = byte_offset
        self.current_visible_size = byte_length
        self._sync_viewport_scrollbar_value()
        if preserve_cursor and anchor_line > 0:
            self._set_document_scroll_line(anchor_line)

    def _on_scroll_bar_changed(self, value: int) -> None:
        if self._uses_viewport_mode():
            if self._suppress_scroll or self.update_in_progress or self._document_mutation_active:
                return
            new_top = max(0, int(value))
            if new_top == self._file_top_line:
                return
            self._file_top_line = new_top
            self._refresh_viewport_after_scroll()
            return
        self._on_document_scroll(value)

    def register_document_highlighter(self, highlighter) -> None:
        if highlighter is not None and highlighter not in self._document_highlighters:
            self._document_highlighters.append(highlighter)

    def _all_document_highlighters(self):
        return list(self._document_highlighters)

    def _suspend_document_highlights(self) -> None:
        suspend_document_highlighters(self._all_document_highlighters())

    def _resume_document_highlights(self) -> None:
        resume_document_highlighters(self.text_edit.document(), self._all_document_highlighters())

    def set_forensic_overlay_spans(self, spans: List[Dict[str, Union[str, int]]]) -> None:
        """Forensic hex overlays disabled — spans are ignored (panels still use context)."""
        self.forensic_overlay_spans = []

    def clear_forensic_overlays(self) -> None:
        self.forensic_overlay_spans = []

    def refresh_overlay_layers(self) -> None:
        return

    def _total_line_count(self) -> int:
        return (self.file_size + self.bytes_per_line - 1) // self.bytes_per_line

    def _viewport_line_count(self) -> int:
        metrics_h = max(1, self.text_edit.fontMetrics().height())
        return max(1, self.text_edit.height() // metrics_h)

    def _max_file_top_line(self) -> int:
        return max(0, self._total_line_count() - self._viewport_line_count())

    def _document_top_line(self) -> int:
        cursor = self.text_edit.cursorForPosition(QPoint(1, 1))
        if cursor.isNull():
            return 0
        return max(0, cursor.blockNumber())

    def _sync_file_position_from_document(self) -> None:
        self._file_top_line = self._document_top_line()
        self.current_visible_start = self._file_top_line * self.bytes_per_line

    def _set_document_scroll_line(self, line: int) -> None:
        document = self.text_edit.document()
        block = document.findBlockByNumber(max(0, int(line)))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        self._suppress_scroll = True
        bar = self.text_edit.verticalScrollBar()
        bar.blockSignals(True)
        try:
            self.text_edit.setTextCursor(cursor)
            self.text_edit.ensureCursorVisible()
        finally:
            bar.blockSignals(False)
            self._suppress_scroll = False
        self._sync_file_position_from_document()

    def _load_full_file_data(self) -> None:
        self.current_visible_start = 0
        self.current_visible_size = self.file_size
        self._file_top_line = 0
        if self._uses_viewport_mode():
            self._viewport_mode_active = True
            self.file_data = None
            return
        self._viewport_mode_active = False
        self.file_data = self._read_with_modifications(0, self.file_size)

    def _render_full_view(self, *, restore_scroll: bool = True) -> None:
        if self._uses_viewport_mode():
            self._render_viewport(preserve_cursor=restore_scroll)
            return
        if not self.file_data:
            return
        self._apply_hex_text(
            bytes_to_hex_view(
                self.file_data,
                bytes_per_line=self.bytes_per_line,
                base_offset=0,
            ),
            restore_scroll=restore_scroll,
        )

    def _on_document_scroll(self, _value: int) -> None:
        if self._uses_viewport_mode():
            return
        if self._suppress_scroll or self.update_in_progress or self._document_mutation_active:
            return
        self._sync_file_position_from_document()

    def _render_plain_text(self) -> str:
        return bytes_to_hex_view(
            self.file_data,
            bytes_per_line=self.bytes_per_line,
            base_offset=0,
        )

    def _render_and_show(self, *, preserve_scroll: bool = True) -> None:
        if self._uses_viewport_mode():
            self._render_viewport(preserve_cursor=preserve_scroll)
            return
        if not self.file_data:
            return
        anchor = self._document_top_line() if preserve_scroll else 0
        self._render_full_view()
        if preserve_scroll:
            self._set_document_scroll_line(anchor)

    def _has_scroll_highlights(self) -> bool:
        if self._overlay_enabled("show_timecodes") and self.timecodes:
            return True
        return bool(self.forensic_overlay_spans)

    def update_display(self):
        """Reload document only when bytes changed; overlays always incremental (R3/R4)."""
        if not self.file_cache:
            return
        self._render_and_show(preserve_scroll=True)

    def document_content_epoch(self) -> int:
        return int(self._document_content_epoch)

    def _format_key_color(self, format_key: str) -> str:
        fmt = self.highlight_formats.get(format_key)
        if fmt is None:
            return ""
        return fmt.background().color().name()

    def _token_color_hex(self, token: str) -> str:
        return self._format_key_color(self._theme_token_to_format(token))

    def _theme_token_to_format(self, token: str) -> str:
        mapping = {
            "timecode.reference": "timecode_reference",
            "timecode.standard": "timecode",
            "anchor.verified": "anchor_verified",
            "anchor.candidate": "anchor_candidate",
            "binary_waterfall.preserve": "preserve",
            "binary_waterfall.candidate_body": "candidate_body",
            "binary_waterfall.validation": "validation",
            "probe_window": "probe_window",
            "binary_waterfall.boundary": "boundary",
            "binary_waterfall.record_family_training": "record_family_training",
            "binary_waterfall.record_family_holdout": "record_family_holdout",
            "plaintext.run": "plaintext_run",
        }
        return mapping.get(str(token or ""), "candidate_body")

    def _overlay_enabled(self, key: str) -> bool:
        overlays = dict((self.ui_policy or {}).get("hex_overlays") or {})
        return bool(overlays.get(key, False))

    def _rebuild_highlight_color_map(self) -> None:
        self._highlight_color_map = {}
        if not self.file_cache:
            return
        visible_start = self.current_visible_start
        visible_end = visible_start + max(1, self.current_visible_size)
        max_ops = int(self._max_highlight_ops or 0)
        if max_ops <= 0:
            return
        priority_order = list(dict((self.ui_policy or {}).get("hex_overlays") or {}).get("overlay_priority") or [])

        def role_priority(role: str) -> int:
            return priority_order.index(role) if role in priority_order else len(priority_order)

        paint_jobs: List[tuple[int, int, int, str]] = []
        if self._overlay_enabled("show_timecodes") and self.timecodes:
            for tc in self.timecodes:
                offset = int(tc.get("offset") or 0)
                key = "timecode_reference" if "reference" in str(tc.get("type") or "").lower() else "timecode"
                color = self._format_key_color(key)
                if color:
                    paint_jobs.append((offset, offset + 1, role_priority("timecode"), color))
        if self._overlay_enabled("show_plaintext_runs") and self.plaintext_runs:
            color = self._format_key_color("plaintext_run")
            if color:
                for row in self.plaintext_runs:
                    start = int(row.get("offset") or 0)
                    length = max(1, int(row.get("length") or 1))
                    paint_jobs.append((start, start + length, role_priority("plaintext"), color))
        if self.forensic_overlay_spans:
            for span in self.forensic_overlay_spans:
                start = int(span.get("offset") or 0)
                length = max(1, int(span.get("length") or 1))
                role = str(span.get("role") or "").replace("_body", "")
                color = self._token_color_hex(str(span.get("theme_token") or ""))
                if color:
                    paint_jobs.append((start, start + length, role_priority(role), color))
        if self._pseudocode_navigation_spans:
            nav_color = self._token_color_hex(self._pseudocode_navigation_theme_token)
            if nav_color:
                for start, length in self._pseudocode_navigation_spans:
                    paint_jobs.append(
                        (int(start), int(start) + max(1, int(length)), role_priority("pseudocode_nav"), nav_color)
                    )
        paint_jobs.sort(key=lambda item: item[2])
        painted = 0
        for start, end, _, color in paint_jobs:
            if painted >= max_ops:
                break
            clip_start = max(start, visible_start)
            clip_end = min(end, visible_end)
            for offset in range(clip_start, clip_end):
                if painted >= max_ops:
                    break
                self._highlight_color_map[offset] = color
                painted += 1

    def _format_hex_groups_html(self, chunk: bytes, absolute_start: int) -> str:
        groups = []
        for group_start in range(0, len(chunk), BYTE_GROUP_SIZE):
            group = chunk[group_start:group_start + BYTE_GROUP_SIZE]
            tokens = []
            for index, byte in enumerate(group):
                absolute = absolute_start + group_start + index
                color = self._highlight_color_map.get(absolute)
                token = f"{byte:02X}"
                if color:
                    tokens.append(f'<span style="background-color:{color}; color:{HEX_TEXT_COLOR}">{escape(token)}</span>')
                else:
                    tokens.append(escape(token))
            groups.append(" ".join(tokens))
        return "  ".join(groups)

    def _render_visible_html(self) -> str:
        self._rebuild_highlight_color_map()
        formatted_lines = []
        for relative in range(0, len(self.file_data), self.bytes_per_line):
            chunk = self.file_data[relative:relative + self.bytes_per_line]
            absolute_start = relative
            hex_part = self._format_hex_groups_html(chunk, absolute_start)
            plain_groups = []
            for group_start in range(0, len(chunk), BYTE_GROUP_SIZE):
                group = chunk[group_start:group_start + BYTE_GROUP_SIZE]
                plain_groups.append(" ".join(f"{byte:02X}" for byte in group))
            plain_hex = "  ".join(plain_groups)
            expected_hex_len = self.bytes_per_line * 3 + (self.bytes_per_line // BYTE_GROUP_SIZE - 1)
            padding = " " * max(0, expected_hex_len - len(plain_hex))
            ascii_part = escape("".join(chr(b) if 32 <= b <= 126 else "." for b in chunk))
            offset_part = escape(f"{absolute_start:08X}:")
            formatted_lines.append(
                f'<span style="color:{OFFSET_COLOR}">{offset_part}</span>  '
                f'<span style="color:{HEX_TEXT_COLOR}">{hex_part}{escape(padding)}</span>  '
                f'<span style="color:{ASCII_COLOR}">|  {ascii_part}</span>'
            )
        return '<pre>' + '<br>'.join(formatted_lines) + '</pre>'

    def _handle_text_changed(self):
        if not self._display_refresh and not self._document_mutation_active and self.file_path:
            self.is_modified = True

    def _source_stat(self, path: str):
        stat = os.stat(path)
        return (stat.st_size, stat.st_mtime_ns)

    def _read_with_modifications(self, offset: int, size: int) -> bytes:
        data = bytearray(self.file_cache.get_data(offset, size))
        end = offset + len(data)
        for absolute, value in self.modifications.items():
            if offset <= absolute < end:
                data[absolute - offset] = value
        return bytes(data)

    def _commit_visible_edits(self) -> bool:
        if not self.file_path or not self.file_cache:
            return True
        if not self.is_modified:
            return True
        if self._uses_viewport_mode():
            base_offset = self._file_top_line * self.bytes_per_line
            edited = hex_view_to_bytes_strict(
                self.text_edit.toPlainText(),
                expected_size=None,
                base_offset=base_offset,
            )
            if not edited:
                return True
            changes = []
            for index, new_byte in enumerate(edited):
                absolute = base_offset + index
                original = self.file_cache.get_data(absolute, 1)
                if not original:
                    continue
                previous_patch = self.modifications.get(absolute)
                current = previous_patch if previous_patch is not None else original[0]
                if new_byte == current:
                    continue
                if new_byte == original[0]:
                    self.modifications.pop(absolute, None)
                else:
                    self.modifications[absolute] = new_byte
                changes.append((absolute, previous_patch, self.modifications.get(absolute)))
            if changes:
                self.undo_stack.append(changes)
                if len(self.undo_stack) > MAX_UNDO_STEPS:
                    self.undo_stack.pop(0)
                self.redo_stack.clear()
            self.is_modified = bool(self.modifications)
            return True
        if not self.file_data:
            return True
        edited = hex_view_to_bytes_strict(
            self.text_edit.toPlainText(),
            expected_size=len(self.file_data),
            base_offset=0,
        )
        if edited == self.file_data:
            return True

        changes = []
        for relative, (previous_byte, new_byte) in enumerate(zip(self.file_data, edited)):
            if previous_byte == new_byte:
                continue
            absolute = relative
            previous_patch = self.modifications.get(absolute)
            original = self.file_cache.get_data(absolute, 1)
            if not original:
                raise ValueError(f"Cannot edit byte at offset 0x{absolute:X}")
            if new_byte == original[0]:
                self.modifications.pop(absolute, None)
            else:
                self.modifications[absolute] = new_byte
            changes.append((absolute, previous_patch, self.modifications.get(absolute)))

        if changes:
            self.undo_stack.append(changes)
            if len(self.undo_stack) > MAX_UNDO_STEPS:
                self.undo_stack.pop(0)
            self.redo_stack.clear()
        self.file_data = edited
        self.is_modified = bool(self.modifications)
        return True

    def _apply_edit_transaction(self, changes, use_new: bool):
        for absolute, previous_patch, new_patch in changes:
            value = new_patch if use_new else previous_patch
            if value is None:
                self.modifications.pop(absolute, None)
            else:
                self.modifications[absolute] = value
        if self._uses_viewport_mode():
            self.file_data = None
        else:
            self.file_data = self._read_with_modifications(0, self.file_size)
        self.is_modified = bool(self.modifications)

    def _write_patches(self, path: str):
        if not self.modifications:
            return
        ordered = sorted(self.modifications.items())
        with open(path, 'r+b') as handle:
            run_start = ordered[0][0]
            run = bytearray([ordered[0][1]])
            previous = run_start
            for offset, value in ordered[1:]:
                if offset == previous + 1:
                    run.append(value)
                else:
                    handle.seek(run_start)
                    handle.write(run)
                    run_start = offset
                    run = bytearray([value])
                previous = offset
            handle.seek(run_start)
            handle.write(run)
            handle.flush()
            os.fsync(handle.fileno())

    def _atomic_save(self, source_path: str, save_path: str):
        destination = Path(save_path).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
        )
        os.close(descriptor)
        try:
            shutil.copy2(source_path, temporary_name)
            self._write_patches(temporary_name)
            if os.path.getsize(temporary_name) != self.file_size:
                raise RuntimeError("Saved file size differs from the loaded source")
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.remove(temporary_name)

    def _create_highlight_format(self, color: QColor) -> QTextCharFormat:
        """Create a text format for highlighting with improved visibility."""
        fmt = QTextCharFormat()
        fmt.setBackground(QBrush(color))
        fmt.setForeground(QBrush(QColor("#000000")))  # Black text for better contrast
        fmt.setFontWeight(75)  # Make highlighted text bold
        return fmt

    def load_file(self, file_path: str) -> bool:
        """
        Load a file into the hex editor.
        
        Args:
            file_path: The path to the file to load
            
        Returns:
            True if the file was loaded successfully, False otherwise
        """
        try:
            file_path = normalize_input_path(file_path)
            if not os.path.exists(file_path):
                self.error_occurred.emit(f"File not found: {file_path}")
                return False

            file_size = os.path.getsize(file_path)
            if self.file_cache:
                self.file_cache.close()
                self.file_cache = None

            self._load_generation += 1
            load_generation = self._load_generation
            self._parse_generation += 1
            parse_generation = self._parse_generation

            self.file_path = file_path
            self.file_size = file_size
            self.file_data = b""
            self.is_ptx_file = False
            self.ptx_handler = None
            self.forensic_overlay_spans = []
            self.undo_stack = []
            self.redo_stack = []
            self.modifications = {}
            self.is_modified = False

            loading_name = os.path.basename(file_path)
            self._apply_hex_text(f"Loading {loading_name}…", restore_scroll=False)

            threading.Thread(
                target=self._load_file_worker,
                args=(load_generation, file_path, file_size),
                daemon=True,
            ).start()
            return True

        except Exception as e:
            self.logger.error(f"Error loading file: {e}", exc_info=True)
            self.error_occurred.emit(f"Error loading file: {e}")
            return False

    def _load_file_worker(
        self,
        load_generation: int,
        file_path: str,
        file_size: int,
    ) -> None:
        try:
            mode = str(self._hex_view_mode or "auto")
            threshold = int(self._hex_viewport_file_bytes or 0)
            use_viewport = mode == "viewport" or (mode == "auto" and threshold > 0 and file_size >= threshold)
            if use_viewport:
                if load_generation != self._load_generation:
                    return
                self._hex_load_ready.emit(load_generation, file_path, file_size, None, "")
                return
            with open(file_path, "rb") as handle:
                data = handle.read()
            if load_generation != self._load_generation:
                return
            hex_text = bytes_to_hex_view(
                data,
                bytes_per_line=self.bytes_per_line,
                base_offset=0,
            )
            if load_generation != self._load_generation:
                return
            self._hex_load_ready.emit(load_generation, file_path, file_size, data, hex_text)
        except Exception as exc:
            if load_generation != self._load_generation:
                return
            self.logger.error(f"Error loading file: {exc}", exc_info=True)
            try:
                self.error_occurred.emit(f"Error loading file: {exc}")
            except RuntimeError:
                return

    def _apply_hex_load(
        self,
        load_generation: int,
        file_path: str,
        file_size: int,
        data,
        hex_text: str,
    ) -> None:
        if load_generation != self._load_generation:
            return
        try:
            self.file_cache = FileCache(file_path, CHUNK_SIZE, MAX_CACHED_CHUNKS)
            self._viewport_mode_active = self._uses_viewport_mode()
            if self._viewport_mode_active:
                self.file_data = None
                self.current_visible_start = 0
                self.current_visible_size = 0
                self._file_top_line = 0
                self._configure_viewport_scrollbar()
                self._render_viewport(preserve_cursor=False)
            else:
                self.file_data = bytes(data)
                self.current_visible_start = 0
                self.current_visible_size = file_size
                self._file_top_line = 0
                self._apply_hex_text(hex_text, restore_scroll=False)

            self._loaded_stat = self._source_stat(file_path)
            self.logger.info(f"Loaded file: {file_path}, size: {file_size} bytes")

            self.setup_file_monitoring(file_path)
            self.is_modified = False
            QTimer.singleShot(0, lambda fp=file_path, sz=file_size: self.file_loaded.emit(fp, sz))
        except Exception as exc:
            self.logger.error(f"Error applying loaded file: {exc}", exc_info=True)
            self.error_occurred.emit(f"Error loading file: {exc}")
    
    def _is_ptx_candidate(self, file_path: str) -> bool:
        return False

    def _finish_ptx_parse(self, parse_generation: int, handler, *, success: bool) -> None:
        if parse_generation != self._parse_generation:
            return
        if success and handler is not None:
            self.ptx_handler = handler
            self.timecodes = list(handler.timecodes or [])
            self.plaintext_runs = []
            if handler.file_path:
                try:
                    from src.services.plaintext_runs import discover_printable_runs_for_path

                    self.plaintext_runs = discover_printable_runs_for_path(str(handler.file_path))
                except Exception:
                    self.plaintext_runs = []
        else:
            self.timecodes = []
            self.plaintext_runs = []
        self.timecodes_found.emit(self.timecodes)
        self.display_refresh_requested.emit()
        if success:
            self.logger.debug(
                "PTX parsing complete, found %s timecodes",
                len(self.timecodes),
            )

    def _parse_ptx_in_background(self, parse_generation: int, ptx_handler=None):
        """Parse the PTX file in a background thread."""
        try:
            self.logger.debug("Starting background parsing of PTX file")
            if parse_generation != self._parse_generation:
                return
            handler = ptx_handler or self.ptx_handler
            if handler is None or not handler.parse():
                self.logger.warning("PTX parsing failed")
                QTimer.singleShot(
                    0,
                    lambda gen=parse_generation, h=handler: self._finish_ptx_parse(gen, h, success=False),
                )
                return
            if parse_generation != self._parse_generation:
                return
            QTimer.singleShot(
                0,
                lambda gen=parse_generation, h=handler: self._finish_ptx_parse(gen, h, success=True),
            )
        except RuntimeError:
            return
        except Exception as e:
            if parse_generation != self._parse_generation:
                return
            self.logger.error(f"Error parsing PTX file: {e}", exc_info=True)
            try:
                self.error_occurred.emit(f"Error parsing PTX file: {e}")
            except RuntimeError:
                return

    def save_file(self, file_path: Optional[str] = None) -> bool:
        """
        Save the current content to a file.
        
        Args:
            file_path: The path to save to, or None to use the current file path
            
        Returns:
            True if the file was saved successfully, False otherwise
        """
        try:
            # Use the provided file path or the current one
            save_path = file_path or self.file_path
            
            if not save_path:
                self.error_occurred.emit("No file path specified")
                return False
            
            self._commit_visible_edits()
            source_path = str(Path(self.file_path).resolve())
            if self._loaded_stat != self._source_stat(source_path):
                self.error_occurred.emit(
                    "The source file changed outside Hex Editor. Reload it before saving."
                )
                return False

            if self.file_path and self.file_path in self.file_watcher.files():
                self.file_watcher.removePath(self.file_path)
            if self.file_cache:
                self.file_cache.close()
                self.file_cache = None
            self._atomic_save(source_path, save_path)
            
            # Update the file information
            self.file_path = save_path
            self.file_size = os.path.getsize(save_path)
            self._loaded_stat = self._source_stat(save_path)
            
            # Log file saving
            self.logger.info(f"Saved file: {save_path}, size: {self.file_size} bytes")
            
            # Recreate the file cache
            if self.file_cache:
                self.file_cache.close()
            self.file_cache = FileCache(save_path, CHUNK_SIZE, MAX_CACHED_CHUNKS)
            self._load_full_file_data()
            self._render_full_view()
            self.setup_file_monitoring(save_path)
            
            # Reset the modified flag
            self.is_modified = False
            self.modifications.clear()
            self.undo_stack.clear()
            self.redo_stack.clear()
            
            # Emit the file saved signal
            self.file_saved.emit(save_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving file: {e}", exc_info=True)
            if self.file_path and os.path.exists(self.file_path) and self.file_cache is None:
                try:
                    self.file_cache = FileCache(self.file_path, CHUNK_SIZE, MAX_CACHED_CHUNKS)
                    self.file_data = self._read_with_modifications(0, self.file_size)
                    self.setup_file_monitoring(self.file_path)
                except Exception as recovery_error:
                    self.logger.error(
                        f"Error restoring file cache after failed save: {recovery_error}",
                        exc_info=True,
                    )
            self.error_occurred.emit(f"Error saving file: {e}")
            return False

    def handle_scroll(self):
        """Legacy hook; scrolling is handled by in-buffer document scroll."""
        return

    def update_visible_range(self):
        """Legacy hook; buffer shifts replace full-file scroll reload."""
        return

    def apply_highlights_for_visible_section(self):
        """Highlights are baked into HTML during update_display()."""
        return

    def apply_ptx_highlights(self):
        """Highlights are baked into HTML during update_display()."""
        return

    def setup_file_monitoring(self, file_path: str):
        """
        Set up monitoring for file changes.
        
        Args:
            file_path: The path to the file to monitor
        """
        # Remove any existing file paths
        for path in self.file_watcher.files():
            self.file_watcher.removePath(path)
        
        # Add the new file path
        self.file_watcher.addPath(file_path)

    def handle_file_changed(self, path: str):
        """
        Handle external changes to the file.
        
        Args:
            path: The path to the file that changed
        """
        # Check if the file still exists
        if not os.path.exists(path):
            self.error_occurred.emit(f"File has been deleted: {path}")
            return
        
        # Emit the file changed signal
        self.file_changed.emit(path)

    def undo(self) -> bool:
        """
        Undo the last edit operation.
        
        Returns:
            True if an operation was undone, False otherwise
        """
        try:
            self._commit_visible_edits()
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return False
        if not self.undo_stack:
            return False
        transaction = self.undo_stack.pop()
        self._apply_edit_transaction(transaction, use_new=False)
        self.redo_stack.append(transaction)
        
        # Update the display
        self.update_display()
        
        return True

    def redo(self) -> bool:
        """
        Redo the last undone operation.
        
        Returns:
            True if an operation was redone, False otherwise
        """
        try:
            self._commit_visible_edits()
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return False
        if not self.redo_stack:
            return False
        
        transaction = self.redo_stack.pop()
        self._apply_edit_transaction(transaction, use_new=True)
        self.undo_stack.append(transaction)
        
        # Update the display
        self.update_display()
        
        return True

    def goto_offset(self, offset: int, *, focus: bool = True) -> bool:
        """
        Move the cursor to the specified offset in the file.
        
        Args:
            offset: The offset to go to
            
        Returns:
            True if the offset was found, False otherwise
        """
        if offset < 0 or offset >= self.file_size:
            return False

        try:
            self._commit_visible_edits()
        except ValueError as exc:
            self.error_occurred.emit(str(exc))
            return False

        target_line = offset // self.bytes_per_line
        if self._uses_viewport_mode():
            viewport = self._viewport_line_count()
            self._file_top_line = max(0, min(max(0, target_line - viewport // 2), self._max_file_top_line()))
            bar = self.text_edit.verticalScrollBar()
            bar.blockSignals(True)
            try:
                bar.setValue(self._file_top_line)
            finally:
                bar.blockSignals(False)
            self._render_viewport(preserve_cursor=False)
            document_line = target_line - self._file_top_line
        else:
            viewport = self._viewport_line_count()
            file_top = max(0, min(max(0, target_line - viewport // 2), self._max_file_top_line()))
            self._set_document_scroll_line(file_top)
            # The full-document renderer keeps every file line in the QTextDocument.
            # Scrolling changes only the viewport; it does not rebase document blocks.
            document_line = target_line

        byte_in_line = offset % self.bytes_per_line
        hex_position = self._hex_column_for_byte(byte_in_line)
        block = self.text_edit.document().findBlockByNumber(document_line)
        if not block.isValid():
            return False
        cursor = QTextCursor(block)
        cursor.movePosition(QTextCursor.Right, QTextCursor.MoveAnchor, hex_position)
        cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
        
        # Set the cursor and ensure it's visible
        self.text_edit.setTextCursor(cursor)
        self.text_edit.ensureCursorVisible()
        if focus:
            self.text_edit.setFocus(Qt.OtherFocusReason)
        
        return True

    @staticmethod
    def _hex_prefix_width() -> int:
        """Width of the rendered offset field and its following spacing."""
        return len(f"{0:08X}:  ")

    def _hex_column_for_byte(self, byte_in_line: int) -> int:
        """Map a byte index to its rendered hex-token column."""
        index = max(0, min(int(byte_in_line), self.bytes_per_line - 1))
        completed_groups = index // BYTE_GROUP_SIZE
        return self._hex_prefix_width() + (index * 3) + completed_groups

    def close(self):
        """Clean up resources when closing."""
        if self.file_cache:
            self.file_cache.close()
            self.file_cache = None

    def read_bytes_at(self, offset: int, length: int) -> bytes:
        if not self.file_cache or length <= 0:
            return b""
        offset = max(0, min(offset, self.file_size))
        length = min(length, self.file_size - offset)
        if length <= 0:
            return b""
        return self._read_with_modifications(offset, length)

    def highlight_pseudocode_navigation_ranges(
        self,
        ranges: Sequence[Mapping[str, Any]],
        *,
        theme_token: str = "",
    ) -> None:
        spans: List[Tuple[int, int]] = []
        for item in ranges:
            if not isinstance(item, Mapping):
                continue
            spans.append((int(item.get("file_offset") or 0), max(1, int(item.get("length") or 1))))
        self._pseudocode_navigation_spans = spans
        self._pseudocode_navigation_theme_token = str(theme_token or "")
        self.update_display()

    def clear_pseudocode_navigation_ranges(self) -> None:
        if not self._pseudocode_navigation_spans:
            return
        self._pseudocode_navigation_spans = []
        self.update_display()

    def get_cursor_byte_offset(self) -> int:
        cursor = self.text_edit.textCursor()
        position = cursor.selectionStart() if cursor.hasSelection() else cursor.position()
        block = self.text_edit.document().findBlock(position)
        block_number = block.blockNumber()
        block_position = block.position()
        column = position - block_position
        byte_in_line = 0
        for candidate in range(self.bytes_per_line):
            if self._hex_column_for_byte(candidate) > column:
                break
            byte_in_line = candidate
        absolute_line = self._file_top_line + block_number if self._uses_viewport_mode() else block_number
        return min(self.file_size - 1, absolute_line * self.bytes_per_line + byte_in_line)

    def get_selection(self) -> Optional[Tuple[int, int]]:
        """
        Get the current selection in the text edit.
        
        Returns:
            A tuple of (start, end) offsets or None if no selection
        """
        cursor = self.text_edit.textCursor()
        if not cursor.hasSelection():
            return None
        
        # Get the selected text
        selected_text = cursor.selectedText()
        
        # Calculate the start and end offsets
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        
        # Convert the text positions to byte offsets
        # This is a simplified calculation and may not be accurate for all cases
        try:
            start_line = self.text_edit.document().findBlock(start).blockNumber()
            start_col = start - self.text_edit.document().findBlock(start).position()
            
            end_line = self.text_edit.document().findBlock(end).blockNumber()
            end_col = end - self.text_edit.document().findBlock(end).position()
            
            # Account for the offset display (e.g., "00000000: ")
            if start_col < 10:
                start_col = 10
            if end_col < 10:
                end_col = 10
                
            # Calculate the byte offsets
            start_offset = start_line * self.bytes_per_line + (start_col - 10) // 3
            end_offset = end_line * self.bytes_per_line + (end_col - 10) // 3
            
            return (start_offset, end_offset)
            
        except Exception as e:
            self.logger.error(f"Error calculating selection offsets: {e}", exc_info=True)
            return None 
