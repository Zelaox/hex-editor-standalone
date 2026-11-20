"""
Search functionality for the HexEditor application.
"""
import re
import logging
import traceback
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Union

from PyQt5.QtCore import QObject, QPoint, pyqtSignal
from PyQt5.QtGui import QTextDocument, QSyntaxHighlighter, QTextCharFormat, QColor, QBrush
from PyQt5.QtWidgets import QPlainTextEdit, QTextEdit


def classify_search_query(query: str) -> tuple[str, str]:
    """Classify a search-box value without format- or file-specific rules.

    Explicit ``text:`` and ``hex:`` prefixes take precedence. Otherwise a
    whitespace-separated sequence of byte pairs is hex; every other value is
    ordinary UTF-8 text. Offset navigation is handled by the application.
    """
    value = query.strip()
    prefix, separator, payload = value.partition(":")
    if separator and prefix.casefold() in {"text", "hex"}:
        return prefix.casefold(), payload.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+", value):
        return "hex", value
    return "text", value

@dataclass
class SearchResult:
    """Class representing a search result."""
    position: int
    context: str
    line_number: int

class SearchHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for search results."""
    
    def __init__(self, document, *, text_edit: Optional[QPlainTextEdit] = None):
        """
        Initialize the search highlighter.
        
        Args:
            document: The QTextDocument to highlight
            text_edit: Optional QTextEdit used for viewport-only refresh
        """
        super().__init__(document)
        self._text_edit = text_edit
        self._viewport_margin_lines = 0
        self.search_text = ""
        self.highlight_color = QColor("green")
        self.highlight_format = QTextCharFormat()
        self.highlight_format.setBackground(QBrush(self.highlight_color))
        self.case_sensitive = False
        self.whole_words = False
        self._pattern = None
        self._overlay_suspended = False
        self._update_pattern()

    def set_overlay_suspended(self, suspended: bool) -> None:
        self._overlay_suspended = bool(suspended)

    def configure_viewport(self, *, policy: Dict[str, Any]) -> None:
        from src.services.ui_policy import load_budget

        self._viewport_margin_lines = load_budget(policy, "hex_overlay_viewport_margin_lines")

    def _refresh_highlights(self) -> None:
        if self._text_edit is not None:
            self.rehighlight_viewport()
            return
        self.rehighlight()

    def rehighlight_viewport(self) -> None:
        document = self.document()
        if document is None or self._text_edit is None:
            return
        cursor = self._text_edit.cursorForPosition(QPoint(1, 1))
        if cursor.isNull():
            return
        block = cursor.block()
        viewport_lines = max(
            1,
            self._text_edit.height() // max(1, self._text_edit.fontMetrics().height()),
        )
        margin = max(0, int(self._viewport_margin_lines or 0))
        limit = viewport_lines + margin
        count = 0
        while block.isValid() and count < limit:
            self.rehighlightBlock(block)
            block = block.next()
            count += 1

    def setSearchText(self, search_text: str) -> None:
        """
        Update the search text and recompile the pattern.
        
        Args:
            search_text: The text to search for
        """
        self.search_text = search_text
        self._update_pattern()
        self._refresh_highlights()

    def setHighlightColor(self, color: QColor) -> None:
        """
        Set the highlight color.
        
        Args:
            color: The color to use for highlighting
        """
        self.highlight_color = color
        self.highlight_format.setBackground(QBrush(color))
        self._refresh_highlights()

    def setCaseSensitive(self, case_sensitive: bool) -> None:
        """
        Set whether the search is case sensitive.
        
        Args:
            case_sensitive: Whether to perform case-sensitive search
        """
        self.case_sensitive = case_sensitive
        self._update_pattern()
        self._refresh_highlights()

    def setWholeWords(self, whole_words: bool) -> None:
        """
        Set whether to match whole words only.
        
        Args:
            whole_words: Whether to match whole words only
        """
        self.whole_words = whole_words
        self._update_pattern()
        self._refresh_highlights()

    def _update_pattern(self) -> None:
        """Update the regex pattern based on current settings."""
        if not self.search_text:
            self._pattern = None
            return

        pattern = re.escape(self.search_text)
        if self.whole_words:
            pattern = r'\b' + pattern + r'\b'
        
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            self._pattern = re.compile(pattern, flags)
        except re.error as e:
            logging.error(f"Invalid regex pattern: {e}")
            self._pattern = None

    def highlightBlock(self, text: str) -> None:
        """
        Apply highlighting to the given block of text.
        
        Args:
            text: The text block to highlight
        """
        if self._overlay_suspended or not self._pattern:
            return

        for match in self._pattern.finditer(text):
            start = match.start()
            length = match.end() - start
            self.setFormat(start, length, self.highlight_format)

class SearchWorker(QObject):
    """Worker class for performing search operations in a separate thread."""
    
    search_finished = pyqtSignal(list)  # List of SearchResult objects
    search_progress = pyqtSignal(int)  # Progress percentage
    search_failed = pyqtSignal(str)

    def __init__(self, source: Union[QTextDocument, bytes, bytearray, memoryview],
                 search_text: str, case_sensitive: bool = False,
                 whole_words: bool = False, search_type: str = "text",
                 bytes_per_line: int = 16):
        """
        Initialize the search worker.

        Args:
            source: Raw file bytes. QTextDocument is retained as a compatibility
                fallback for callers which do not have a binary data source.
            search_text: The text to search for
            case_sensitive: Whether to perform case-sensitive search
            whole_words: Whether to match whole words only
            search_type: Type of search ("text", "hex", "regex")
            bytes_per_line: Current editor layout width, used for result metadata
        """
        super().__init__()
        self.source = source
        self.search_text = search_text
        self.case_sensitive = case_sensitive
        self.whole_words = whole_words
        self.search_type = search_type
        self.bytes_per_line = max(1, int(bytes_per_line))
        self._stop_requested = False

    def stop(self) -> None:
        """Request the search to stop."""
        self._stop_requested = True

    def run(self) -> None:
        """Perform the search operation."""
        try:
            if not self.search_text:
                self.search_failed.emit("No search text provided.")
                return

            data = self._source_bytes()
            pattern = self._compile_search_pattern(binary=True)
            if not pattern:
                self.search_failed.emit("Invalid search pattern.")
                return

            search_results = []
            for match in pattern.finditer(data):
                if self._stop_requested:
                    break
                position = match.start()
                context_bytes = data[max(0, position - 20):min(len(data), match.end() + 20)]
                context = "".join(chr(value) if 32 <= value <= 126 else "." for value in context_bytes)
                search_results.append(SearchResult(
                    position=position,
                    context=context,
                    line_number=(position // self.bytes_per_line) + 1,
                ))

            self.search_progress.emit(100)

            if not self._stop_requested:
                self.search_finished.emit(search_results)
            else:
                self.search_failed.emit("Search stopped by user.")

        except Exception as e:
            logging.error(f"Search error: {e}")
            traceback.print_exc()
            self.search_failed.emit(str(e))

    def _source_bytes(self) -> bytes:
        """Return a stable byte snapshot for raw, cross-line searching."""
        if isinstance(self.source, (bytes, bytearray, memoryview)):
            return bytes(self.source)
        # Compatibility only: searching a rendered document cannot recover raw
        # binary bytes, but older external callers may still pass one.
        return self.source.toPlainText().encode("utf-8")

    def _compile_search_pattern(self, *, binary: bool = False) -> Optional[re.Pattern]:
        """
        Compile the search pattern based on search type and options.
        
        Returns:
            A compiled regex pattern or None if compilation fails
        """
        try:
            if self.search_type == "text":
                raw_pattern = self.search_text.encode("utf-8") if binary else self.search_text
                pattern = re.escape(raw_pattern)
            elif self.search_type == "hex":
                hex_bytes = bytes.fromhex(self.search_text.replace(" ", ""))
                pattern = re.escape(hex_bytes if binary else hex_bytes.decode('latin1'))
            elif self.search_type == "regex":
                pattern = self.search_text.encode("utf-8") if binary else self.search_text
            else:
                raise ValueError(f"Unsupported search type: {self.search_type}")

            if self.whole_words:
                boundary = br'\b' if binary else r'\b'
                pattern = boundary + pattern + boundary

            flags = 0 if self.case_sensitive else re.IGNORECASE
            return re.compile(pattern, flags)

        except Exception as e:
            logging.error(f"Pattern compilation error: {e}")
            return None 
