"""Forensic text encoding inspector panel."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from PyQt5.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.logging_config import get_logger
from src.services.representation_sweep import sweep_region
from src.services.text_encoding import TEXT_ENCODINGS
from src.services.transform_preview import inspect_transform_preview, load_transform_preview_policy

logger = get_logger("text_inspector")


class TextInspectorWidget(QWidget):
    """Decode selected bytes or a window at the cursor."""

    DEFAULT_WINDOW = 256
    MAX_WINDOW = 65536

    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_result: Optional[Dict[str, Any]] = None
        self._last_preview: Optional[Dict[str, Any]] = None
        self._preview_policy = load_transform_preview_policy()
        self._on_refresh = None
        self._on_goto_source = None
        self._on_export_full_file = None
        self._async_preview_request = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        intro = QLabel(
            "Forensic text decode for the current selection or bytes at the cursor. "
            "Modes are policy-driven: RAW, TRANSFORM PREVIEW, MATERIALIZED and SEMANTIC."
        )
        intro.setWordWrap(True)

        controls = QHBoxLayout()
        self.mode_selector = QComboBox()
        for item in self._preview_policy["modes"]:
            self.mode_selector.addItem(str(item["label"]), str(item["id"]))
        default_index = self.mode_selector.findData(str(self._preview_policy["default_mode"]))
        if default_index >= 0:
            self.mode_selector.setCurrentIndex(default_index)
        self.encoding_selector = QComboBox()
        for name in sorted(TEXT_ENCODINGS):
            self.encoding_selector.addItem(name)

        self.errors_selector = QComboBox()
        self.errors_selector.addItems(["strict", "replace", "ignore"])

        self.window_spin = QSpinBox()
        self.window_spin.setRange(1, self.MAX_WINDOW)
        self.window_spin.setValue(self.DEFAULT_WINDOW)
        self.window_spin.setSuffix(" bytes")

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._request_refresh)
        self.export_button = QPushButton("Export full file preview")
        self.export_button.clicked.connect(self._request_full_file_export)
        self.goto_source_button = QPushButton("Go to source bytes")
        self.goto_source_button.clicked.connect(self._goto_source)

        controls.addWidget(QLabel("Mode"))
        controls.addWidget(self.mode_selector)
        controls.addWidget(QLabel("Encoding"))
        controls.addWidget(self.encoding_selector, stretch=1)
        controls.addWidget(QLabel("Errors"))
        controls.addWidget(self.errors_selector)
        controls.addWidget(QLabel("Window"))
        controls.addWidget(self.window_spin)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.export_button)
        controls.addWidget(self.goto_source_button)

        self.truth_badge = QLabel("—")
        self.truth_badge.setWordWrap(True)
        self.conflict_banner = QLabel("")
        self.conflict_banner.setWordWrap(True)

        meta_group = QGroupBox("Range")
        meta_layout = QFormLayout()
        self.offset_label = QLabel("—")
        self.length_label = QLabel("—")
        self.meta_label = QLabel("Load a file and select bytes or move the cursor.")
        self.meta_label.setWordWrap(True)
        meta_layout.addRow("Offset", self.offset_label)
        meta_layout.addRow("Length", self.length_label)
        meta_layout.addRow("Truth", self.truth_badge)
        meta_layout.addRow("Summary", self.meta_label)
        meta_group.setLayout(meta_layout)

        self.tabs = QTabWidget()
        self.decoded_output = self._make_output()
        self.raw_output = self._make_output()
        self.hex_output = self._make_output()
        self.binary_output = self._make_output()
        self.base64_output = self._make_output()
        self.decimal_output = self._make_output()
        self.chain_output = self._make_output()

        self.tabs.addTab(self.decoded_output, "Decoded composite")
        self.tabs.addTab(self.raw_output, "Raw source")
        self.tabs.addTab(self.hex_output, "Hex")
        self.tabs.addTab(self.binary_output, "Binary")
        self.tabs.addTab(self.base64_output, "Base64")
        self.tabs.addTab(self.decimal_output, "Decimal")
        self.tabs.addTab(self.chain_output, "Chain steps")

        self.mode_selector.currentIndexChanged.connect(self._settings_changed)
        self.encoding_selector.currentTextChanged.connect(self._settings_changed)
        self.errors_selector.currentTextChanged.connect(self._settings_changed)
        self.window_spin.valueChanged.connect(self._settings_changed)

        layout.addWidget(intro)
        layout.addLayout(controls)
        layout.addWidget(self.conflict_banner)
        layout.addWidget(meta_group)
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def _make_output(self) -> QTextEdit:
        field = QTextEdit()
        field.setReadOnly(True)
        field.setLineWrapMode(QTextEdit.NoWrap)
        return field

    def set_refresh_callback(self, callback):
        self._on_refresh = callback

    def set_goto_source_callback(self, callback):
        self._on_goto_source = callback

    def set_export_full_file_callback(self, callback):
        self._on_export_full_file = callback

    def set_async_preview_request(self, callback: Callable[..., None]):
        self._async_preview_request = callback

    def _goto_source(self):
        if self._on_goto_source and self._last_result:
            self._on_goto_source(int(self._last_result["offset"]))

    def _settings_changed(self, *_args):
        if self._on_refresh:
            self._on_refresh()

    def _request_refresh(self):
        if self._on_refresh:
            self._on_refresh()

    def _request_full_file_export(self):
        if self._on_export_full_file:
            self._on_export_full_file()

    def clear(self):
        self._last_result = None
        self._last_preview = None
        self.offset_label.setText("—")
        self.length_label.setText("—")
        self.truth_badge.setText("—")
        self.conflict_banner.setText("")
        self.meta_label.setText("Load a file and select bytes or move the cursor.")
        for field in (
            self.decoded_output,
            self.raw_output,
            self.hex_output,
            self.binary_output,
            self.base64_output,
            self.decimal_output,
            self.chain_output,
        ):
            field.clear()

    def apply_preview_payload(self, payload: Dict[str, Any]) -> None:
        preview = dict(payload.get("result") or payload.get("preview") or payload)
        self._apply_preview(preview)

    def inspect_bytes(self, offset: int, data: bytes):
        if not data:
            self.clear()
            self.meta_label.setText("Nothing to decode at the current position.")
            return

        brief = sweep_region(data, offset=offset, include_binary_decimal=True)
        encoding = self.encoding_selector.currentText()
        text_match = next(
            (item for item in brief.get("text_candidates") or [] if item.get("encoding") == encoding),
            None,
        )
        if text_match is None and brief.get("text_candidates"):
            text_match = brief["text_candidates"][0]

        result = {
            "offset": offset,
            "byte_count": brief.get("length"),
            "decoded_text": str((text_match or {}).get("preview") or ""),
            "hex": dict(brief.get("representation") or {}).get("hex", ""),
            "binary": dict(brief.get("representation") or {}).get("binary", ""),
            "base64": dict(brief.get("representation") or {}).get("base64", ""),
            "bytes_decimal": dict(brief.get("representation") or {}).get("decimal", ""),
            "bom_detected": (text_match or {}).get("bom_detected"),
            "non_ascii_byte_count": sum(1 for value in data if value > 127),
            "replacement_count": int((text_match or {}).get("replacement_count") or 0),
            "decode_error": (text_match or {}).get("error_detail"),
            "note": None,
            "interpreter_signals": brief.get("interpreter_signals") or [],
        }
        if result["interpreter_signals"]:
            top = result["interpreter_signals"][0]
            result["note"] = f"Signal: {top.get('id')} — {top.get('evidence')}"
        self._apply_result(result)

    def refresh(
        self,
        *,
        data_provider,
        selection_provider,
        cursor_provider,
        force: bool = False,
    ):
        del force
        if data_provider is None:
            self.clear()
            return

        file_size = data_provider.file_size
        if not file_size:
            self.clear()
            self.meta_label.setText("No file loaded.")
            return

        selection = selection_provider() if selection_provider else None
        if selection:
            start, end = selection
            offset = max(0, min(start, end))
            length = max(1, abs(end - start))
        else:
            offset = max(0, min(cursor_provider(), file_size - 1))
            length = self.window_spin.value()

        length = min(length, self.MAX_WINDOW, max(0, file_size - offset))
        mode = str(self.mode_selector.currentData() or "")
        threshold = int(self._preview_policy.get("background_worker_threshold_bytes") or 0)
        if self._async_preview_request and length >= threshold > 0 and mode != "raw":
            self._async_preview_request(
                file_path=data_provider.file_path,
                offset=offset,
                length=length,
                mode=mode,
                policy=self._preview_policy,
            )
            self.meta_label.setText("Preview running in background…")
            return

        preview = inspect_transform_preview(
            data_provider.file_path,
            offset=offset,
            length=length,
            mode=mode,
            policy=self._preview_policy,
        )
        self._apply_preview(preview)

    def _apply_preview(self, preview: Dict[str, Any]) -> None:
        self._last_preview = dict(preview)
        offset = int(preview["offset"])
        output = bytes(preview["output_bytes"])
        raw = bytes(preview.get("raw_bytes") or output)
        brief = sweep_region(output, offset=offset, include_binary_decimal=True)
        raw_brief = sweep_region(raw, offset=offset, include_binary_decimal=True)
        result = {
            "offset": offset,
            "byte_count": len(output),
            "decoded_text": str(preview["decoded_text"]),
            "hex": dict(brief.get("representation") or {}).get("hex", ""),
            "binary": dict(brief.get("representation") or {}).get("binary", ""),
            "base64": dict(brief.get("representation") or {}).get("base64", ""),
            "bytes_decimal": dict(brief.get("representation") or {}).get("decimal", ""),
            "bom_detected": None,
            "non_ascii_byte_count": sum(1 for value in output if value > 127),
            "replacement_count": 0,
            "decode_error": None,
            "note": f"Mode: {preview['mode']} | State: {preview['state']} | Provider: {preview['provider']}",
            "interpreter_signals": brief.get("interpreter_signals") or [],
            "file_lineage": preview.get("file_lineage") or {},
            "chain_steps": preview.get("chain_steps") or [],
            "conflicts": preview.get("conflicts") or [],
            "composite_spans": preview.get("composite_spans") or [],
            "truth_state": preview.get("truth_state") or "",
            "raw_hex": dict(raw_brief.get("representation") or {}).get("hex", ""),
            "raw_text": raw.decode("utf-8", errors="replace") if raw else "",
        }
        lineage = dict(preview.get("file_lineage") or {})
        if lineage:
            result["note"] += f" | File role: {lineage.get('matched_role')}"
        if preview.get("conflicts"):
            result["note"] += f" | Conflicts: {len(preview['conflicts'])}"
        if preview.get("chain_steps"):
            result["note"] += f" | Chain steps: {len(preview['chain_steps'])}"
        if preview.get("coverage_gaps"):
            result["note"] += f" | Coverage gaps: {len(preview['coverage_gaps'])}"
        if preview.get("diagnostics"):
            result["note"] += " | " + ", ".join(map(str, preview["diagnostics"]))
        self._apply_result(result)

    def _apply_result(self, result: Dict[str, Any]):
        self._last_result = result
        self.offset_label.setText(f"0x{result['offset']:X} ({result['offset']})")
        self.length_label.setText(str(result["byte_count"]))
        self.truth_badge.setText(str(result.get("truth_state") or "—"))

        conflicts = list(result.get("conflicts") or [])
        if conflicts:
            self.conflict_banner.setText(
                f"Conflict: {len(conflicts)} overlapping or incompatible scope(s) in this range."
            )
        else:
            self.conflict_banner.setText("")

        summary_parts = []
        if result.get("bom_detected"):
            summary_parts.append(f"BOM: {result['bom_detected']}")
        summary_parts.append(f"Non-ASCII bytes: {result['non_ascii_byte_count']}")
        if result.get("replacement_count"):
            summary_parts.append(f"Replacements: {result['replacement_count']}")
        if result.get("decode_error"):
            error = result["decode_error"]
            summary_parts.append(
                f"Decode error at 0x{error['absolute_start']:X}: {error['reason']} "
                f"({error['problem_bytes_hex']})"
            )
        elif result.get("note"):
            summary_parts.append(result["note"])
        else:
            summary_parts.append("Decode succeeded.")
        self.meta_label.setText(" | ".join(summary_parts))

        self.decoded_output.setPlainText(result.get("decoded_text", ""))
        self.raw_output.setPlainText(result.get("raw_text") or result.get("raw_hex") or "")
        self.hex_output.setPlainText(result.get("hex", ""))
        self.binary_output.setPlainText(result.get("binary", ""))
        self.base64_output.setPlainText(result.get("base64", ""))
        self.decimal_output.setPlainText(result.get("bytes_decimal", ""))
        steps = result.get("chain_steps") or []
        if steps:
            lines = []
            for step in steps:
                lines.append(
                    f"{step.get('step_id') or step.get('descriptor_id')}: "
                    f"offset=0x{int(step.get('offset') or 0):X} "
                    f"len={step.get('length')} op={step.get('operation')} "
                    f"in={str(step.get('input_digest') or '')[:12]} "
                    f"out={str(step.get('output_digest') or '')[:12]}"
                )
            self.chain_output.setPlainText("\n".join(lines))
        else:
            self.chain_output.setPlainText("No chain steps for this range.")

    def last_preview(self) -> Optional[Dict[str, Any]]:
        return dict(self._last_preview) if self._last_preview else None
