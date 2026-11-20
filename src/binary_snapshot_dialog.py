"""Binary Snapshot dialog — view run history and export workspace artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from src.snapshot_run_catalog import artifact_root, list_runs_for_source


class BinarySnapshotDialog(QDialog):
    """Show BinarySnapshot details, related investigation runs, and export actions."""

    def __init__(
        self,
        *,
        source_path: str,
        snapshot: Mapping[str, Any],
        validation: Optional[Mapping[str, Any]] = None,
        waterfall: Optional[Mapping[str, Any]] = None,
        forensic_context: Optional[Mapping[str, Any]] = None,
        on_refresh: Optional[Callable[[], Dict[str, Any]]] = None,
        on_goto_offset: Optional[Callable[[int], None]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._source_path = str(source_path)
        self._snapshot = dict(snapshot)
        self._validation = dict(validation or {})
        self._waterfall = dict(waterfall or {})
        self._forensic_context = dict(forensic_context or {})
        self._on_refresh = on_refresh
        self._on_goto_offset = on_goto_offset
        self._last_export_path = ""
        self.setWindowTitle("Binary Snapshot")
        self.resize(920, 640)
        self._build_ui()
        self._populate_all()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.tabs = QTabWidget()

        self.overview_table = self._make_table(["Field", "Value"])
        self.tabs.addTab(self.overview_table, "Snapshot")

        self.runs_table = self._make_table(
            ["Run ID", "Investigation", "Updated", "Milestones", "Phase", "Keys", "Workspace"]
        )
        self.tabs.addTab(self.runs_table, "Runs")

        self.signals_view = QPlainTextEdit()
        self.signals_view.setReadOnly(True)
        self.tabs.addTab(self.signals_view, "Signals")

        self.probe_ledger_table = self._make_table(["Timestamp", "Phase", "Cursor", "Best Key", "Score", "Keys Found"])
        self.tabs.addTab(self.probe_ledger_table, "Probe Results")

        self.best_rejected_view = QPlainTextEdit()
        self.best_rejected_view.setReadOnly(True)
        self.tabs.addTab(self.best_rejected_view, "Best Rejected")

        self.derived_windows_table = self._make_table(["Name", "Offset", "Length", "Role", "Evidence"])
        self.tabs.addTab(self.derived_windows_table, "Derived Windows")

        self.scope_summary_table = self._make_table(["Field", "Value"])
        self.scope_ranges_table = self._make_table(["Range", "Length", "Transform", "Role"])
        scope_tab = QTabWidget()
        scope_tab.addTab(self.scope_summary_table, "Summary")
        scope_tab.addTab(self.scope_ranges_table, "Ranges")
        self.tabs.addTab(scope_tab, "Transform Diff")

        self.goto_button = QPushButton("Go to selected offset")
        self.goto_button.clicked.connect(self._goto_selected_offset)

        layout.addWidget(self.tabs)

        action_row = QHBoxLayout()
        self.refresh_button = QPushButton("Reload Snapshot")
        self.refresh_button.clicked.connect(self._handle_refresh)
        self.export_workspace_button = QPushButton("Export Workspace…")
        self.export_workspace_button.clicked.connect(self._handle_export_workspace)
        self.export_json_button = QPushButton("Export Snapshot JSON…")
        self.export_json_button.clicked.connect(self._handle_export_json)
        self.open_inspector_button = QPushButton("Show Binary Inspector")
        self.open_inspector_button.clicked.connect(self.accept)
        try:
            from src.services.representation_registry import load_representation_policy

            rep_policy = load_representation_policy()
            default_sweep = bool(
                rep_policy.get("export_defaults", {}).get("include_representation_sweep")
                if isinstance(rep_policy.get("export_defaults"), dict)
                else rep_policy.get("workspace_sweep_on_export")
            )
        except Exception:
            default_sweep = False
        self.include_representation_sweep_checkbox = QCheckBox("Generate representation briefs on export")
        self.include_representation_sweep_checkbox.setChecked(default_sweep)
        self.include_representation_sweep_checkbox.setToolTip(
            "When enabled, unknown regions get hex/text/integer/float decoder sweeps cached under representation/."
        )
        action_row.addWidget(self.refresh_button)
        action_row.addWidget(self.export_workspace_button)
        action_row.addWidget(self.export_json_button)
        action_row.addWidget(self.include_representation_sweep_checkbox)
        action_row.addStretch(1)
        action_row.addWidget(self.open_inspector_button)
        action_row.addWidget(self.goto_button)
        layout.addLayout(action_row)

        self.export_status = QLabel("")
        self.export_status.setWordWrap(True)
        layout.addWidget(self.export_status)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _make_table(self, headers: List[str]) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._snapshot)

    def _populate_all(self) -> None:
        snap = self._snapshot
        source = dict(snap.get("source") or {})
        plugin = str(snap.get("format_plugin") or "unknown")
        snap_id = str(snap.get("snapshot_id") or "")
        self.summary_label.setText(
            f"{Path(self._source_path).name} — {plugin} snapshot — {snap_id}"
        )

        rows = [
            ("source_path", self._source_path),
            ("format_plugin", plugin),
            ("snapshot_id", snap_id),
            ("source_sha256", source.get("sha256")),
            ("source_size", source.get("size")),
            ("registry_revision", snap.get("registry_revision")),
            ("node_count", len(snap.get("nodes") or [])),
            ("edge_count", len(snap.get("edges") or [])),
            ("coverage_ranges", len(snap.get("coverage") or [])),
            ("diagnostics", len(snap.get("diagnostics") or [])),
            ("validation_ok", self._validation.get("ok")),
            ("promotion_blocked", self._validation.get("promotion_blocked")),
            ("validation_issues", ", ".join(self._validation.get("issues") or []) or "none"),
        ]
        self._fill_table(self.overview_table, rows)

        run_rows = []
        for run in list_runs_for_source(self._source_path):
            run_rows.append(
                (
                    run.get("run_id", ""),
                    run.get("investigation_id", ""),
                    run.get("updated_at", run.get("created_at", "")),
                    ", ".join(run.get("completed_milestones") or []),
                    run.get("probe_phase_id") or run.get("phase") or "",
                    "yes" if run.get("keys_found") else "no",
                    run.get("workspace_path", ""),
                )
            )
        self._fill_table(self.runs_table, run_rows)

        payload = {
            "signals": snap.get("signals") or {},
            "validation": self._validation,
            "waterfall": self._waterfall,
        }
        self.signals_view.setPlainText(json.dumps(payload, indent=2, sort_keys=True, default=str))

        self._populate_forensic_tabs()

    def _populate_forensic_tabs(self) -> None:
        context = self._forensic_context
        investigation = dict(context.get("investigation") or {})
        ledger_rows = []
        for event in investigation.get("ledger_events") or []:
            ledger_rows.append(
                (
                    event.get("ts", ""),
                    event.get("probe_phase_id", ""),
                    event.get("key_cursor", ""),
                    event.get("best_key_hex", ""),
                    event.get("best_score", ""),
                    "yes" if event.get("keys_found") else "no",
                )
            )
        self._fill_table(self.probe_ledger_table, ledger_rows)

        best_rejected = dict(investigation.get("best_rejected") or {})
        self.best_rejected_view.setPlainText(json.dumps(best_rejected, indent=2, sort_keys=True, default=str) if best_rejected else "No best_rejected artifact.")

        derived_rows = []
        for window in investigation.get("derived_windows") or []:
            derived_rows.append(
                (
                    window.get("name", ""),
                    window.get("offset", 0),
                    window.get("length", 0),
                    window.get("role", ""),
                    ", ".join(str(item) for item in window.get("evidence_refs") or []),
                )
            )
        self._fill_table(self.derived_windows_table, derived_rows, offset_column=1)

        scope = dict(context.get("scope_evidence") or {})
        summary = dict(scope.get("summary") or {})
        summary_rows = [(key, summary.get(key, "")) for key in (
            "changed_bytes",
            "total_bytes",
            "changed_ratio",
            "first_changed_offset",
            "last_changed_offset",
            "transform_relation",
            "range_count",
            "run_id",
        ) if key in summary or summary.get(key) not in (None, "")]
        if not summary_rows:
            summary_rows = list(summary.items())
        self._fill_table(self.scope_summary_table, summary_rows)

        range_rows = []
        for item in scope.get("ranges") or []:
            range_rows.append(
                (
                    item.get("range", ""),
                    item.get("length", 0),
                    item.get("transform", ""),
                    item.get("role", ""),
                )
            )
        self._fill_table(self.scope_ranges_table, range_rows, offset_column=None)
        for row_index, item in enumerate(scope.get("ranges") or []):
            offset_item = self.scope_ranges_table.item(row_index, 0)
            if offset_item is not None:
                offset_item.setData(Qt.UserRole, int(item.get("offset") or 0))

    def _goto_selected_offset(self) -> None:
        if self._on_goto_offset is None:
            return
        current = self.tabs.currentWidget()
        table = current
        if isinstance(current, QTabWidget):
            table = current.currentWidget()
        if not isinstance(table, QTableWidget):
            return
        row = table.currentRow()
        if row < 0:
            return
        for column in range(table.columnCount()):
            item = table.item(row, column)
            if item is None:
                continue
            offset = item.data(Qt.UserRole)
            if offset is not None:
                self._on_goto_offset(int(offset))
                return

    def _fill_table(self, table: QTableWidget, rows: List[tuple], *, offset_column: Optional[int] = None) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                if offset_column is not None and column_index == offset_column:
                    try:
                        item.setData(Qt.UserRole, int(value))
                    except (TypeError, ValueError):
                        pass
                table.setItem(row_index, column_index, item)

    def _handle_refresh(self) -> None:
        if self._on_refresh is None:
            QMessageBox.information(self, "Binary Snapshot", "No refresh handler is available.")
            return
        try:
            payload = self._on_refresh()
            self._snapshot = dict(payload.get("snapshot") or {})
            self._validation = dict(payload.get("validation") or {})
            self._waterfall = dict(payload.get("waterfall") or {})
            self._forensic_context = dict(payload.get("forensic_context") or self._forensic_context)
            self._populate_all()
            self.export_status.setText("Snapshot reloaded.")
        except Exception as exc:
            QMessageBox.critical(self, "Binary Snapshot", f"Reload failed:\n{exc}")

    def _handle_export_workspace(self) -> None:
        try:
            from src.services.binary_workspace import export_binary_workspace

            default_dir = str(artifact_root())
            target_dir = QFileDialog.getExistingDirectory(
                self,
                "Choose artifact export folder",
                default_dir,
            )
            if not target_dir:
                return
            result = export_binary_workspace(
                self._source_path,
                self._snapshot,
                target_dir,
                include_representation_sweep=self.include_representation_sweep_checkbox.isChecked(),
            )
            self._last_export_path = str(result.get("artifact_directory") or "")
            pointer = dict(result.get("artifact_pointer") or {})
            digest = ""
            if pointer.get("operation_id"):
                try:
                    from src.services.snapshot_brief_compiler import brief_digest, compile_snapshot_brief

                    brief = compile_snapshot_brief(pointer)
                    digest = str(brief.get("brief_digest") or brief_digest(brief))
                except Exception:
                    digest = str(pointer.get("manifest_sha256") or "")[:16]
            status_lines = [
                f"Workspace exported to: {self._last_export_path}",
                f"Operation: {result.get('operation_id') or result.get('operation') or 'binary-unpack'}",
            ]
            if pointer.get("operation_id"):
                status_lines.append(f"ArtifactPointer: {pointer.get('operation_id')}")
                status_lines.append(f"Brief digest: {digest or 'pending'}")
            sweep = dict(result.get("representation_sweep") or {})
            if sweep.get("skipped"):
                status_lines.append(f"Representation sweep: skipped ({sweep.get('reason') or 'disabled'})")
            elif sweep.get("swept_count") is not None:
                status_lines.append(f"Representation sweep: {sweep.get('swept_count')} region(s)")
            self.export_status.setText("\n".join(status_lines))
        except Exception as exc:
            QMessageBox.critical(self, "Export Workspace", str(exc))

    def _handle_export_json(self) -> None:
        default_name = f"{Path(self._source_path).stem}_snapshot.json"
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Export Snapshot JSON",
            default_name,
            "JSON Files (*.json)",
        )
        if not target:
            return
        try:
            Path(target).write_text(
                json.dumps(self._snapshot, indent=2, sort_keys=True, default=str),
                encoding="utf-8",
            )
            self.export_status.setText(f"Snapshot JSON exported to: {target}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Snapshot JSON", str(exc))
