"""Desktop GUI for the PTX parser/converter pipeline."""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.services.ptx_pipeline import run_export, run_pipeline
from src.services.ptx_pipeline_gui_spec import (
    build_source_spec,
    export_formats_from_policy,
    list_archive_ids,
    list_materialization_rails,
    stages_from_selection,
)
from src.services.ptx_pipeline_policy import (
    hex_editor_root,
    load_ptx_converter_policy,
    load_ptx_pipeline_policy,
    pipeline_artifact_root,
)
from src.services.ptx_source_archive import load_archive_registry


class PipelineWorker(QThread):
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)
    log_line = pyqtSignal(str)

    def __init__(
        self,
        *,
        spec: Dict[str, Any],
        stages: List[str],
        export_format: Optional[str],
        artifact_root: Path,
    ):
        super().__init__()
        self._spec = spec
        self._stages = stages
        self._export_format = export_format
        self._artifact_root = artifact_root

    def run(self) -> None:
        try:
            self.log_line.emit("Running pipeline…")
            outcome = run_pipeline(
                self._spec,
                stages=[s for s in self._stages if s != "export"],
                artifact_root=self._artifact_root,
                export_format=None,
            )
            if "export" in self._stages:
                if not self._export_format:
                    raise ValueError("Export stage selected but no export format is enabled in policy")
                graph_stage = (outcome.get("stages") or {}).get("graph")
                if not graph_stage:
                    self.log_line.emit("Graph stage missing; running graph before export…")
                    outcome = run_pipeline(
                        self._spec,
                        stages=["bind", "analyze", "extract", "graph"],
                        artifact_root=self._artifact_root,
                    )
                    graph_stage = outcome["stages"]["graph"]
                graph_dir = graph_stage["artifact_directory"]
                self.log_line.emit(f"Export format: {self._export_format}")
                outcome.setdefault("stages", {})["export"] = run_export(
                    graph_artifact_dir=graph_dir,
                    export_format=self._export_format,
                    artifact_root=self._artifact_root,
                )
            self.finished_ok.emit(outcome)
        except Exception as exc:
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")


class PtxPipelineMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._pipeline_policy = load_ptx_pipeline_policy()
        self._converter_policy = load_ptx_converter_policy()
        self._registry = load_archive_registry()
        gui_cfg = dict(self._pipeline_policy.get("gui") or {})
        self.setWindowTitle(str(gui_cfg.get("window_title") or self._pipeline_policy.get("policy_id")))
        self.resize(880, 640)

        self._worker: Optional[PipelineWorker] = None
        self._last_outcome: Optional[Dict[str, Any]] = None

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        layout.addWidget(self._build_source_group())
        layout.addWidget(self._build_stages_group())
        layout.addLayout(self._build_action_row())
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)

        self.artifact_label = QLabel("")
        self.artifact_label.setWordWrap(True)
        layout.addWidget(self.artifact_label)
        self._refresh_artifact_label()
        self._on_kind_changed()

    def _build_source_group(self) -> QGroupBox:
        box = QGroupBox("Source")
        form = QFormLayout(box)

        self.kind_combo = QComboBox()
        self.kind_combo.addItem("PTX file on disk", "filesystem")
        self.kind_combo.addItem("Archived source (registry)", "archive")
        self.kind_combo.addItem("Materialization run", "materialization")
        self.kind_combo.currentIndexChanged.connect(self._on_kind_changed)
        form.addRow("Binding", self.kind_combo)

        file_row = QHBoxLayout()
        self.file_path = QLineEdit()
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_ptx)
        file_row.addWidget(self.file_path)
        file_row.addWidget(browse)
        self.file_row_widget = QWidget()
        self.file_row_widget.setLayout(file_row)
        form.addRow("File", self.file_row_widget)

        self.archive_combo = QComboBox()
        for archive_id in list_archive_ids(self._registry):
            self.archive_combo.addItem(archive_id, archive_id)
        self.archive_row_label = QLabel("Archive id")
        form.addRow(self.archive_row_label, self.archive_combo)

        self.rail_combo = QComboBox()
        for rail in list_materialization_rails(self._pipeline_policy):
            self.rail_combo.addItem(rail, rail)
        self.run_id_edit = QLineEdit()
        self.use_candidate = QCheckBox("Use candidate output path")
        self.require_promotion = QCheckBox("Require promotion-eligible manifest")
        self.require_promotion.setChecked(True)
        self.material_widget = QWidget()
        mat_form = QFormLayout(self.material_widget)
        mat_form.addRow("Rail", self.rail_combo)
        mat_form.addRow("Run id", self.run_id_edit)
        mat_form.addRow("", self.use_candidate)
        mat_form.addRow("", self.require_promotion)
        form.addRow("Materialization", self.material_widget)

        return box

    def _build_stages_group(self) -> QGroupBox:
        box = QGroupBox("Stages")
        row = QHBoxLayout(box)
        self.stage_checks: Dict[str, QCheckBox] = {}
        defaults = set(self._pipeline_policy.get("gui", {}).get("default_stages") or [])
        for key, label in [
            ("bind", "Bind"),
            ("analyze", "Analyze"),
            ("extract", "Extract"),
            ("graph", "Graph"),
            ("export", "Export"),
        ]:
            cb = QCheckBox(label)
            cb.setChecked(key in defaults)
            self.stage_checks[key] = cb
            row.addWidget(cb)

        self.export_format = QComboBox()
        formats = export_formats_from_policy(self._converter_policy)
        for fmt in formats:
            self.export_format.addItem(fmt, fmt)
        if not formats:
            self.export_format.addItem("(none enabled in policy)", "")
        self.stage_checks["export"].toggled.connect(self._on_export_toggled)
        row.addWidget(QLabel("Export as"))
        row.addWidget(self.export_format)
        self._on_export_toggled(self.stage_checks["export"].isChecked())
        return box

    def _build_action_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        run_btn = QPushButton("Run pipeline")
        run_btn.clicked.connect(self._run_pipeline)
        open_btn = QPushButton("Open last artifact folder")
        open_btn.clicked.connect(self._open_last_artifact)
        row.addWidget(run_btn)
        row.addWidget(open_btn)
        row.addStretch()
        return row

    def _on_kind_changed(self) -> None:
        kind = self.kind_combo.currentData()
        self.file_row_widget.setVisible(kind == "filesystem")
        self.archive_combo.setVisible(kind == "archive")
        self.archive_row_label.setVisible(kind == "archive")
        self.material_widget.setVisible(kind == "materialization")

    def _on_export_toggled(self, checked: bool) -> None:
        self.export_format.setEnabled(checked)

    def _browse_ptx(self) -> None:
        start = self.file_path.text().strip() or str(hex_editor_root())
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PTX file",
            start,
            "Pro Tools sessions (*.ptx);;All files (*.*)",
        )
        if path:
            self.file_path.setText(path)

    def _append_log(self, text: str) -> None:
        self.log_view.appendPlainText(text.rstrip())

    def _refresh_artifact_label(self) -> None:
        root = pipeline_artifact_root()
        self.artifact_label.setText(f"Artifact root (policy): {root}")

    def _build_spec(self) -> Dict[str, Any]:
        kind = str(self.kind_combo.currentData())
        return build_source_spec(
            kind=kind,
            filesystem_path=self.file_path.text(),
            archive_id=str(self.archive_combo.currentData() or ""),
            materialization_rail=str(self.rail_combo.currentData() or ""),
            materialization_run_id=self.run_id_edit.text(),
            use_candidate=self.use_candidate.isChecked(),
            require_promotion=self.require_promotion.isChecked(),
        )

    def _selected_stages(self) -> List[str]:
        selected = {key: cb.isChecked() for key, cb in self.stage_checks.items()}
        include_bind = bool(self._pipeline_policy.get("gui", {}).get("include_bind_on_full_run", True))
        return stages_from_selection(selected, include_bind=include_bind)

    def _run_pipeline(self) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(self, "Busy", "Pipeline is already running.")
            return
        try:
            spec = self._build_spec()
            stages = self._selected_stages()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid input", str(exc))
            return

        export_fmt: Optional[str] = None
        if self.stage_checks["export"].isChecked():
            export_fmt = str(self.export_format.currentData() or "").strip() or None
            if not export_fmt:
                QMessageBox.warning(
                    self,
                    "Export disabled",
                    "No export format is enabled in config/ptx_converter_policy.json.",
                )
                return

        self.log_view.clear()
        self._append_log(json.dumps(spec, indent=2))
        self._append_log(f"Stages: {', '.join(stages)}")

        self._worker = PipelineWorker(
            spec=spec,
            stages=stages,
            export_format=export_fmt,
            artifact_root=pipeline_artifact_root(),
        )
        self._worker.log_line.connect(self._append_log)
        self._worker.finished_ok.connect(self._on_pipeline_ok)
        self._worker.failed.connect(self._on_pipeline_failed)
        self._worker.start()

    def _on_pipeline_ok(self, outcome: Dict[str, Any]) -> None:
        self._last_outcome = outcome
        self._append_log(json.dumps(outcome, indent=2, default=str))
        QMessageBox.information(self, "Done", "Pipeline finished successfully.")

    def _on_pipeline_failed(self, message: str) -> None:
        self._append_log(message)
        QMessageBox.critical(self, "Pipeline failed", message.splitlines()[0] if message else "Unknown error")

    def _open_last_artifact(self) -> None:
        if not self._last_outcome:
            QMessageBox.information(self, "No run yet", "Run the pipeline first.")
            return
        stages = dict(self._last_outcome.get("stages") or {})
        target_dir = ""
        for key in ("export", "graph", "extract", "analyze", "bind"):
            stage = stages.get(key)
            if isinstance(stage, dict) and stage.get("artifact_directory"):
                target_dir = str(stage["artifact_directory"])
                break
        if not target_dir:
            target_dir = str(pipeline_artifact_root())
        path = Path(target_dir)
        if not path.is_dir():
            QMessageBox.warning(self, "Missing folder", str(path))
            return
        os.startfile(str(path))


def main(argv: Optional[List[str]] = None) -> int:
    app = QApplication(argv or sys.argv)
    window = PtxPipelineMainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
