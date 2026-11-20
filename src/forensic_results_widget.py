"""Saved forensic fields navigate using verified identities, never report commands."""
from pathlib import Path
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTreeWidget, QTreeWidgetItem, QFileDialog, QLabel, QTextBrowser, QTabWidget

from src.services.browser_forensics import engine
from src.services.browser_forensics.common import read_json, file_hash
from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy


class ForensicResultsWidget(QWidget):
    selection_resolved = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.policy = load_pseudocode_navigation_policy()["forensic_navigation"]
        self.run_root = None
        self.input_root = None
        self.case_id = None
        layout = QVBoxLayout(self)
        button = QPushButton(self.policy["open_action"])
        button.clicked.connect(self.open_run)
        layout.addWidget(button)
        self.status = QLabel()
        layout.addWidget(self.status)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(self.policy["headers"])
        self.tree.itemClicked.connect(self.select_item)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.tree, self.policy["records_tab"])
        self.report = QTextBrowser()
        self.report.setOpenLinks(False)
        self.report.anchorClicked.connect(self.select_report_finding)
        self.tabs.addTab(self.report, self.policy["report_tab"])
        layout.addWidget(self.tabs)
        self.field_items = {}

    def open_run(self):
        path = QFileDialog.getExistingDirectory(self, self.policy["open_action"])
        if path:
            try:
                self.load_run(path)
            except (ValueError, OSError, KeyError):
                self.status.setText(self.policy["verification_failed"])

    def load_run(self, run_root, input_root=None):
        # Reuse the central workspace allowlist before dereferencing any report path.
        from hexeditor_tools.api import _forensic_root
        self.run_root = _forensic_root(str(run_root))
        if not engine.verify(self.run_root)["ok"]:
            raise ValueError("evidence_verification_failed")
        manifest = read_json(self.run_root/"manifest.json")
        self.input_root = _forensic_root(str(input_root or manifest["input_root"]))
        self.case_id = manifest["case_id"]
        self.tree.clear()
        self.field_items.clear()
        result = read_json(self.run_root/"result.json")
        self.report.setHtml(engine.render_report(result, manifest))
        self.status.setText(result["status"])
        for source in result["files"]:
            top = QTreeWidgetItem([source["path"], source["detection"]["format_id"], source["status"]])
            self.tree.addTopLevelItem(top)
            for record in source.get("records", []):
                node = QTreeWidgetItem([str(record["locator"]), "record", ""])
                top.addChild(node)
                for field in record["fields"]:
                    child = QTreeWidgetItem([str(field["ordinal"]), field["type"], field["mapping_precision"]])
                    child.setData(0, Qt.UserRole, field["field_id"])
                    node.addChild(child)
                    self.field_items[field["field_id"]] = child
                    for index, source_span in enumerate(field["source_spans"]):
                        segment = QTreeWidgetItem([source_span["source_path"], str(source_span["offset"]), str(source_span["length"])])
                        segment.setData(0, Qt.UserRole, field["field_id"])
                        segment.setData(0, Qt.UserRole+1, index)
                        child.addChild(segment)

    def select_item(self, item, column=0):
        field_id = item.data(0, Qt.UserRole)
        if not field_id or not self.run_root:
            return
        try:
            mapped = engine.resolve_field(self.run_root, field_id, input_root=self.input_root, case_id=self.case_id)
            selected_range = item.data(0, Qt.UserRole+1)
            if selected_range is not None:
                n = int(selected_range)
                mapped["ranges"] = mapped["ranges"][n:] + mapped["ranges"][:n]
            from hexeditor_tools.api import _path
            for source_range in mapped["ranges"]:
                _path(source_range["path"])
            self.status.setText(mapped["mapping_precision"])
            self.selection_resolved.emit(mapped)
        except (ValueError, OSError, KeyError):
            self.status.setText(self.policy["verification_failed"])

    def select_report_finding(self, url):
        if url.scheme() != "forensic-finding" or not self.run_root:
            return
        finding_id = url.path()
        try:
            from hexeditor_tools.api import binary_forensic_resolve
            mapped = binary_forensic_resolve(str(self.run_root), finding_id, str(self.input_root), self.case_id)
            self.selection_resolved.emit(mapped)
        except (ValueError, OSError, KeyError):
            self.status.setText(self.policy["verification_failed"])

    def reflect_hex_offset(self, path, offset):
        if not self.run_root or not self.input_root:
            return
        matches = engine.fields_at_offset(self.run_root, source_sha256=file_hash(path), offset=offset)["field_ids"]
        for item in self.tree.selectedItems():
            item.setSelected(False)
        for field_id in matches:
            if field_id in self.field_items:
                self.field_items[field_id].setSelected(True)
                self.tree.scrollToItem(self.field_items[field_id])
