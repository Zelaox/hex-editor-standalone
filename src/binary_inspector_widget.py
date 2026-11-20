"""Binary Inspector — format-driven static + runtime PyQt widget."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from pathlib import Path

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QComboBox,
    QFrame,
    QLabel,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from src.binary_inspector_view import inspector_view_model
from src.gui_evidence_presenter import present_coverage_rows
from src.services.candidate_lineage.present import (
    present_lineage_candidate_rows,
    present_lineage_hash_rows,
    present_lineage_overview_rows,
    present_lineage_rail_rows,
)


class BinaryInspectorWidget(QWidget):
    """Renders BinarySnapshot nodes with format-specific tabs and optional runtime view."""

    goto_offset_signal = pyqtSignal(int)
    analyze_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._generation = 0
        self._view_model: Dict[str, Any] = {}
        self._forensic_context: Dict[str, Any] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.header = QLabel("Binary Inspector — no snapshot loaded")
        layout.addWidget(self.header)

        self.mode_tabs = QTabWidget()
        self.runtime_tabs = QTabWidget()
        self.static_tabs = QTabWidget()
        self._static_sections = []

        self.overview_table = self._make_table(["Field", "Value"])
        self.nodes_table = self._make_table(["Kind", "Label", "Offset", "RVA", "Length", "Confidence", "Evidence"])
        self.coverage_table = self._make_table(["Metric", "Value"])
        self.unknown_table = self._make_table(["Region", "Offset", "Length", "Class", "Entropy", "Neighbors"])
        self.anchors_table = self._make_table(["Anchor", "Kind", "Offset", "Length", "Count", "Level"])
        self.families_table = self._make_table(["Family", "Kind", "Support", "Level", "Anchors"])
        self.plaintext_runs_table = self._make_table(["Offset", "Length", "Preview", "Digest"])
        self.representation_table = self._make_table(["Region", "Brief", "Status", "Rule", "Promotion"])
        self.full_decode_table = self._make_table(["Class", "Offset", "Length", "Proof", "Segment"])
        self.full_decode_status_table = self._make_table(["Metric", "Value"])
        self.semantic_graph_table = self._make_table(["Metric", "Value"])
        self.graph_nodes_table = self._make_table(["Type", "State", "Node", "Offset", "Length"])
        self.graph_edges_table = self._make_table(["Relationship", "State", "Source", "Target", "Evidence"])
        self.ownership_table = self._make_table(["Span", "Classification", "State", "Proof", "Detector"])
        self.lineage_overview_table = self._make_table(["Metric", "Value"])
        self.lineage_rails_table = self._make_table(["Rail", "Run", "Status", "Verified", "Candidate", "Graph", "Upstream"])
        self.lineage_candidates_table = self._make_table(["Rail", "Candidate", "Run", "Graph", "SHA256"])
        self.lineage_hashes_table = self._make_table(["Label", "OK", "Expected", "Actual", "Path missing"])
        self.graph_panel = self._make_graph_panel()
        self.diagnostics_table = self._make_table(["Code", "Message", "Severity"])
        self.crosslinks_table = self._make_table(["Static ID", "Runtime ID", "Strategy", "Confidence"])

        self._register_static_sections(
            [
                ("Overview", self.overview_table),
                ("Objects", self.nodes_table),
                ("Coverage", self.coverage_table),
                ("Unknown", self.unknown_table),
                ("Anchors", self.anchors_table),
                ("Record families", self.families_table),
                ("Plaintext runs", self.plaintext_runs_table),
                ("Representation", self.representation_table),
                ("Full Decode", self.full_decode_table),
                ("Decode status", self.full_decode_status_table),
                ("Binary graph", self.graph_panel),
                ("Ownership", self.ownership_table),
                ("Lineage", self.lineage_overview_table),
                ("Lineage rails", self.lineage_rails_table),
                ("Candidates", self.lineage_candidates_table),
                ("Lineage hashes", self.lineage_hashes_table),
                ("Diagnostics", self.diagnostics_table),
            ]
        )
        self.static_panel = self._build_static_panel()
        self.mode_tabs.addTab(self.static_panel, "Static")
        self.mode_tabs.addTab(self.runtime_tabs, "Runtime")
        self.mode_tabs.setTabEnabled(1, False)
        self.runtime_tabs.addTab(self.crosslinks_table, "Crosslinks")
        layout.addWidget(self.mode_tabs)
        self._configure_mode_tabs_from_policy()

        button_row = QHBoxLayout()
        self.goto_button = QPushButton("Go to selected offset")
        self.goto_button.clicked.connect(self._goto_selected)
        button_row.addWidget(self.goto_button)
        self.analyze_button = QPushButton("Analyze current file")
        self.analyze_button.clicked.connect(self.analyze_requested.emit)
        button_row.addWidget(self.analyze_button)
        layout.addLayout(button_row)
        self._set_empty_state()

    def _static_section_nav_policy(self, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        if policy is None:
            from src.services.ui_policy import load_ui_policy

            policy = load_ui_policy()
        hints = dict((dict(policy.get("dock_layout_hints") or {})).get("binary_inspector_dock") or {})
        nav = dict(hints.get("static_section_nav") or {})
        nav_mode = str(nav.get("nav_mode") or "tab_widget").strip().lower()
        if nav_mode not in {"tab_widget", "button_strip"}:
            raise ValueError(f"unsupported static_section_nav.nav_mode: {nav_mode}")
        return {"nav_mode": nav_mode}

    def _register_static_sections(self, sections: list[tuple[str, QWidget]]) -> None:
        self._static_sections = list(sections)

    def _build_static_panel(self) -> QWidget:
        nav_policy = self._static_section_nav_policy()
        if str(nav_policy.get("nav_mode") or "") == "button_strip":
            return self._build_button_strip_static_panel()
        for label, widget in self._static_sections:
            self.static_tabs.addTab(widget, label)
        bar = self.static_tabs.tabBar()
        bar.setExpanding(False)
        self.static_tabs.setUsesScrollButtons(True)
        self.static_tabs.setDocumentMode(False)
        bar.setDrawBase(True)
        return self.static_tabs

    def _build_button_strip_static_panel(self) -> QWidget:
        from src.services.ui_policy import load_ui_policy, theme_color

        policy = load_ui_policy()
        hints = dict((dict(policy.get("dock_layout_hints") or {})).get("binary_inspector_dock") or {})
        nav = dict(hints.get("static_section_nav") or {})
        scroll_height = int(nav.get("scroll_height_px") or 0)
        if scroll_height <= 0:
            raise ValueError("button_strip nav requires static_section_nav.scroll_height_px")
        style = dict(nav.get("style") or {})
        strip_bg = theme_color(policy, str(style.get("strip_background_token") or "inspector_nav.strip"))
        button_bg = theme_color(policy, str(style.get("button_background_token") or "inspector_nav.button"))
        button_text = theme_color(policy, str(style.get("button_text_token") or "inspector_nav.button_text"))
        button_border = theme_color(policy, str(style.get("button_border_token") or "inspector_nav.button_border"))
        active_bg = theme_color(policy, str(style.get("active_background_token") or "inspector_nav.active"))
        active_text = theme_color(policy, str(style.get("active_text_token") or "inspector_nav.active_text"))
        min_height = int(style.get("button_min_height_px") or 0)
        padding = int(style.get("button_padding_px") or 0)
        if min_height <= 0 or padding <= 0:
            raise ValueError("button_strip nav requires style.button_min_height_px and style.button_padding_px")

        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(4)

        nav_host = QWidget()
        nav_layout = QHBoxLayout(nav_host)
        nav_layout.setContentsMargins(4, 2, 4, 2)
        nav_layout.setSpacing(4)
        self._static_section_buttons = []
        for index, (label, _widget) in enumerate(self._static_sections):
            button = QPushButton(label)
            button.setCheckable(True)
            button.setAutoExclusive(True)
            button.clicked.connect(lambda _checked, section_index=index: self._select_static_section(section_index))
            nav_layout.addWidget(button)
            self._static_section_buttons.append(button)

        nav_scroll = QScrollArea()
        nav_scroll.setWidget(nav_host)
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setFrameShape(QFrame.NoFrame)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        nav_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        nav_scroll.setFixedHeight(scroll_height)
        nav_scroll.setStyleSheet(f"QScrollArea {{ background-color: {strip_bg}; border: none; }}")
        nav_host.setStyleSheet(f"QWidget {{ background-color: {strip_bg}; }}")
        button_style = (
            f"QPushButton {{ background-color: {button_bg}; color: {button_text}; border: 1px solid {button_border};"
            f" border-radius: 3px; padding: {padding}px {padding + 4}px; min-height: {min_height}px; font-weight: 600; }}"
            f"QPushButton:checked {{ background-color: {active_bg}; color: {active_text}; border-color: {active_bg}; }}"
            f"QPushButton:hover {{ border-color: {active_bg}; }}"
        )
        for button in self._static_section_buttons:
            button.setStyleSheet(button_style)

        stack = QStackedWidget()
        for _label, widget in self._static_sections:
            stack.addWidget(widget)
        self._static_button_stack = stack

        panel_layout.addWidget(nav_scroll)
        panel_layout.addWidget(stack, 1)
        self._select_static_section(0)
        return panel

    def _static_section_container(self):
        nav_policy = self._static_section_nav_policy()
        if str(nav_policy.get("nav_mode") or "") == "button_strip":
            return getattr(self, "_static_button_stack", self.static_tabs)
        return self.static_tabs

    def _select_static_section(self, index: int) -> None:
        container = self._static_section_container()
        if index < 0 or index >= container.count():
            return
        if container is self.static_tabs:
            self.static_tabs.setCurrentIndex(index)
            return
        container.setCurrentIndex(index)
        for section_index, button in enumerate(getattr(self, "_static_section_buttons", []) or []):
            button.setChecked(section_index == index)

    def show_static_section(self, label: str) -> None:
        target = str(label or "").strip().lower()
        for index, (section_label, _widget) in enumerate(self._static_sections):
            if str(section_label).strip().lower() == target:
                self._select_static_section(index)
                return

    def _configure_mode_tabs_from_policy(self, policy: Mapping[str, Any] | None = None) -> None:
        for tabs in (self.mode_tabs, self.runtime_tabs):
            tabs.tabBar().setExpanding(False)
            tabs.setUsesScrollButtons(True)

    def configure_tab_bar_policy(self, policy: Mapping[str, Any]) -> None:
        self._configure_mode_tabs_from_policy(policy)

    def _set_empty_state(self) -> None:
        self.header.setText("Binary Inspector — open or analyze a PTX/PE file")
        self._fill_table(self.overview_table, [("Status", "No snapshot loaded"), ("Next step", "Open a supported file or click Analyze current file")])
        self.goto_button.setEnabled(False)
        self.analyze_button.setEnabled(True)

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    def _apply_policy_headers(self, context: Mapping[str, Any]) -> None:
        policy = dict(context.get("ui_policy") or {})
        panels = dict(policy.get("panels") or {})
        mapping = {
            self.coverage_table: "binary_inspector_coverage",
            self.anchors_table: "binary_inspector_anchors",
            self.unknown_table: "binary_inspector_unknown",
            self.families_table: "binary_inspector_record_families",
            self.representation_table: "binary_inspector_representation",
            self.full_decode_table: "binary_inspector_full_decode",
            self.ownership_table: "binary_inspector_ownership",
        }
        for table, panel_id in mapping.items():
            panel = dict(panels.get(panel_id) or {})
            columns = panel.get("columns")
            if isinstance(columns, list) and columns:
                table.setColumnCount(len(columns))
                table.setHorizontalHeaderLabels([str(item) for item in columns])

    def clear(self) -> None:
        self._generation += 1
        self._view_model = {}
        self._forensic_context = {}
        self.header.setText("Binary Inspector — no snapshot loaded")
        for table in (
            self.overview_table,
            self.nodes_table,
            self.coverage_table,
            self.unknown_table,
            self.anchors_table,
            self.families_table,
            self.representation_table,
            self.full_decode_table,
            self.full_decode_status_table,
            self.semantic_graph_table,
            self.graph_nodes_table,
            self.graph_edges_table,
            self.ownership_table,
            self.diagnostics_table,
            self.crosslinks_table,
        ):
            table.setRowCount(0)
        self.mode_tabs.setTabEnabled(1, False)
        self._set_empty_state()

    def set_analyzing(self, source_path: str) -> None:
        self._view_model = {}
        self._forensic_context = {}
        name = Path(source_path).name if source_path else "file"
        self.header.setText(f"Binary Inspector — analyzing {name}…")
        self.analyze_button.setEnabled(False)
        self.goto_button.setEnabled(False)
        for table in (
            self.overview_table,
            self.nodes_table,
            self.coverage_table,
            self.unknown_table,
            self.anchors_table,
            self.families_table,
            self.representation_table,
            self.full_decode_table,
            self.full_decode_status_table,
            self.semantic_graph_table,
            self.graph_nodes_table,
            self.graph_edges_table,
            self.ownership_table,
            self.diagnostics_table,
            self.crosslinks_table,
        ):
            table.setRowCount(0)
        self.mode_tabs.setTabEnabled(1, False)

    def _make_graph_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        self.graph_banner = QLabel("No verified Binary Semantic Graph loaded")
        self.graph_banner.setFrameShape(QFrame.StyledPanel)
        self.graph_banner.setWordWrap(True)
        layout.addWidget(self.graph_banner)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Truth state:"))
        self.graph_state_filter = QComboBox()
        self.graph_state_filter.addItems(["All", "verified", "observed", "tested", "hypothesized", "inconclusive", "falsified", "superseded"])
        self.graph_state_filter.currentTextChanged.connect(self._render_graph_rows)
        controls.addWidget(self.graph_state_filter)
        controls.addStretch(1)
        layout.addLayout(controls)
        tabs = QTabWidget()
        tabs.addTab(self.semantic_graph_table, "Summary")
        tabs.addTab(self.graph_nodes_table, "Nodes")
        tabs.addTab(self.graph_edges_table, "Edges")
        layout.addWidget(tabs)
        self.graph_nodes_table.itemSelectionChanged.connect(self._graph_node_selected)
        self.graph_nodes_table.itemDoubleClicked.connect(lambda _item: self._emit_graph_offset())
        return panel

    def update_snapshot(
        self,
        snapshot: Mapping[str, Any],
        *,
        generation: int,
        runtime_snapshot: Mapping[str, Any] | None = None,
        merge_view: Mapping[str, Any] | None = None,
        forensic_context: Mapping[str, Any] | None = None,
    ) -> None:
        self._generation = int(generation)
        self._forensic_context = dict(forensic_context or {})
        self._view_model = inspector_view_model(snapshot, runtime_snapshot=runtime_snapshot)
        plugin = self._view_model.get("format_plugin", "unknown")
        snap_id = self._view_model.get("snapshot_id", "")
        self.header.setText(
            f"Binary Inspector — {plugin} — {snap_id} — "
            f"anchors={self._view_model.get('anchor_count')} unknown={self._view_model.get('unknown_region_count')}"
        )
        self.analyze_button.setEnabled(True)
        self.goto_button.setEnabled(True)

        if self._forensic_context:
            self._apply_policy_headers(self._forensic_context)

        overview_rows = [
            ("format_plugin", plugin),
            ("snapshot_id", snap_id),
            ("node_count", self._view_model.get("node_count")),
            ("source_sha256", (snapshot.get("source") or {}).get("sha256")),
            ("source_size", (snapshot.get("source") or {}).get("size")),
            ("registry_revision", snapshot.get("registry_revision")),
            ("anchor_count", self._view_model.get("anchor_count")),
            ("unknown_region_count", self._view_model.get("unknown_region_count")),
            ("record_family_count", self._view_model.get("record_family_count")),
        ]
        self._fill_table(self.overview_table, overview_rows)

        node_rows = []
        from src.services.ui_policy import load_budget, load_ui_policy

        row_limit = load_budget(load_ui_policy(), "max_inspector_table_rows")
        for node in snapshot.get("nodes") or []:
            if row_limit > 0 and len(node_rows) >= row_limit:
                break
            source_range = (node.get("source_ranges") or [{}])[0]
            node_rows.append(
                (
                    node.get("kind", ""),
                    node.get("label", ""),
                    source_range.get("offset", 0),
                    source_range.get("rva", ""),
                    source_range.get("length", 0),
                    node.get("confidence", ""),
                    node.get("evidence_class", "static"),
                )
            )
        self._fill_table(self.nodes_table, node_rows, offset_column=2)

        context = self._forensic_context
        coverage_rows = context.get("coverage_rows") or present_coverage_rows(snapshot)
        self._fill_table(self.coverage_table, [(key, value) for key, value in coverage_rows])

        self._fill_dict_table(self.unknown_table, list(context.get("unknown_rows") or []), offset_key="offset")
        self._fill_dict_table(self.anchors_table, list(context.get("anchor_rows") or []), offset_key="offset")
        self._fill_dict_table(self.families_table, list(context.get("record_family_rows") or []), offset_key=None)
        self._fill_dict_table(self.plaintext_runs_table, list(context.get("plaintext_run_rows") or []), offset_key="offset")
        self._fill_dict_table(self.representation_table, list(context.get("representation_rows") or []), offset_key=None)
        full_decode = dict(context.get("full_decode") or {})
        decode_rows = []
        for segment in (full_decode.get("coverage") or {}).get("segments") or []:
            decode_rows.append({"class": segment.get("class", ""), "offset": segment.get("offset", 0), "length": segment.get("length", 0), "proof": ",".join(segment.get("proof_refs") or []), "segment": segment.get("segment_id", "")})
        self._fill_dict_table(self.full_decode_table, decode_rows, offset_key="offset")
        decision = dict(full_decode.get("decision") or {})
        decode_status = [
            ("state_source", full_decode.get("state_source", "not_run")),
            ("run_id", full_decode.get("run_id", "")),
            ("status", full_decode.get("status", "not_run")),
            ("verified", full_decode.get("verified", False)),
            ("coverage_complete", decision.get("coverage_complete", False)),
            ("unresolved_bytes", decision.get("unresolved_bytes", "")),
            ("ascii_roundtrip_verified", decision.get("ascii_roundtrip_verified", False)),
            ("verified_decryption", decision.get("verified_decryption", False)),
            ("promotion_eligible", decision.get("promotion_eligible", False)),
            ("plaintext_corpus", (full_decode.get("exports") or {}).get("plaintext_corpus", "")),
            ("lossless_ascii", (full_decode.get("exports") or {}).get("lossless_ascii", "")),
        ]
        self._fill_table(self.full_decode_status_table, decode_status, policy=context.get("ui_policy"))
        unresolved = dict(context.get("unresolved_inference") or {})
        graph_summary = dict(unresolved.get("graph_summary") or {})
        unresolved_decision = dict(unresolved.get("decision") or {})
        graph_rows = [("status", unresolved.get("status", "not_run")), ("verified", unresolved.get("verified", False)), ("graph_id", graph_summary.get("graph_id", "")), ("nodes", graph_summary.get("node_count", 0)), ("edges", graph_summary.get("edge_count", 0)), ("graph_valid", (graph_summary.get("validation") or {}).get("valid", False)), ("unresolved_bytes", unresolved_decision.get("unresolved_bytes", "")), ("semantic_graph", (unresolved.get("artifacts") or {}).get("semantic_graph", ""))]
        self._fill_table(self.semantic_graph_table, graph_rows)
        self._graph_nodes = list(unresolved.get("graph_nodes") or [])
        self._graph_edges = list(unresolved.get("graph_edges") or [])
        state = str(unresolved.get("status") or "not_run")
        graph_valid = bool((graph_summary.get("validation") or {}).get("valid"))
        self.graph_banner.setText(f"{state}  •  {graph_summary.get('node_count', 0)} nodes  •  {graph_summary.get('edge_count', 0)} edges  •  {unresolved_decision.get('unresolved_bytes', 0)} unresolved bytes")
        token = "binary_graph.verified" if unresolved.get("verified") and graph_valid else "binary_graph.inconclusive"
        color = str(((context.get("ui_policy") or {}).get("theme_tokens") or {}).get(token) or "#607D8B")
        self.graph_banner.setStyleSheet(f"QLabel {{ border-left: 5px solid {color}; padding: 8px; font-weight: 600; }}")
        self._render_graph_rows()
        ownership_rows = [{"span": item.get("span_id", ""), "classification": item.get("classification", ""), "state": item.get("state", ""), "proof": item.get("proof_id", ""), "detector": item.get("detector_id", "")} for item in unresolved.get("ownership_proofs") or []]
        self._fill_dict_table(self.ownership_table, ownership_rows, offset_key=None)

        lineage = dict(context.get("candidate_lineage") or {})
        file_match = dict(context.get("lineage_file_match") or {})
        overview_rows = present_lineage_overview_rows(lineage)
        if file_match:
            overview_rows = [
                ("file_lineage_match", "YES" if file_match.get("matched") else "NO"),
                ("lineage_role", file_match.get("role")),
                ("graph_id", file_match.get("graph_id") or ""),
            ] + overview_rows
        self._fill_table(self.lineage_overview_table, overview_rows)
        self._fill_dict_table(self.lineage_rails_table, present_lineage_rail_rows(lineage), offset_key=None)
        self._fill_dict_table(self.lineage_candidates_table, present_lineage_candidate_rows(lineage), offset_key=None)
        self._fill_dict_table(self.lineage_hashes_table, present_lineage_hash_rows(lineage), offset_key=None)

        diag_rows = [
            (item.get("code", ""), item.get("message", ""), item.get("severity", ""))
            for item in snapshot.get("diagnostics") or []
        ]
        self._fill_table(self.diagnostics_table, diag_rows)

        has_runtime = bool(runtime_snapshot)
        self.mode_tabs.setTabEnabled(1, has_runtime)
        if merge_view:
            link_rows = [
                (
                    link.get("static_node_id", ""),
                    link.get("runtime_node_id", ""),
                    link.get("merge_strategy", ""),
                    link.get("confidence", ""),
                )
                for link in merge_view.get("crosslinks") or []
            ]
            self._fill_table(self.crosslinks_table, link_rows)

    def _render_graph_rows(self) -> None:
        selected_state = self.graph_state_filter.currentText() if hasattr(self, "graph_state_filter") else "All"
        nodes = [item for item in getattr(self, "_graph_nodes", []) if selected_state == "All" or item.get("truth_state") == selected_state]
        node_rows = []
        for node in nodes:
            attributes = dict(node.get("attributes") or {})
            node_rows.append((node.get("node_type", ""), node.get("truth_state", ""), node.get("node_id", ""), attributes.get("offset", ""), attributes.get("length", "")))
        self._fill_table(self.graph_nodes_table, node_rows, offset_column=3)
        edges = [item for item in getattr(self, "_graph_edges", []) if selected_state == "All" or item.get("truth_state") == selected_state]
        self._fill_table(self.graph_edges_table, [(item.get("edge_type", ""), item.get("truth_state", ""), item.get("source_id", ""), item.get("target_id", ""), ",".join(item.get("evidence_refs") or [])) for item in edges])

    def _graph_node_selected(self) -> None:
        row = self.graph_nodes_table.currentRow()
        if row < 0: return
        item = self.graph_nodes_table.item(row, 2)
        if item is None: return
        node_id = item.text()
        edges = [edge for edge in getattr(self, "_graph_edges", []) if edge.get("source_id") == node_id or edge.get("target_id") == node_id]
        self._fill_table(self.graph_edges_table, [(edge.get("edge_type", ""), edge.get("truth_state", ""), edge.get("source_id", ""), edge.get("target_id", ""), ",".join(edge.get("evidence_refs") or [])) for edge in edges])

    def _emit_graph_offset(self) -> None:
        row = self.graph_nodes_table.currentRow()
        item = self.graph_nodes_table.item(row, 3) if row >= 0 else None
        if item is not None and item.data(Qt.UserRole) is not None:
            self.goto_offset_signal.emit(int(item.data(Qt.UserRole)))

    def _fill_dict_table(self, table: QTableWidget, rows: list[Dict[str, Any]], *, offset_key: Optional[str]) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            keys = list(row.keys())[: table.columnCount()]
            for column_index, key in enumerate(keys):
                value = row.get(key, "")
                item = QTableWidgetItem(str(value))
                if offset_key and key == offset_key:
                    try:
                        item.setData(Qt.UserRole, int(value))
                    except (TypeError, ValueError):
                        pass
                table.setItem(row_index, column_index, item)

    def _fill_table(self, table: QTableWidget, rows: list[tuple], *, offset_column: Optional[int] = None, policy: Mapping[str, Any] | None = None) -> None:
        from src.services.ui_policy import format_display_scalar, load_ui_policy

        ui_policy = dict(policy or load_ui_policy())
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                display = format_display_scalar(value, policy=ui_policy)
                item = QTableWidgetItem(display)
                if offset_column is not None and column_index == offset_column:
                    try:
                        item.setData(Qt.UserRole, int(value))
                    except (TypeError, ValueError):
                        pass
                table.setItem(row_index, column_index, item)

    def _goto_selected(self) -> None:
        table = self.static_tabs.currentWidget()
        if table is self.graph_panel:
            self._emit_graph_offset()
            return
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
                self.goto_offset_signal.emit(int(offset))
                return

    def selected_offset(self) -> Optional[int]:
        table = self.nodes_table
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, 2)
        if item is None:
            return None
        offset = item.data(Qt.UserRole)
        return int(offset) if offset is not None else None
