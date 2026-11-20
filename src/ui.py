"""
UI components for the HexEditor application.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple
import json

from PyQt5.QtWidgets import (
    QMainWindow, QPlainTextEdit, QTextEdit, QAction, QWidget, QFileDialog,
    QVBoxLayout, QMessageBox, QLineEdit, QLabel, QInputDialog, QHBoxLayout,
    QListWidget, QDockWidget, QPushButton, QStatusBar, QListWidgetItem,
    QProgressBar, QCheckBox, QComboBox, QMenu, QApplication, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QSize, QTimer, pyqtSignal
from PyQt5.QtGui import (
    QTextCursor, QTextCharFormat, QColor, QFont, QSyntaxHighlighter,
    QTextCharFormat, QBrush, QPalette, QIcon
)

from src.constants import DEFAULT_FONT_FAMILY, DEFAULT_FONT_SIZE
from src.logging_config import get_logger
from src.text_inspector_widget import TextInspectorWidget
from src.binary_inspector_widget import BinaryInspectorWidget

# Get a logger for this module
logger = get_logger('ui')

class PTXMetadataWidget(QWidget):
    """A widget for displaying PTX metadata."""
    
    def __init__(self, parent=None):
        """Initialize the PTX metadata widget."""
        super().__init__(parent)
        self.logger = get_logger('ptx_metadata_widget')
        self.logger.debug("Initializing PTX Metadata Widget")
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tabs for different views
        self.tabs = QTabWidget()
        
        # Timecode tab
        self.timecode_widget = QTableWidget()
        self.timecode_widget.setColumnCount(4)
        self.timecode_widget.setHorizontalHeaderLabels(["Offset", "Value", "Type", "Go to"])
        self.timecode_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.timecode_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.timecode_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Session metadata tab
        self.metadata_widget = QTableWidget()
        self.metadata_widget.setColumnCount(3)
        self.metadata_widget.setHorizontalHeaderLabels(["Description", "Value", "Go to"])
        self.metadata_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.metadata_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.metadata_widget.setEditTriggers(QTableWidget.NoEditTriggers)

        self.session_inspector_widget = QTableWidget()
        self.session_inspector_widget.setColumnCount(5)
        self.session_inspector_widget.setHorizontalHeaderLabels(["Kind", "Name", "Offset", "Length", "Confidence"])
        self.session_inspector_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.session_inspector_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.session_inspector_widget.setEditTriggers(QTableWidget.NoEditTriggers)

        self.binary_waterfall_widget = QTableWidget()
        self.binary_waterfall_widget.setColumnCount(4)
        self.binary_waterfall_widget.setHorizontalHeaderLabels(["Offset", "Length", "Class", "Objects"])
        self.binary_waterfall_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.binary_waterfall_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.binary_waterfall_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Add widgets to tabs
        self.tabs.addTab(self.timecode_widget, "Timecodes")
        self.tabs.addTab(self.metadata_widget, "Session Metadata")
        self.tabs.addTab(self.session_inspector_widget, "Session Inspector")
        self.tabs.addTab(self.binary_waterfall_widget, "Binary Waterfall")
        
        # Add buttons for PTX-specific operations
        button_layout = QHBoxLayout()
        
        self.decrypt_button = QPushButton("Decrypt PTX")
        self.decrypt_button.clicked.connect(self.on_decrypt_clicked)
        
        self.extract_button = QPushButton("Extract Sections")
        self.extract_button.clicked.connect(self.on_extract_clicked)
        
        self.export_json_button = QPushButton("Export as JSON")
        self.export_json_button.clicked.connect(self.on_export_json_clicked)
        
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.extract_button)
        button_layout.addWidget(self.export_json_button)
        
        # Add to layout
        layout.addWidget(self.tabs)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def clear(self):
        """Clear all data from the widget."""
        self.timecode_widget.setRowCount(0)
        self.metadata_widget.setRowCount(0)
        self.session_inspector_widget.setRowCount(0)
        self.binary_waterfall_widget.setRowCount(0)

    def update_runtime_snapshot(self, snapshot):
        """Render one immutable runtime snapshot without inventing missing semantics."""
        nodes = list(snapshot.get("nodes") or [])
        self.session_inspector_widget.setRowCount(len(nodes))
        for row, node in enumerate(nodes):
            source_range = (node.get("source_ranges") or [{}])[0]
            values = (node.get("kind", "unknown"), node.get("label", ""), source_range.get("offset", 0), source_range.get("length", 0), node.get("confidence", 0))
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 2:
                    item.setData(Qt.UserRole, int(source_range.get("offset", 0)))
                self.session_inspector_widget.setItem(row, column, item)
        self.update_waterfall_rows(list(snapshot.get("coverage") or []), anchors=snapshot.get("anchors"), unknown_regions=snapshot.get("unknown_regions"))

    def update_waterfall_rows(self, coverage_ranges, *, anchors=None, unknown_regions=None):
        rows = []
        for source_range in coverage_ranges or []:
            rows.append((source_range.get("offset", 0), source_range.get("length", 0), source_range.get("class", "unknown"), ", ".join(source_range.get("node_ids") or [])))
        for anchor in anchors or []:
            span = dict(anchor.get("span") or {})
            rows.append((span.get("offset", 0), span.get("length", 0), f"anchor:{anchor.get('kind', '')}", str(anchor.get("anchor_id") or "")))
        for region in unknown_regions or []:
            span = dict(region.get("span") or {})
            rows.append((span.get("offset", 0), span.get("length", 0), str(region.get("classification") or "unknown"), str(region.get("region_id") or "")))
        self.binary_waterfall_widget.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.UserRole, int(values[0]))
                self.binary_waterfall_widget.setItem(row, column, item)

    def update_forensic_context(self, forensic_context):
        """Populate waterfall tab from presenter rows when available."""
        rows = list((forensic_context or {}).get("waterfall_rows") or [])
        if not rows:
            return
        self.binary_waterfall_widget.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            values = (item.get("offset", 0), item.get("length", 0), item.get("class", ""), item.get("objects", ""))
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.UserRole, int(item.get("offset") or 0))
                self.binary_waterfall_widget.setItem(row_index, column, cell)
        
    def update_from_ptx_file(self, ptx_file):
        """
        Update the widget with data from a PTX file.
        
        Args:
            ptx_file: PTXFile instance to get data from
        """
        self.clear()
        
        # Update timecodes
        if hasattr(ptx_file, 'timecodes') and ptx_file.timecodes:
            self.update_timecodes(ptx_file.timecodes)
            
        # Update metadata
        if hasattr(ptx_file, 'metadata') and ptx_file.metadata:
            self.update_metadata(ptx_file.metadata)
            
        # Update button states
        self.decrypt_button.setEnabled(ptx_file.header and ptx_file.header.is_encrypted())
        self.extract_button.setEnabled(bool(ptx_file.sections))
        self.export_json_button.setEnabled(True)
        
    def update_timecodes(self, timecodes):
        """
        Update the timecode widget with the given timecodes.
        
        Args:
            timecodes: List of timecode dictionaries
        """
        self.timecode_widget.setRowCount(len(timecodes))
        
        for row, tc in enumerate(timecodes):
            # Offset
            offset_item = QTableWidgetItem(f"0x{tc['offset']:08x}")
            self.timecode_widget.setItem(row, 0, offset_item)
            
            # Value
            value_item = QTableWidgetItem(tc['value'])
            self.timecode_widget.setItem(row, 1, value_item)
            
            # Type
            type_item = QTableWidgetItem(tc['type'])
            self.timecode_widget.setItem(row, 2, type_item)
            
            # Go to button
            goto_widget = QWidget()
            goto_layout = QHBoxLayout(goto_widget)
            goto_button = QPushButton("Go")
            goto_button.setProperty("offset", tc['offset'])
            goto_button.clicked.connect(self.on_goto_offset)
            goto_layout.addWidget(goto_button)
            goto_layout.setContentsMargins(0, 0, 0, 0)
            self.timecode_widget.setCellWidget(row, 3, goto_widget)
    
    def update_metadata(self, metadata):
        """
        Update the metadata widget with the given metadata.
        
        Args:
            metadata: Dictionary containing metadata
        """
        # Handle standard metadata first
        standard_metadata = {k: v for k, v in metadata.items() if not isinstance(k, int)}
        key_offset_metadata = {k: v for k, v in metadata.items() if isinstance(k, int)}
        
        row_count = len(standard_metadata) + len(key_offset_metadata)
        self.metadata_widget.setRowCount(row_count)
        
        row = 0
        
        # Add standard metadata
        for key, value in standard_metadata.items():
            # Description
            desc_item = QTableWidgetItem(key)
            self.metadata_widget.setItem(row, 0, desc_item)
            
            # Value
            if isinstance(value, dict):
                value_text = json.dumps(value, indent=2)
            else:
                value_text = str(value)
            value_item = QTableWidgetItem(value_text)
            self.metadata_widget.setItem(row, 1, value_item)
            
            # No goto button for standard metadata
            row += 1
        
        # Add key offset metadata
        for offset, data in key_offset_metadata.items():
            # Description
            desc_item = QTableWidgetItem(data['description'])
            self.metadata_widget.setItem(row, 0, desc_item)
            
            # Value - Try to show a readable representation
            if 'interpretation' in data and 'ascii' in data['interpretation']:
                value_text = data['interpretation']['ascii']
            else:
                value_text = data['data']
            value_item = QTableWidgetItem(value_text)
            self.metadata_widget.setItem(row, 1, value_item)
            
            # Go to button
            goto_widget = QWidget()
            goto_layout = QHBoxLayout(goto_widget)
            goto_button = QPushButton("Go")
            goto_button.setProperty("offset", offset)
            goto_button.clicked.connect(self.on_goto_offset)
            goto_layout.addWidget(goto_button)
            goto_layout.setContentsMargins(0, 0, 0, 0)
            self.metadata_widget.setCellWidget(row, 2, goto_widget)
            
            row += 1
    
    def on_goto_offset(self):
        """Handle clicking the Go button to navigate to an offset."""
        button = self.sender()
        offset = button.property("offset")
        
        if offset is not None:
            # Emit a signal to navigate to the offset
            self.parent().parent().goto_offset_signal.emit(offset)
    
    def on_decrypt_clicked(self):
        """Handle clicking the Decrypt PTX button."""
        # This will be connected to the decrypt_file method in the app
        self.parent().parent().decrypt_ptx_signal.emit()
    
    def on_extract_clicked(self):
        """Handle clicking the Extract Sections button."""
        # This will be connected to the extract_ptx_sections method in the app
        self.parent().parent().extract_ptx_signal.emit()
    
    def on_export_json_clicked(self):
        """Handle clicking the Export as JSON button."""
        # This will be connected to the export_ptx_json method in the app
        self.parent().parent().export_ptx_json_signal.emit()

class HexEditorMainWindow(QMainWindow):
    """Main window for the HexEditor application."""
    
    # Add signals for PTX operations
    goto_offset_signal = pyqtSignal(int)
    decrypt_ptx_signal = pyqtSignal()
    extract_ptx_signal = pyqtSignal()
    export_ptx_json_signal = pyqtSignal()
    next_timecode_signal = pyqtSignal()
    prev_timecode_signal = pyqtSignal()
    goto_timecode_signal = pyqtSignal()
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        
        logger.info("Initializing HexEditorMainWindow")
        
        self.setObjectName("hex_editor_main_window")
        self.setWindowTitle("HexEditor")
        self.resize(1024, 768)
        self._layout_restored = False
        self._layout_autosave = None
        self._ui_policy: Dict[str, Any] = {}
        self._dock_updates: Optional["DockUpdateRegistry"] = None
        
        # Create the central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create the layout
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Create the hex editor — QPlainTextEdit handles large line counts far better than QTextEdit.
        self.hex_editor = QPlainTextEdit()
        self.hex_editor.setReadOnly(False)
        self.hex_editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.hex_editor.setTabChangesFocus(False)
        self.hex_editor.setFont(QFont(DEFAULT_FONT_FAMILY, DEFAULT_FONT_SIZE))
        
        # Set background color for better contrast with text
        self.hex_editor.setStyleSheet("QPlainTextEdit { background-color: #202020; }")
        
        self.layout.addWidget(self.hex_editor)
        
        # Create the status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create the status bar labels
        self.position_label = QLabel("Position: 0x00000000")
        self.status_bar.addWidget(self.position_label)
        
        self.selection_label = QLabel("Selection: 0 bytes")
        self.status_bar.addWidget(self.selection_label)
        
        self.file_size_label = QLabel("File Size: 0 bytes")
        self.status_bar.addWidget(self.file_size_label)

        self.knowledge_metrics_label = QLabel("")
        self.status_bar.addPermanentWidget(self.knowledge_metrics_label)
        
        # Add a status message label
        self.status_message = QLabel("")
        self.status_bar.addPermanentWidget(self.status_message)
        
        # Create actions
        self.create_actions()
        
        # Set up the dark mode
        self.dark_mode_enabled = False
        self.toggle_dark_mode(True)  # Default to dark mode
        
        logger.info("HexEditorMainWindow initialized")

    def create_actions(self):
        """Create actions for the application."""
        logger.debug("Creating actions")
        
        # Create the open action
        self.open_action = QAction("Open", self)
        self.open_action.setShortcut("Ctrl+O")
        self.open_action.setStatusTip("Open a file")
        
        # Create the save action
        self.save_action = QAction("Save", self)
        self.save_action.setShortcut("Ctrl+S")
        self.save_action.setStatusTip("Save the current file")
        
        # Create the undo action
        self.undo_action = QAction("Undo", self)
        self.undo_action.setShortcut("Ctrl+Z")
        self.undo_action.setStatusTip("Undo the last action")
        
        # Create the redo action
        self.redo_action = QAction("Redo", self)
        self.redo_action.setShortcut("Ctrl+Y")
        self.redo_action.setStatusTip("Redo the last undone action")
        
        # Create the search action
        self.search_action = QAction("Search", self)
        self.search_action.setShortcut("Ctrl+F")
        self.search_action.setStatusTip("Search for a pattern")
        
        # Create the goto action
        self.goto_action = QAction("Goto", self)
        self.goto_action.setShortcut("Ctrl+G")
        self.goto_action.setStatusTip("Go to a specific offset")
        
        # Create the disassemble action
        self.disassemble_action = QAction("Disassemble", self)
        self.disassemble_action.setStatusTip("Disassemble the current file")
        
        logger.debug("Actions created")

    def create_dock_widgets(self):
        """Create and set up dock widgets."""
        logger.debug("Creating dock widgets")
        
        # Create the disassembly dock
        self.disassembly_dock = QDockWidget("Disassembly", self)
        self.disassembly_dock.setObjectName("disassembly_dock")
        self.disassembly_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.disassembly_text = QTextEdit()
        self.disassembly_text.setReadOnly(True)
        self.disassembly_dock.setWidget(self.disassembly_text)
        self.addDockWidget(Qt.RightDockWidgetArea, self.disassembly_dock)
        
        # Create the pseudocode dock
        self.pseudocode_dock = QDockWidget("Pseudocode", self)
        self.pseudocode_dock.setObjectName("pseudocode_dock")
        self.pseudocode_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.pseudocode_text = QTextEdit()
        self.pseudocode_text.setReadOnly(True)
        self.pseudocode_dock.setWidget(self.pseudocode_text)
        self.addDockWidget(Qt.RightDockWidgetArea, self.pseudocode_dock)

        # Text inspector dock
        self.text_inspector_dock = QDockWidget("Text Inspector", self)
        self.text_inspector_dock.setObjectName("text_inspector_dock")
        self.text_inspector_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.text_inspector_widget = TextInspectorWidget(self.text_inspector_dock)
        self.text_inspector_dock.setWidget(self.text_inspector_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, self.text_inspector_dock)
        
        # Create the symbols dock
        self.symbols_dock = QDockWidget("Symbols", self)
        self.symbols_dock.setObjectName("symbols_dock")
        self.symbols_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.symbols_widget = QListWidget()
        self.symbols_dock.setWidget(self.symbols_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.symbols_dock)
        
        # Create the bookmarks dock
        self.bookmarks_dock = QDockWidget("Bookmarks", self)
        self.bookmarks_dock.setObjectName("bookmarks_dock")
        self.bookmarks_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.bookmarks_widget = QListWidget()
        self.bookmarks_dock.setWidget(self.bookmarks_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.bookmarks_dock)
        
        # Create the search results dock
        self.search_results_dock = QDockWidget("Search Results", self)
        self.search_results_dock.setObjectName("search_results_dock")
        self.search_results_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.search_results_widget = QListWidget()
        self.search_results_dock.setWidget(self.search_results_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.search_results_dock)
        
        # Create the file structure dock
        self.file_structure_dock = QDockWidget("File Structure", self)
        self.file_structure_dock.setObjectName("file_structure_dock")
        self.file_structure_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.file_structure_widget = QListWidget()
        self.file_structure_dock.setWidget(self.file_structure_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.file_structure_dock)
        
        # PTX metadata dock
        self.ptx_metadata_dock = QDockWidget("PTX Metadata", self)
        self.ptx_metadata_dock.setObjectName("ptx_metadata_dock")
        self.ptx_metadata_widget = PTXMetadataWidget(self.ptx_metadata_dock)
        self.ptx_metadata_dock.setWidget(self.ptx_metadata_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, self.ptx_metadata_dock)

        # Binary Inspector dock (PTX + PE unified snapshot view)
        self.binary_inspector_dock = QDockWidget("Binary Inspector", self)
        self.binary_inspector_dock.setObjectName("binary_inspector_dock")
        self.binary_inspector_dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.binary_inspector_widget = BinaryInspectorWidget(self.binary_inspector_dock)
        self.binary_inspector_dock.setWidget(self.binary_inspector_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, self.binary_inspector_dock)

        self._apply_initial_dock_visibility()
        
        logger.debug("Dock widgets created")

    def _apply_initial_dock_visibility(self) -> None:
        """First-run dock visibility from ui_policy; skipped once layout is restored."""
        if self._layout_restored:
            return
        from src.services.desktop_layout import apply_dock_defaults

        if self._ui_policy:
            apply_dock_defaults(self, self._ui_policy)

    def install_layout_persistence(self, policy: Dict[str, Any]) -> None:
        """Restore saved layout and autosave dock changes without forcing visibility resets."""
        from src.services.desktop_layout import LayoutAutosave, restore_layout

        self._ui_policy = dict(policy)
        persistence = dict(self._ui_policy.get("desktop_persistence") or {})
        window_name = str(persistence.get("main_window_object_name") or "")
        toolbar_name = str(persistence.get("main_toolbar_object_name") or "")
        if window_name:
            self.setObjectName(window_name)
        if toolbar_name and hasattr(self, "toolbar") and self.toolbar is not None:
            self.toolbar.setObjectName(toolbar_name)
        self._layout_restored = restore_layout(self, self._ui_policy)
        self._apply_initial_dock_visibility()
        if hasattr(self, "binary_inspector_widget"):
            self.binary_inspector_widget.configure_tab_bar_policy(self._ui_policy)
        self._layout_autosave = LayoutAutosave(self, policy=self._ui_policy)
        self._layout_autosave.attach()
        self.install_dock_update_gates()

    def install_dock_update_gates(self) -> None:
        from src.services.desktop_layout import dock_widgets
        from src.services.dock_update_gate import DockUpdateRegistry

        self._dock_updates = DockUpdateRegistry(self)
        self._dock_updates.register_docks(dock_widgets(self))

    def deliver_dock_update(self, dock_name: str, apply, *, coalesce: bool = True) -> None:
        if self._dock_updates is None:
            apply()
            return
        self._dock_updates.deliver(dock_name, apply, coalesce=coalesce)

    def dock_is_visible(self, dock_name: str) -> bool:
        if self._dock_updates is None:
            from src.services.dock_update_gate import dock_panel_shown

            dock = self.findChild(QDockWidget, dock_name)
            return dock is not None and dock_panel_shown(dock)
        return self._dock_updates.is_visible(dock_name)

    def clear_dock_pending_updates(self) -> None:
        if self._dock_updates is not None:
            self._dock_updates.clear_all()

    def set_layout_autosave_suspended(self, suspended: bool) -> None:
        if self._layout_autosave is not None:
            self._layout_autosave.set_suspended(suspended)

    def layout_was_restored(self) -> bool:
        return bool(self._layout_restored)

    def flush_layout_save(self, *, recent_files: Optional[List[str]] = None) -> None:
        from src.services.desktop_layout import save_layout

        if self._layout_autosave is not None:
            self._layout_autosave._timer.stop()
        if self._ui_policy:
            save_layout(self, self._ui_policy, recent_files=recent_files)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.flush_layout_save()
        super().closeEvent(event)

    def create_toolbar(self):
        """Create and set up the toolbar."""
        logger.debug("Creating toolbar")
        
        # Create the toolbar
        self.toolbar = self.addToolBar("Toolbar")
        
        # Add actions to the toolbar
        self.toolbar.addAction(self.open_action)
        self.toolbar.addAction(self.save_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.undo_action)
        self.toolbar.addAction(self.redo_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.search_action)
        self.toolbar.addAction(self.goto_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.disassemble_action)
        
        logger.debug("Toolbar created")

    def create_menu_bar(self):
        """Create and set up the menu bar."""
        logger.debug("Creating menu bar")
        
        # Create the menu bar
        self.menu_bar = self.menuBar()
        
        # Create the file menu
        self.file_menu = self.menu_bar.addMenu("&File")
        
        # Add actions to the file menu
        self.file_menu.addAction(self.open_action)
        self.file_menu.addAction(self.save_action)
        self.file_menu.addSeparator()
        self.file_menu.addAction(QAction("Exit", self, triggered=self.close))
        
        # Create the edit menu
        self.edit_menu = self.menu_bar.addMenu("&Edit")
        
        # Add actions to the edit menu
        self.edit_menu.addAction(self.undo_action)
        self.edit_menu.addAction(self.redo_action)
        self.edit_menu.addSeparator()
        self.edit_menu.addAction(self.search_action)
        self.edit_menu.addAction(self.goto_action)
        
        # Create the view menu
        self.view_menu = self.menu_bar.addMenu("&View")
        
        # Create the hex view action
        self.hex_view_action = QAction("Hex View", self, checkable=True)
        self.hex_view_action.setChecked(True)
        self.view_menu.addAction(self.hex_view_action)
        
        # Create the ASCII view action
        self.ascii_view_action = QAction("ASCII View", self, checkable=True)
        self.ascii_view_action.setChecked(True)
        self.view_menu.addAction(self.ascii_view_action)
        
        # Create the dark mode action
        self.dark_mode_action = QAction("Dark Mode", self, checkable=True)
        self.dark_mode_action.setChecked(True)
        self.dark_mode_action.triggered.connect(self.toggle_dark_mode)
        self.view_menu.addAction(self.dark_mode_action)
        
        self.view_menu.addSeparator()
        
        # Add dock widget visibility actions
        self.view_menu.addAction(self.disassembly_dock.toggleViewAction())
        self.view_menu.addAction(self.pseudocode_dock.toggleViewAction())
        self.view_menu.addAction(self.text_inspector_dock.toggleViewAction())
        self.view_menu.addAction(self.symbols_dock.toggleViewAction())
        self.view_menu.addAction(self.bookmarks_dock.toggleViewAction())
        self.view_menu.addAction(self.search_results_dock.toggleViewAction())
        self.view_menu.addAction(self.file_structure_dock.toggleViewAction())
        if hasattr(self, "binary_inspector_dock"):
            self.view_menu.addAction(self.binary_inspector_dock.toggleViewAction())
        
        # Create the extract menu
        self.extract_menu = self.menu_bar.addMenu("&Extract")
        
        # Create the extract all action
        self.extract_all_action = QAction("Extract All...", self)
        self.extract_all_action.setStatusTip("Extract all available sections and data")
        self.extract_menu.addAction(self.extract_all_action)
        
        # Create the tools menu
        self.tools_menu = self.menu_bar.addMenu("&Tools")
        
        # Add actions to the tools menu
        self.tools_menu.addAction(self.disassemble_action)
        
        self.binary_snapshot_action = QAction("Binary Snapshot…", self)
        self.binary_snapshot_action.setStatusTip("View runtime snapshot, investigation runs, and export workspace")
        self.tools_menu.addAction(self.binary_snapshot_action)
        self.show_scope_on_hex_action = QAction("Show Scope Evidence on Hex", self)
        self.show_scope_on_hex_action.setStatusTip("Paint scope-evidence ranges on the hex view")
        self.tools_menu.addAction(self.show_scope_on_hex_action)
        self.show_record_family_on_hex_action = QAction("Show Record Family on Hex", self)
        self.show_record_family_on_hex_action.setStatusTip("Paint record-family training and holdout ranges on the hex view")
        self.tools_menu.addAction(self.show_record_family_on_hex_action)
        self.verify_candidate_lineage_action = QAction("Verify Candidate Lineage", self)
        self.verify_candidate_lineage_action.setStatusTip("Verify cross-rail candidate hashes and upstream run linkage")
        self.tools_menu.addAction(self.verify_candidate_lineage_action)
        
        # Add PTX-specific actions to the Tools menu
        self.decrypt_action = QAction("Decrypt PTX File", self)
        self.decrypt_action.setStatusTip("Decrypt the current PTX file")
        
        self.extract_ptx_action = QAction("Extract PTX Sections", self)
        self.extract_ptx_action.setStatusTip("Extract sections from the current PTX file")
        
        self.export_ptx_json_action = QAction("Export PTX as JSON", self)
        self.export_ptx_json_action.setStatusTip("Export PTX file analysis as JSON")
        
        # Initially disable PTX-specific actions
        self.decrypt_action.setEnabled(False)
        self.extract_ptx_action.setEnabled(False)
        self.export_ptx_json_action.setEnabled(False)
        
        # Add to Tools menu
        self.tools_menu.addSeparator()
        self.tools_menu.addAction(self.decrypt_action)
        self.tools_menu.addAction(self.extract_ptx_action)
        self.tools_menu.addAction(self.export_ptx_json_action)
        
        # Create the help menu
        self.help_menu = self.menu_bar.addMenu("&Help")
        
        # Create the about action
        self.about_action = QAction("About", self)
        self.help_menu.addAction(self.about_action)
        
        logger.debug("Menu bar created")

    def toggle_dark_mode(self, enabled=None):
        """
        Toggle dark mode.
        
        Args:
            enabled: Whether to enable dark mode. If None, toggle the current mode.
        """
        if enabled is None:
            enabled = not self.dark_mode_enabled
        
        self.dark_mode_enabled = enabled
        
        if enabled:
            logger.info("Enabling dark mode")
            self.set_dark_palette()
        else:
            logger.info("Disabling dark mode")
            QApplication.setPalette(QApplication.style().standardPalette())
            QApplication.instance().setStyleSheet("")
        
        # Update dark mode action if it exists
        if hasattr(self, 'dark_mode_action'):
            self.dark_mode_action.setChecked(enabled)

    def set_dark_palette(self):
        """Set the application palette to dark mode."""
        dark_palette = QPalette()
        
        # Base colors
        dark_color = QColor(45, 45, 45)
        disabled_color = QColor(127, 127, 127)
        text_color = QColor(210, 210, 210)
        highlight_color = QColor(42, 130, 218)
        highlight_text_color = QColor(0, 0, 0)
        link_color = QColor(42, 130, 218)
        
        # Set colors for different color roles
        dark_palette.setColor(QPalette.Window, dark_color)
        dark_palette.setColor(QPalette.WindowText, text_color)
        dark_palette.setColor(QPalette.Base, QColor(18, 18, 18))
        dark_palette.setColor(QPalette.AlternateBase, dark_color)
        dark_palette.setColor(QPalette.ToolTipBase, text_color)
        dark_palette.setColor(QPalette.ToolTipText, text_color)
        dark_palette.setColor(QPalette.Text, text_color)
        dark_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_color)
        dark_palette.setColor(QPalette.Button, dark_color)
        dark_palette.setColor(QPalette.ButtonText, text_color)
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_color)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, link_color)
        dark_palette.setColor(QPalette.Highlight, highlight_color)
        dark_palette.setColor(QPalette.HighlightedText, highlight_text_color)
        dark_palette.setColor(QPalette.Disabled, QPalette.HighlightedText, disabled_color)
        
        # Apply the palette
        QApplication.setPalette(dark_palette)
        QApplication.instance().setStyleSheet(
            """
            QMainWindow, QWidget, QDialog { background-color: #242424; color: #e6e6e6; }
            QMenuBar { background-color: #242424; color: #e6e6e6; border-bottom: 1px solid #4a4a4a; }
            QMenuBar::item { background: transparent; padding: 4px 8px; }
            QMenuBar::item:selected { background-color: #3d3d3d; }
            QMenu { background-color: #2d2d2d; color: #e6e6e6; border: 1px solid #555555; }
            QMenu::item:selected { background-color: #2a82da; color: #ffffff; }
            QToolBar, QStatusBar { background-color: #282828; color: #e6e6e6; border-color: #4a4a4a; }
            QDockWidget { color: #e6e6e6; }
            QDockWidget::title { background-color: #292929; padding: 5px; border-bottom: 1px solid #444444; }
            QTabWidget::pane { border: 1px solid #555555; background-color: #1d1d1d; }
            QTabBar::tab { background-color: #333333; color: #dcdcdc; border: 1px solid #555555; padding: 5px 10px; }
            QTabBar::tab:selected { background-color: #242424; color: #ffffff; border-bottom-color: #242424; }
            QTabBar::tab:hover { background-color: #414141; }
            QTabBar::tab:disabled { background-color: #292929; color: #858585; }
            QTableWidget, QTreeWidget, QListWidget, QTextEdit, QPlainTextEdit, QLineEdit,
            QComboBox, QSpinBox { background-color: #121212; color: #e6e6e6; border: 1px solid #555555; selection-background-color: #2a82da; selection-color: #ffffff; }
            QHeaderView::section { background-color: #333333; color: #f0f0f0; border: 0; border-right: 1px solid #555555; border-bottom: 1px solid #555555; padding: 5px; }
            QTableCornerButton::section { background-color: #333333; border: 1px solid #555555; }
            QPushButton { background-color: #383838; color: #ededed; border: 1px solid #606060; border-radius: 3px; padding: 4px 10px; }
            QPushButton:hover { background-color: #474747; border-color: #777777; }
            QPushButton:pressed { background-color: #202020; }
            QPushButton:disabled { background-color: #2b2b2b; color: #8f8f8f; border-color: #484848; }
            QComboBox::drop-down, QSpinBox::up-button, QSpinBox::down-button { background-color: #383838; border-left: 1px solid #555555; }
            QGroupBox { color: #e6e6e6; border: 1px solid #555555; border-radius: 3px; margin-top: 8px; padding-top: 8px; }
            QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
            QToolTip { background-color: #f0f0f0; color: #111111; border: 1px solid #777777; }
            QScrollBar:vertical, QScrollBar:horizontal { background-color: #202020; }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background-color: #565656; min-width: 18px; min-height: 18px; }
            QScrollBar::add-line, QScrollBar::sub-line { background: none; border: none; }
            """
        )

    def show_file_dialog(self, title, file_filter="All Files (*)"):
        """
        Show a file open dialog.
        
        Args:
            title: The title of the dialog
            file_filter: The file filter to use
            
        Returns:
            The selected file path, or None if the dialog was cancelled
        """
        logger.debug(f"Showing file dialog: {title}")
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", file_filter)
        if file_path:
            logger.info(f"Selected file: {file_path}")
            return file_path
        return None

    def show_save_dialog(self, title, suggested_path="", file_filter="All Files (*)"):
        """
        Show a file save dialog.
        
        Args:
            title: The title of the dialog
            suggested_path: Initial destination path shown to the user
            file_filter: The file filter to use
            
        Returns:
            The selected file path, or None if the dialog was cancelled
        """
        logger.debug(f"Showing save dialog: {title}")
        file_path, _ = QFileDialog.getSaveFileName(self, title, suggested_path, file_filter)
        if file_path:
            logger.info(f"Selected save path: {file_path}")
            return file_path
        return None

    def show_input_dialog(self, title, label, default=""):
        """
        Show an input dialog.
        
        Args:
            title: The title of the dialog
            label: The label text
            default: The default text
            
        Returns:
            The entered text, or None if the dialog was cancelled
        """
        logger.debug(f"Showing input dialog: {title}")
        text, ok = QInputDialog.getText(self, title, label, QLineEdit.Normal, default)
        if ok and text:
            logger.debug(f"Input dialog result: {text}")
            return text
        return None

    def show_message(self, title, message, icon=QMessageBox.Information):
        """
        Show a message box.
        
        Args:
            title: The title of the message box
            message: The message text
            icon: The message box icon
        """
        logger.debug(f"Showing message: {message}")
        dialog = QMessageBox(self)
        dialog.setIcon(icon)
        dialog.setWindowTitle(title)
        dialog.setText(message)
        dialog.setStandardButtons(QMessageBox.Ok)
        dialog.exec_()

    def update_status_message(self, message: str):
        """Update the status message."""
        self.status_message.setText(message)
        # Auto-clear the message after a delay
        QTimer.singleShot(5000, lambda: self.status_message.clear())
    
    def update_status_bar(self, offset: int, file_size: int, selection: Optional[Tuple[int, int]] = None):
        """
        Update the status bar with current information.
        
        Args:
            offset: Current byte offset
            file_size: Size of the file
            selection: Tuple of (start, end) offsets for selection, or None
        """
        # Update position
        self.position_label.setText(f"Position: 0x{offset:08X}")
        
        # Update file size
        if file_size > 1024 * 1024:
            size_str = f"{file_size / (1024 * 1024):.2f} MB"
        elif file_size > 1024:
            size_str = f"{file_size / 1024:.2f} KB"
        else:
            size_str = f"{file_size} bytes"
        
        self.file_size_label.setText(f"File Size: {size_str}")
        
        # Update selection
        if selection:
            start, end = selection
            selection_size = end - start
            
            if selection_size > 1024 * 1024:
                sel_str = f"{selection_size / (1024 * 1024):.2f} MB"
            elif selection_size > 1024:
                sel_str = f"{selection_size / 1024:.2f} KB"
            else:
                sel_str = f"{selection_size} bytes"
            
            self.selection_label.setText(f"Selection: {sel_str}")
        else:
            self.selection_label.setText("Selection: 0 bytes")

    def set_forensic_knowledge_metrics(self, text: str) -> None:
        """Show disjoint byte-knowledge percentages from compiled artifacts."""
        self.knowledge_metrics_label.setText(text or "")

    def load_settings(self):
        """
        Load application settings.
        
        Returns:
            The list of recent files
        """
        logger.debug("Loading settings")
        from src.services.desktop_layout import load_dark_mode, load_recent_files
        from src.services.ui_policy import load_ui_policy

        policy = load_ui_policy()
        recent_files = load_recent_files(policy)
        dark_mode = load_dark_mode(policy, default=True)
        self.toggle_dark_mode(dark_mode)
        logger.debug(f"Settings loaded. Recent files: {recent_files}")
        return recent_files

    def save_settings(self, recent_files):
        """
        Save application settings.
        
        Args:
            recent_files: The list of recent files
        """
        logger.debug("Saving settings")
        self.flush_layout_save(recent_files=list(recent_files or []))
        logger.debug("Settings saved")

    def show_ptx_view(self, visible=True):
        """
        Enable PTX-specific actions without forcing dock visibility.
        
        Args:
            visible: Whether PTX menu actions should be enabled
        """
        self.decrypt_action.setEnabled(visible)
        self.extract_ptx_action.setEnabled(visible)
        self.export_ptx_json_action.setEnabled(visible)

    def enable_ptx_menu(self, enabled: bool):
        """
        Enable or disable PTX-specific menu items.
        
        Args:
            enabled: Whether to enable or disable the items
        """
        # Make sure the PTX menu exists
        if not hasattr(self, 'ptx_menu'):
            self.create_ptx_menu()
        
        # Set enabled state for all actions in the menu
        for action in self.ptx_menu.actions():
            action.setEnabled(enabled)
    
    def create_ptx_menu(self):
        """Create the PTX menu in the main menu bar."""
        # Create the PTX menu
        self.ptx_menu = self.menuBar().addMenu("PTX")
        
        # Create decrypt action
        self.decrypt_action = QAction("Decrypt PTX File", self)
        self.decrypt_action.setStatusTip("Decrypt an encrypted PTX file")
        self.decrypt_action.triggered.connect(self.decrypt_ptx_signal.emit)
        self.ptx_menu.addAction(self.decrypt_action)
        
        # Create extract action
        self.extract_ptx_action = QAction("Extract PTX Sections", self)
        self.extract_ptx_action.setStatusTip("Extract sections from a PTX file")
        self.extract_ptx_action.triggered.connect(self.extract_ptx_signal.emit)
        self.ptx_menu.addAction(self.extract_ptx_action)
        
        # Create export action
        self.export_ptx_json_action = QAction("Export PTX Analysis", self)
        self.export_ptx_json_action.setStatusTip("Export PTX file analysis as JSON")
        self.export_ptx_json_action.triggered.connect(self.export_ptx_json_signal.emit)
        self.ptx_menu.addAction(self.export_ptx_json_action)
        
        self.ptx_menu.addSeparator()
        
        # Create timecode navigation actions
        self.next_tc_action = QAction("Next Timecode", self)
        self.next_tc_action.setStatusTip("Navigate to the next timecode")
        self.next_tc_action.setShortcut("Ctrl+Right")
        self.next_tc_action.triggered.connect(self.next_timecode_signal.emit)
        self.ptx_menu.addAction(self.next_tc_action)
        
        self.prev_tc_action = QAction("Previous Timecode", self)
        self.prev_tc_action.setStatusTip("Navigate to the previous timecode")
        self.prev_tc_action.setShortcut("Ctrl+Left")
        self.prev_tc_action.triggered.connect(self.prev_timecode_signal.emit)
        self.ptx_menu.addAction(self.prev_tc_action)
        
        self.goto_tc_action = QAction("Go to Timecode Reference...", self)
        self.goto_tc_action.setStatusTip("Navigate to a specific timecode reference point")
        self.goto_tc_action.setShortcut("Ctrl+T")
        self.goto_tc_action.triggered.connect(self.goto_timecode_signal.emit)
        self.ptx_menu.addAction(self.goto_tc_action)
        
        # Disable all actions initially
        self.enable_ptx_menu(False) 
