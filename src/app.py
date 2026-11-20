"""
Main application module for the HexEditor application.
"""
import sys
import os
import logging
import traceback
from typing import List, Optional, Dict, Any, Mapping
from pathlib import Path
import datetime
import json

from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QInputDialog, QFileDialog, QListWidgetItem, QMenu, QAction
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QSettings, pyqtSlot, QSize, QTimer

from src.ui import HexEditorMainWindow
from src.hex_editor import HexEditor
from src.search import SearchWorker, SearchHighlighter, SearchResult, classify_search_query
from src.disassembler import DisassemblerWorker
from src.extractor import BinaryExtractor
from src.ptx_handler import PTXFile, detect_file_type
from src.services.path_utils import normalize_input_path
from src.logging_config import get_logger
from src.utils import setup_logging, exception_hook
from src.snapshot_run_catalog import list_investigation_runs, list_runs_for_source
from src.snapshot_worker import ForensicContextWorker, SnapshotAnalysisWorker

# Get a logger for this module
logger = get_logger('app')

class HexEditorApp:
    """Main application class for the HexEditor."""
    
    def __init__(self):
        """Initialize the application."""
        logger.info("Initializing HexEditorApp")
        
        # Set up exception handling
        sys.excepthook = exception_hook
        
        # Create the main window
        self.main_window = HexEditorMainWindow()
        
        # Create the hex editor
        self.hex_editor = HexEditor(self.main_window.hex_editor)
        
        # Set up the UI
        self.setup_ui()
        
        # Connect signals and slots
        self.connect_signals()
        
        # Load application state
        self.load_app_state()
        
        # Initialize search-related variables
        self.search_thread = None
        self.search_worker = None
        self.search_results = []
        self.current_search_index = -1
        from src.services.ui_policy import load_ui_policy

        self.search_highlighter = SearchHighlighter(
            self.main_window.hex_editor.document(),
            text_edit=self.main_window.hex_editor,
        )
        self.search_highlighter.configure_viewport(
            policy=self.hex_editor.ui_policy or load_ui_policy(),
        )
        self.hex_editor.register_document_highlighter(self.search_highlighter)
        
        # Initialize disassembly-related variables
        self.disassembly_thread = None
        self.disassembly_worker = None

        self._snapshot_thread = None
        self._snapshot_worker = None
        self._forensic_thread = None
        self._forensic_worker = None
        
        # Initialize extractor
        self.extractor = None
        
        # Initialize file handler
        self.file_handler = None
        self.lab_bridge = None
        self.lab_bridge_root = None
        from src.snapshot_controller import SnapshotController
        from src.transform_preview_controller import TransformPreviewController

        self.snapshot_controller = SnapshotController()
        self.transform_preview_controller = TransformPreviewController()
        self._recent_files: List[str] = []
        
        logger.info("HexEditorApp initialized")

    def setup_ui(self):
        """Set up the user interface."""
        # Create dock widgets
        self.main_window.create_dock_widgets()
        
        # Create toolbar
        self.main_window.create_toolbar()
        
        # Create menu bar
        self.main_window.create_menu_bar()

        from src.services.ui_policy import load_ui_policy

        self.main_window.install_layout_persistence(load_ui_policy())
        
        # Connect UI actions
        self.main_window.open_action.triggered.connect(self.load_file)
        self.main_window.save_action.triggered.connect(self.save_file)
        self.main_window.undo_action.triggered.connect(self.hex_editor.undo)
        self.main_window.redo_action.triggered.connect(self.hex_editor.redo)
        self.main_window.search_action.triggered.connect(self.search)
        self.main_window.goto_action.triggered.connect(self.goto_offset)
        self.main_window.disassemble_action.triggered.connect(self.disassemble)
        self.main_window.hex_view_action.triggered.connect(self.toggle_hex_view)
        self.main_window.ascii_view_action.triggered.connect(self.toggle_ascii_view)
        self.main_window.about_action.triggered.connect(self.show_about)
        self._forensic_results_widget = None
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy
        forensic_ui = load_pseudocode_navigation_policy()["forensic_navigation"]
        forensic_action = QAction(forensic_ui["dock_title"], self.main_window)
        forensic_action.triggered.connect(self.show_forensic_results)
        self.main_window.menuBar().addAction(forensic_action)
        from src.services.browser_forensics.private_recovery import recovery_policy
        private_action = QAction(recovery_policy()["open_action"], self.main_window)
        private_action.triggered.connect(self.show_private_recovery)
        self.main_window.menuBar().addAction(private_action)
        
        # Connect extraction action
        self.main_window.extract_all_action.triggered.connect(self.extract_all)
        
        # Connect list widgets
        self.main_window.bookmarks_widget.itemClicked.connect(self.navigate_bookmark)
        self.main_window.symbols_widget.itemClicked.connect(self.navigate_symbol)
        self.main_window.search_results_widget.itemClicked.connect(self.navigate_search_result)
        
        # Set up context menu for hex editor
        self.main_window.hex_editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.main_window.hex_editor.customContextMenuRequested.connect(self.show_context_menu)

    def connect_signals(self):
        """Connect signals and slots."""
        logger.debug("Connecting signals and slots")
        
        # Connect hex editor signals — queued so load_file returns before heavy UI work.
        self.hex_editor.file_loaded.connect(self.handle_file_loaded, Qt.QueuedConnection)
        self.hex_editor.file_saved.connect(self.handle_file_saved)
        self.hex_editor.file_changed.connect(self.handle_file_changed)
        self.hex_editor.error_occurred.connect(self.handle_error)
        
        # Connect cursor position change signal
        self.main_window.hex_editor.cursorPositionChanged.connect(self.update_status_bar)

        if hasattr(self.main_window, "text_inspector_widget"):
            self.main_window.text_inspector_widget.set_refresh_callback(
                self.refresh_text_inspector
            )
            self.main_window.text_inspector_widget.set_goto_source_callback(
                self.goto_offset_from_signal
            )
            self.main_window.text_inspector_widget.set_export_full_file_callback(
                self.export_transform_preview_full_file
            )
            self.main_window.text_inspector_widget.set_async_preview_request(
                self._request_async_transform_preview
            )

        if hasattr(self.main_window, "binary_inspector_widget"):
            self.main_window.binary_inspector_widget.goto_offset_signal.connect(
                self.goto_offset_from_signal
            )
            self.main_window.binary_inspector_widget.analyze_requested.connect(
                self.analyze_current_binary
            )
            self.main_window.binary_inspector_dock.visibilityChanged.connect(
                self._on_binary_inspector_visibility_changed
            )
        if hasattr(self.main_window, "pseudocode_dock"):
            self.main_window.pseudocode_dock.visibilityChanged.connect(
                self._on_pseudocode_visibility_changed
            )
        self._pseudocode_source_map = []
        self._pseudocode_source_map_error = ""
        self._pseudocode_navigation_generation: Dict[str, Any] = {}
        self._nav_sync_in_progress = False
        self._nav_suppress_hex_to_pseudo = False
        self._pseudocode_to_hex_timer = QTimer()
        self._pseudocode_to_hex_timer.setSingleShot(True)
        self._pseudocode_to_hex_timer.timeout.connect(self._sync_pseudocode_to_hex)
        self._hex_to_pseudocode_timer = QTimer()
        self._hex_to_pseudocode_timer.setSingleShot(True)
        self._hex_to_pseudocode_timer.timeout.connect(self._sync_hex_to_pseudocode)
        if hasattr(self.main_window, "pseudocode_text"):
            self.main_window.pseudocode_text.cursorPositionChanged.connect(self._schedule_pseudocode_to_hex)
            self.main_window.pseudocode_text.selectionChanged.connect(self._schedule_pseudocode_to_hex)
        self.main_window.hex_editor.cursorPositionChanged.connect(self._schedule_hex_to_pseudocode)
        
        # Connect PTX-specific signals
        self.main_window.goto_offset_signal.connect(self.goto_offset_from_signal)
        self.main_window.decrypt_ptx_signal.connect(self.decrypt_ptx_file)
        self.main_window.extract_ptx_signal.connect(self.extract_ptx_sections)
        self.main_window.export_ptx_json_signal.connect(self.export_ptx_json)
        self.hex_editor.timecodes_found.connect(self.handle_timecodes_found, Qt.QueuedConnection)

        if hasattr(self.main_window, "next_timecode_signal"):
            self.main_window.next_timecode_signal.connect(self.goto_next_timecode)
        if hasattr(self.main_window, "prev_timecode_signal"):
            self.main_window.prev_timecode_signal.connect(self.goto_prev_timecode)
        if hasattr(self.main_window, "goto_timecode_signal"):
            self.main_window.goto_timecode_signal.connect(self.goto_timecode_reference)

        self._current_timecode_index = -1
        self._forensic_context: Dict[str, Any] = {}
        self._forensic_generation = 0
        self._pending_forensic_timer = QTimer()
        self._pending_forensic_timer.setSingleShot(True)
        self._pending_forensic_timer.timeout.connect(self._apply_deferred_forensic_context)
        self._text_inspector_timer = QTimer()
        self._text_inspector_timer.setSingleShot(True)
        self._text_inspector_timer.timeout.connect(self.refresh_text_inspector)
        self._text_inspector_debounce_ms = 250
        try:
            from src.services.ui_policy import load_budget, load_ui_policy

            self._text_inspector_debounce_ms = load_budget(load_ui_policy(), "text_inspector_debounce_ms")
        except Exception:
            pass
        
        # Connect decrypt action
        if hasattr(self.main_window, 'decrypt_action'):
            self.main_window.decrypt_action.triggered.connect(self.decrypt_file)
        
        # Connect PTX-specific actions
        if hasattr(self.main_window, 'extract_ptx_action'):
            self.main_window.extract_ptx_action.triggered.connect(self.extract_ptx_sections)
        
        if hasattr(self.main_window, 'export_ptx_json_action'):
            self.main_window.export_ptx_json_action.triggered.connect(self.export_ptx_json)

        if hasattr(self.main_window, 'binary_snapshot_action'):
            self.main_window.binary_snapshot_action.triggered.connect(self.show_binary_snapshot_dialog)
        if hasattr(self.main_window, 'show_scope_on_hex_action'):
            self.main_window.show_scope_on_hex_action.triggered.connect(self.show_scope_evidence_on_hex)
        if hasattr(self.main_window, 'show_record_family_on_hex_action'):
            self.main_window.show_record_family_on_hex_action.triggered.connect(self.show_record_family_on_hex)
        if hasattr(self.main_window, 'verify_candidate_lineage_action'):
            self.main_window.verify_candidate_lineage_action.triggered.connect(self.verify_candidate_lineage)
        logger.debug("Signals and slots connected")

    def enable_lab_bridge(self, runtime_root: str) -> None:
        """Watch optional external inbox commands (UVE/MCP host) and apply them in the desktop editor."""
        from src.lab_bridge import LabCommandBridge

        self.lab_bridge_root = runtime_root
        self.lab_bridge = LabCommandBridge(runtime_root, parent=self.main_window)
        self.lab_bridge.command_received.connect(self._handle_lab_command)
        logger.info("Lab command bridge enabled at %s", runtime_root)

    def _handle_lab_command(self, command: Dict[str, Any]) -> None:
        action = str(command.get("action") or "").strip().lower()
        path = str(command.get("path") or "").strip()
        try:
            if action == "forensic_finding":
                from hexeditor_tools.api import binary_forensic_resolve
                payload = dict(command["payload"])
                claimed = payload.pop("mapping_digest")
                resolved = binary_forensic_resolve(**payload)
                if claimed != resolved["mapping_digest"]:
                    raise ValueError("mapping_digest_mismatch")
                self._apply_forensic_selection(resolved)
                if self.lab_bridge is not None:
                    self.lab_bridge.acknowledge(command, ok=True, detail=resolved["mapping_precision"])
                return
            if action == "open" and path:
                self.load_file(path)
                if self.lab_bridge is not None:
                    self.lab_bridge.acknowledge(command, ok=True, detail="file_opened")
                return
            if action == "reload" and path:
                self.load_file(path)
                offset = command.get("offset")
                if offset is not None:
                    self.hex_editor.goto_offset(int(offset))
                if self.lab_bridge is not None:
                    self.lab_bridge.acknowledge(command, ok=True, detail="file_reloaded")
                return
            if action == "goto" and path:
                current = normalize_input_path(self.hex_editor.file_path or "")
                target = normalize_input_path(path)
                if current != target:
                    self.load_file(target)
                offset = command.get("offset")
                if offset is not None:
                    self.hex_editor.goto_offset(int(offset))
                if self.lab_bridge is not None:
                    self.lab_bridge.acknowledge(command, ok=True, detail="cursor_moved")
                return
            if self.lab_bridge is not None:
                self.lab_bridge.acknowledge(command, ok=False, detail=f"unsupported_action:{action or 'missing'}")
        except Exception as exc:
            logger.error("Lab command failed: %s", exc, exc_info=True)
            if self.lab_bridge is not None:
                self.lab_bridge.acknowledge(command, ok=False, detail=str(exc))

    def load_app_state(self):
        """Load application state from settings."""
        logger.debug("Loading application state")
        self._recent_files = list(self.main_window.load_settings() or [])
        logger.debug(f"Application state loaded with {len(self._recent_files)} recent files")

    def show_forensic_results(self):
        if self._forensic_results_widget is None:
            from PyQt5.QtWidgets import QDockWidget
            from src.forensic_results_widget import ForensicResultsWidget
            from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy
            ui = load_pseudocode_navigation_policy()["forensic_navigation"]
            dock = QDockWidget(ui["dock_title"], self.main_window)
            self._forensic_results_widget = ForensicResultsWidget(dock)
            self._forensic_results_widget.selection_resolved.connect(self._apply_forensic_selection)
            dock.setWidget(self._forensic_results_widget)
            self.main_window.addDockWidget(Qt.RightDockWidgetArea, dock)
            self._forensic_results_dock = dock
        self._forensic_results_dock.show()

    def show_private_recovery(self):
        from src.services.browser_forensics.private_recovery import recovery_policy
        from src.services.browser_forensics.common import read_json
        from hexeditor_tools.api import _forensic_root
        from src.private_recovery_viewer import create_private_viewer
        config = recovery_policy()
        folder = QFileDialog.getExistingDirectory(self.main_window, config["open_action"])
        if not folder:
            return
        try:
            root = _forensic_root(folder)
            summary = read_json(root/"summary.json")
            self._private_recovery_dialog = create_private_viewer(root, summary["case_id"], self.main_window)
            self._private_recovery_dialog.showMaximized()
        except (OSError, ValueError, RuntimeError, KeyError):
            QMessageBox.warning(self.main_window, config["open_action"], config["open_failed"])

    def _apply_forensic_selection(self, resolved):
        ranges = resolved.get("ranges", [])
        if not ranges:
            return
        target = ranges[0]["path"]
        if normalize_input_path(self.hex_editor.file_path or "") != normalize_input_path(target):
            self.load_file(target)
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy
        ui = load_pseudocode_navigation_policy()["forensic_navigation"]
        selected = [{"file_offset": r["offset"], "offset": r["offset"], "length": r["length"]}
                    for r in ranges if r["path"] == target]
        self.hex_editor.highlight_pseudocode_navigation_ranges(selected, theme_token=ui["theme_token"])
        self.hex_editor.goto_offset(selected[0]["offset"], focus=False)
        self.main_window.statusBar().showMessage(resolved["mapping_precision"])

    def save_app_state(self):
        """Save application state to settings."""
        logger.debug("Saving application state")
        self.main_window.save_settings(self._recent_files)
        logger.debug("Application state saved")

    def _remember_recent_file(self, file_path: str) -> None:
        normalized = normalize_input_path(file_path)
        self._recent_files = [item for item in self._recent_files if item != normalized]
        self._recent_files.insert(0, normalized)

    def load_file(self, file_path=None):
        """Load a file into the hex editor."""
        if isinstance(file_path, bool):
            file_path = None
        if not file_path:
            logger.info("Opening file dialog")
            file_filter = "All Files (*);; PTX Files (*.ptx);; PE Files (*.exe *.dll)"
            file_path = self.main_window.show_file_dialog("Open File", file_filter)
        if not file_path:
            logger.debug("File dialog canceled")
            return

        file_path = normalize_input_path(file_path)
            
        logger.info(f"Loading file: {file_path}")

        self.file_handler = self._resolve_file_handler(file_path)

        self.main_window.set_layout_autosave_suspended(True)
        try:
            self.hex_editor.load_file(file_path)
        finally:
            QTimer.singleShot(0, lambda: self.main_window.set_layout_autosave_suspended(False))
        
        QTimer.singleShot(0, lambda: self._deferred_post_load(file_path))
        
        logger.info(f"File loaded: {file_path}")

    def _deferred_post_load(self, file_path: str) -> None:
        """Initialize lightweight helpers after the hex view is visible."""
        try:
            self.extractor = BinaryExtractor(file_path)
        except Exception as exc:
            logger.warning("Binary extractor unavailable: %s", exc)
            self.extractor = None

    def save_file(self):
        """Save the current file."""
        if not self.hex_editor.file_path:
            logger.info("No file loaded, showing save dialog")
            file_path = self.main_window.show_save_dialog("Save File")
            if not file_path:
                logger.debug("Save dialog canceled")
                return
        else:
            file_path = self.hex_editor.file_path
            logger.info(f"Saving file: {file_path}")
        
        self.hex_editor.save_file(file_path)
        
        # Reinitialize the extractor and file handler with the saved file
        self.extractor = BinaryExtractor(file_path)
        self.file_handler = detect_file_type(file_path)
        
        # Update the file structure
        self.update_file_structure()
        
        logger.info(f"File saved: {file_path}")

    def update_file_structure(self):
        """Update the file structure view based on the file type."""

        def apply_update() -> None:
            from src.services.file_structure_presenter import (
                cached_source_summary,
                knowledge_metrics_items,
                preserved_binary_items,
                ptx_handler_items,
                record_family_items,
            )
            from src.services.local_transform.core import _load_bundle as load_local_transform_bundle

            logger.info("Updating file structure view")
            self.main_window.file_structure_widget.clear()
            preview_limit = int(load_local_transform_bundle()["policy"]["scan"]["maximum_preview_bytes"])
            source_sha = ""
            if self.hex_editor.file_path:
                try:
                    import hashlib

                    source_sha = hashlib.sha256(Path(self.hex_editor.file_path).read_bytes()).hexdigest()
                except OSError:
                    source_sha = ""

            for label, _offset in cached_source_summary(source_sha):
                self.main_window.file_structure_widget.addItem(label)

            if self.file_handler:
                for label, offset in ptx_handler_items(self.file_handler, preview_limit=preview_limit):
                    item = QListWidgetItem(label)
                    if offset is not None:
                        item.setData(Qt.UserRole, offset)
                    self.main_window.file_structure_widget.addItem(item)
            else:
                self.main_window.file_structure_widget.addItem("No structure information available for this file type")

            for label, offset in record_family_items(source_sha):
                item = QListWidgetItem(label)
                if offset is not None:
                    item.setData(Qt.UserRole, offset)
                self.main_window.file_structure_widget.addItem(item)

            for label, offset in preserved_binary_items(source_sha):
                item = QListWidgetItem(label)
                if offset is not None:
                    item.setData(Qt.UserRole, offset)
                self.main_window.file_structure_widget.addItem(item)

            for label, offset in knowledge_metrics_items(source_sha):
                item = QListWidgetItem(label)
                if offset is not None:
                    item.setData(Qt.UserRole, offset)
                self.main_window.file_structure_widget.addItem(item)

            self._refresh_knowledge_metrics_status(source_sha)

            self.main_window.file_structure_widget.addItem("File Properties:")
            self.main_window.file_structure_widget.addItem(f"Size: {self.hex_editor.file_size} bytes")
            self.main_window.file_structure_widget.addItem(f"Path: {self.hex_editor.file_path}")

        self.main_window.deliver_dock_update("file_structure_dock", apply_update)

    def decrypt_file(self):
        """Decrypt the current file."""
        if not self.hex_editor.file_path:
            self.handle_error("No file loaded")
            return
            
        # If this is a PTX file, use the PTX-specific decryption
        if isinstance(self.file_handler, PTXFile):
            self.decrypt_ptx_file()
            return
        
        # Generic decryption for other file types
        # ... existing code ...

    def decrypt_ptx_file(self):
        """Decrypt a PTX file."""
        if not self.hex_editor.file_path or not isinstance(self.file_handler, PTXFile):
            self.handle_error("No PTX file loaded")
            return
            
        if not self.file_handler.header or not self.file_handler.header.is_encrypted():
            self.handle_error("File is not encrypted or has an unknown encryption type")
            return
            
        # Ask for confirmation
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setWindowTitle("Decrypt PTX File")
        msg_box.setText(f"Decrypt {os.path.basename(self.hex_editor.file_path)}?")
        msg_box.setInformativeText("This will create a new decrypted file.")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg_box.setDefaultButton(QMessageBox.Yes)
        
        if msg_box.exec_() != QMessageBox.Yes:
            return
            
        # Get the output path
        output_path = self.main_window.show_save_dialog("Save Decrypted File", 
                                                     f"{os.path.splitext(self.hex_editor.file_path)[0]}_decrypted.ptx")
        if not output_path:
            return
            
        # Show progress dialog
        progress_dialog = QMessageBox(self.main_window)
        progress_dialog.setIcon(QMessageBox.Information)
        progress_dialog.setWindowTitle("Decrypting")
        progress_dialog.setText("Decrypting PTX file...")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        QApplication.processEvents()
        
        try:
            from src.services.ptx_desktop_decrypt import decrypt_ptx_with_verified_probe

            result = decrypt_ptx_with_verified_probe(self.hex_editor.file_path, output_path)
            
            progress_dialog.close()
            
            if result.get("ok"):
                # Successfully decrypted
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Information)
                msg_box.setWindowTitle("Decryption Successful")
                msg_box.setText("PTX file decrypted successfully.")
                msg_box.setInformativeText(f"Decrypted file saved to: {output_path}")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Open)
                msg_box.setDefaultButton(QMessageBox.Ok)
                
                if msg_box.exec_() == QMessageBox.Open:
                    # Load the decrypted file
                    self.hex_editor.load_file(output_path)
            else:
                self.handle_error(result.get("error") or "Failed to decrypt PTX file")
                
        except Exception as e:
            progress_dialog.close()
            self.handle_error(f"Error decrypting PTX file: {str(e)}")

    def extract_ptx_sections(self):
        """Extract sections from a PTX file."""
        if not self.hex_editor.file_path or not isinstance(self.file_handler, PTXFile):
            self.handle_error("No PTX file loaded")
            return
            
        if not self.file_handler.sections:
            self.handle_error("No sections found in PTX file")
            return
            
        # Ask for output directory
        output_dir = QFileDialog.getExistingDirectory(self.main_window, "Select Output Directory")
        if not output_dir:
            return
            
        # Show progress dialog
        progress_dialog = QMessageBox(self.main_window)
        progress_dialog.setIcon(QMessageBox.Information)
        progress_dialog.setWindowTitle("Extracting")
        progress_dialog.setText("Extracting PTX sections...")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        QApplication.processEvents()
        
        try:
            # Extract each section
            extracted_files = []
            
            for i, section in enumerate(self.file_handler.sections):
                output_path = os.path.join(output_dir, f"section_{i:04d}.bin")
                result = self.file_handler.extract_section_data(i, output_path)
                
                if result:
                    extracted_files.append(result)
            
            progress_dialog.close()
            
            if extracted_files:
                # Successfully extracted
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Information)
                msg_box.setWindowTitle("Extraction Successful")
                msg_box.setText(f"Extracted {len(extracted_files)} sections to {output_dir}")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Open)
                msg_box.setDefaultButton(QMessageBox.Ok)
                
                if msg_box.exec_() == QMessageBox.Open:
                    # Open the output directory
                    import subprocess
                    import platform
                    
                    if platform.system() == "Windows":
                        os.startfile(output_dir)
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.Popen(["open", output_dir])
                    else:  # Linux
                        subprocess.Popen(["xdg-open", output_dir])
            else:
                # Failed to extract any sections
                self.handle_error("Failed to extract any sections from PTX file")
                
        except Exception as e:
            progress_dialog.close()
            self.handle_error(f"Error extracting PTX sections: {str(e)}")
        
    def export_ptx_json(self):
        """Export PTX file analysis as JSON."""
        if not self.hex_editor.file_path or not isinstance(self.file_handler, PTXFile):
            self.handle_error("No PTX file loaded")
            return
            
        # Ask for output file
        output_path = self.main_window.show_save_dialog(
            "Save JSON Report",
            f"{os.path.splitext(self.hex_editor.file_path)[0]}_report.json",
            "JSON Files (*.json);;All Files (*)",
        )
        if not output_path:
            return
            
        try:
            # Get the summary
            summary = self.file_handler.get_summary()
            
            # Save as JSON
            destination = Path(output_path).expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp")
            try:
                with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                    json.dump(summary, handle, indent=2, ensure_ascii=False, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink()
                
            # Show success message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setWindowTitle("Export Successful")
            msg_box.setText("PTX file analysis exported successfully.")
            msg_box.setInformativeText(f"Report saved to: {output_path}")
            msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Open)
            msg_box.setDefaultButton(QMessageBox.Ok)
            
            if msg_box.exec_() == QMessageBox.Open:
                # Open the JSON file
                import subprocess
                import platform
                
                if platform.system() == "Windows":
                    os.startfile(output_path)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.Popen(["open", output_path])
                else:  # Linux
                    subprocess.Popen(["xdg-open", output_path])
                    
        except Exception as e:
            self.handle_error(f"Error exporting PTX analysis: {str(e)}")
    
    def goto_offset_from_signal(self, offset):
        """Navigate to an offset from a signal."""
        self.goto_offset(offset=offset)
    
    def search(self):
        """Search for a pattern in the hex editor."""
        logger.info("Starting search operation")
        
        # Show search dialog
        search_text = self.main_window.show_input_dialog("Search", "Enter search text:")
        if not search_text:
            logger.debug("Search dialog canceled")
            return
        
        logger.info(f"Searching for: {search_text}")

        stripped_query = search_text.strip()
        if stripped_query.lower().startswith("0x"):
            try:
                offset = int(stripped_query, 16)
            except ValueError:
                self.handle_search_failed("Invalid hexadecimal offset.")
                return
            if self.hex_editor.file_path:
                from src.services.region_routed_pseudocode.address_resolve import resolve_raw_to_file_offset
                from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

                resolved = resolve_raw_to_file_offset(
                    offset,
                    file_size=int(self.hex_editor.file_size or 0),
                    source_path=Path(self.hex_editor.file_path),
                    navigation_policy=load_pseudocode_navigation_policy(),
                )
                if resolved is not None:
                    offset = resolved[0]
            if not self.hex_editor.goto_offset(offset):
                self.handle_search_failed(
                    f"Offset 0x{offset:X} is outside the loaded file."
                )
                return
            logger.info("Search query navigated to offset 0x%X", offset)
            return

        search_type, normalized_query = classify_search_query(stripped_query)
        if not normalized_query:
            self.handle_search_failed("No search value provided.")
            return
        
        # Clean up any existing search thread
        self.cleanup_search_thread()
        
        try:
            # Include unsaved edits, then detach the worker from mutable UI state.
            self.hex_editor._commit_visible_edits()
            search_data = bytes(self.hex_editor.file_data)
        except ValueError as exc:
            self.handle_search_failed(str(exc))
            return

        if not search_data:
            self.handle_search_failed("No file data is loaded.")
            return

        # Search the actual file bytes, not the rendered hex-view document.
        self.search_worker = SearchWorker(
            search_data,
            normalized_query,
            case_sensitive=False,
            whole_words=False,
            search_type=search_type,
            bytes_per_line=self.hex_editor.bytes_per_line,
        )
        
        # Create a new thread for the search worker
        self.search_thread = QThread()
        self.search_worker.moveToThread(self.search_thread)
        
        # Connect signals and slots
        self.search_thread.started.connect(self.search_worker.run)
        self.search_worker.search_finished.connect(self.handle_search_finished)
        self.search_worker.search_failed.connect(self.handle_search_failed)
        self.search_worker.search_finished.connect(self.search_thread.quit)
        self.search_worker.search_failed.connect(self.search_thread.quit)
        self.search_thread.finished.connect(self.cleanup_search_thread)
        
        # Start the search thread
        logger.debug("Starting search thread")
        self.search_thread.start()
        
        # Update the search highlighter
        self.search_highlighter.setSearchText(
            normalized_query if search_type == "text" else ""
        )
        
    def cleanup_search_thread(self):
        """Clean up the search thread and worker."""
        if self.search_thread and self.search_thread.isRunning():
            logger.debug("Cleaning up search thread")
            self.search_worker.stop()
            self.search_thread.quit()
            self.search_thread.wait()
        
        self.search_thread = None
        self.search_worker = None
        
    def handle_search_finished(self, results: List[SearchResult]):
        """
        Handle search completion.
        
        Args:
            results: List of search results
        """
        logger.info(f"Search completed with {len(results)} results")
        self.search_results = results
        self.current_search_index = 0 if results else -1
        
        # Clear the search results widget
        self.main_window.search_results_widget.clear()
        
        # Add the search results to the widget
        for i, result in enumerate(results):
            self.main_window.search_results_widget.addItem(
                f"Result {i+1}: Offset 0x{result.position:08X} - {result.context}"
            )
        
        # Navigate to the first result if any
        if results:
            logger.debug("Navigating to first search result")
            self.navigate_search_result(self.main_window.search_results_widget.item(0))
        else:
            logger.debug("No search results found")
            self.main_window.show_message("Search", "No results found", QMessageBox.Information)
            
    def handle_search_failed(self, error_message: str):
        """
        Handle search failure.
        
        Args:
            error_message: The error message
        """
        logger.error(f"Search failed: {error_message}")
        self.main_window.show_message("Search Error", error_message, QMessageBox.Warning)
        
    def navigate_search_result(self, item):
        """
        Navigate to a search result.
        
        Args:
            item: The selected item in the search results widget
        """
        if not item:
            return
        
        # Get the index of the selected item
        index = self.main_window.search_results_widget.row(item)
        if 0 <= index < len(self.search_results):
            # Get the result
            result = self.search_results[index]
            
            logger.debug(f"Navigating to search result at offset 0x{result.position:08X}")
            # Navigate to the offset
            self.hex_editor.goto_offset(result.position)
            
            # Update the current search index
            self.current_search_index = index

    def handle_file_loaded(self, file_path: str, file_size: int):
        """
        Handle a file being loaded.
        
        Args:
            file_path: Path to the loaded file
            file_size: Size of the loaded file
        """
        logger.info(f"File loaded: {file_path}, size: {file_size}")
        self._remember_recent_file(file_path)
        # Update the window title
        self.main_window.setWindowTitle(f"{os.path.basename(file_path)} - HexEditor")
        
        # Clear any previous search results
        self.main_window.search_results_widget.clear()
        self.search_results = []
        self.current_search_index = -1
        
        # Clear any previous disassembly results
        if hasattr(self.main_window, 'disassembly_text'):
            self.main_window.disassembly_text.clear()
        if hasattr(self.main_window, "pseudocode_text"):
            self.main_window.pseudocode_text.clear()
        self._pseudocode_source_map = []
        self._pseudocode_source_map_error = ""
        self._pseudocode_navigation_generation = {}
        self.hex_editor.clear_pseudocode_navigation_ranges()

        if hasattr(self.main_window, "text_inspector_widget"):
            self.main_window.text_inspector_widget.clear()

        self.snapshot_controller.clear()
        if hasattr(self.main_window, "binary_inspector_widget"):
            self.main_window.binary_inspector_widget.clear()
        
        file_ext = os.path.splitext(file_path)[1].lower()
        self.file_handler = self._resolve_file_handler(file_path)

        if self._is_ptx_file(file_path):
            logger.info("PTX file detected - initializing PTX-specific UI")
            self.main_window.enable_ptx_menu(True)
            self.main_window.show_ptx_view(True)
            self.update_file_structure()

        self._start_snapshot_analysis(file_path, file_ext)
        from src.services.ui_policy import feature_enabled, load_ui_policy

        ui_policy = self.hex_editor.ui_policy or load_ui_policy()
        if feature_enabled(ui_policy, "auto_disassemble_on_load") and self.main_window.dock_is_visible("pseudocode_dock"):
            QTimer.singleShot(0, self.disassemble)
        if hasattr(self.main_window, "binary_snapshot_action"):
            from src.runtime.config import load_binary_dynamic_config
            from src.runtime.format_router import detect_format_plugin

            try:
                plugin = detect_format_plugin(file_path, cfg=load_binary_dynamic_config())
                self.main_window.binary_snapshot_action.setEnabled(plugin in {"ptx", "pe"})
            except Exception:
                self.main_window.binary_snapshot_action.setEnabled(False)
        
        self.main_window.status_bar.showMessage(f"Loaded: {file_path} ({file_size} bytes)")
        self.update_status_bar()
        
        logger.debug("File loaded event handled")

    def handle_file_saved(self, file_path: str):
        """
        Handle file saved event.
        
        Args:
            file_path: The path to the saved file
        """
        logger.info(f"File saved: {file_path}")
        
        # Update the window title
        self.main_window.setWindowTitle(f"HexEditor - {file_path}")
        
        # Show a message
        self.main_window.status_bar.showMessage(f"File saved: {file_path}", 3000)
        
        # Reinitialize the extractor
        self.extractor = BinaryExtractor(file_path)
        
        # Reinitialize the file handler
        self.file_handler = detect_file_type(file_path)
        
        # Update the file structure
        self.update_file_structure()
        
        logger.info("File save handlers completed")

    def handle_file_changed(self, file_path: str):
        """
        Handle file changed event.
        
        Args:
            file_path: The path to the changed file
        """
        logger.info(f"File changed externally: {file_path}")
        
        # Show a message box asking if the user wants to reload the file
        result = QMessageBox.question(
            self.main_window,
            "File Changed",
            f"The file has been modified externally:\n{file_path}\n\nDo you want to reload it?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        
        if result == QMessageBox.Yes:
            logger.info("Reloading file after external change")
            
            # Reload the file
            self.hex_editor.load_file(file_path)
            
            # Reinitialize the extractor
            self.extractor = BinaryExtractor(file_path)
            
            # Reinitialize the file handler
            self.file_handler = detect_file_type(file_path)
            
            # Update the file structure
            self.update_file_structure()
        else:
            logger.info("User chose not to reload file after external change")

    def handle_error(self, error_message: str):
        """
        Handle error event.
        
        Args:
            error_message: The error message
        """
        logger.error(f"Error occurred: {error_message}")
        self.main_window.show_message("Error", error_message, QMessageBox.Critical)

    def show_about(self):
        """Show the about dialog."""
        logger.debug("Showing about dialog")
        about_text = (
            "HexEditor\n\n"
            "A modular hex editor application with disassembly and decryption capabilities.\n\n"
            "Features:\n"
            "- Hex editing of binary files\n"
            "- Disassembly of executable files\n"
            "- PTX file analysis and decryption\n"
            "- Extraction of file components\n"
            "- Dark mode support\n\n"
            "Version: 1.0.0\n"
            "License: MIT"
        )
        
        self.main_window.show_message("About HexEditor", about_text, QMessageBox.Information)

    def extract_all(self):
        """Extract all available sections and data from the binary."""
        logger.info("Starting extraction of all file components")
        
        if not self.hex_editor.file_path:
            logger.warning("No file loaded, cannot extract")
            self.main_window.show_message("Error", 
                                         "No file loaded. Please open a file first.", 
                                         QMessageBox.Warning)
            return
        
        # Ask for output directory
        output_dir = QFileDialog.getExistingDirectory(self.main_window, "Select Output Directory for All Extractions")
        if not output_dir:
            logger.debug("Extract operation canceled")
            return
        
        # Create a summary file
        summary_path = os.path.join(output_dir, "extraction_summary.txt")
        summary_content = []
        
        # Track extraction results
        extraction_results = {
            "File Type": "Unknown",
            "Components Extracted": 0,
            "Details": {}
        }
        
        # Handle PTX files
        if isinstance(self.file_handler, PTXFile):
            logger.info("Extracting PTX file components")
            
            # Make sure the file is parsed
            if not self.file_handler.parsing_complete:
                self.file_handler.parse()
            
            # Set file type in results
            extraction_results["File Type"] = "PTX"
            
            # Extract all sections
            ptx_dir = os.path.join(output_dir, "ptx_sections")
            extracted_files = self.file_handler.extract_all(ptx_dir)
            
            # Update extraction results
            extraction_results["Components Extracted"] = len(extracted_files)
            extraction_results["Details"] = extracted_files
            
            # Add to summary
            summary_content.append(f"PTX File: {self.hex_editor.file_path}")
            summary_content.append(f"Version: {self.file_handler.header.version}")
            summary_content.append(f"Encryption: {self.file_handler.header.get_encryption_info()['description']}")
            summary_content.append(f"Extracted {len(extracted_files)} components to {ptx_dir}")
            summary_content.append("")
            
            for section_name, file_path in extracted_files.items():
                summary_content.append(f"  - {section_name}: {os.path.basename(file_path)}")
            
            logger.info(f"Extracted {len(extracted_files)} PTX components")
            
        # Handle PE files    
        elif self.extractor and self.extractor.is_pe_file:
            logger.info("Extracting PE file components")
            
            # Set file type in results
            extraction_results["File Type"] = "PE"
            
            # Create directories for different components
            pe_sections_dir = os.path.join(output_dir, "sections")
            os.makedirs(pe_sections_dir, exist_ok=True)
            
            resources_dir = os.path.join(output_dir, "resources")
            os.makedirs(resources_dir, exist_ok=True)
            
            # Extract PE headers
            headers_path = os.path.join(output_dir, "pe_headers.bin")
            headers_data = self.extractor.extract_pe_headers(headers_path)
            if headers_data:
                extraction_results["Details"]["PE Headers"] = headers_path
                summary_content.append(f"PE Headers: Extracted to {headers_path}")
            
            # Extract PE sections
            sections = self.extractor.extract_all_pe_sections(pe_sections_dir)
            if sections:
                extraction_results["Details"]["PE Sections"] = list(sections.keys())
                summary_content.append(f"PE Sections: Extracted {len(sections)} sections to {pe_sections_dir}")
                for section_name in sections.keys():
                    summary_content.append(f"  - {section_name}")
            
            # Extract import table
            imports_path = os.path.join(output_dir, "import_table.txt")
            imports = self.extractor.extract_import_table(imports_path)
            if imports:
                extraction_results["Details"]["Import Table"] = len(imports)
                summary_content.append(f"Import Table: Extracted {len(imports)} DLLs to {imports_path}")
            
            # Extract export table
            exports_path = os.path.join(output_dir, "export_table.txt")
            exports = self.extractor.extract_export_table(exports_path)
            if exports:
                extraction_results["Details"]["Export Table"] = len(exports)
                summary_content.append(f"Export Table: Extracted {len(exports)} functions to {exports_path}")
            
            # Extract resources
            resources = self.extractor.extract_resource_section(resources_dir)
            if resources:
                extraction_results["Details"]["Resources"] = len(resources)
                summary_content.append(f"Resources: Extracted {len(resources)} resources to {resources_dir}")
            
            # Extract encryption algorithms
            encryption_path = os.path.join(output_dir, "encryption_algorithms.txt")
            encryption_algos = self.extractor.extract_encryption_algorithms(encryption_path)
            if encryption_algos:
                extraction_results["Details"]["Encryption Algorithms"] = len(encryption_algos)
                summary_content.append(f"Encryption Algorithms: Found {len(encryption_algos)} potential algorithms")
            
            # Extract decryption algorithms
            decryption_path = os.path.join(output_dir, "decryption_algorithms.txt")
            decryption_algos = self.extractor.extract_decryption_algorithms(decryption_path)
            if decryption_algos:
                extraction_results["Details"]["Decryption Algorithms"] = len(decryption_algos)
                summary_content.append(f"Decryption Algorithms: Found {len(decryption_algos)} potential algorithms")
            
            # Update total components extracted
            extraction_results["Components Extracted"] = len(extraction_results["Details"])
            
            logger.info(f"Extracted {extraction_results['Components Extracted']} PE components")
            
        # Handle generic binary files
        else:
            logger.info("Extracting generic binary file")
            
            # Set file type in results
            extraction_results["File Type"] = "Raw Binary"
            
            # Create a copy of the entire file
            file_name = os.path.basename(self.hex_editor.file_path)
            copy_path = os.path.join(output_dir, file_name)
            
            with open(self.hex_editor.file_path, 'rb') as src, open(copy_path, 'wb') as dst:
                dst.write(src.read())
            
            extraction_results["Components Extracted"] = 1
            extraction_results["Details"]["Full File"] = copy_path
            
            summary_content.append(f"Raw Binary File: {self.hex_editor.file_path}")
            summary_content.append(f"Size: {os.path.getsize(self.hex_editor.file_path)} bytes")
            summary_content.append(f"Copied to: {copy_path}")
            
            logger.info(f"Copied raw binary file to {copy_path}")
        
        # Write the summary file
        logger.info(f"Writing extraction summary to {summary_path}")
        with open(summary_path, 'w') as f:
            f.write("HexEditor Extraction Summary\n")
            f.write("===========================\n\n")
            f.write(f"Source file: {self.hex_editor.file_path}\n")
            f.write(f"Extraction date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if not summary_content:
                f.write("No data was extracted.\n")
            else:
                f.write("Extracted Data:\n")
                f.write("---------------\n\n")
                for line in summary_content:
                    f.write(f"{line}\n")
        
        # Show a summary message
        if extraction_results["Components Extracted"] == 0:
            logger.warning("No components were extracted")
            self.main_window.show_message("Extraction Complete", 
                                         "No components were extracted.",
                                         QMessageBox.Information)
        else:
            logger.info(f"Extraction complete - {extraction_results['Components Extracted']} components extracted")
            self.main_window.show_message("Extraction Complete", 
                                         f"Extracted {extraction_results['Components Extracted']} components to {output_dir}\n"
                                         f"See {summary_path} for details.",
                                         QMessageBox.Information)

    def run(self):
        """Run the application."""
        logger.info("Showing main window")
        self.main_window.show()

    def goto_offset(self, offset=None):
        """Go to a specific offset in the hex editor."""
        logger.info("Go to offset operation started")
        
        # If offset is provided directly, use it
        if offset is not None:
            logger.info(f"Going to offset: 0x{offset:X}")
            if not self.hex_editor.goto_offset(offset):
                logger.warning(f"Invalid offset: {offset}")
                self.main_window.show_message("Error", f"Invalid offset: {offset}", QMessageBox.Warning)
            return
        
        # Otherwise, show a dialog to get the offset
        offset_text = self.main_window.show_input_dialog("Go to Offset", "Enter offset (hex):", "0x")
        if not offset_text:
            logger.debug("Go to offset dialog canceled")
            return
        
        try:
            # Parse the offset
            if offset_text.startswith("0x"):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
            
            logger.info(f"Going to offset: 0x{offset:X}")
            # Navigate to the offset
            if not self.hex_editor.goto_offset(offset):
                logger.warning(f"Invalid offset: {offset_text}")
                self.main_window.show_message("Error", f"Invalid offset: {offset_text}", QMessageBox.Warning)
                
        except ValueError:
            logger.error(f"Invalid offset format: {offset_text}")
            self.main_window.show_message("Error", f"Invalid offset format: {offset_text}", QMessageBox.Warning)
    
    def disassemble(self):
        """Disassemble the current file."""
        logger.info("Starting disassembly operation")
        if not self.hex_editor.file_path:
            logger.warning("No file loaded, cannot disassemble")
            self.main_window.show_message("Error", "No file loaded", QMessageBox.Warning)
            return
        if self.disassembly_thread is not None:
            logger.debug("Disassembly/pseudocode worker already active")
            return
        
        # Create a new disassembler worker
        self.disassembly_worker = DisassemblerWorker(
            self.hex_editor.file_path,
            self.hex_editor.comments
        )
            
        # Create a new thread for the disassembler worker
        self.disassembly_thread = QThread()
        self.disassembly_worker.moveToThread(self.disassembly_thread)
        
        # Connect signals and slots
        self.disassembly_thread.started.connect(self.disassembly_worker.run)
        self.disassembly_worker.disassembly_finished.connect(self.handle_disassembly_finished)
        self.disassembly_worker.disassembly_failed.connect(self.handle_disassembly_failed)
        self.disassembly_worker.disassembly_finished.connect(self.disassembly_thread.quit)
        self.disassembly_worker.disassembly_failed.connect(self.disassembly_thread.quit)
        self.disassembly_thread.finished.connect(self.cleanup_disassembly_thread)
        
        # Start the disassembly thread
        logger.debug("Starting disassembly thread")
        self.disassembly_thread.start()

    def _pseudocode_navigation_enabled(self) -> bool:
        from src.services.ui_policy import feature_enabled, load_ui_policy

        policy = load_ui_policy()
        return feature_enabled(policy, "pseudocode_byte_navigation")

    def _navigation_status(self, navigation_policy: Mapping[str, Any], key: str, **values: Any) -> None:
        messages = dict(navigation_policy.get("status_messages") or {})
        message = str(messages[key]).format(**values)
        logger.info(message)
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, 5000)

    def _navigation_block_reason(self, navigation_policy: Mapping[str, Any]) -> Optional[str]:
        if self.disassembly_thread is not None:
            return "analysis_running"
        if not self.hex_editor.file_path:
            return "no_file"
        pseudo = getattr(self.main_window, "pseudocode_text", None)
        has_pseudocode = bool(pseudo and pseudo.toPlainText().strip())
        if not has_pseudocode and not self._pseudocode_source_map:
            return "no_pseudocode"
        guard = dict(navigation_policy.get("generation_guard") or {})
        if bool(guard.get("require_loaded_source_map")) and not self._pseudocode_source_map:
            return "source_map_unavailable"
        stored_path = str((self._pseudocode_navigation_generation or {}).get("source_path") or "")
        loaded_path = str(self.hex_editor.file_path or "")
        if bool(guard.get("require_matching_source_path")) and not stored_path:
            return "source_path_missing"
        if stored_path and loaded_path:
            from src.services.region_routed_pseudocode.navigation import navigation_generation_matches

            current = dict(self._pseudocode_navigation_generation or {})
            current["source_path"] = loaded_path
            if not navigation_generation_matches(
                self._pseudocode_navigation_generation,
                current,
                navigation_policy=navigation_policy,
            ):
                return "source_path_mismatch"
        return None

    def _navigation_generation_valid(self) -> bool:
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

        return self._navigation_block_reason(load_pseudocode_navigation_policy()) is None

    def _schedule_pseudocode_to_hex(self) -> None:
        if not self._pseudocode_navigation_enabled():
            return
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

        delay = int((load_pseudocode_navigation_policy().get("debounce_ms") or {}).get("pseudocode_to_hex") or 16)
        self._pseudocode_to_hex_timer.start(max(1, delay))

    def _clear_nav_suppress_hex_to_pseudo(self) -> None:
        self._nav_suppress_hex_to_pseudo = False

    def _schedule_hex_to_pseudocode(self) -> None:
        if not self._pseudocode_navigation_enabled():
            return
        if self._nav_suppress_hex_to_pseudo or self._nav_sync_in_progress:
            return
        if hasattr(self.main_window, "pseudocode_text") and self.main_window.pseudocode_text.hasFocus():
            return
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

        delay = int((load_pseudocode_navigation_policy().get("debounce_ms") or {}).get("hex_to_pseudocode") or 16)
        self._hex_to_pseudocode_timer.start(max(1, delay))

    def _ensure_pseudocode_source_map(self) -> bool:
        if self._pseudocode_source_map or not self.hex_editor.file_path:
            return bool(self._pseudocode_source_map)
        try:
            from src.services.region_routed_pseudocode import render_region_routed_bundle

            bundle = render_region_routed_bundle(self.hex_editor.file_path)
            self._pseudocode_source_map = list(bundle.get("source_map") or [])
            generation = dict(bundle.get("navigation_generation") or {})
            generation.setdefault("source_path", str(self.hex_editor.file_path))
            self._pseudocode_navigation_generation = generation
            self._pseudocode_source_map_error = ""
            return bool(self._pseudocode_source_map)
        except Exception as exc:
            self._pseudocode_source_map_error = str(exc)
            logger.warning("Pseudocode navigation source-map recovery failed: %s", exc, exc_info=True)
            return False

    def _sync_pseudocode_to_hex(self) -> None:
        if self._nav_sync_in_progress:
            return
        if not hasattr(self.main_window, "pseudocode_text"):
            return
        from src.services.region_routed_pseudocode.navigation import ranges_for_selection
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

        nav_policy = load_pseudocode_navigation_policy()
        self._ensure_pseudocode_source_map()
        blocked = self._navigation_block_reason(nav_policy)
        if blocked is not None:
            self._navigation_status(nav_policy, blocked)
            return
        editor = self.main_window.pseudocode_text
        cursor = editor.textCursor()
        start_line = cursor.selectionStart()
        end_line = cursor.selectionEnd()
        start_block = editor.document().findBlock(start_line).blockNumber()
        end_block = editor.document().findBlock(max(start_line, end_line - 1)).blockNumber()
        start_block_position = editor.document().findBlock(start_line).position()
        start_column = max(0, start_line - start_block_position)
        if end_block < start_block:
            start_block, end_block = end_block, start_block
        pseudo_cfg = dict(nav_policy.get("pseudocode_to_hex") or {})
        triggers = list(pseudo_cfg.get("triggers") or ["caret"])
        if cursor.hasSelection() and "selection" not in triggers:
            return
        if not cursor.hasSelection() and "caret" not in triggers:
            return
        line_texts = editor.toPlainText().splitlines()
        source_path = Path(self.hex_editor.file_path) if self.hex_editor.file_path else None
        file_size = int(self.hex_editor.file_size or 0)
        try:
            result = ranges_for_selection(
                self._pseudocode_source_map,
                start_line=start_block,
                end_line=end_block,
                navigation_policy=nav_policy,
                line_texts=line_texts,
                file_size=file_size,
                source_path=source_path,
                selection_start_column=start_column,
            )
        except Exception as exc:
            logger.warning("Pseudocode navigation address resolution failed: %s", exc, exc_info=True)
            self._navigation_status(nav_policy, "resolution_error", error=str(exc))
            return
        if result is None:
            self._navigation_status(nav_policy, "no_offset", line=start_block + 1)
            return
        anchor = int(result["anchor_file_offset"])
        if file_size > 0 and anchor >= file_size:
            self._navigation_status(nav_policy, "outside_file", offset=anchor, file_size=file_size)
            return
        self._nav_sync_in_progress = True
        self._nav_suppress_hex_to_pseudo = True
        pseudo_focus = self.main_window.pseudocode_text if hasattr(self.main_window, "pseudocode_text") else None
        saved_cursor = editor.textCursor() if pseudo_focus is not None else None
        try:
            # Highlighting re-renders the hex document. Apply it before the final
            # goto so the render cannot erase the destination cursor/selection.
            highlight_mode = str(pseudo_cfg.get("highlight_mode") or "none")
            if highlight_mode == "ranges":
                token = str(nav_policy.get("hex_highlight_theme_token") or "")
                self.hex_editor.highlight_pseudocode_navigation_ranges(result.get("ranges") or [], theme_token=token)
            elif highlight_mode == "anchor_only" and result.get("ranges"):
                first = dict(result["ranges"][0])
                token = str(nav_policy.get("hex_highlight_theme_token") or "")
                self.hex_editor.highlight_pseudocode_navigation_ranges([first], theme_token=token)
            else:
                self.hex_editor.clear_pseudocode_navigation_ranges()
            if not self.hex_editor.goto_offset(anchor, focus=False):
                self.hex_editor.clear_pseudocode_navigation_ranges()
                self._navigation_status(nav_policy, "goto_failed", offset=anchor)
                return
            source_coordinate = dict(result.get("anchor_source_coordinate") or {})
            if str(source_coordinate.get("coordinate_space") or "") == "virtual_address":
                self._navigation_status(
                    nav_policy,
                    "success_virtual_address",
                    virtual_address=int(source_coordinate["value"]),
                    offset=anchor,
                )
            else:
                self._navigation_status(nav_policy, "success", offset=anchor)
        finally:
            self._nav_sync_in_progress = False
            if saved_cursor is not None and pseudo_focus is not None:
                editor.setTextCursor(saved_cursor)
                if pseudo_focus.hasFocus():
                    pseudo_focus.setFocus(Qt.OtherFocusReason)
            QTimer.singleShot(120, self._clear_nav_suppress_hex_to_pseudo)

    def _sync_hex_to_pseudocode(self) -> None:
        if self._nav_sync_in_progress or self._nav_suppress_hex_to_pseudo:
            return
        forensic_view = getattr(self, "_forensic_results_widget", None)
        if forensic_view is not None and self.hex_editor.file_path:
            try:
                forensic_view.reflect_hex_offset(self.hex_editor.file_path, int(self.hex_editor.get_cursor_byte_offset()))
            except (OSError, ValueError, KeyError):
                pass
        if hasattr(self.main_window, "pseudocode_text") and self.main_window.pseudocode_text.hasFocus():
            return
        if not hasattr(self.main_window, "pseudocode_text"):
            return
        from src.services.region_routed_pseudocode.navigation import line_for_offset
        from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

        nav_policy = load_pseudocode_navigation_policy()
        self._ensure_pseudocode_source_map()
        if self._navigation_block_reason(nav_policy) is not None:
            return
        hex_cfg = dict(nav_policy.get("hex_to_pseudocode") or {})
        triggers = list(hex_cfg.get("triggers") or ["caret"])
        selection = self.hex_editor.get_selection()
        if selection and "selection" not in triggers:
            return
        if not selection and "caret" not in triggers:
            return
        file_offset = int(selection[0]) if selection else int(self.hex_editor.get_cursor_byte_offset())
        line_number = line_for_offset(self._pseudocode_source_map, file_offset)
        if line_number is None:
            return
        editor = self.main_window.pseudocode_text
        block = editor.document().findBlockByNumber(int(line_number))
        if not block.isValid():
            return
        self._nav_sync_in_progress = True
        try:
            cursor = editor.textCursor()
            cursor.setPosition(block.position())
            if bool(hex_cfg.get("highlight_lines")) and cursor.blockNumber() == line_number:
                end_block = editor.document().findBlockByNumber(int(line_number))
                for entry in self._pseudocode_source_map:
                    if int(entry.get("line_start") or -1) <= line_number <= int(entry.get("line_end") or -1):
                        end_block = editor.document().findBlockByNumber(int(entry.get("line_end") or line_number))
                        break
                cursor.setPosition(block.position())
                cursor.setPosition(end_block.position() + end_block.length() - 1, cursor.KeepAnchor)
            editor.setTextCursor(cursor)
            editor.ensureCursorVisible()
        finally:
            self._nav_sync_in_progress = False

    def _on_pseudocode_visibility_changed(self, visible: bool) -> None:
        """Generate pseudocode on demand; hidden docks never start analysis."""
        if not visible or not self.hex_editor.file_path:
            return
        from src.services.ui_policy import feature_enabled, load_ui_policy

        ui_policy = self.hex_editor.ui_policy or load_ui_policy()
        if not feature_enabled(ui_policy, "auto_disassemble_on_dock_show"):
            return
        if self.disassembly_thread is not None:
            return
        if self.main_window.pseudocode_text.toPlainText().strip():
            return
        QTimer.singleShot(0, self.disassemble)
    
    def cleanup_disassembly_thread(self):
        """Clean up the disassembly thread and worker."""
        logger.debug("Cleaning up disassembly thread")
        self.disassembly_thread = None
        self.disassembly_worker = None
    
    def handle_disassembly_finished(self, asm, pseudocode, symbols, iat, eat, strings):
        """
        Handle disassembly completion.
        
        Args:
            asm: List of assembly instructions
            pseudocode: List of pseudocode lines
            symbols: List of symbols
            iat: List of import address table entries
            eat: List of export address table entries
            strings: List of strings
        """
        logger.info("Analysis completed kind=%s", getattr(self.disassembly_worker, "_analysis_kind", "unspecified"))

        asm_text = "\n".join(asm)
        pseudo_text = "\n".join(pseudocode)
        worker_map = getattr(self.disassembly_worker, "_pseudocode_source_map", None)
        if worker_map:
            self._pseudocode_source_map = list(worker_map)
            self._pseudocode_source_map_error = ""
        worker_generation = getattr(self.disassembly_worker, "_pseudocode_navigation_generation", None)
        if worker_generation:
            self._pseudocode_navigation_generation = dict(worker_generation)
        self.main_window.deliver_dock_update(
            "disassembly_dock",
            lambda text=asm_text: self.main_window.disassembly_text.setPlainText(text),
        )
        self.main_window.deliver_dock_update(
            "pseudocode_dock",
            lambda text=pseudo_text: self.main_window.pseudocode_text.setPlainText(text),
        )

        def apply_symbols() -> None:
            self.main_window.symbols_widget.clear()
            for symbol in symbols:
                self.main_window.symbols_widget.addItem(symbol)
            for entry in iat:
                self.main_window.symbols_widget.addItem(entry)
            for entry in eat:
                self.main_window.symbols_widget.addItem(entry)
            for string in strings:
                self.main_window.symbols_widget.addItem(string)

        self.main_window.deliver_dock_update("symbols_dock", apply_symbols)
        
        logger.debug(f"Added {len(symbols) + len(iat) + len(eat) + len(strings)} items to symbols widget")
    
    def handle_disassembly_failed(self, error_message: str):
        """
        Handle disassembly failure.
        
        Args:
            error_message: The error message
        """
        logger.error(f"Disassembly failed: {error_message}")
        self.main_window.show_message("Disassembly Error", error_message, QMessageBox.Warning)

    def toggle_hex_view(self, show: bool):
        """
        Toggle the display of hex values.
        
        Args:
            show: Whether to show hex values
        """
        logger.info(f"Toggling hex view: {show}")
        self.hex_editor.toggle_hex_view(show)
    
    def toggle_ascii_view(self, show: bool):
        """
        Toggle the display of ASCII values.
        
        Args:
            show: Whether to show ASCII values
        """
        logger.info(f"Toggling ASCII view: {show}")
        self.hex_editor.toggle_ascii_view(show)
    
    def show_context_menu(self, position):
        """
        Show the context menu for the hex editor.
        
        Args:
            position: The position where the context menu should be shown
        """
        logger.debug(f"Showing context menu at position: {position}")
        # Create context menu
        context_menu = QMenu(self.main_window.hex_editor)
        
        # Add actions to the context menu
        copy_action = context_menu.addAction("Copy")
        copy_action.triggered.connect(self.main_window.hex_editor.copy)
        
        # Add a separator
        context_menu.addSeparator()
        
        # Add action to go to offset
        goto_action = context_menu.addAction("Go to Offset...")
        goto_action.triggered.connect(self.goto_offset)
        
        # Add action to add bookmark
        add_bookmark_action = context_menu.addAction("Add Bookmark...")
        # add_bookmark_action.triggered.connect(self.add_bookmark)
        
        # Add action to add comment
        add_comment_action = context_menu.addAction("Add Comment...")
        # add_comment_action.triggered.connect(self.add_comment)
        
        # Add action to decode selection in text inspector
        decode_action = context_menu.addAction("Decode in Text Inspector")
        decode_action.triggered.connect(self.refresh_text_inspector)

        # Show the context menu
        context_menu.exec_(self.main_window.hex_editor.mapToGlobal(position))
    
    def navigate_bookmark(self, item):
        """
        Navigate to a bookmark.
        
        Args:
            item: The selected item in the bookmarks widget
        """
        if not item:
            return
        
        # Get the text of the selected item
        text = item.text()
        
        # Extract the offset from the text
        try:
            offset_text = text.split(":", 1)[0]
            offset = int(offset_text, 16)
            
            logger.debug(f"Navigating to bookmark at offset 0x{offset:X}")
            # Navigate to the offset
            self.hex_editor.goto_offset(offset)
            
        except (ValueError, IndexError):
            logger.error(f"Invalid bookmark format: {text}")
    
    def navigate_symbol(self, item):
        """
        Navigate to a symbol.
        
        Args:
            item: The selected item in the symbols widget
        """
        if not item:
            return
        
        # Get the text of the selected item
        text = item.text()
        
        # Extract the offset from the text
        try:
            offset_text = text.split(":", 1)[0]
            offset = int(offset_text, 16)
            
            logger.debug(f"Navigating to symbol at offset 0x{offset:X}")
            # Navigate to the offset
            self.hex_editor.goto_offset(offset)
            
        except (ValueError, IndexError):
            logger.error(f"Invalid symbol format: {text}")
    
    def _is_ptx_file(self, file_path: str) -> bool:
        from src.runtime.config import load_binary_dynamic_config
        from src.runtime.format_router import detect_format_plugin

        try:
            return detect_format_plugin(file_path, cfg=load_binary_dynamic_config()) == "ptx"
        except Exception:
            return False

    def _resolve_file_handler(self, file_path: str):
        if self._is_ptx_file(file_path):
            if self.hex_editor.ptx_handler is not None:
                return self.hex_editor.ptx_handler
            return detect_file_type(file_path)
        return detect_file_type(file_path)

    def _refresh_knowledge_metrics_status(self, source_sha256: str = "") -> None:
        if not source_sha256 and self.hex_editor.file_path:
            try:
                import hashlib

                source_sha256 = hashlib.sha256(Path(self.hex_editor.file_path).read_bytes()).hexdigest()
            except OSError:
                source_sha256 = ""
        if not source_sha256:
            self.main_window.set_forensic_knowledge_metrics("")
            return
        try:
            from src.services.forensic_knowledge_metrics import (
                load_forensic_knowledge_metrics_policy,
                load_knowledge_coverage_for_source,
            )

            payload = load_knowledge_coverage_for_source(source_sha256)
            if not payload:
                self.main_window.set_forensic_knowledge_metrics("")
                return
            labels = dict(load_forensic_knowledge_metrics_policy()["policy"]["display_labels"])
            percentages = dict(payload.get("percentages") or {})
            parts = []
            for key in ("byte_ownership", "structural_knowledge", "semantic_knowledge", "plaintext_readable"):
                label = str(labels.get(key) or key)
                value = percentages.get(key)
                if value is None:
                    continue
                parts.append(f"{label}: {value}%")
            self.main_window.set_forensic_knowledge_metrics(" | ".join(parts))
        except Exception:
            self.main_window.set_forensic_knowledge_metrics("")

    def update_status_bar(self):
        """Update the status bar with current information."""
        if getattr(self.hex_editor, "_document_mutation_active", False):
            return
        if not self.hex_editor.file_path:
            return
        # Get the current cursor position
        cursor = self.main_window.hex_editor.textCursor()
        position = cursor.position()
        
        # Calculate the byte offset from the cursor position
        # This is a simplified calculation and may not be accurate for all cases
        block_number = self.main_window.hex_editor.document().findBlock(position).blockNumber()
        block_position = self.main_window.hex_editor.document().findBlock(position).position()
        column = position - block_position
        
        # Calculate the byte offset
        byte_offset = block_number * self.hex_editor.bytes_per_line + column // 3
        
        # Get the selection if any
        selection = self.hex_editor.get_selection()
        
        # Update the status bar
        self.main_window.update_status_bar(byte_offset, self.hex_editor.file_size, selection)
        if self.main_window.dock_is_visible("text_inspector_dock"):
            self._text_inspector_timer.start(max(1, int(self._text_inspector_debounce_ms or 250)))
        else:
            self._text_inspector_timer.stop()
        
        # Log position for debugging
        if selection:
            start, end = selection
            logger.debug(f"Cursor position: 0x{byte_offset:X}, Selection: 0x{start:X}-0x{end:X}")
        else:
            logger.debug(f"Cursor position: 0x{byte_offset:X}")

    def _resolve_investigation_root(self, source_path: str, source_sha256: str | None = None) -> Optional[str]:
        for row in list_investigation_runs(source_path):
            workspace = str(row.get("workspace_path") or "")
            if not workspace:
                continue
            manifest_path = Path(workspace) / "manifest.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            manifest_sha = str(manifest.get("source_sha256") or "")
            if source_sha256 and manifest_sha and manifest_sha != source_sha256:
                continue
            return workspace
        return None

    def _cleanup_snapshot_thread(self) -> None:
        thread = self._snapshot_thread
        worker = self._snapshot_worker
        self._snapshot_thread = None
        self._snapshot_worker = None
        if thread is not None:
            if thread.isRunning():
                thread.quit()
            thread.finished.connect(thread.deleteLater)
        if worker is not None:
            worker.deleteLater()

    def _cleanup_forensic_thread(self) -> None:
        thread = self._forensic_thread
        worker = self._forensic_worker
        self._forensic_thread = None
        self._forensic_worker = None
        if thread is not None:
            if thread.isRunning():
                thread.quit()
            thread.finished.connect(thread.deleteLater)
        if worker is not None:
            worker.deleteLater()

    def _start_snapshot_analysis(self, file_path: str, file_ext: str) -> None:
        """Analyze binary snapshot on a worker thread so the hex view stays responsive."""
        if not hasattr(self.main_window, "binary_inspector_widget"):
            return
        self._pending_binary_analysis = None
        binary_visible = self.main_window.dock_is_visible("binary_inspector_dock")
        metadata_visible = self.main_window.dock_is_visible("ptx_metadata_dock")
        self._cleanup_snapshot_thread()
        self._cleanup_forensic_thread()
        self._pending_forensic_timer.stop()
        try:
            from src.runtime.config import load_binary_dynamic_config
            from src.runtime.format_router import detect_format_plugin

            cfg = load_binary_dynamic_config()
            plugin = detect_format_plugin(file_path, cfg=cfg)
            if plugin not in {"ptx", "pe"}:
                if binary_visible:
                    self.main_window.binary_inspector_widget.clear()
                return

            if binary_visible:
                self.main_window.deliver_dock_update(
                    "binary_inspector_dock",
                    lambda path=file_path: self.main_window.binary_inspector_widget.set_analyzing(path),
                )
            generation = self.snapshot_controller.generation
            self._snapshot_worker = SnapshotAnalysisWorker(file_path, policy=cfg, generation=generation)
            self._snapshot_thread = QThread()
            self._snapshot_worker.moveToThread(self._snapshot_thread)
            self._snapshot_thread.started.connect(self._snapshot_worker.run)
            self._snapshot_worker.finished.connect(self._handle_snapshot_analysis_finished)
            self._snapshot_worker.failed.connect(self._handle_snapshot_analysis_failed)
            self._snapshot_worker.finished.connect(self._snapshot_thread.quit)
            self._snapshot_worker.failed.connect(self._snapshot_thread.quit)
            self._snapshot_thread.finished.connect(self._cleanup_snapshot_thread)
            self._snapshot_thread.start()
            logger.info("Started background snapshot analysis for %s", file_path)
        except Exception as exc:
            logger.warning("Binary Inspector unavailable: %s", exc)
            if binary_visible and hasattr(self.main_window, "binary_inspector_widget"):
                self.main_window.binary_inspector_widget.clear()

    def _sync_binary_inspector_from_controller(self) -> None:
        """Push the latest cached snapshot into the inspector when its dock is shown."""
        if not hasattr(self.main_window, "binary_inspector_widget"):
            return
        snapshot = self.snapshot_controller.static_snapshot()
        if not snapshot:
            return
        generation = int(self.snapshot_controller.generation)
        if self.snapshot_controller.is_stale(generation):
            return
        context = dict(getattr(self, "_forensic_context", {}) or {})

        def apply() -> None:
            self.main_window.binary_inspector_widget.update_snapshot(
                snapshot,
                generation=generation,
                forensic_context=context,
            )

        self.main_window.deliver_dock_update("binary_inspector_dock", apply)

    def analyze_current_binary(self) -> None:
        """Analyze the currently loaded supported file from the inspector."""
        file_path = str(self.hex_editor.file_path or "")
        if not file_path:
            self.main_window.show_message("Binary Inspector", "Open a PTX or PE file first.")
            return
        self._start_snapshot_analysis(file_path, Path(file_path).suffix.lower())

    def _on_binary_inspector_visibility_changed(self, visible: bool) -> None:
        """Refresh inspector from cache or start analysis when its dock becomes shown."""
        if not visible:
            return
        self._sync_binary_inspector_from_controller()
        if self.snapshot_controller.static_snapshot():
            forensic = getattr(self, "_pending_forensic_payload", None)
            if forensic and not self.snapshot_controller.is_stale(int(forensic.get("generation") or 0)):
                self._launch_deferred_forensic_worker()
            elif self.hex_editor.file_path and not getattr(self, "_forensic_context", None):
                self._start_deferred_forensic_context(
                    str(self.hex_editor.file_path),
                    self.snapshot_controller.static_snapshot(),
                    self.snapshot_controller.generation,
                )
            return
        file_path = str(self.hex_editor.file_path or "")
        if file_path:
            self._start_snapshot_analysis(file_path, Path(file_path).suffix.lower())

    def _handle_snapshot_analysis_finished(self, payload: Dict[str, Any]) -> None:
        generation = int(payload.get("generation") or 0)
        if self.snapshot_controller.is_stale(generation):
            return
        try:
            loaded = self.snapshot_controller.adopt_analysis(
                payload["result"],
                source_path=payload["source_path"],
            )
        except Exception as exc:
            logger.warning("Snapshot adoption failed: %s", exc)
            if hasattr(self.main_window, "binary_inspector_widget"):
                self.main_window.deliver_dock_update(
                    "binary_inspector_dock",
                    lambda msg=str(exc): self.main_window.binary_inspector_widget.header.setText(
                        f"Binary Inspector — analysis failed: {msg}"
                    ),
                )
            return

        file_path = str(payload["source_path"])
        snapshot = loaded["snapshot"]
        generation = int(loaded["generation"])
        if self.snapshot_controller.is_stale(generation):
            return

        if hasattr(self.main_window, "ptx_metadata_widget"):
            self.main_window.deliver_dock_update(
                "ptx_metadata_dock",
                lambda snap=snapshot: self.main_window.ptx_metadata_widget.update_runtime_snapshot(snap),
            )
        QTimer.singleShot(
            0,
            lambda fp=file_path, snap=snapshot, gen=generation: self._apply_snapshot_analysis_ui(
                file_path=fp,
                snapshot=snap,
                generation=gen,
            ),
        )

    def _apply_snapshot_analysis_ui(
        self,
        *,
        file_path: str,
        snapshot: Mapping[str, Any],
        generation: int,
    ) -> None:
        if self.snapshot_controller.is_stale(generation):
            return
        if hasattr(self.main_window, "binary_inspector_widget"):
            self.main_window.deliver_dock_update(
                "binary_inspector_dock",
                lambda snap=snapshot, gen=generation: self.main_window.binary_inspector_widget.update_snapshot(
                    snap,
                    generation=gen,
                    forensic_context={},
                ),
            )
        self.main_window.status_bar.showMessage(
            f"Analysis complete: {Path(file_path).name}",
            5000,
        )
        self._start_deferred_forensic_context(file_path, snapshot, generation)
        self._sync_binary_inspector_from_controller()
        logger.info("Binary Inspector loaded snapshot %s", snapshot.get("snapshot_id"))

    def _handle_snapshot_analysis_failed(self, error_message: str, generation: int) -> None:
        if self.snapshot_controller.is_stale(generation):
            return
        logger.warning("Snapshot analysis failed: %s", error_message)
        if hasattr(self.main_window, "binary_inspector_widget"):
            self.main_window.deliver_dock_update(
                "binary_inspector_dock",
                lambda msg=error_message: self.main_window.binary_inspector_widget.header.setText(
                    f"Binary Inspector — analysis failed: {msg}"
                ),
            )

    def _start_deferred_forensic_context(
        self,
        file_path: str,
        snapshot: Mapping[str, Any],
        generation: int,
    ) -> None:
        from src.services.ui_policy import load_ui_policy

        delay = int(load_ui_policy().get("load_budgets", {}).get("defer_forensic_context_ms") or 0)
        self._forensic_generation = generation
        self._pending_forensic_payload = {
            "file_path": file_path,
            "snapshot": dict(snapshot),
            "generation": generation,
        }
        binary_visible = self.main_window.dock_is_visible("binary_inspector_dock")
        metadata_visible = self.main_window.dock_is_visible("ptx_metadata_dock")
        if not binary_visible and not metadata_visible:
            return
        if delay > 0:
            self._pending_forensic_timer.start(delay)
        else:
            self._launch_deferred_forensic_worker()

    def _launch_deferred_forensic_worker(self) -> None:
        payload = getattr(self, "_pending_forensic_payload", None) or {}
        file_path = str(payload.get("file_path") or "")
        snapshot = dict(payload.get("snapshot") or {})
        generation = int(payload.get("generation") or 0)
        if not file_path or not snapshot:
            return
        if self.snapshot_controller.is_stale(generation):
            return
        self._pending_forensic_payload = None

        self._cleanup_forensic_thread()
        self._forensic_worker = ForensicContextWorker(
            source_path=file_path,
            snapshot=snapshot,
            generation=generation,
            include_representation=False,
            include_scope_discovery=self.main_window.dock_is_visible("binary_inspector_dock"),
            include_lineage_discovery=True,
        )
        self._forensic_thread = QThread()
        self._forensic_worker.moveToThread(self._forensic_thread)
        self._forensic_thread.started.connect(self._forensic_worker.run)
        self._forensic_worker.finished.connect(self._handle_deferred_forensic_finished)
        self._forensic_worker.failed.connect(self._handle_deferred_forensic_failed)
        self._forensic_worker.finished.connect(self._forensic_thread.quit)
        self._forensic_worker.failed.connect(self._forensic_thread.quit)
        self._forensic_thread.finished.connect(self._cleanup_forensic_thread)
        self._forensic_thread.start()

    def _handle_deferred_forensic_finished(self, payload: Dict[str, Any]) -> None:
        generation = int(payload.get("generation") or 0)
        if self.snapshot_controller.is_stale(generation):
            return
        context = dict(payload.get("context") or {})
        snapshot = dict(payload.get("snapshot") or {})
        file_path = str(payload.get("source_path") or "")
        self._forensic_context = context
        self.hex_editor.configure_ui_policy(context.get("ui_policy") or {})
        spans = list(context.get("hex_overlay_spans") or [])
        if spans:
            self.hex_editor.set_forensic_overlay_spans(spans)
        if hasattr(self.main_window, "binary_inspector_widget"):
            self.main_window.deliver_dock_update(
                "binary_inspector_dock",
                lambda snap=snapshot, gen=generation, ctx=context: self.main_window.binary_inspector_widget.update_snapshot(
                    snap,
                    generation=gen,
                    forensic_context=ctx,
                ),
            )
        if hasattr(self.main_window, "ptx_metadata_widget"):
            self.main_window.deliver_dock_update(
                "ptx_metadata_dock",
                lambda ctx=context: self.main_window.ptx_metadata_widget.update_forensic_context(ctx),
                coalesce=False,
            )

    def _handle_deferred_forensic_failed(self, error_message: str, generation: int) -> None:
        if self.snapshot_controller.is_stale(generation):
            return
        logger.warning("Deferred forensic context failed: %s", error_message)

    def _apply_deferred_forensic_context(self) -> None:
        self._launch_deferred_forensic_worker()

    def _refresh_forensic_context(
        self,
        file_path: str,
        snapshot: Mapping[str, Any],
        *,
        include_representation: bool = False,
        include_scope_discovery: bool = False,
    ) -> Dict[str, Any]:
        from src.gui_evidence_presenter import build_forensic_context

        source_sha = str((snapshot.get("source") or {}).get("sha256") or "")
        investigation_root = self._resolve_investigation_root(file_path, source_sha256=source_sha or None)
        workspace_root = investigation_root
        if not workspace_root:
            runs = list_runs_for_source(file_path)
            if runs:
                workspace_root = str(runs[0].get("workspace_path") or "") or None
        context = build_forensic_context(
            source_path=file_path,
            snapshot=snapshot,
            investigation_root=investigation_root,
            workspace_root=workspace_root,
            include_representation=include_representation,
            include_scope_discovery=include_scope_discovery,
        )
        self._forensic_context = context
        self.hex_editor.configure_ui_policy(context.get("ui_policy") or {})
        spans = list(context.get("hex_overlay_spans") or [])
        if spans:
            self.hex_editor.set_forensic_overlay_spans(spans)
        return context

    def show_scope_evidence_on_hex(self) -> None:
        """Merge scope-evidence ranges from forensic context onto hex overlays."""
        context = dict(getattr(self, "_forensic_context", {}) or {})
        scope_evidence = dict(context.get("scope_evidence") or {})
        if not scope_evidence.get("ranges"):
            self.main_window.show_message("Scope on Hex", "No scope evidence ranges in current forensic context.")
            return
        from src.gui_evidence_presenter import build_scope_evidence_overlay_spans
        from src.services.ui_policy import load_ui_policy

        policy = load_ui_policy()
        scope_spans = build_scope_evidence_overlay_spans(scope_evidence, policy=policy)
        merged = list(context.get("hex_overlay_spans") or []) + scope_spans
        self.hex_editor.set_forensic_overlay_spans(merged)
        self.main_window.status_message.setText("Scope evidence ranges applied to hex overlays.")

    def show_record_family_on_hex(self) -> None:
        """Merge record-family training/holdout ranges from the latest verified run."""
        file_path = self.hex_editor.file_path
        if not file_path:
            self.main_window.show_message("Record Family on Hex", "Open a file first.")
            return
        from src.gui_evidence_presenter import build_record_family_overlay_spans
        from src.services.record_family import discover_record_family_run_for_source, inspect_record_family_run
        from src.services.ui_policy import load_ui_policy

        run_path = discover_record_family_run_for_source(file_path)
        if not run_path:
            self.main_window.show_message(
                "Record Family on Hex",
                "No record-family run found for this file identity.",
            )
            return
        inspected = inspect_record_family_run(run_path)
        if not inspected.get("verified"):
            self.main_window.show_message(
                "Record Family on Hex",
                f"Latest run failed verification: {run_path}",
            )
            return
        policy = load_ui_policy()
        family_spans = build_record_family_overlay_spans(inspected, policy=policy)
        if not family_spans:
            self.main_window.show_message(
                "Record Family on Hex",
                "Verified run has no record-family overlay ranges (check View overlay toggles).",
            )
            return
        context = dict(getattr(self, "_forensic_context", {}) or {})
        merged = list(context.get("hex_overlay_spans") or []) + family_spans
        self.hex_editor.set_forensic_overlay_spans(merged)
        self.main_window.status_message.setText(
            f"Record-family overlays applied ({len(family_spans)} spans, run {inspected.get('run_id', '')})."
        )

    def verify_candidate_lineage(self) -> None:
        file_path = self.hex_editor.file_path
        if not file_path:
            self.main_window.show_message("Verify Candidate Lineage", "Open a file first.")
            return
        import hashlib

        from src.services.candidate_lineage import resolve_candidate_lineage, verify_candidate_lineage_chain
        from src.services.candidate_lineage.present import present_lineage_verify_message

        file_sha = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
        packet = resolve_candidate_lineage(file_path=file_path)
        verification = verify_candidate_lineage_chain(packet)
        message = present_lineage_verify_message(
            file_path=str(file_path),
            file_sha256=file_sha,
            packet=packet,
            verification=verification,
        )
        if not packet.get("nodes"):
            self.main_window.show_message(
                "Verify Candidate Lineage",
                f"No verified candidate lineage artifacts match this file.\n\nFile SHA-256:\n{file_sha}",
            )
            return
        self._forensic_context = dict(getattr(self, "_forensic_context", {}) or {})
        self._forensic_context["candidate_lineage"] = packet
        from src.services.candidate_lineage.graph_bridge import unresolved_inference_from_lineage

        hydrated = unresolved_inference_from_lineage(packet)
        if hydrated:
            self._forensic_context["unresolved_inference"] = {
                **dict(self._forensic_context.get("unresolved_inference") or {}),
                **hydrated,
            }
        self.main_window.show_message("Verify Candidate Lineage", message)
        if hasattr(self.main_window, "binary_inspector_widget") and hydrated.get("graph_nodes"):
            self.main_window.binary_inspector_dock.setVisible(True)
            snapshot = self.snapshot_controller.static_snapshot()
            generation = int(self.snapshot_controller.generation)
            if snapshot:
                self.main_window.binary_inspector_widget.update_snapshot(
                    snapshot,
                    generation=generation,
                    forensic_context=self._forensic_context,
                )
            self.main_window.binary_inspector_widget.show_static_section("Binary graph")

    def _refresh_binary_inspector(self, file_path: str, file_ext: str) -> None:
        """Load unified BinarySnapshot into Binary Inspector for PTX and PE files."""
        self._start_snapshot_analysis(file_path, file_ext)

    def show_binary_snapshot_dialog(self) -> None:
        """Open Binary Snapshot dialog for the current file."""
        file_path = self.hex_editor.file_path
        if not file_path:
            self.main_window.show_message("Binary Snapshot", "Open a PTX or PE file first.")
            return
        try:
            from src.runtime.config import load_binary_dynamic_config
            from src.runtime.format_router import detect_format_plugin
            from src.binary_snapshot_dialog import BinarySnapshotDialog

            cfg = load_binary_dynamic_config()
            plugin = detect_format_plugin(file_path, cfg=cfg)
            if plugin not in {"ptx", "pe"}:
                self.main_window.show_message(
                    "Binary Snapshot",
                    "Binary Snapshot is available for PTX and PE files only.",
                )
                return

            loaded = self.snapshot_controller.load_path(file_path, policy=cfg)
            generation = loaded["generation"]
            snapshot = loaded["snapshot"]
            forensic_context = self._refresh_forensic_context(
                file_path,
                snapshot,
                include_representation=True,
                include_scope_discovery=True,
            )
            self.main_window.ptx_metadata_widget.update_runtime_snapshot(snapshot)
            self.main_window.ptx_metadata_widget.update_forensic_context(forensic_context)
            self.main_window.binary_inspector_widget.update_snapshot(
                snapshot,
                generation=generation,
                forensic_context=forensic_context,
            )
            self.main_window.binary_inspector_dock.setVisible(True)

            def refresh_snapshot() -> Dict[str, Any]:
                reloaded = self.snapshot_controller.load_path(file_path, policy=cfg)
                generation = reloaded["generation"]
                context = self._refresh_forensic_context(
                    file_path,
                    reloaded["snapshot"],
                    include_representation=True,
                    include_scope_discovery=True,
                )
                self.main_window.binary_inspector_widget.update_snapshot(
                    reloaded["snapshot"],
                    generation=generation,
                    forensic_context=context,
                )
                reloaded["forensic_context"] = context
                return reloaded

            dialog = BinarySnapshotDialog(
                source_path=file_path,
                snapshot=snapshot,
                validation=loaded.get("validation"),
                waterfall=loaded.get("waterfall"),
                forensic_context=forensic_context,
                on_refresh=refresh_snapshot,
                on_goto_offset=self.goto_offset_from_signal,
                parent=self.main_window,
            )
            if dialog.exec_() == dialog.Accepted:
                self.main_window.binary_inspector_dock.setVisible(True)
                self.main_window.binary_inspector_dock.raise_()
        except Exception as exc:
            logger.exception("Binary Snapshot dialog failed")
            self.main_window.show_message("Binary Snapshot", f"Failed to open snapshot dialog:\n{exc}")

    def refresh_text_inspector(self):
        """Refresh the forensic text inspector from current bytes."""
        if not hasattr(self.main_window, "text_inspector_widget"):
            return

        def apply_refresh() -> None:
            self.main_window.text_inspector_widget.refresh(
                data_provider=self.hex_editor if self.hex_editor.file_path else None,
                selection_provider=self.hex_editor.get_selection,
                cursor_provider=self.hex_editor.get_cursor_byte_offset,
            )
            preview = self.main_window.text_inspector_widget.last_preview()
            if preview:
                self._apply_transform_preview_overlays(preview)

        self.main_window.deliver_dock_update("text_inspector_dock", apply_refresh)

    def _request_async_transform_preview(
        self,
        *,
        file_path: str,
        offset: int,
        length: int,
        mode: str,
        policy: Mapping[str, Any],
    ) -> None:
        if not self.main_window.dock_is_visible("text_inspector_dock"):
            return

        def on_finished(payload: Dict[str, Any]) -> None:
            generation = int(payload.get("generation") or 0)
            if self.transform_preview_controller.is_stale(generation):
                return

            def apply() -> None:
                self.main_window.text_inspector_widget.apply_preview_payload(payload)
                preview = dict(payload.get("result") or {})
                if preview:
                    self._apply_transform_preview_overlays(preview)

            self.main_window.deliver_dock_update("text_inspector_dock", apply)

        def on_failed(message: str, generation: int) -> None:
            if self.transform_preview_controller.is_stale(generation):
                return
            self.main_window.show_message("Transform Preview", f"Preview failed:\n{message}")

        self.transform_preview_controller.request_preview(
            source_path=file_path,
            offset=offset,
            length=length,
            mode=mode,
            policy=policy,
            on_finished=on_finished,
            on_failed=on_failed,
        )

    def _apply_transform_preview_overlays(self, preview: Mapping[str, Any]) -> None:
        from src.services.transform_preview import build_transform_preview_overlay_spans
        from src.services.ui_policy import load_ui_policy

        ui_policy = self.hex_editor.ui_policy or load_ui_policy()
        preview_spans = build_transform_preview_overlay_spans(preview, ui_policy=ui_policy)
        if not preview_spans:
            return
        merged = list(self.hex_editor.forensic_overlay_spans or []) + preview_spans
        self.hex_editor.set_forensic_overlay_spans(merged)

    def export_transform_preview_full_file(self) -> None:
        if not self.hex_editor.file_path:
            self.main_window.show_message("Transform Preview", "No file loaded.")
            return
        if not self.main_window.dock_is_visible("text_inspector_dock"):
            self.main_window.show_message("Transform Preview", "Open Text Inspector to export preview.")
            return
        from src.services.transform_preview import export_full_file_preview, load_transform_preview_policy

        mode = str(self.main_window.text_inspector_widget.mode_selector.currentData() or "raw")
        policy = load_transform_preview_policy()
        destination, _ = QFileDialog.getSaveFileName(
            self.main_window,
            "Export full file preview",
            str(Path(self.hex_editor.file_path).with_suffix(".preview.bin")),
        )
        if not destination:
            return

        def on_finished(payload: Dict[str, Any]) -> None:
            report = dict(payload.get("report") or {})
            self.main_window.show_message(
                "Transform Preview",
                f"Exported {report.get('output_length', 0)} bytes "
                f"({'complete' if report.get('complete') else 'partial'}).\n"
                f"Report: {report.get('report_path', destination)}",
            )

        def on_failed(message: str, generation: int) -> None:
            if self.transform_preview_controller.is_stale(generation):
                return
            self.main_window.show_message("Transform Preview", f"Export failed:\n{message}")

        self.transform_preview_controller.request_preview(
            source_path=self.hex_editor.file_path,
            offset=0,
            length=0,
            mode=mode,
            policy=policy,
            on_finished=on_finished,
            on_failed=on_failed,
            full_file=True,
        )

    def handle_timecodes_found(self, timecodes):
        """Handle timecodes found by the PTX handler."""
        logger.info(f"Received {len(timecodes)} timecodes from PTX handler")
        if self.hex_editor.ptx_handler is not None:
            self.file_handler = self.hex_editor.ptx_handler
            if hasattr(self.main_window, "ptx_metadata_widget"):
                handler = self.file_handler
                self.main_window.deliver_dock_update(
                    "ptx_metadata_dock",
                    lambda ptx=handler: self.main_window.ptx_metadata_widget.update_from_ptx_file(ptx),
                )
        elif hasattr(self.main_window, "ptx_metadata_widget"):
            self.main_window.deliver_dock_update(
                "ptx_metadata_dock",
                lambda codes=timecodes: self.main_window.ptx_metadata_widget.update_timecodes(codes),
            )
        self._current_timecode_index = -1
        self.update_file_structure()
        self.hex_editor.update_display()
        self.update_status_bar()

    def _sorted_timecode_offsets(self) -> List[int]:
        if not self.file_handler or not hasattr(self.file_handler, "timecodes"):
            return []
        return sorted(int(tc.get("offset") or 0) for tc in self.file_handler.timecodes)

    def goto_next_timecode(self) -> None:
        offsets = self._sorted_timecode_offsets()
        if not offsets:
            return
        cursor = self.hex_editor.get_cursor_byte_offset() if hasattr(self.hex_editor, "get_cursor_byte_offset") else 0
        next_offsets = [item for item in offsets if item > cursor]
        target = next_offsets[0] if next_offsets else offsets[0]
        self.goto_offset_from_signal(target)

    def goto_prev_timecode(self) -> None:
        offsets = self._sorted_timecode_offsets()
        if not offsets:
            return
        cursor = self.hex_editor.get_cursor_byte_offset() if hasattr(self.hex_editor, "get_cursor_byte_offset") else 0
        prev_offsets = [item for item in offsets if item < cursor]
        target = prev_offsets[-1] if prev_offsets else offsets[-1]
        self.goto_offset_from_signal(target)

    def goto_timecode_reference(self) -> None:
        if not self.file_handler or not hasattr(self.file_handler, "timecodes"):
            return
        references = [
            int(tc.get("offset") or 0)
            for tc in self.file_handler.timecodes
            if "reference" in str(tc.get("type") or "").lower()
        ]
        if references:
            self.goto_offset_from_signal(references[0])
            return
        offsets = self._sorted_timecode_offsets()
        if offsets:
            self.goto_offset_from_signal(offsets[0])

def main(open_path=None, lab_bridge_root=None):
    """Main entry point for the application."""
    # Create the application
    app = QApplication(sys.argv)
    
    # Create and run the hex editor application
    logger.info("Creating HexEditorApp instance")
    hex_editor_app = HexEditorApp()
    app.aboutToQuit.connect(hex_editor_app.save_app_state)
    if lab_bridge_root:
        hex_editor_app.enable_lab_bridge(lab_bridge_root)
    if open_path:
        hex_editor_app.load_file(normalize_input_path(open_path))
    hex_editor_app.run()
    
    # Run the application event loop
    logger.info("Starting application event loop")
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 
