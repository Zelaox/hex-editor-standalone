"""
Main window for the PTX Converter GUI
"""

import os
import sys
import json
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QPushButton, QFileDialog, QComboBox, QTabWidget, 
                            QTextEdit, QTreeWidget, QTreeWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QObject
from ptx_converter.core.application import PTXConverter
from ptx_converter.utils.logger import logger

class WorkerSignals(QObject):
    """Signals for worker thread"""
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(int)
    message = pyqtSignal(str)

class ConversionWorker(threading.Thread):
    """Worker thread for file conversion"""
    
    def __init__(self, converter, input_file, output_file, output_format):
        """Initialize the worker thread"""
        super().__init__()
        self.converter = converter
        self.input_file = input_file
        self.output_file = output_file
        self.output_format = output_format
        self.signals = WorkerSignals()
        
    def run(self):
        """Run the conversion"""
        try:
            self.signals.message.emit(f"Converting {self.input_file} to {self.output_format} format...")
            success = self.converter.convert_file(self.input_file, self.output_file, self.output_format)
            
            if success:
                self.signals.message.emit(f"Successfully converted to {self.output_file}")
                self.signals.finished.emit(True, self.output_file)
            else:
                self.signals.message.emit(f"Failed to convert {self.input_file}")
                self.signals.finished.emit(False, "Conversion failed")
                
        except Exception as e:
            error_msg = f"Error during conversion: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.signals.message.emit(error_msg)
            self.signals.finished.emit(False, error_msg)

class MetadataWorker(threading.Thread):
    """Worker thread for metadata extraction"""
    
    def __init__(self, converter, file_path):
        """Initialize the worker thread"""
        super().__init__()
        self.converter = converter
        self.file_path = file_path
        self.signals = WorkerSignals()
        
    def run(self):
        """Run the metadata extraction"""
        try:
            self.signals.message.emit(f"Extracting metadata from {self.file_path}...")
            metadata = self.converter.extract_metadata(self.file_path)
            
            if metadata:
                self.signals.message.emit(f"Successfully extracted metadata")
                self.signals.finished.emit(True, json.dumps(metadata))
            else:
                self.signals.message.emit(f"Failed to extract metadata from {self.file_path}")
                self.signals.finished.emit(False, "Metadata extraction failed")
                
        except Exception as e:
            error_msg = f"Error during metadata extraction: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.signals.message.emit(error_msg)
            self.signals.finished.emit(False, error_msg)

class MainWindow(QMainWindow):
    """Main window for the PTX Converter GUI"""
    
    def __init__(self):
        """Initialize the main window"""
        super().__init__()
        
        # Initialize the application
        self.converter = PTXConverter()
        
        # Set up the UI
        self.init_ui()
        
        # Initialize state
        self.input_file = ""
        self.output_file = ""
        self.conversion_worker = None
        self.metadata_worker = None
        
        # Log GUI startup
        logger.info("GUI started")
        
    def init_ui(self):
        """Initialize the user interface"""
        # Set window properties
        self.setWindowTitle("PTX Converter")
        self.setMinimumSize(800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Create tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Conversion tab
        conversion_tab = QWidget()
        conversion_layout = QVBoxLayout()
        conversion_tab.setLayout(conversion_layout)
        tabs.addTab(conversion_tab, "Conversion")
        
        # Input file selection
        input_layout = QHBoxLayout()
        input_label = QLabel("Input File:")
        self.input_path_label = QLabel("No file selected")
        input_button = QPushButton("Browse...")
        input_button.clicked.connect(self.select_input_file)
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_path_label, 1)
        input_layout.addWidget(input_button)
        conversion_layout.addLayout(input_layout)
        
        # Output format selection
        format_layout = QHBoxLayout()
        format_label = QLabel("Output Format:")
        self.format_combo = QComboBox()
        for fmt in self.converter.get_supported_formats():
            self.format_combo.addItem(fmt.upper())
        self.format_combo.currentIndexChanged.connect(self.update_output_extension)
        format_layout.addWidget(format_label)
        format_layout.addWidget(self.format_combo, 1)
        conversion_layout.addLayout(format_layout)
        
        # Output file selection
        output_layout = QHBoxLayout()
        output_label = QLabel("Output File:")
        self.output_path_label = QLabel("No file selected")
        output_button = QPushButton("Browse...")
        output_button.clicked.connect(self.select_output_file)
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_path_label, 1)
        output_layout.addWidget(output_button)
        conversion_layout.addLayout(output_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        conversion_layout.addWidget(self.progress_bar)
        
        # Convert button
        convert_button = QPushButton("Convert")
        convert_button.clicked.connect(self.convert_file)
        conversion_layout.addWidget(convert_button)
        
        # Log output
        log_label = QLabel("Log:")
        conversion_layout.addWidget(log_label)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        conversion_layout.addWidget(self.log_text)
        
        # Metadata tab
        metadata_tab = QWidget()
        metadata_layout = QVBoxLayout()
        metadata_tab.setLayout(metadata_layout)
        tabs.addTab(metadata_tab, "Metadata")
        
        # File selection for metadata
        metadata_file_layout = QHBoxLayout()
        metadata_file_label = QLabel("File:")
        self.metadata_file_path_label = QLabel("No file selected")
        metadata_file_button = QPushButton("Browse...")
        metadata_file_button.clicked.connect(self.select_metadata_file)
        metadata_file_layout.addWidget(metadata_file_label)
        metadata_file_layout.addWidget(self.metadata_file_path_label, 1)
        metadata_file_layout.addWidget(metadata_file_button)
        metadata_layout.addLayout(metadata_file_layout)
        
        # Extract button
        extract_button = QPushButton("Extract Metadata")
        extract_button.clicked.connect(self.extract_metadata)
        metadata_layout.addWidget(extract_button)
        
        # Metadata display
        metadata_display_label = QLabel("Metadata:")
        metadata_layout.addWidget(metadata_display_label)
        
        # Create a tab widget for different metadata views
        metadata_tabs = QTabWidget()
        metadata_layout.addWidget(metadata_tabs)
        
        # Text view
        self.metadata_text = QTextEdit()
        self.metadata_text.setReadOnly(True)
        metadata_tabs.addTab(self.metadata_text, "Text View")
        
        # Tree view
        self.metadata_tree = QTreeWidget()
        self.metadata_tree.setHeaderLabels(["Property", "Value"])
        self.metadata_tree.setColumnWidth(0, 200)
        metadata_tabs.addTab(self.metadata_tree, "Tree View")
        
        # Show the window
        self.show()
        
    def select_input_file(self):
        """Select an input file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Input File", "", "PTX Files (*.ptx);;All Files (*.*)"
        )
        
        if file_path:
            self.input_file = file_path
            self.input_path_label.setText(file_path)
            
            # Set default output file
            if not self.output_file:
                self.update_output_file(file_path)
    
    def select_output_file(self):
        """Select an output file"""
        current_format = self.format_combo.currentText().lower()
        file_extension = "song" if current_format == "studio_one" else current_format
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "", f"{current_format.upper()} Files (*.{file_extension});;All Files (*.*)"
        )
        
        if file_path:
            self.output_file = file_path
            self.output_path_label.setText(file_path)
    
    def update_output_extension(self):
        """Update the output file extension based on the selected format"""
        if self.input_file:
            self.update_output_file(self.input_file)
    
    def update_output_file(self, input_file):
        """Update the output file path based on the input file"""
        base_name = os.path.splitext(input_file)[0]
        current_format = self.format_combo.currentText().lower()
        
        if current_format == "studio_one":
            self.output_file = f"{base_name}.song"
        else:
            self.output_file = f"{base_name}.{current_format}"
            
        self.output_path_label.setText(self.output_file)
    
    def convert_file(self):
        """Convert the selected file"""
        if not self.input_file:
            QMessageBox.warning(self, "Warning", "Please select an input file")
            return
        
        if not self.output_file:
            QMessageBox.warning(self, "Warning", "Please select an output file")
            return
        
        # Get the selected format
        output_format = self.format_combo.currentText().lower()
        
        # Create and start the worker thread
        self.conversion_worker = ConversionWorker(
            self.converter, self.input_file, self.output_file, output_format
        )
        self.conversion_worker.signals.message.connect(self.log_message)
        self.conversion_worker.signals.progress.connect(self.update_progress)
        self.conversion_worker.signals.finished.connect(self.conversion_finished)
        self.conversion_worker.start()
        
        # Disable the convert button
        self.findChild(QPushButton, "").setEnabled(False)
    
    def log_message(self, message):
        """Log a message to the log text area"""
        self.log_text.append(message)
    
    def update_progress(self, value):
        """Update the progress bar"""
        self.progress_bar.setValue(value)
    
    def conversion_finished(self, success, message):
        """Handle conversion completion"""
        # Re-enable the convert button
        self.findChild(QPushButton, "").setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Success", f"Conversion completed successfully.\nOutput file: {message}")
        else:
            QMessageBox.critical(self, "Error", f"Conversion failed: {message}")
    
    def select_metadata_file(self):
        """Select a file for metadata extraction"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*.*)"
        )
        
        if file_path:
            self.metadata_file_path_label.setText(file_path)
            
            # Extract metadata automatically
            self.extract_metadata()
    
    def extract_metadata(self):
        """Extract metadata from the selected file"""
        file_path = self.metadata_file_path_label.text()
        
        if file_path == "No file selected":
            QMessageBox.warning(self, "Warning", "Please select a file")
            return
        
        # Create and start the worker thread
        self.metadata_worker = MetadataWorker(self.converter, file_path)
        self.metadata_worker.signals.message.connect(self.log_message)
        self.metadata_worker.signals.finished.connect(self.metadata_extraction_finished)
        self.metadata_worker.start()
    
    def metadata_extraction_finished(self, success, metadata_json):
        """Handle metadata extraction completion"""
        if success:
            try:
                # Parse the JSON
                metadata = json.loads(metadata_json)
                
                # Display in text view
                self.metadata_text.clear()
                self.metadata_text.append(json.dumps(metadata, indent=2))
                
                # Display in tree view
                self.metadata_tree.clear()
                self.populate_metadata_tree(metadata)
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to parse metadata: {str(e)}")
        else:
            QMessageBox.critical(self, "Error", f"Metadata extraction failed: {metadata_json}")
    
    def populate_metadata_tree(self, metadata, parent=None):
        """Populate the metadata tree view"""
        if parent is None:
            parent = self.metadata_tree
        
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                if isinstance(value, (dict, list)):
                    item = QTreeWidgetItem(parent, [str(key), ""])
                    self.populate_metadata_tree(value, item)
                else:
                    QTreeWidgetItem(parent, [str(key), str(value)])
        elif isinstance(metadata, list):
            for i, value in enumerate(metadata):
                if isinstance(value, (dict, list)):
                    item = QTreeWidgetItem(parent, [f"[{i}]", ""])
                    self.populate_metadata_tree(value, item)
                else:
                    QTreeWidgetItem(parent, [f"[{i}]", str(value)])

def run_gui():
    """
    Run the GUI application
    
    Returns:
        int: Exit code
    """
    app = QApplication(sys.argv)
    window = MainWindow()
    return app.exec_()

if __name__ == "__main__":
    sys.exit(run_gui()) 