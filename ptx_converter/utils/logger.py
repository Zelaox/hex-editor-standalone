"""
Logging functionality for the PTX Converter
"""

import os
import logging
from logging.handlers import RotatingFileHandler

class Logger:
    """Logger class for the PTX Converter"""
    
    def __init__(self):
        """Initialize the logger"""
        self.logger = logging.getLogger("PTXConverter")
        self.logger.setLevel(logging.DEBUG)
        
        # Create logs directory if it doesn't exist
        logs_dir = "logs"
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
        
        # Create formatters
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)  # Default to INFO for console
        console_handler.setFormatter(console_formatter)
        
        # Create application log file handler
        app_log_file = os.path.join(logs_dir, "application.log")
        app_file_handler = RotatingFileHandler(app_log_file, maxBytes=1024*1024, backupCount=5)
        app_file_handler.setLevel(logging.INFO)
        app_file_handler.setFormatter(file_formatter)
        
        # Create debug log file handler
        debug_log_file = os.path.join(logs_dir, "debug.log")
        debug_file_handler = RotatingFileHandler(debug_log_file, maxBytes=1024*1024, backupCount=5)
        debug_file_handler.setLevel(logging.DEBUG)
        debug_file_handler.setFormatter(file_formatter)
        
        # Create error log file handler
        error_log_file = os.path.join(logs_dir, "errors.log")
        error_file_handler = RotatingFileHandler(error_log_file, maxBytes=1024*1024, backupCount=5)
        error_file_handler.setLevel(logging.ERROR)
        error_file_handler.setFormatter(file_formatter)
        
        # Create file operations log file handler
        file_ops_log_file = os.path.join(logs_dir, "fileOperations.log")
        file_ops_file_handler = RotatingFileHandler(file_ops_log_file, maxBytes=1024*1024, backupCount=5)
        file_ops_file_handler.setLevel(logging.INFO)
        file_ops_file_handler.setFormatter(file_formatter)
        
        # Add handlers to logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(app_file_handler)
        self.logger.addHandler(debug_file_handler)
        self.logger.addHandler(error_file_handler)
        
        # Store handlers for later use
        self.console_handler = console_handler
        self.app_file_handler = app_file_handler
        self.debug_file_handler = debug_file_handler
        self.error_file_handler = error_file_handler
        self.file_ops_file_handler = file_ops_file_handler
        
        # Create a separate logger for file operations
        self.file_ops_logger = logging.getLogger("PTXConverter.FileOps")
        self.file_ops_logger.setLevel(logging.INFO)
        self.file_ops_logger.addHandler(file_ops_file_handler)
        
        # Prevent propagation to avoid duplicate logs
        self.file_ops_logger.propagate = False
    
    def set_verbose(self, verbose=True):
        """
        Set verbose mode for console output
        
        Args:
            verbose (bool): Whether to enable verbose mode
        """
        if verbose:
            self.console_handler.setLevel(logging.DEBUG)
        else:
            self.console_handler.setLevel(logging.INFO)
    
    def debug(self, message):
        """
        Log a debug message
        
        Args:
            message (str): The message to log
        """
        self.logger.debug(message)
    
    def info(self, message):
        """
        Log an info message
        
        Args:
            message (str): The message to log
        """
        self.logger.info(message)
    
    def warning(self, message):
        """
        Log a warning message
        
        Args:
            message (str): The message to log
        """
        self.logger.warning(message)
    
    def error(self, message, exc_info=False):
        """
        Log an error message
        
        Args:
            message (str): The message to log
            exc_info (bool): Whether to include exception info
        """
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message, exc_info=False):
        """
        Log a critical message
        
        Args:
            message (str): The message to log
            exc_info (bool): Whether to include exception info
        """
        self.logger.critical(message, exc_info=exc_info)
    
    def log_file_operation(self, operation, file_path, status, message=""):
        """
        Log a file operation
        
        Args:
            operation (str): The operation being performed (READ, WRITE, CONVERT, etc.)
            file_path (str): The path of the file being operated on
            status (str): The status of the operation (SUCCESS, FAILURE, etc.)
            message (str, optional): Additional message
        """
        log_message = f"{operation} - {file_path} - {status}"
        if message:
            log_message += f" - {message}"
        self.file_ops_logger.info(log_message)

# Create a global logger instance
logger = Logger() 