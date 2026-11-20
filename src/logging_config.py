"""
Logging configuration for the HexEditor application.
"""
import os
import sys
import logging
import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Constants
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

# Component-specific loggers
UI_LOGGER_NAME = 'hexeditor.ui'
HEX_EDITOR_LOGGER_NAME = 'hexeditor.editor'
SEARCH_LOGGER_NAME = 'hexeditor.search'
DISASSEMBLER_LOGGER_NAME = 'hexeditor.disassembler'
EXTRACTOR_LOGGER_NAME = 'hexeditor.extractor'
APP_LOGGER_NAME = 'hexeditor.app'

def setup_logging():
    """
    Set up logging for the application.
    
    Creates a logs directory if it doesn't exist and configures logging
    to write to both a file and the console.
    """
    # Create logs directory using current working directory (should be set by main.py)
    # Fall back to script directory if working directory is not set correctly
    try:
        logs_dir = Path('logs').resolve()
    except (OSError, ValueError):
        # If relative path fails, use script directory
        script_dir = Path(__file__).resolve().parent.parent
        logs_dir = script_dir / 'logs'
    logs_dir.mkdir(exist_ok=True)
    
    # Create a formatter
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    
    # Create a root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create a console handler - only show INFO and above messages
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)  # Only show INFO and above in console
    root_logger.addHandler(console_handler)
    
    # Create a daily rotating file handler for general logs
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    log_file = logs_dir / f'hexeditor_{today}.log'
    file_handler = TimedRotatingFileHandler(
        log_file,
        when='midnight',
        interval=1,
        backupCount=BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(LOG_LEVEL)
    root_logger.addHandler(file_handler)
    
    # Create a size-based rotating file handler for detailed logs
    detailed_log_file = logs_dir / 'hexeditor_detailed.log'
    detailed_handler = RotatingFileHandler(
        detailed_log_file,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT
    )
    detailed_handler.setFormatter(formatter)
    detailed_handler.setLevel(LOG_LEVEL)
    root_logger.addHandler(detailed_handler)
    
    # Set up component-specific log files
    setup_component_logger(UI_LOGGER_NAME, logs_dir / 'ui.log', formatter)
    setup_component_logger(HEX_EDITOR_LOGGER_NAME, logs_dir / 'editor.log', formatter)
    setup_component_logger(SEARCH_LOGGER_NAME, logs_dir / 'search.log', formatter)
    setup_component_logger(DISASSEMBLER_LOGGER_NAME, logs_dir / 'disassembler.log', formatter)
    setup_component_logger(EXTRACTOR_LOGGER_NAME, logs_dir / 'extractor.log', formatter)
    setup_component_logger(APP_LOGGER_NAME, logs_dir / 'app.log', formatter)
    
    # Log startup information
    logging.info("=" * 80)
    logging.info("HexEditor application starting")
    logging.info(f"Log files directory: {logs_dir.absolute()}")
    logging.info(f"Python version: {sys.version}")
    logging.info(f"Platform: {sys.platform}")
    logging.info("=" * 80)
    
    return root_logger

def setup_component_logger(logger_name, log_file, formatter):
    """
    Set up a logger for a specific component.
    
    Args:
        logger_name: Name of the logger
        log_file: Path to the log file
        formatter: Log formatter to use
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(LOG_LEVEL)
    
    # Create a rotating file handler
    handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT
    )
    handler.setFormatter(formatter)
    handler.setLevel(LOG_LEVEL)
    
    # Add the handler to the logger
    logger.addHandler(handler)
    
    return logger

def get_logger(component_name):
    """
    Get a logger for a specific component.
    
    Args:
        component_name: Name of the component
        
    Returns:
        Logger for the component
    """
    if component_name == 'ui':
        return logging.getLogger(UI_LOGGER_NAME)
    elif component_name == 'editor':
        return logging.getLogger(HEX_EDITOR_LOGGER_NAME)
    elif component_name == 'search':
        return logging.getLogger(SEARCH_LOGGER_NAME)
    elif component_name == 'disassembler':
        return logging.getLogger(DISASSEMBLER_LOGGER_NAME)
    elif component_name == 'extractor':
        return logging.getLogger(EXTRACTOR_LOGGER_NAME)
    elif component_name == 'app':
        return logging.getLogger(APP_LOGGER_NAME)
    else:
        return logging.getLogger()

def log_exception(exc_type, exc_value, exc_traceback):
    """
    Log an exception.
    
    Args:
        exc_type: Exception type
        exc_value: Exception value
        exc_traceback: Exception traceback
    """
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)) 