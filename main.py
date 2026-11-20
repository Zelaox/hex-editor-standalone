#!/usr/bin/env python3
"""
Main entry point for the HexEditor application.
"""
import sys
import os
import argparse
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).resolve().parent

# Change to the script directory to ensure relative imports work correctly
os.chdir(SCRIPT_DIR)

# Ensure logs directory exists (using absolute path)
logs_dir = SCRIPT_DIR / 'logs'
logs_dir.mkdir(exist_ok=True)

# Add the script directory to Python path if needed
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# Import our modules
from src.app import main
from src.logging_config import setup_logging, get_logger

# Set up logging
setup_logging()

# Get a logger for this module
logger = get_logger('main')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hex Editor with PTX analysis")
    parser.add_argument("--open", dest="open_path", help="Open a file when the desktop editor starts")
    parser.add_argument(
        "--lab-bridge",
        dest="lab_bridge_root",
        help="Optional external runtime dir (UVE, MCP host, AI Lab, etc.) for inbox/outbox desktop commands",
    )
    args = parser.parse_args()
    logger.info("Starting HexEditor application")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"Script directory: {SCRIPT_DIR}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    # Run the application
    try:
        main(args.open_path, args.lab_bridge_root)
    except Exception as e:
        logger.error("Unhandled exception in main", exc_info=True)
        raise
    finally:
        logger.info("HexEditor application exiting") 
