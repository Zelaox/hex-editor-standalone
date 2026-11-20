"""
Main entry point for PTX Converter
"""

import sys
from ptx_converter.core.cli import run_cli
from ptx_converter.gui.main_window import run_gui

def main():
    """
    Main entry point for the application
    
    Returns:
        int: Exit code
    """
    # If no arguments are provided, run the GUI
    if len(sys.argv) == 1:
        return run_gui()
    
    # Otherwise, run the CLI
    return run_cli()

if __name__ == "__main__":
    sys.exit(main()) 