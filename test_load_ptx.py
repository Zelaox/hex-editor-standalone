#!/usr/bin/env python
"""
Simple test script to load a PTX file with minimal logging.
"""
import os
import sys
import argparse
import logging
from src.ptx_handler import PTXFile, detect_file_type
from src.logging_config import get_logger

def quiet_setup_logging():
    """Set up logging with console output completely disabled."""
    # Configure logging with only errors showing
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.ERROR)  # Only process ERROR and higher
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add a null handler to prevent "No handlers could be found" warnings
    root_logger.addHandler(logging.NullHandler())
    
    return root_logger

def main():
    # Set up minimal logging
    quiet_setup_logging()
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Test loading a PTX file with minimal output")
    parser.add_argument("input", help="Input PTX file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    
    args = parser.parse_args()
    
    # Get the file path
    file_path = args.input
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist")
        return 1
    
    # Detect file type
    print("-" * 50)
    print(f"Testing file: {file_path}")
    print("-" * 50)
    
    file_handler = detect_file_type(file_path)
    if not file_handler:
        print("ERROR: Unknown file type")
        return 1
    
    # Parse the file
    if not file_handler.parse():
        print("ERROR: Failed to parse file")
        return 1
    
    # Get encryption info
    encryption_info = file_handler.header.get_encryption_info()
    
    # Print summary information
    print("File Summary:")
    print(f"- File size: {os.path.getsize(file_path):,} bytes")
    print(f"- Magic: {file_handler.header.magic}")
    print(f"- Encrypted: {encryption_info['encrypted']}")
    print(f"- Encryption type: {encryption_info['description']}")
    print(f"- Sections: {len(file_handler.sections)}")
    
    # Print section information if verbose
    if args.verbose:
        print("\nSection Information:")
        for i, section in enumerate(file_handler.sections):
            print(f"Section {i+1}:")
            print(f"- Type: {section.type} ({section.get_section_type_name()})")
            print(f"- Size: {section.size:,} bytes")
            print(f"- Offset: 0x{section.offset:08x}")
            print(f"- Flags: 0x{section.flags:08x}")
            print()
    
    print("-" * 50)
    print("SUCCESS: File parsed successfully")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 