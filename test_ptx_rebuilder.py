#!/usr/bin/env python
"""
Test script for PTX Rebuilder functionality.

This script demonstrates:
1. Loading PTX components from an extracted directory or a source PTX file
2. Modifying header fields, timecodes, and sections
3. Rebuilding the PTX file with changes
4. Optionally encrypting the output

Usage:
    python test_ptx_rebuilder.py [path_to_components/source_ptx] [output_path] [--encrypt] [--source-file]
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/ptx_rebuilder_test.log')
    ]
)
logger = logging.getLogger('ptx_rebuilder_test')

# Add the project root to the path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Import our PTX rebuilder module
from src.ptx_rebuilder import PTXRebuilder
from src.constants import PTX_TIMECODE_REFERENCES, PTX_SECTION_TYPES

def run_rebuilder_test(input_path=None, output_path=None, encrypt=False, source_file=False):
    """
    Run a test of the PTX rebuilder functionality.
    
    Args:
        input_path: Path to components directory or source PTX file
        output_path: Path to save the rebuilt PTX file
        encrypt: Whether to encrypt the output file
        source_file: Whether input_path is a source PTX file
    """
    logger.info(f"Starting PTX rebuilder test with {'source file' if source_file else 'components'}")
    
    # Use default paths if not provided
    if input_path is None:
        if source_file:
            input_path = "ac240_decrypted.ptx"  # Default PTX file
        else:
            input_path = "test_output"  # Default components directory
    
    if output_path is None:
        output_path = "rebuilt_ptx.ptx"
    
    # Create a PTX rebuilder instance
    if source_file:
        rebuilder = PTXRebuilder(source_ptx=input_path)
    else:
        rebuilder = PTXRebuilder(components_dir=input_path)
    
    if not rebuilder.header_data:
        logger.error(f"Failed to load {'source file' if source_file else 'components'} from {input_path}")
        return False
    
    logger.info(f"Successfully loaded {len(rebuilder.sections)} sections and {len(rebuilder.timecodes)} timecodes")
    
    # Perform some modifications
    
    # 1. Modify a header field (e.g., version)
    logger.info("Modifying header field (version)")
    rebuilder.set_header_field("version", 1)
    
    # 2. Modify a timecode (e.g., first reference point)
    if rebuilder.timecodes:
        reference_points = [tc for tc in rebuilder.timecodes if tc.get("reference_point", False)]
        if reference_points:
            logger.info("Modifying a reference timecode")
            # Change the first reference point to 01:00:00:00
            ref_point = reference_points[0]
            rebuilder.set_timecode(
                ref_point["offset"],
                "01:00:00:00",
                ref_point["type"],
                True
            )
            logger.info(f"Modified timecode at offset 0x{ref_point['offset']:08x}")
        else:
            logger.warning("No reference timecodes found to modify")
    else:
        logger.warning("No timecodes found to modify")
    
    # 3. Add a new section if we have at least one existing section
    if rebuilder.sections:
        logger.info("Adding a new custom section")
        # Create a simple text section
        section_data = b"This is a custom section added by the PTX rebuilder test"
        # Use a common section type (Session Info)
        section_type = next((k for k, v in PTX_SECTION_TYPES.items() if "Session Info" in v), 1)
        rebuilder.add_section(section_data, section_type)
    
    # Now rebuild the PTX file
    logger.info(f"Rebuilding PTX file to {output_path}")
    success = rebuilder.rebuild(output_path, encrypt=encrypt)
    
    if success:
        logger.info(f"Successfully rebuilt PTX file: {output_path}, size: {rebuilder.output_size} bytes")
        logger.info(f"Encryption: {'Enabled' if encrypt else 'Disabled'}")
        
        # Verify the file was created and has the expected size
        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            logger.info(f"Output file size: {file_size} bytes")
            if file_size != rebuilder.output_size:
                logger.warning(f"Output file size ({file_size}) doesn't match expected size ({rebuilder.output_size})")
        else:
            logger.error(f"Output file was not created at {output_path}")
            return False
    else:
        logger.error("Failed to rebuild PTX file")
        return False
    
    return True

def main():
    """Main function to parse arguments and run the test."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Test PTX Rebuilder functionality")
    parser.add_argument("input_path", nargs="?", default=None,
                        help="Path to components directory or source PTX file")
    parser.add_argument("output_path", nargs="?", default=None,
                        help="Path to save the rebuilt PTX file")
    parser.add_argument("--encrypt", action="store_true",
                        help="Encrypt the output file using AC240 encryption")
    parser.add_argument("--source-file", action="store_true",
                        help="Treat input_path as a source PTX file instead of a components directory")
    
    args = parser.parse_args()
    
    # Ensure the logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Run the test
    success = run_rebuilder_test(args.input_path, args.output_path, args.encrypt, args.source_file)
    
    # Return appropriate exit code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 