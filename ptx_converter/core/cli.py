"""
Command-line interface for PTX Converter
"""

import os
import sys
import argparse
from ptx_converter.core.application import PTXConverter
from ptx_converter.utils.logger import logger

def parse_args():
    """
    Parse command-line arguments
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='PTX Converter - Convert Pro Tools PTX files to other formats')
    
    parser.add_argument('input_file', help='Input PTX file')
    parser.add_argument('-o', '--output', help='Output file path (default: same as input with new extension)')
    parser.add_argument('-f', '--format', choices=['cpr', 'studio_one'], default='cpr',
                        help='Output format (default: cpr)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    return parser.parse_args()

def run_cli():
    """
    Run the command-line interface
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    args = parse_args()
    
    if args.verbose:
        logger.debug("Verbose mode enabled")
    
    if args.version:
        print("PTX Converter v1.0.0")
        return 0
    
    print("PTX Converter v1.0.0")
    
    # Create converter instance
    converter = PTXConverter()
    
    # Determine output file path if not specified
    output_file = args.output
    if not output_file:
        base_name = os.path.splitext(args.input_file)[0]
        if args.format == 'cpr':
            output_file = f"{base_name}.cpr"
        elif args.format == 'studio_one':
            output_file = f"{base_name}.song"
    
    # Convert the file
    print(f"Converting {args.input_file} to {args.format} format")
    success = converter.convert_file(args.input_file, output_file, args.format)
    
    if success:
        print(f"Successfully converted to {output_file}")
        return 0
    else:
        print(f"Failed to convert {args.input_file}")
        return 1

if __name__ == "__main__":
    sys.exit(run_cli()) 