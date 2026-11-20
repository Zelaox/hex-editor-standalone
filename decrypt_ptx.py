#!/usr/bin/env python
"""
Script to decrypt PTX files from the command line.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from src.ptx_handler import PTXFile, detect_file_type
from src.logging_config import setup_logging, get_logger

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

def decrypt_ptx_file(input_path, output_path=None, output_dir=None, minimal_output=False):
    """
    Decrypt a PTX file.
    
    Args:
        input_path: Path to the PTX file
        output_path: Path to save the decrypted file (optional)
        output_dir: Directory to save extracted sections (optional)
        minimal_output: Whether to use minimal output
    
    Returns:
        True if successful, False otherwise
    """
    # Resolve paths
    input_path = os.path.abspath(input_path)
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        return False
    
    # Determine output path if not provided
    if not output_path:
        output_path = f"{input_path}.decrypted"
    
    # Detect file type
    file_handler = detect_file_type(input_path)
    if not file_handler:
        print(f"Error: Unknown file type: {input_path}")
        return False
    
    # Decrypt the file
    if not minimal_output:
        print(f"Decrypting {input_path} to {output_path}...")
    
    success = file_handler.decrypt(output_path)
    
    if not success:
        print("Error: Decryption failed")
        return False
    
    if not minimal_output:
        print(f"File successfully decrypted to {output_path}")
    
    # Extract sections if output_dir provided
    if output_dir:
        if not minimal_output:
            print(f"Extracting sections to {output_dir}...")
        
        # Create the output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Load the decrypted file
        decrypted_handler = PTXFile(output_path)
        if not decrypted_handler.parse():
            print("Error: Failed to parse decrypted file")
            return False
        
        # Extract all sections
        extracted_files = decrypted_handler.extract_all(output_dir)
        
        if not extracted_files:
            print("Error: Failed to extract sections")
            return False
        
        if minimal_output:
            print(f"Extracted {len(extracted_files)} sections to {output_dir}")
        else:
            # Print extraction summary
            print("\nExtraction Summary:")
            print("-" * 60)
            for section_name, section_path in extracted_files.items():
                print(f"  {section_name}: {os.path.basename(section_path)}")
            print("-" * 60)
    
    return True

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Decrypt and extract PTX files")
    parser.add_argument("input", help="Input PTX file path")
    parser.add_argument("-o", "--output", help="Output decrypted file path")
    parser.add_argument("-d", "--extract-dir", help="Directory to extract sections to")
    parser.add_argument("-f", "--force", action="store_true", help="Force overwrite if output file exists")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimize output messages")
    parser.add_argument("-r", "--results-only", action="store_true", help="Show only results, no logging")
    
    args = parser.parse_args()
    
    # Set up appropriate logging
    if args.results_only:
        quiet_setup_logging()
    else:
        setup_logging()
        # Set console handler level based on quiet flag
        if args.quiet:
            for handler in logging.getLogger().handlers:
                if isinstance(handler, logging.StreamHandler):
                    handler.setLevel(logging.ERROR)  # Only show errors
    
    # Check if output file exists
    if args.output and os.path.exists(args.output) and not args.force:
        print(f"Error: Output file {args.output} already exists. Use --force to overwrite.")
        return 1
    
    # Run the decryption
    success = decrypt_ptx_file(args.input, args.output, args.extract_dir, 
                              minimal_output=args.results_only)
    
    # Show only the final result
    if success:
        output_path = args.output if args.output else f"{args.input}.decrypted"
        if args.results_only:
            print(f"SUCCESS: {args.input} → {output_path}")
        elif not args.quiet:
            print(f"\nSuccess: Decrypted {args.input} to {output_path}")
        return 0
    else:
        if args.results_only:
            print(f"FAILED: {args.input}")
        else:
            print(f"\nError: Failed to decrypt {args.input}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 