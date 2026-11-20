#!/usr/bin/env python
"""
Command-line interface for PTX Rebuilder tool.

This tool allows users to:
1. Rebuild a PTX file from extracted components
2. Restructure a PTX file from a source file
3. Modify header fields, timecodes, and sections
4. Encrypt or decrypt PTX files

Examples:
    # Rebuild from components
    python ptx_rebuild_cli.py rebuild --components test_output --output rebuilt.ptx

    # Rebuild from source file
    python ptx_rebuild_cli.py rebuild --source ac240_decrypted.ptx --output rebuilt.ptx

    # Encrypt a PTX file
    python ptx_rebuild_cli.py encrypt input.ptx output.ptx

    # Decrypt a PTX file
    python ptx_rebuild_cli.py decrypt input.ptx output.ptx

    # Modify a specific timecode
    python ptx_rebuild_cli.py modify --input ac240_decrypted.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
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
        logging.FileHandler(os.path.join('logs', 'ptx_rebuilder_cli.log'))
    ]
)
logger = logging.getLogger('ptx_rebuilder_cli')

# Ensure we can import our modules
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Import the PTX rebuilder
from src.ptx_rebuilder import PTXRebuilder

def cmd_rebuild(args):
    """
    Rebuild a PTX file from components or a source file.
    
    Args:
        args: Command-line arguments
    """
    # Check if components or source is provided
    if not args.components and not args.source:
        logger.error("Either --components or --source must be provided")
        return False
    
    # Create the rebuilder instance
    if args.components:
        logger.info(f"Rebuilding from components: {args.components}")
        rebuilder = PTXRebuilder(components_dir=args.components)
    else:
        logger.info(f"Rebuilding from source: {args.source}")
        rebuilder = PTXRebuilder(source_ptx=args.source)
    
    # Check if rebuilder initialized successfully
    if not rebuilder.header_data:
        logger.error("Failed to initialize rebuilder")
        return False
    
    # Apply header modifications if provided
    if args.header:
        for header_mod in args.header:
            try:
                field, value = header_mod.split('=')
                logger.info(f"Setting header field: {field} = {value}")
                rebuilder.set_header_field(field, value)
            except Exception as e:
                logger.error(f"Failed to set header field: {str(e)}")
    
    # Apply timecode modifications if provided
    if args.timecode:
        for tc_mod in args.timecode:
            try:
                # Format: offset=value[,type][,ref]
                tc_parts = tc_mod.split('=')
                if len(tc_parts) != 2:
                    logger.error(f"Invalid timecode format: {tc_mod}")
                    continue
                
                offset = tc_parts[0]
                value_parts = tc_parts[1].split(',')
                value = value_parts[0]
                tc_type = value_parts[1] if len(value_parts) > 1 else None
                is_ref = value_parts[2].lower() in ['true', 'yes', '1'] if len(value_parts) > 2 else None
                
                logger.info(f"Setting timecode: offset={offset}, value={value}, type={tc_type}, ref={is_ref}")
                rebuilder.set_timecode(offset, value, tc_type, is_ref)
            except Exception as e:
                logger.error(f"Failed to set timecode: {str(e)}")
    
    # Rebuild the file
    logger.info(f"Rebuilding to: {args.output}")
    success = rebuilder.rebuild(args.output, encrypt=args.encrypt)
    
    if success:
        logger.info(f"Successfully rebuilt PTX file: {args.output}")
        logger.info(f"File size: {rebuilder.output_size} bytes")
        logger.info(f"Encrypted: {args.encrypt}")
    else:
        logger.error(f"Failed to rebuild PTX file")
    
    return success

def cmd_encrypt(args):
    """
    Encrypt a PTX file.
    
    Args:
        args: Command-line arguments
    """
    logger.info(f"Encrypting: {args.input} -> {args.output}")
    
    # Create a rebuilder instance from the source file
    rebuilder = PTXRebuilder(source_ptx=args.input)
    
    # Check if the rebuilder initialized successfully
    if not rebuilder.header_data:
        logger.error(f"Failed to load source file: {args.input}")
        return False
    
    # Encrypt the file
    encryption_key = args.key if args.key is not None else 0x94
    success = rebuilder.encrypt_file(args.input, args.output, encryption_key)
    
    if success:
        logger.info(f"Successfully encrypted file with key 0x{encryption_key:02x}")
    else:
        logger.error("Failed to encrypt file")
    
    return success

def cmd_decrypt(args):
    """
    Decrypt a PTX file.
    
    Args:
        args: Command-line arguments
    """
    logger.info(f"Decrypting: {args.input} -> {args.output}")
    
    # Create a PTXFile instance to check encryption type
    from src.ptx_handler import PTXFile
    ptx_file = PTXFile(args.input)
    if not ptx_file.parse():
        logger.error(f"Failed to parse PTX file: {args.input}")
        return False
    
    # Check if the file is encrypted
    if not ptx_file.header.is_encrypted():
        logger.warning(f"File appears to not be encrypted: {args.input}")
        if args.force:
            logger.info("Continuing anyway due to --force")
        else:
            logger.error("Use --force to decrypt anyway")
            return False
    
    # Determine encryption type and key
    encryption_info = ptx_file.header.get_encryption_info()
    encryption_type = encryption_info.get("type", 0)
    
    # Default to 0x94 if AC240 encryption
    encryption_key = args.key
    if encryption_key is None:
        if encryption_type == 2298806321:  # AC240
            encryption_key = 0x94
        else:
            encryption_key = 0x01  # Default for unknown types
    
    logger.info(f"Using encryption key: 0x{encryption_key:02x}")
    
    # Decrypt by applying the same key (XOR is its own inverse)
    with open(args.input, 'rb') as f_in:
        with open(args.output, 'wb') as f_out:
            # Copy header up to offset 16 unchanged
            header = f_in.read(16)
            f_out.write(header)
            
            # Change encryption type to 0 (not encrypted)
            f_out.write(b'\x00\x00\x00\x00')
            
            # Skip encryption type in input file
            f_in.seek(20)
            
            # Apply XOR decryption to the rest
            while True:
                chunk = f_in.read(4096)
                if not chunk:
                    break
                
                # XOR with key
                decrypted_chunk = bytes([b ^ encryption_key for b in chunk])
                f_out.write(decrypted_chunk)
    
    logger.info(f"Successfully decrypted file: {args.output}")
    return True

def cmd_modify(args):
    """
    Modify a PTX file without fully rebuilding it.
    
    Args:
        args: Command-line arguments
    """
    logger.info(f"Modifying PTX file: {args.input} -> {args.output}")
    
    # Create a rebuilder instance from the source file
    rebuilder = PTXRebuilder(source_ptx=args.input)
    
    # Check if the rebuilder initialized successfully
    if not rebuilder.header_data:
        logger.error(f"Failed to load source file: {args.input}")
        return False
    
    # Track if any modifications were made
    modifications_made = False
    
    # Apply header modifications if provided
    if args.header:
        for header_mod in args.header:
            try:
                field, value = header_mod.split('=')
                logger.info(f"Setting header field: {field} = {value}")
                success = rebuilder.set_header_field(field, value)
                modifications_made = modifications_made or success
            except Exception as e:
                logger.error(f"Failed to set header field: {str(e)}")
    
    # Apply timecode modifications if provided
    if args.timecode:
        for tc_mod in args.timecode:
            try:
                # Format: offset=value[,type][,ref]
                tc_parts = tc_mod.split('=')
                if len(tc_parts) != 2:
                    logger.error(f"Invalid timecode format: {tc_mod}")
                    continue
                
                offset = tc_parts[0]
                value_parts = tc_parts[1].split(',')
                value = value_parts[0]
                tc_type = value_parts[1] if len(value_parts) > 1 else None
                is_ref = value_parts[2].lower() in ['true', 'yes', '1'] if len(value_parts) > 2 else None
                
                logger.info(f"Setting timecode: offset={offset}, value={value}, type={tc_type}, ref={is_ref}")
                success = rebuilder.set_timecode(offset, value, tc_type, is_ref)
                modifications_made = modifications_made or success
            except Exception as e:
                logger.error(f"Failed to set timecode: {str(e)}")
    
    # If no modifications were made, return error
    if not modifications_made:
        logger.error("No modifications were made to the file")
        return False
    
    # Create a copy of the file with modifications
    logger.info(f"Saving modified file to: {args.output}")
    success = rebuilder.rebuild(args.output, encrypt=args.encrypt)
    
    if success:
        logger.info(f"Successfully modified PTX file: {args.output}")
        logger.info(f"File size: {rebuilder.output_size} bytes")
        logger.info(f"Encrypted: {args.encrypt}")
    else:
        logger.error(f"Failed to save modified PTX file")
    
    return success

def main():
    """Main function to parse command-line arguments and execute commands."""
    # Create the main parser
    parser = argparse.ArgumentParser(
        description="PTX Rebuilder - Tool for rebuilding and modifying PTX files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Add common arguments
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Rebuild command
    rebuild_parser = subparsers.add_parser("rebuild", help="Rebuild a PTX file")
    rebuild_parser.add_argument("--components", "-c", help="Directory containing extracted components")
    rebuild_parser.add_argument("--source", "-s", help="Source PTX file to rebuild from")
    rebuild_parser.add_argument("--output", "-o", required=True, help="Output file path")
    rebuild_parser.add_argument("--encrypt", "-e", action="store_true", help="Encrypt the output file")
    rebuild_parser.add_argument("--header", "-H", action="append", 
                                help="Modify header field (format: field=value)")
    rebuild_parser.add_argument("--timecode", "-t", action="append", 
                                help="Modify timecode (format: offset=value[,type][,ref])")
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a PTX file")
    encrypt_parser.add_argument("input", help="Input PTX file")
    encrypt_parser.add_argument("output", help="Output encrypted file")
    encrypt_parser.add_argument("--key", "-k", type=int, help="Encryption key (default: 0x94 for AC240)")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a PTX file")
    decrypt_parser.add_argument("input", help="Input encrypted PTX file")
    decrypt_parser.add_argument("output", help="Output decrypted file")
    decrypt_parser.add_argument("--key", "-k", type=int, help="Decryption key (default: 0x94 for AC240)")
    decrypt_parser.add_argument("--force", "-f", action="store_true", 
                                help="Force decryption even if file appears unencrypted")
    
    # Modify command
    modify_parser = subparsers.add_parser("modify", help="Modify a PTX file")
    modify_parser.add_argument("--input", "-i", required=True, help="Input PTX file")
    modify_parser.add_argument("--output", "-o", required=True, help="Output modified file")
    modify_parser.add_argument("--encrypt", "-e", action="store_true", help="Encrypt the output file")
    modify_parser.add_argument("--header", "-H", action="append", 
                                help="Modify header field (format: field=value)")
    modify_parser.add_argument("--timecode", "-t", action="append", 
                                help="Modify timecode (format: offset=value[,type][,ref])")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set log level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Ensure the logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Execute the appropriate command
    if args.command == "rebuild":
        success = cmd_rebuild(args)
    elif args.command == "encrypt":
        success = cmd_encrypt(args)
    elif args.command == "decrypt":
        success = cmd_decrypt(args)
    elif args.command == "modify":
        success = cmd_modify(args)
    else:
        parser.print_help()
        success = False
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 