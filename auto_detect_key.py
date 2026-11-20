#!/usr/bin/env python
"""
Script to automatically detect the decryption key for unknown PTX files.

This script analyzes a PTX file and attempts to determine the decryption key
by testing common XOR patterns and looking for known file signatures.
"""
import os
import sys
import binascii
import argparse
import struct
from typing import List, Tuple, Optional

# Known encryption types and their corresponding keys
KNOWN_ENCRYPTION_TYPES = {
    0: None,  # Not encrypted
    1: bytes([0x55, 0xAA, 0x33, 0x77, 0x12, 0x34, 0x56, 0x78]),  # Basic XOR (example pattern)
    2298806321: bytes([0x94])  # AC240 format (single-byte XOR)
}

# Common text patterns that might appear in decrypted content
COMMON_PATTERNS = [
    b"Tools",
    b"Pro Tools",
    b"Session",
    b"File",
    b"Windows",
    b"Version",
    b"Release",
    b"Audio",
]

def read_ptx_header(file_path: str) -> Tuple[bytes, int]:
    """
    Read a PTX file header and extract encryption type.
    
    Args:
        file_path: Path to the PTX file
    
    Returns:
        Tuple of (header_data, encryption_type)
    """
    with open(file_path, 'rb') as f:
        header_data = f.read(32)
        if len(header_data) < 32:
            raise ValueError("File too small to be a valid PTX file")
        
        # Extract encryption type (bytes 16-20)
        encryption_type = struct.unpack('<I', header_data[16:20])[0]
        
    return header_data, encryption_type

def test_decryption_key(file_path: str, key: bytes, start_offset: int = 16) -> Tuple[bool, List[str]]:
    """
    Test a decryption key on a file and check for common patterns.
    
    Args:
        file_path: Path to the file to test
        key: Decryption key to test
        start_offset: Offset at which to start decrypting
        
    Returns:
        Tuple of (is_likely_correct, matching_patterns)
    """
    matching_patterns = []
    
    with open(file_path, 'rb') as f:
        # Read first 1024 bytes for testing
        data = f.read(1024)
        
    # Apply the key to the data
    decrypted = bytearray(data)
    key_len = len(key)
    
    for i in range(start_offset, len(decrypted)):
        decrypted[i] ^= key[i % key_len]
    
    # Convert to bytes for pattern matching
    decrypted_bytes = bytes(decrypted)
    
    # Check for common patterns
    for pattern in COMMON_PATTERNS:
        if pattern in decrypted_bytes:
            matching_patterns.append(pattern.decode('ascii'))
    
    # If we found at least 2 patterns, it's likely correct
    is_likely_correct = len(matching_patterns) >= 2
    
    return is_likely_correct, matching_patterns

def generate_test_keys() -> List[bytes]:
    """
    Generate a list of potential decryption keys to test.
    
    Returns:
        List of key byte patterns to test
    """
    # Start with known keys from our registry
    keys = list(filter(None, KNOWN_ENCRYPTION_TYPES.values()))
    
    # Add single-byte XOR keys (0x00 - 0xFF)
    for i in range(256):
        # Skip keys we already have
        if bytes([i]) not in keys:
            keys.append(bytes([i]))
    
    # Add some common multi-byte patterns
    additional_patterns = [
        bytes([0xFF, 0xFF]),
        bytes([0xAA, 0xBB]),
        bytes([0x12, 0x34]),
        bytes([0xDE, 0xAD, 0xBE, 0xEF]),
    ]
    
    keys.extend(additional_patterns)
    
    return keys

def find_decryption_key(file_path: str) -> Optional[bytes]:
    """
    Find the most likely decryption key for a PTX file.
    
    Args:
        file_path: Path to the PTX file
        
    Returns:
        Most likely decryption key or None if not found
    """
    # Read header and encryption type
    try:
        header_data, encryption_type = read_ptx_header(file_path)
    except (IOError, ValueError) as e:
        print(f"Error reading PTX header: {e}")
        return None
    
    print(f"File: {file_path}")
    print(f"Header: {binascii.hexlify(header_data[:16]).decode()}")
    print(f"Encryption type from header: {encryption_type}")
    
    # If we know this encryption type, use the known key
    if encryption_type in KNOWN_ENCRYPTION_TYPES:
        key = KNOWN_ENCRYPTION_TYPES[encryption_type]
        if key is None:
            print("File is not encrypted according to the header.")
            return None
        
        print(f"Found known encryption type {encryption_type}, using key: {binascii.hexlify(key).decode()}")
        return key
    
    # Try to detect the key if unknown
    print("Unknown encryption type, testing common keys...")
    
    # Generate test keys
    test_keys = generate_test_keys()
    
    # Track the best match
    best_key = None
    best_match_count = 0
    best_patterns = []
    
    # Test each key
    for key in test_keys:
        is_likely, patterns = test_decryption_key(file_path, key)
        
        if is_likely and len(patterns) > best_match_count:
            best_key = key
            best_match_count = len(patterns)
            best_patterns = patterns
    
    if best_key:
        print("Detected likely decryption key:")
        print(f"Key: 0x{binascii.hexlify(best_key).decode()}")
        print(f"Matches: {', '.join(best_patterns)}")
        
        # If it's a single byte key, show its decimal value
        if len(best_key) == 1:
            print(f"Single-byte key decimal value: {best_key[0]}")
        
        return best_key
    
    print("Could not detect a likely decryption key.")
    return None

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Auto-detect decryption key for PTX files")
    parser.add_argument("file", help="Path to the PTX file")
    parser.add_argument("--test-decrypt", "-t", action="store_true", 
                        help="Create a test decryption with the detected key")
    
    args = parser.parse_args()
    
    # Find the key
    key = find_decryption_key(args.file)
    
    # If requested, create a test decryption
    if key and args.test_decrypt:
        output_path = f"{args.file}.test_decrypted"
        print(f"\nCreating test decryption at: {output_path}")
        
        try:
            with open(args.file, 'rb') as src, open(output_path, 'wb') as dst:
                data = src.read()
                decrypted = bytearray(data)
                
                # Apply key from offset 16
                key_len = len(key)
                for i in range(16, len(decrypted)):
                    decrypted[i] ^= key[i % key_len]
                
                dst.write(decrypted)
                
            print("Test decryption completed successfully.")
        except IOError as e:
            print(f"Error creating test decryption: {e}")

if __name__ == "__main__":
    main() 