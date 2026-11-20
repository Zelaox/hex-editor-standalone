#!/usr/bin/env python
"""
Script to search for meaningful strings in a decrypted PTX file.
"""
import os
import re
import sys
import binascii
import argparse
from datetime import datetime

def is_printable(s):
    """Check if a string consists of printable ASCII characters."""
    return all(32 <= ord(c) <= 126 for c in s)

def extract_strings(file_path, min_length=4, context_bytes=16):
    """
    Extract meaningful strings from a binary file.
    
    Args:
        file_path: Path to the binary file
        min_length: Minimum string length to consider
        context_bytes: Number of bytes of context to show around each string
    
    Returns:
        List of tuples containing (offset, string, hex_context)
    """
    results = []
    
    # Common patterns to look for
    date_pattern = re.compile(r'\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2}')
    time_pattern = re.compile(r'\d{2}:\d{2}:\d{2}')
    
    # Pro Tools specific patterns
    pro_tools_patterns = [
        re.compile(r'Pro Tools'),
        re.compile(r'Session'),
        re.compile(r'Track'),
        re.compile(r'Clip'),
        re.compile(r'Audio'),
        re.compile(r'MIDI'),
        re.compile(r'Plugin'),
        re.compile(r'Instrument'),
        re.compile(r'Tempo'),
        re.compile(r'Sample Rate'),
        re.compile(r'Bit Depth'),
        re.compile(r'Markers'),
        re.compile(r'Version'),
        re.compile(r'Format'),
        re.compile(r'\d+.\d+ ?[kK][hH][zZ]'),  # Sample rate pattern
        re.compile(r'\d+ ?[bB][iI][tT]'),  # Bit depth pattern
    ]
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Extract ASCII strings
    current_string = ""
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # ASCII printable
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                # Check for meaningful patterns
                is_meaningful = False
                
                # Check for dates and times
                if date_pattern.search(current_string) or time_pattern.search(current_string):
                    is_meaningful = True
                
                # Check for Pro Tools specific patterns
                for pattern in pro_tools_patterns:
                    if pattern.search(current_string):
                        is_meaningful = True
                        break
                
                # Check if it's mostly alphanumeric
                alpha_ratio = sum(c.isalnum() or c.isspace() for c in current_string) / len(current_string)
                if alpha_ratio > 0.8 and len(current_string) >= 6:
                    is_meaningful = True
                
                if is_meaningful:
                    # Get context
                    start = max(0, i - len(current_string) - context_bytes)
                    end = min(len(data), i + context_bytes)
                    context = data[start:end]
                    
                    results.append((
                        i - len(current_string),
                        current_string,
                        binascii.hexlify(context).decode()
                    ))
            
            current_string = ""
    
    # Check the last string
    if len(current_string) >= min_length:
        results.append((
            len(data) - len(current_string),
            current_string,
            binascii.hexlify(data[max(0, len(data) - len(current_string) - context_bytes):]).decode()
        ))
    
    return results

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Extract meaningful strings from a binary file")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("-l", "--min-length", type=int, default=4,
                       help="Minimum string length to consider")
    parser.add_argument("-c", "--context", type=int, default=16,
                       help="Number of bytes of context to show")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    
    args = parser.parse_args()
    
    # Extract strings
    print(f"Searching for meaningful strings in {args.file}...")
    strings = extract_strings(args.file, args.min_length, args.context)
    
    # Sort by offset
    strings.sort(key=lambda x: x[0])
    
    # Format output
    output = []
    output.append(f"Meaningful Strings in {args.file}")
    output.append("=" * 80)
    output.append(f"Extracted on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output.append(f"Total strings found: {len(strings)}")
    output.append("-" * 80)
    
    for offset, string, context in strings:
        output.append(f"Offset: 0x{offset:08x}")
        output.append(f"String: {string}")
        output.append(f"Context: {context}")
        output.append("-" * 40)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write("\n".join(output))
        print(f"Results written to {args.output}")
    else:
        print("\n".join(output))

if __name__ == "__main__":
    main() 