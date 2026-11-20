#!/usr/bin/env python3
"""
PTX Key Offset Analyzer
-----------------------
A targeted tool to examine specific offsets in the PTX file where we discovered 
timecode and session information during our analysis.
"""

import os
import sys
import struct
import binascii
from datetime import datetime

# Key offsets found during analysis with their descriptions
KEY_OFFSETS = [
    (0x00084058, 32, "Timeline Start Marker"),
    (0x00084090, 32, "Timecode Reference"),
    (0x0008418c, 32, "Timecode Marker (00:01)"),
    (0x000846ec, 32, "Timecode Marker (00:00:00:01)"),
    (0x00084a58, 64, "Project Metadata"),
    (0x00084a70, 32, "Timestamp Data")
]

def hex_dump(data, bytes_per_line=16):
    """Format binary data as hexdump with ASCII representation"""
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f"{hex_part.ljust(bytes_per_line*3)}   {ascii_part}")
    return '\n'.join(result)

def interpret_as_values(data):
    """Attempt to interpret the binary data in various ways"""
    results = []
    
    # Try ASCII strings
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    results.append(f"ASCII: {ascii_str}")
    
    # Try 32-bit integers (both endianness)
    if len(data) >= 4:
        try:
            int_le = struct.unpack("<I", data[0:4])[0]
            int_be = struct.unpack(">I", data[0:4])[0]
            results.append(f"32-bit int: {int_le} (LE), {int_be} (BE)")
        except:
            pass
    
    # Check for potential SMPTE timecode bytes (4 bytes: HH:MM:SS:FF)
    for i in range(len(data) - 4):
        hour, minute, second, frame = data[i:i+4]
        if hour < 24 and minute < 60 and second < 60 and frame < 30:
            results.append(f"Potential timecode at +{i}: {hour:02d}:{minute:02d}:{second:02d}:{frame:02d}")
    
    # Look for time strings like "00:00:00:00" in the bytes
    ascii_bytes = data.replace(b'\x00', b' ')
    for i in range(len(ascii_bytes) - 10):
        chunk = ascii_bytes[i:i+11]
        if (b':' in chunk or b'.' in chunk) and sum(1 for b in chunk if 48 <= b <= 57) >= 6:  # Has colons and digits
            results.append(f"Potential time string at +{i}: {chunk.decode('ascii', errors='replace')}")
    
    return results

def extract_known_offset_data(filename):
    """Extract data from specific known offsets"""
    try:
        with open(filename, 'rb') as f:
            file_size = os.path.getsize(filename)
            
            for offset, size, description in KEY_OFFSETS:
                if offset > file_size:
                    print(f"\n[!] Offset 0x{offset:08x} ({description}) exceeds file size!")
                    continue
                    
                f.seek(offset)
                data = f.read(size)
                
                print(f"\n=== {description} (Offset: 0x{offset:08x}) ===")
                print("Hex Dump:")
                print(hex_dump(data))
                
                print("\nInterpretations:")
                interpretations = interpret_as_values(data)
                for interp in interpretations:
                    print(f"  {interp}")
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python extract_key_offsets.py <ptx_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
        
    print(f"Analyzing key offsets in PTX file: {filename}")
    print(f"File size: {os.path.getsize(filename)} bytes")
    print(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    extract_known_offset_data(filename)

if __name__ == "__main__":
    main() 