#!/usr/bin/env python3
"""
PTX Timecode Extractor
----------------------
A tool to extract timecodes, markers, and session information from Pro Tools PTX files.
Focuses on the specific offsets identified during PTX file format analysis.
"""

import os
import sys
import struct
import binascii
import re
from datetime import datetime

# Known offset patterns found during analysis
KNOWN_OFFSETS = {
    # Offset: (description, size to read)
    0x00084058: ("Timeline Start Marker", 32),
    0x00084090: ("Timecode Reference", 32),
    0x0008418c: ("Timecode Marker", 32),
    0x000840e8: ("Session Information Block", 64),
    0x00084a58: ("Project Metadata", 64),
    0x00084a70: ("Timestamp Data", 32),
}

# SMPTE timecode pattern (HH:MM:SS:FF)
TIMECODE_PATTERN = re.compile(rb'(\d\d)[:\.](\d\d)[:\.](\d\d)[:\.](\d\d)')

def hex_dump(data, bytes_per_line=16):
    """Format binary data as a hexdump with ASCII representation"""
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f"{hex_part.ljust(bytes_per_line*3)}   {ascii_part}")
    return '\n'.join(result)

def extract_ascii_strings(data, min_length=4):
    """Extract printable ASCII strings from binary data"""
    pattern = re.compile(b'[\x20-\x7E]{%d,}' % min_length)
    return [m.group(0).decode('ascii') for m in pattern.finditer(data)]

def extract_timecodes(data):
    """Extract potential SMPTE timecodes from binary data"""
    matches = TIMECODE_PATTERN.finditer(data)
    return [f"{m.group(1).decode()}:{m.group(2).decode()}:{m.group(3).decode()}:{m.group(4).decode()}" 
            for m in matches]

def binary_scan_for_timecodes(data):
    """Scan binary data for potential timecode values stored as raw bytes"""
    timecodes = []
    
    # Look for patterns of 4 consecutive bytes that could be hours, minutes, seconds, frames
    for i in range(len(data) - 4):
        hour, minute, second, frame = data[i:i+4]
        
        # Check if these values make sense as a timecode
        if hour < 24 and minute < 60 and second < 60 and frame < 30:
            timecode = f"{hour:02d}:{minute:02d}:{second:02d}:{frame:02d}"
            offset = i
            timecodes.append((offset, timecode))
    
    return timecodes

def find_potential_markers(data):
    """Try to identify session markers in the binary data"""
    # Look for patterns that might indicate marker names or positions
    patterns = [
        # Timecode patterns
        br'\d\d:\d\d:\d\d[:.]\d\d',
        # Marker name patterns (often after 'Mark' or similar text)
        br'Mark[^;]{2,30}',
        br'marker[^;]{2,30}',
        # Potential session name
        br'Session[^;]{2,30}',
        # Typical marker words
        br'Verse|Chorus|Intro|Outro|Bridge|Solo|[A-Za-z]+\d+'
    ]
    
    results = []
    for pattern in patterns:
        p = re.compile(pattern, re.IGNORECASE)
        for match in p.finditer(data):
            try:
                text = match.group(0).decode('utf-8', errors='replace')
                results.append((match.start(), text))
            except:
                pass
    
    return results

def examine_section_by_offset(filename, offset, description, size_to_read):
    """Examine a specific section of the PTX file at a given offset"""
    try:
        with open(filename, 'rb') as f:
            f.seek(offset)
            data = f.read(size_to_read)
            
        print(f"\n=== {description} (Offset: 0x{offset:08x}) ===")
        print("Hex Dump:")
        print(hex_dump(data))
        
        # Try to interpret the data in different ways
        print("\nPotential ASCII strings:")
        strings = extract_ascii_strings(data)
        if strings:
            for s in strings:
                print(f"  - {s}")
        else:
            print("  No printable ASCII strings found")
        
        print("\nPotential Timecodes (ASCII):")
        timecodes = extract_timecodes(data)
        if timecodes:
            for tc in timecodes:
                print(f"  - {tc}")
        else:
            print("  No ASCII timecodes found")
        
        print("\nPotential Timecodes (Binary):")
        bin_timecodes = binary_scan_for_timecodes(data)
        if bin_timecodes:
            for offset, tc in bin_timecodes:
                print(f"  - {tc} (at relative offset +{offset})")
        else:
            print("  No binary timecodes found")
            
        try:
            # Try to interpret first 4 bytes as a 32-bit integer
            if len(data) >= 4:
                int_le = struct.unpack("<I", data[0:4])[0]
                int_be = struct.unpack(">I", data[0:4])[0]
                print(f"\nFirst 4 bytes as 32-bit int: {int_le} (little-endian), {int_be} (big-endian)")
        except:
            pass
            
        return data
    except Exception as e:
        print(f"Error examining offset 0x{offset:08x}: {e}")
        return None

def scan_for_section_headers(filename):
    """Scan file for potential section headers matching the observed pattern"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            
        print("\n=== Scanning for Section Headers ===")
        section_count = 0
        
        # Based on our analysis, section headers are 8+ bytes:
        # 4 bytes type, 4 bytes size, then data
        for i in range(0, len(data) - 16, 4):  # Step by 4 to check alignment
            if i + 8 > len(data):
                break
                
            # Extract potential type and size
            type_value = struct.unpack("<I", data[i:i+4])[0]
            size_value = struct.unpack("<I", data[i+4:i+8])[0]
            
            # Validate: sizes typically reasonable (not too small, not too large)
            # Looking for sizes that fit within file but aren't tiny
            if 1000 < size_value < 1000000 and i + 8 + size_value <= len(data):
                section_count += 1
                if section_count <= 10:  # Limit output to first 10 sections
                    print(f"\nSection at offset 0x{i:08x}:")
                    print(f"  Type: {type_value}")
                    print(f"  Size: {size_value} bytes")
                    
                    # Show the header bytes
                    header_bytes = data[i:i+16]
                    print(f"  Header: {binascii.hexlify(header_bytes).decode()}")
                    
                    # Try to extract ASCII strings from the section
                    section_data = data[i+8:i+8+min(size_value, 100)]  # First 100 bytes max
                    strings = extract_ascii_strings(section_data)
                    if strings:
                        print("  Strings in section start:")
                        for s in strings[:3]:  # Show up to 3 strings
                            print(f"    - {s}")
        
        print(f"\nTotal potential sections found: {section_count}")
        
    except Exception as e:
        print(f"Error scanning for section headers: {e}")

def scan_specific_known_offsets(filename):
    """Examine all predefined offsets known to contain interesting data"""
    for offset, (description, size) in KNOWN_OFFSETS.items():
        examine_section_by_offset(filename, offset, description, size)

def scan_for_markers(filename):
    """Scan the entire file for potential markers and named points"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            
        print("\n=== Scanning for Potential Markers and Named Points ===")
        markers = find_potential_markers(data)
        
        if markers:
            for offset, text in markers:
                print(f"0x{offset:08x}: {text}")
        else:
            print("No potential markers found")
            
    except Exception as e:
        print(f"Error scanning for markers: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python extract_timecodes.py <ptx_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
        
    print(f"Analyzing PTX file: {filename}")
    print(f"File size: {os.path.getsize(filename)} bytes")
    print(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Examine known offsets
    scan_specific_known_offsets(filename)
    
    # Scan for section headers
    scan_for_section_headers(filename)
    
    # Scan for potential markers
    scan_for_markers(filename)

if __name__ == "__main__":
    main() 
