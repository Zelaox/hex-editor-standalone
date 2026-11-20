#!/usr/bin/env python3
import os
import sys
import re
import struct
import binascii
from datetime import datetime, timedelta

def extract_strings(binary_data, min_length=4):
    """Extract ASCII strings from binary data"""
    strings = []
    current_string = ""
    for byte in binary_data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Add the last string if it meets the minimum length
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings

def find_timestamps(binary_data):
    """Look for potential timestamps in the binary data"""
    # Different timestamp formats
    timestamps = []
    
    # Look for typical Pro Tools timecodes (HH:MM:SS:FF)
    # This format is often stored as 4 consecutive bytes
    for i in range(len(binary_data) - 4):
        bytes_sequence = binary_data[i:i+4]
        # Check if bytes could be hours, minutes, seconds, frames
        hour, minute, second, frame = bytes_sequence
        
        if hour < 24 and minute < 60 and second < 60 and frame < 30:
            timestamp = f"{hour:02d}:{minute:02d}:{second:02d}:{frame:02d}"
            timestamps.append((i, timestamp, bytes_sequence))
    
    # Look for Unix timestamps (32-bit integer)
    for i in range(len(binary_data) - 4):
        try:
            # Try both little and big endian
            timestamp_le = struct.unpack("<I", binary_data[i:i+4])[0]
            timestamp_be = struct.unpack(">I", binary_data[i:i+4])[0]
            
            # Check if it looks like a reasonable Unix timestamp (1990-2030)
            if 631152000 <= timestamp_le <= 1893456000:  # 1990-01-01 to 2030-01-01
                dt = datetime.fromtimestamp(timestamp_le)
                timestamps.append((i, f"Unix LE: {dt}", bytes_sequence))
                
            if 631152000 <= timestamp_be <= 1893456000:
                dt = datetime.fromtimestamp(timestamp_be)
                timestamps.append((i, f"Unix BE: {dt}", bytes_sequence))
        except:
            pass
    
    return timestamps

def find_sample_rates(binary_data):
    """Look for common sample rate values in the binary data"""
    sample_rates = []
    
    # Common sample rates as 32-bit integers or floats
    rates = [44100, 48000, 88200, 96000, 176400, 192000]
    
    for i in range(len(binary_data) - 4):
        try:
            # Try as integer
            int_le = struct.unpack("<I", binary_data[i:i+4])[0]
            int_be = struct.unpack(">I", binary_data[i:i+4])[0]
            
            # Try as float
            float_le = struct.unpack("<f", binary_data[i:i+4])[0]
            float_be = struct.unpack(">f", binary_data[i:i+4])[0]
            
            # Check against common rates with some tolerance for floats
            for rate in rates:
                if int_le == rate:
                    sample_rates.append((i, f"{rate} Hz (Int LE)", binary_data[i:i+4]))
                if int_be == rate:
                    sample_rates.append((i, f"{rate} Hz (Int BE)", binary_data[i:i+4]))
                if abs(float_le - rate) < 1.0:
                    sample_rates.append((i, f"{float_le:.1f} Hz (Float LE)", binary_data[i:i+4]))
                if abs(float_be - rate) < 1.0:
                    sample_rates.append((i, f"{float_be:.1f} Hz (Float BE)", binary_data[i:i+4]))
        except:
            pass
    
    return sample_rates

def find_bit_depths(binary_data):
    """Look for common bit depth values in the binary data"""
    bit_depths = []
    
    # Common bit depths
    depths = [8, 16, 24, 32]
    
    for i in range(len(binary_data) - 2):
        # Check 16-bit values
        try:
            int16_le = struct.unpack("<H", binary_data[i:i+2])[0]
            int16_be = struct.unpack(">H", binary_data[i:i+2])[0]
            
            for depth in depths:
                if int16_le == depth:
                    bit_depths.append((i, f"{depth}-bit (LE)", binary_data[i:i+2]))
                if int16_be == depth:
                    bit_depths.append((i, f"{depth}-bit (BE)", binary_data[i:i+2]))
        except:
            pass
    
    return bit_depths

def find_potential_structs(binary_data):
    """Find potential data structures in the binary data"""
    results = {}
    
    # Look for magic numbers common in various file formats
    magic_patterns = {
        b'RIFF': "WAVE file header",
        b'ID3\x03': "MP3 ID3 tag",
        b'ftyp': "MP4/QuickTime",
        b'OggS': "Ogg container",
        b'FORM': "AIFF file",
        b'PTX\x00': "Pro Tools PTX marker",
        b'Sess': "Possible Session marker"
    }
    
    for pattern, description in magic_patterns.items():
        for i in range(len(binary_data) - len(pattern) + 1):
            if binary_data[i:i+len(pattern)] == pattern:
                offset = i
                hex_dump = binascii.hexlify(binary_data[i:i+32]).decode('ascii')
                results.setdefault('Magic Numbers', []).append(
                    f"0x{offset:08x}: {description} - {hex_dump}"
                )
    
    # Look for potential PTX sections by finding typical section header patterns
    # Typically may have flag values followed by size/type fields
    for i in range(0, len(binary_data) - 16, 4):
        # Pattern: potential sections often have fields like type, size, flags
        # Check for potential PTX section header (looking for patterns of non-zero values)
        
        if sum(binary_data[i:i+16]) > 0:  # Make sure it's not all zeros
            data_segment = binary_data[i:i+16]
            
            # Try to parse first 4 bytes as potential section type 
            potential_type = struct.unpack("<I", data_segment[0:4])[0]
            # Try to parse next 4 bytes as potential section size
            potential_size = struct.unpack("<I", data_segment[4:8])[0]
            
            # Heuristic: Section sizes are typically reasonable values (not too small, not too large)
            if 12 < potential_size < 10000000:  # Reasonable size for a section
                hex_dump = binascii.hexlify(data_segment).decode('ascii')
                entry = f"0x{i:08x}: Type={potential_type}, Size={potential_size}, Hex={hex_dump}"
                results.setdefault('Potential Sections', []).append(entry)
    
    # Extract ASCII strings that might be meaningful
    strings = extract_strings(binary_data)
    if strings:
        filtered_strings = []
        for string in strings:
            # Filter for strings that may be session info
            if len(string) >= 5 and not string.isupper() and not all(c.isdigit() for c in string):
                filtered_strings.append(string)
                
        if filtered_strings:
            results['ASCII Strings'] = filtered_strings[:30]  # Limit to 30 strings
    
    # Find potential timestamps
    timestamps = find_timestamps(binary_data)
    if timestamps:
        results['Potential Timestamps'] = [
            f"0x{offset:08x}: {timestamp} (Bytes: {binascii.hexlify(bytes_seq).decode('ascii')})"
            for offset, timestamp, bytes_seq in timestamps[:20]  # Limit to 20 timestamps
        ]
    
    # Find potential sample rates
    sample_rates = find_sample_rates(binary_data)
    if sample_rates:
        results['Potential Sample Rates'] = [
            f"0x{offset:08x}: {description} (Bytes: {binascii.hexlify(bytes_seq).decode('ascii')})"
            for offset, description, bytes_seq in sample_rates[:10]  # Limit to 10 sample rates
        ]
    
    # Find potential bit depths
    bit_depths = find_bit_depths(binary_data)
    if bit_depths:
        results['Potential Bit Depths'] = [
            f"0x{offset:08x}: {description} (Bytes: {binascii.hexlify(bytes_seq).decode('ascii')})"
            for offset, description, bytes_seq in bit_depths[:10]  # Limit to 10 bit depths
        ]
    
    return results

def analyze_binary_file(filename):
    """Analyze a binary file for potential Pro Tools PTX metadata"""
    print(f"Analyzing binary file: {filename}")
    print("=" * 80)
    
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found.")
        return
    
    try:
        with open(filename, 'rb') as f:
            binary_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    print(f"File size: {len(binary_data)} bytes")
    
    # Find potential data structures
    results = find_potential_structs(binary_data)
    
    # Print results
    if not results:
        print("No interesting data structures found.")
    else:
        for category, items in results.items():
            print(f"\n{category}:")
            print("-" * 40)
            
            for i, item in enumerate(items, 1):
                print(f"{i}. {item}")
    
    print("\n" + "=" * 80)
    print(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_binary_data.py <binary_file>")
        sys.exit(1)
    
    analyze_binary_file(sys.argv[1])

if __name__ == "__main__":
    main() 