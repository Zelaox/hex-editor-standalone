#!/usr/bin/env python3
import re
import sys
import os
from datetime import datetime

def read_binary_file(filename, chunk_size=4096):
    """Read binary file in chunks and convert to string for analysis"""
    if not os.path.exists(filename):
        print(f"File {filename} not found")
        return None
        
    # Try to read file in binary mode
    try:
        with open(filename, 'rb') as f:
            content = f.read()
        
        # Convert to string with different encodings to catch different types of text
        text_content = ""
        
        # Try ascii first (replacing non-ascii chars)
        text_content += content.decode('ascii', errors='replace')
        
        # Try utf-16 for potential unicode text
        try:
            text_content += "\n" + content.decode('utf-16', errors='replace')
        except:
            pass
            
        # Try latin-1 which can decode any byte
        text_content += "\n" + content.decode('latin-1', errors='replace')
        
        return text_content
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def search_for_metadata(filename):
    print(f"Searching for metadata in {filename}")
    print("=" * 80)
    
    # First try to read file as text
    try:
        with open(filename, 'r', errors='ignore') as f:
            content = f.read()
    except:
        print("Could not read file as text, trying binary mode...")
        content = read_binary_file(filename)
        
    if not content:
        print("Could not read file content")
        return
    
    # More specific patterns for Pro Tools PTX files
    patterns = {
        'Session Info': r'(?i)session|(?i)pro\s+tools',
        'Track Names': r'(?i)track\s+[\w\s]+',
        'Dates (MM/DD/YYYY)': r'\d{1,2}[/-]\d{1,2}[/-]\d{4}',
        'Dates (YYYY/MM/DD)': r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',
        'Times': r'\d{1,2}:\d{2}(:\d{2})?(\s*[AP]M)?',
        'Format Dates': r'(?i)[a-z]+\s+\d{1,2},\s+\d{4}',
        'Sampling Info': r'(?i)\d+\s*hz|(?i)\d+\s*khz|(?i)\d+\s*bit',
        'File Info': r'(?i)wav|(?i)aiff|(?i)mp3|(?i)audio\s+file',
        'Tempo Info': r'(?i)tempo|(?i)bpm|(?i)\d+\s*bpm',
        'Version Info': r'(?i)version\s+\d+(\.\d+)*',
        'SMPTE Timecodes': r'\d{2}:\d{2}:\d{2}[:;]\d{2}',
        'Recording Time': r'(?i)rec\s+time|(?i)recording\s+time',
        'Audio Region': r'(?i)region|(?i)marker|(?i)clip',
        'Sample Rate': r'(?i)sample\s+rate|(?i)\d+\.\d+\s*khz',
        'Bit Depth': r'(?i)bit\s+depth|(?i)bit-depth|(?i)\d+\s*bit',
        'Channel Info': r'(?i)mono|(?i)stereo|(?i)surround|(?i)5\.1|(?i)7\.1',
        'Pro Tools Sections': r'(?i)section\s+\d+|(?i)header section'
    }
    
    # Add patterns for timecode display formats
    timecode_patterns = [
        r'\d{2}:\d{2}:\d{2}[:;]\d{2}',  # 00:00:00:00 SMPTE
        r'\d+\s*hrs\s*\d+\s*min\s*\d+\s*sec\s*\d+\s*frames',  # Word format
        r'\d+[:|.]\d+[:|.]\d+[:|.]\d+',  # Various separator formats
        r'(?i)timecode\s*[:=]\s*\d+',    # Labeled timecode
        r'(?i)time\s*code'               # General mention
    ]
    patterns['Timecodes'] = '|'.join(timecode_patterns)
    
    # PTX specific section identifiers
    ptx_sections = [
        r'(?i)header\s*section',
        r'(?i)data\s*section',
        r'(?i)metadata\s*section',
        r'(?i)section\s*\d+',
        r'(?i)section\s*type',
        r'(?i)section\s*offset',
        r'(?i)section\s*size'
    ]
    patterns['PTX Sections'] = '|'.join(ptx_sections)
    
    # Look for common strings that might be in chunks
    chunk_markers = [
        r'(?i)audio\s*data',
        r'(?i)edit\s*data',
        r'(?i)clip\s*data',
        r'(?i)session\s*data',
        r'(?i)metadata',
        r'(?i)unknown_\(\d+\)'
    ]
    patterns['Data Chunks'] = '|'.join(chunk_markers)
    
    # Search for strings that might be in hexadecimal representation
    hex_strings = [
        r'0x[0-9a-fA-F]+',  # Hex values
        r'\\x[0-9a-fA-F]{2}',  # Escaped hex
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'  # GUID format
    ]
    patterns['Hex Values'] = '|'.join(hex_strings)
    
    results = {}
    
    # First pass - find all matches for each pattern
    for label, pattern in patterns.items():
        try:
            matches = re.findall(pattern, content)
            if matches:
                # Convert matches to strings if they're tuples (from regex groups)
                clean_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        clean_matches.append(''.join([m for m in match if m]))
                    else:
                        clean_matches.append(match)
                
                # Remove duplicates while preserving order
                unique_matches = []
                for match in clean_matches:
                    if match and match.strip() and match not in unique_matches:
                        unique_matches.append(match)
                
                if unique_matches:
                    results[label] = unique_matches
        except Exception as e:
            print(f"Error with pattern '{label}': {e}")
    
    # Special search for strings that might contain markers or region names
    # Look for strings that are at least 3 chars and composed of letters/numbers/spaces
    try:
        potential_names = re.findall(r'[A-Za-z0-9][A-Za-z0-9\s_-]{2,}[A-Za-z0-9]', content)
        if potential_names:
            # Filter out common binary garbage and keep only likely names
            filtered_names = [
                name for name in potential_names 
                if len(name) >= 3 and len(name) <= 50  # Reasonable name length
                and not all(c.isdigit() for c in name)  # Not all digits
                and sum(1 for c in name if c.isalpha()) > len(name) * 0.3  # At least 30% letters
                and name.strip() not in ['Offset', 'String', 'Context', 'Extracted', 'Meaningful']  # Not from our output format
            ]
            
            # Remove duplicates
            unique_names = []
            for name in filtered_names:
                if name not in unique_names:
                    unique_names.append(name)
                    
            if unique_names:
                results['Potential Names/Labels'] = unique_names[:30]  # Limit to first 30 to avoid overwhelming output
    except Exception as e:
        print(f"Error finding potential names: {e}")
    
    # Look for specific byte sequences that might indicate time stamps
    # Try to find sequences that look like time or date values in binary form
    try:
        binary_time_patterns = [
            # Look for sequences of bytes that might represent time values
            rb'\x00\x00\x00[\x00-\x59]{1}\x00[\x00-\x59]{1}\x00[\x00-\x59]{1}',  # Potential time values
            rb'[\x00-\x31]{1}[\x00-\x12]{1}[\x00-\x31]{1}[\x00-\x24]{1}',  # Potential date values (DD/MM/YY/HH)
        ]
        
        for i, pattern in enumerate(binary_time_patterns):
            if isinstance(content, str):
                # Skip binary patterns for text content
                continue
                
            try:
                with open(filename, 'rb') as f:
                    bin_content = f.read()
                
                bin_matches = []
                for match in re.finditer(pattern, bin_content):
                    # Convert to hex representation for display
                    match_bytes = bin_content[match.start():match.end()]
                    hex_repr = ' '.join([f"{b:02x}" for b in match_bytes])
                    offset = match.start()
                    bin_matches.append(f"Offset 0x{offset:08x}: {hex_repr}")
                
                if bin_matches:
                    category = f"Binary Pattern {i+1}"
                    results[category] = bin_matches[:20]  # Limit to 20 matches
            except Exception as inner_e:
                print(f"Error processing binary pattern {i+1}: {inner_e}")
    except Exception as e:
        print(f"Error processing binary patterns: {e}")
    
    # Print results
    if not results:
        print("No metadata found.")
    else:
        for label, matches in results.items():
            print(f"\n{label}:")
            print("-" * 40)
            for i, match in enumerate(matches, 1):
                if i <= 20:  # Limit output to 20 items per category
                    print(f"{i}. {match}")
                else:
                    remaining = len(matches) - 20
                    print(f"... and {remaining} more matches")
                    break
    
    print("\n" + "=" * 80)
    print(f"Search completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python find_metadata.py <strings_file> OR <binary_file>")
        sys.exit(1)
    
    search_for_metadata(sys.argv[1])

if __name__ == "__main__":
    main() 