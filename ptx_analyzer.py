#!/usr/bin/env python3
"""
PTX Analyzer - Comprehensive Pro Tools PTX file analyzer

This utility combines our various PTX analysis tools into a single script
that can decrypt, extract metadata, and analyze PTX files.

Usage:
    python ptx_analyzer.py <ptx_file> [options]
"""

import os
import sys
import re
import json
import argparse
import binascii
import struct
from datetime import datetime
from collections import namedtuple

# Constants
KNOWN_KEY_OFFSETS = {
    0x00084058: "Timeline marker (main)",
    0x00084090: "SMPTE timecode format",
    0x0008418c: "Timeline marker (secondary)"
}

# Patterns
TIMECODE_PATTERN = re.compile(r'(\d{2}):(\d{2}):(\d{2}):(\d{2})')
DECIMAL_TIME_PATTERN = re.compile(r'(\d+):(\d{2})\.(\d{3})')
SESSION_INFO_PATTERN = re.compile(r'(Pro Tools|Session|Track|Plugin|Instrument|Audio|MIDI|Sample Rate|Bit Depth)', re.IGNORECASE)

class PTXDecryptor:
    """Handles decryption of PTX files"""
    
    def __init__(self, ptx_path):
        self.ptx_path = ptx_path
        self.decrypted_path = None
        self.sections_dir = None
    
    def decrypt(self, output_path=None, extract_dir=None):
        """Decrypt the PTX file using the decrypt_ptx.py script"""
        if not os.path.exists(self.ptx_path):
            print(f"Error: PTX file not found at {self.ptx_path}")
            return False
            
        # Generate output paths if not provided
        if not output_path:
            base_name = os.path.splitext(os.path.basename(self.ptx_path))[0]
            output_path = f"{base_name}_decrypted.ptx"
        
        if not extract_dir:
            extract_dir = f"{os.path.splitext(output_path)[0]}_sections"
            
        self.decrypted_path = output_path
        self.sections_dir = extract_dir
        
        # Check if decrypt_ptx.py exists
        if not os.path.exists("decrypt_ptx.py"):
            print("Error: decrypt_ptx.py script not found")
            print("Assuming file is already decrypted")
            self.decrypted_path = self.ptx_path
            return True
            
        try:
            import subprocess
            cmd = ["python", "decrypt_ptx.py", self.ptx_path, "-o", output_path, "-d", extract_dir, "-f"]
            print(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Decryption failed: {result.stderr}")
                return False
                
            print(f"Decryption successful. Decrypted file: {output_path}")
            print(f"Extracted sections to: {extract_dir}")
            return True
        except Exception as e:
            print(f"Error during decryption: {str(e)}")
            return False


class PTXAnalyzer:
    """Main class for analyzing PTX files"""
    
    def __init__(self, ptx_path):
        self.ptx_path = ptx_path
        self.file_size = os.path.getsize(ptx_path) if os.path.exists(ptx_path) else 0
        self.metadata = {}
        self.sections = []
        self.strings = []
        self.timecodes = []
        
    def read_file_bytes(self, offset=0, length=None):
        """Read bytes from the PTX file"""
        if not os.path.exists(self.ptx_path):
            print(f"Error: File not found at {self.ptx_path}")
            return b''
            
        try:
            with open(self.ptx_path, 'rb') as f:
                f.seek(offset)
                if length is None:
                    return f.read()
                return f.read(length)
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            return b''
    
    def analyze_header(self):
        """Analyze the PTX file header"""
        header_data = self.read_file_bytes(0, 32)
        if not header_data:
            return False
            
        magic = binascii.hexlify(header_data[:4]).decode()
        self.metadata['header'] = {
            'magic': magic,
            'hex_dump': binascii.hexlify(header_data).decode(),
            'size': len(header_data)
        }
        return True
        
    def find_sections(self):
        """Find sections in the PTX file"""
        data = self.read_file_bytes()
        if not data:
            return False
            
        # Look for section patterns
        offset = 32  # Skip header
        while offset < len(data) - 8:
            try:
                section_type = struct.unpack("<I", data[offset:offset+4])[0]
                section_size = struct.unpack("<I", data[offset+4:offset+8])[0]
                
                # Sanity check for section size
                if section_size > 0 and section_size < self.file_size - offset:
                    section = {
                        'offset': offset,
                        'type': section_type,
                        'size': section_size,
                        'end_offset': offset + 8 + section_size
                    }
                    self.sections.append(section)
                    offset = section['end_offset']
                else:
                    offset += 4
            except:
                offset += 4
                
        return True
    
    def extract_strings(self, min_length=4):
        """Extract ASCII strings from the file"""
        data = self.read_file_bytes()
        if not data:
            return False
            
        # Extract printable ASCII strings
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
        matches = ascii_pattern.finditer(data)
        
        for match in matches:
            string_data = match.group(0).decode('ascii', errors='replace')
            offset = match.start()
            
            # Check if the string might be meaningful
            is_meaningful = False
            if re.search(SESSION_INFO_PATTERN, string_data):
                is_meaningful = True
            elif re.search(TIMECODE_PATTERN, string_data):
                is_meaningful = True
                self.timecodes.append({
                    'offset': offset,
                    'value': string_data,
                    'type': 'SMPTE'
                })
            elif re.search(DECIMAL_TIME_PATTERN, string_data):
                is_meaningful = True
                self.timecodes.append({
                    'offset': offset,
                    'value': string_data,
                    'type': 'Decimal'
                })
                
            if is_meaningful:
                context_start = max(0, offset - 16)
                context_end = min(len(data), offset + len(string_data) + 16)
                context = data[context_start:context_end]
                
                self.strings.append({
                    'offset': offset,
                    'value': string_data,
                    'context': binascii.hexlify(context).decode(),
                    'is_timecode': bool(re.search(TIMECODE_PATTERN, string_data) or 
                                       re.search(DECIMAL_TIME_PATTERN, string_data))
                })
                
        return True
    
    def analyze_key_offsets(self):
        """Analyze known key offsets for timeline data"""
        results = {}
        
        for offset, description in KNOWN_KEY_OFFSETS.items():
            if offset < self.file_size:
                # Read 16 bytes before and after the key offset
                context_start = max(0, offset - 16)
                data = self.read_file_bytes(context_start, 48)
                if data:
                    offset_in_data = offset - context_start
                    
                    # Format the output
                    hex_dump = self._format_hex_dump(data, offset_in_data)
                    ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                    
                    results[f"0x{offset:08x}"] = {
                        'description': description,
                        'hex_dump': hex_dump,
                        'ascii': ascii_repr,
                        'offset': offset
                    }
        
        self.metadata['key_offsets'] = results
        return True
    
    def _format_hex_dump(self, data, highlight_pos=None):
        """Format binary data as a hex dump with optional highlighting"""
        result = []
        chunk_size = 16
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            hex_values = []
            
            for j, b in enumerate(chunk):
                pos = i + j
                if highlight_pos is not None and pos == highlight_pos:
                    hex_values.append(f"[{b:02x}]")
                else:
                    hex_values.append(f"{b:02x}")
                    
            result.append(' '.join(hex_values))
            
        return '\n'.join(result)
    
    def generate_report(self):
        """Generate a comprehensive report of the findings"""
        report = {
            'file_info': {
                'path': self.ptx_path,
                'size': self.file_size,
                'analysis_time': datetime.now().isoformat()
            },
            'header': self.metadata.get('header', {}),
            'sections': self.sections,
            'timecodes': self.timecodes,
            'key_offsets': self.metadata.get('key_offsets', {}),
            'meaningful_strings': [s for s in self.strings if s.get('is_timecode') or 
                                  re.search(SESSION_INFO_PATTERN, s.get('value', ''))]
        }
        
        return report


def save_json_report(report, output_path):
    """Save the report as a JSON file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {output_path}")
        return True
    except Exception as e:
        print(f"Error saving report: {str(e)}")
        return False


def save_text_report(report, output_path):
    """Save the report as a human-readable text file"""
    try:
        with open(output_path, 'w') as f:
            f.write("# PTX File Analysis Report\n\n")
            
            # File info
            f.write("## File Information\n")
            for key, value in report['file_info'].items():
                f.write(f"- {key}: {value}\n")
            f.write("\n")
            
            # Header
            f.write("## File Header\n")
            if report['header']:
                for key, value in report['header'].items():
                    f.write(f"- {key}: {value}\n")
            else:
                f.write("No header information available\n")
            f.write("\n")
            
            # Sections
            f.write("## File Sections\n")
            if report['sections']:
                for i, section in enumerate(report['sections']):
                    f.write(f"### Section {i+1}\n")
                    f.write(f"- Offset: 0x{section['offset']:08x}\n")
                    f.write(f"- Type: {section['type']}\n")
                    f.write(f"- Size: {section['size']} bytes\n")
                    f.write(f"- End: 0x{section['end_offset']:08x}\n\n")
            else:
                f.write("No sections identified\n")
            f.write("\n")
            
            # Timecodes
            f.write("## Timecode References\n")
            if report['timecodes']:
                for tc in report['timecodes']:
                    f.write(f"- 0x{tc['offset']:08x}: {tc['value']} (Type: {tc['type']})\n")
            else:
                f.write("No timecode references found\n")
            f.write("\n")
            
            # Key offsets
            f.write("## Known Key Offsets\n")
            if report['key_offsets']:
                for offset, data in report['key_offsets'].items():
                    f.write(f"### {offset}: {data['description']}\n")
                    f.write("```\n")
                    f.write(f"Hex: {data['hex_dump']}\n")
                    f.write(f"ASCII: {data['ascii']}\n")
                    f.write("```\n\n")
            else:
                f.write("No key offset information available\n")
            f.write("\n")
            
            # Meaningful strings
            f.write("## Meaningful Strings\n")
            if report['meaningful_strings']:
                for s in report['meaningful_strings']:
                    f.write(f"- 0x{s['offset']:08x}: {s['value']}\n")
            else:
                f.write("No meaningful strings found\n")
                
        print(f"Text report saved to {output_path}")
        return True
    except Exception as e:
        print(f"Error saving text report: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PTX Analyzer - Analyze Pro Tools PTX files")
    parser.add_argument("ptx_file", help="Path to the PTX file to analyze")
    parser.add_argument("--output", "-o", help="Output path for the report (default: <filename>_report.json)")
    parser.add_argument("--text", "-t", action="store_true", help="Generate human-readable text report")
    parser.add_argument("--decrypt", "-d", action="store_true", help="Decrypt the PTX file before analysis")
    parser.add_argument("--extract-dir", "-e", help="Directory to extract sections to (if decrypting)")
    parser.add_argument("--min-string", "-m", type=int, default=4, help="Minimum string length to extract (default: 4)")
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.ptx_file):
        print(f"Error: File not found: {args.ptx_file}")
        return 1
    
    # Decrypt if requested
    file_to_analyze = args.ptx_file
    if args.decrypt:
        print(f"Decrypting PTX file: {args.ptx_file}")
        decryptor = PTXDecryptor(args.ptx_file)
        if not decryptor.decrypt(extract_dir=args.extract_dir):
            print("Decryption failed. Analyzing original file.")
        else:
            file_to_analyze = decryptor.decrypted_path
            print(f"Analyzing decrypted file: {file_to_analyze}")
    
    # Analyze the file
    print(f"Analyzing PTX file: {file_to_analyze}")
    analyzer = PTXAnalyzer(file_to_analyze)
    
    # Run analysis steps
    print("Analyzing file header...")
    analyzer.analyze_header()
    
    print("Finding file sections...")
    analyzer.find_sections()
    
    print("Extracting strings...")
    analyzer.extract_strings(min_length=args.min_string)
    
    print("Analyzing key offsets...")
    analyzer.analyze_key_offsets()
    
    # Generate report
    print("Generating report...")
    report = analyzer.generate_report()
    
    # Save report
    output_base = args.output or os.path.splitext(os.path.basename(args.ptx_file))[0] + "_report"
    
    if args.text:
        text_output = output_base + ".txt"
        save_text_report(report, text_output)
    
    json_output = output_base + ".json"
    save_json_report(report, json_output)
    
    # Print summary
    print("\nAnalysis Summary:")
    print(f"- File: {args.ptx_file}")
    print(f"- Size: {analyzer.file_size} bytes")
    print(f"- Sections found: {len(analyzer.sections)}")
    print(f"- Timecodes found: {len(analyzer.timecodes)}")
    print(f"- Meaningful strings: {len([s for s in analyzer.strings if s.get('is_timecode') or re.search(SESSION_INFO_PATTERN, s.get('value', ''))])}")
    print(f"- Report saved to: {json_output}")
    if args.text:
        print(f"- Text report saved to: {text_output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 