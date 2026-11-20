"""
PTX Rebuilder module for restructuring and rebuilding PTX files.

This module provides functionality for rebuilding PTX files from their individual components,
allowing for structural editing, component replacement, and modifications to timecodes and metadata.
"""
import os
import logging
import struct
import binascii
import json
import re
from typing import Dict, List, Optional, Tuple, Any, BinaryIO
from pathlib import Path

from src.logging_config import get_logger
from src.constants import (
    PTX_HEADER_SIZE, PTX_SECTION_HEADER_SIZE, PTX_KEY_OFFSETS, 
    PTX_ENCRYPTION_TYPES, PTX_SAMPLE_RATES, PTX_SECTION_TYPES,
    PTX_TIMECODE_REFERENCES, PTX_BIT_DEPTHS, PTX_HEADER_FIELDS
)
from src.ptx_handler import PTXFile, PTXHeader, PTXSection

# Get the logger for this module
logger = get_logger('ptx_rebuilder')

class PTXRebuilder:
    """
    Class for rebuilding PTX files from their components.
    
    This class provides the ability to restructure a PTX file by:
    1. Reading the extracted components
    2. Modifying components as needed
    3. Rebuilding the file with proper structure
    4. Optionally encrypting the result
    """
    
    def __init__(self, components_dir: str = None, source_ptx: str = None):
        """
        Initialize the PTX rebuilder.
        
        Args:
            components_dir: Directory containing extracted PTX components
            source_ptx: Path to a source PTX file to use as reference
        """
        self.components_dir = components_dir
        self.source_ptx = source_ptx
        self.header_data = None
        self.sections = []
        self.metadata = {}
        self.timecodes = []
        self.custom_data = {}  # For storing modifications at specific offsets
        self.output_size = 0
        self.logger = logger
        
        # Initialize from components if directory provided
        if components_dir and os.path.isdir(components_dir):
            self.load_from_components(components_dir)
        
        # Initialize from source file if provided
        elif source_ptx and os.path.isfile(source_ptx):
            self.load_from_source(source_ptx)
    
    def load_from_components(self, components_dir: str) -> bool:
        """
        Load PTX components from a directory.
        
        Args:
            components_dir: Path to directory containing extracted components
            
        Returns:
            True if components were loaded successfully, False otherwise
        """
        self.logger.info(f"Loading PTX components from {components_dir}")
        
        try:
            # Load header
            header_path = os.path.join(components_dir, "header.bin")
            if os.path.exists(header_path):
                with open(header_path, "rb") as f:
                    self.header_data = f.read(PTX_HEADER_SIZE)
                    self.logger.info(f"Loaded header: {len(self.header_data)} bytes")
            else:
                self.logger.error(f"Header file not found: {header_path}")
                return False
            
            # Load metadata from JSON
            metadata_path = os.path.join(components_dir, "metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                    if "metadata" in metadata:
                        self.metadata = metadata["metadata"]
                    else:
                        self.metadata = metadata
                    self.logger.info(f"Loaded metadata: {len(self.metadata)} entries")
            
            # Load sections by finding all section_*.bin files
            section_files = [f for f in os.listdir(components_dir) if f.startswith("section_") and f.endswith(".bin")]
            section_files.sort(key=lambda x: int(re.search(r"section_(\d+)_", x).group(1)) if re.search(r"section_(\d+)_", x) else 999)
            
            for section_file in section_files:
                section_path = os.path.join(components_dir, section_file)
                
                # Extract section index and type from filename
                section_info = re.search(r"section_(\d+)_(.+)\.bin", section_file)
                if section_info:
                    section_index = int(section_info.group(1))
                    section_type_name = section_info.group(2)
                    
                    # Find section type from name
                    section_type = None
                    for type_id, name in PTX_SECTION_TYPES.items():
                        if name.lower().replace(" ", "_").replace("(", "").replace(")", "") == section_type_name:
                            section_type = type_id
                            break
                    
                    # If type not found, use a default
                    if section_type is None:
                        section_type = 0
                    
                    # Read section data
                    with open(section_path, "rb") as f:
                        section_data = f.read()
                        
                        # Add to sections list
                        self.sections.append({
                            "index": section_index,
                            "type": section_type,
                            "type_name": section_type_name,
                            "data": section_data,
                            "size": len(section_data)
                        })
                        self.logger.info(f"Loaded section {section_index}: {section_type_name}, {len(section_data)} bytes")
            
            # Sort sections by index
            self.sections.sort(key=lambda x: x["index"])
            
            # Load timecodes from timecodes.txt if available
            timecodes_path = os.path.join(components_dir, "timecodes.txt")
            if os.path.exists(timecodes_path):
                self.timecodes = self._parse_timecodes_file(timecodes_path)
                self.logger.info(f"Loaded {len(self.timecodes)} timecodes")
            
            self.logger.info(f"Successfully loaded PTX components: {len(self.sections)} sections")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading PTX components: {str(e)}", exc_info=True)
            return False
    
    def load_from_source(self, source_ptx: str) -> bool:
        """
        Load PTX structure from a source file.
        
        Args:
            source_ptx: Path to the source PTX file
            
        Returns:
            True if the source file was loaded successfully, False otherwise
        """
        self.logger.info(f"Loading PTX structure from {source_ptx}")
        
        try:
            # Use PTXFile to parse the source file
            ptx_file = PTXFile(source_ptx)
            if not ptx_file.parse():
                self.logger.error(f"Failed to parse source PTX file: {source_ptx}")
                return False
            
            # Copy the header data
            with open(source_ptx, "rb") as f:
                self.header_data = f.read(PTX_HEADER_SIZE)
            
            # Copy the metadata
            self.metadata = ptx_file.metadata if hasattr(ptx_file, 'metadata') else {}
            
            # Copy the timecodes
            # Ensure we preserve offset, value, type, and reference_point
            if hasattr(ptx_file, 'timecodes'):
                for tc in ptx_file.timecodes:
                    # Make sure each timecode has correct structure
                    timecode_entry = {}
                    
                    # Handle different structures of timecode entries
                    if isinstance(tc, dict):
                        # Already in dict format
                        timecode_entry = tc.copy()
                    else:
                        # Other format - try to extract needed fields
                        timecode_entry = {
                            "offset": getattr(tc, 'offset', 0),
                            "value": getattr(tc, 'value', ''),
                            "type": getattr(tc, 'type', 'Unknown'),
                            "reference_point": getattr(tc, 'reference_point', False)
                        }
                    
                    # Ensure offset is an integer
                    if isinstance(timecode_entry.get("offset"), str) and timecode_entry["offset"].startswith("0x"):
                        timecode_entry["offset"] = int(timecode_entry["offset"], 16)
                        
                    self.timecodes.append(timecode_entry)
                
                self.logger.info(f"Copied {len(self.timecodes)} timecodes")
            
            # Read section data
            for i, section in enumerate(ptx_file.sections):
                with open(source_ptx, "rb") as f:
                    data_offset = getattr(section, 'data_offset', section.offset + PTX_SECTION_HEADER_SIZE)
                    f.seek(data_offset)
                    section_data = f.read(section.size)
                    
                    # Add to sections list
                    self.sections.append({
                        "index": i,
                        "type": section.type,
                        "type_name": section.get_section_type_name(),
                        "data": section_data,
                        "size": len(section_data),
                        "offset": section.offset
                    })
            
            self.logger.info(f"Successfully loaded PTX structure: {len(self.sections)} sections")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading PTX structure: {str(e)}", exc_info=True)
            return False
    
    def _parse_timecodes_file(self, timecodes_path: str) -> List[Dict[str, Any]]:
        """
        Parse a timecodes.txt file to extract timecode information.
        
        Args:
            timecodes_path: Path to the timecodes text file
            
        Returns:
            List of timecode dictionaries
        """
        timecodes = []
        
        try:
            with open(timecodes_path, "r") as f:
                lines = f.readlines()
                
                for line in lines:
                    # Skip header lines and empty lines
                    if not line.strip() or line.startswith("PTX File Timecodes") or line.startswith("="):
                        continue
                    
                    # Check for reference timecode marker
                    is_reference = line.strip().startswith("*")
                    if is_reference:
                        line = line.strip()[1:]  # Remove the marker
                    
                    # Parse the line for offset, type, and value
                    match = re.search(r"Offset: (0x[0-9a-fA-F]+), Type: ([^,]+), Value: (.+)", line)
                    if match:
                        offset_str, tc_type, value = match.groups()
                        offset = int(offset_str, 16)
                        
                        timecodes.append({
                            "offset": offset,
                            "value": value.strip(),
                            "type": tc_type.strip(),
                            "reference_point": is_reference
                        })
            
            return timecodes
            
        except Exception as e:
            self.logger.error(f"Error parsing timecodes file: {str(e)}", exc_info=True)
            return []
    
    def set_header_field(self, field_name: str, value: Any) -> bool:
        """
        Set a field in the PTX header.
        
        Args:
            field_name: Name of the header field (magic, version, flags, size, encryption_type)
            value: Value to set for the field
            
        Returns:
            True if the field was set successfully, False otherwise
        """
        if not self.header_data or len(self.header_data) != PTX_HEADER_SIZE:
            self.logger.error("Cannot set header field: header data not loaded")
            return False
        
        try:
            # Convert header data to bytearray for modification
            header = bytearray(self.header_data)
            
            # Check if the field name exists in header fields
            if field_name not in PTX_HEADER_FIELDS:
                self.logger.error(f"Unknown header field: {field_name}")
                return False
            
            # Get the field offset and size
            start, end = PTX_HEADER_FIELDS[field_name]
            
            # Handle different field types
            if field_name == "magic":
                # Magic is a 4-byte string
                if isinstance(value, str):
                    value = value.encode('ascii')
                if len(value) != 4:
                    value = value.ljust(4, b'\0')
                header[start:end] = value[:4]
            
            elif field_name in ["version", "flags", "size", "encryption_type"]:
                # These are 32-bit integers
                if isinstance(value, str) and value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)
                header[start:end] = struct.pack("<I", value)
            
            elif field_name == "reserved":
                # Reserved is 12 bytes
                if isinstance(value, str):
                    # Handle hex string
                    if value.startswith("0x"):
                        value = bytes.fromhex(value[2:])
                    else:
                        value = value.encode('ascii')
                if len(value) != 12:
                    value = value.ljust(12, b'\0')
                header[start:end] = value[:12]
            
            # Update the header data
            self.header_data = bytes(header)
            self.logger.info(f"Set header field {field_name} to {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting header field: {str(e)}", exc_info=True)
            return False
    
    def replace_section(self, section_index: int, new_data: bytes, new_type: int = None) -> bool:
        """
        Replace a section with new data.
        
        Args:
            section_index: Index of the section to replace
            new_data: New section data
            new_type: New section type (optional)
            
        Returns:
            True if the section was replaced successfully, False otherwise
        """
        if section_index < 0 or section_index >= len(self.sections):
            self.logger.error(f"Invalid section index: {section_index}")
            return False
        
        try:
            # Update the section
            section = self.sections[section_index]
            section["data"] = new_data
            section["size"] = len(new_data)
            
            if new_type is not None:
                section["type"] = new_type
                # Try to find the type name
                if new_type in PTX_SECTION_TYPES:
                    section["type_name"] = PTX_SECTION_TYPES[new_type]
                else:
                    section["type_name"] = f"Unknown ({new_type})"
            
            self.logger.info(f"Replaced section {section_index}: {section['type_name']}, {section['size']} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"Error replacing section: {str(e)}", exc_info=True)
            return False
    
    def add_section(self, section_data: bytes, section_type: int, section_index: int = None) -> bool:
        """
        Add a new section to the PTX file.
        
        Args:
            section_data: Data for the new section
            section_type: Type of the new section
            section_index: Index for the new section (optional, will be added at the end if not provided)
            
        Returns:
            True if the section was added successfully, False otherwise
        """
        try:
            # Create the new section
            new_section = {
                "type": section_type,
                "data": section_data,
                "size": len(section_data)
            }
            
            # Try to find the type name
            if section_type in PTX_SECTION_TYPES:
                new_section["type_name"] = PTX_SECTION_TYPES[section_type]
            else:
                new_section["type_name"] = f"Unknown ({section_type})"
            
            # Add the section at the specified index or at the end
            if section_index is not None:
                if section_index < 0 or section_index > len(self.sections):
                    self.logger.error(f"Invalid section index: {section_index}")
                    return False
                
                new_section["index"] = section_index
                self.sections.insert(section_index, new_section)
                
                # Update indices for sections after this one
                for i in range(section_index + 1, len(self.sections)):
                    self.sections[i]["index"] = i
            else:
                new_section["index"] = len(self.sections)
                self.sections.append(new_section)
            
            self.logger.info(f"Added new section {new_section['index']}: {new_section['type_name']}, {new_section['size']} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding section: {str(e)}", exc_info=True)
            return False
    
    def remove_section(self, section_index: int) -> bool:
        """
        Remove a section from the PTX file.
        
        Args:
            section_index: Index of the section to remove
            
        Returns:
            True if the section was removed successfully, False otherwise
        """
        if section_index < 0 or section_index >= len(self.sections):
            self.logger.error(f"Invalid section index: {section_index}")
            return False
        
        try:
            # Remove the section
            removed = self.sections.pop(section_index)
            
            # Update indices for sections after this one
            for i in range(section_index, len(self.sections)):
                self.sections[i]["index"] = i
            
            self.logger.info(f"Removed section {section_index}: {removed['type_name']}, {removed['size']} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing section: {str(e)}", exc_info=True)
            return False
    
    def set_timecode(self, offset: int, value: str, tc_type: str = None, is_reference: bool = None) -> bool:
        """
        Set a timecode at a specific offset.
        
        Args:
            offset: Offset to set the timecode at
            value: Timecode value (e.g., "00:00:01:00")
            tc_type: Timecode type (e.g., "SMPTE", "Decimal")
            is_reference: Whether this is a reference timecode
            
        Returns:
            True if the timecode was set successfully, False otherwise
        """
        try:
            # Handle string offsets (convert to int)
            if isinstance(offset, str):
                if offset.startswith("0x"):
                    offset = int(offset, 16)
                else:
                    offset = int(offset)
            
            # Check if there's already a timecode at this offset
            existing = next((tc for tc in self.timecodes if tc["offset"] == offset), None)
            
            if existing:
                # Update existing timecode
                existing["value"] = value
                if tc_type is not None:
                    existing["type"] = tc_type
                if is_reference is not None:
                    existing["reference_point"] = is_reference
                self.logger.info(f"Updated timecode at offset 0x{offset:08x}: {value}")
            else:
                # Create new timecode
                new_tc = {
                    "offset": offset,
                    "value": value,
                    "type": tc_type or "SMPTE",
                    "reference_point": bool(is_reference)
                }
                self.timecodes.append(new_tc)
                self.logger.info(f"Added timecode at offset 0x{offset:08x}: {value}")
            
            # Store the actual binary data for this timecode
            # For SMPTE timecodes (00:00:00:00 format), convert to binary for direct writing
            if tc_type == "SMPTE (Binary)" or (tc_type is None and ":" in value and len(value.split(":")) == 4):
                try:
                    # Parse 00:00:00:00 format
                    hh, mm, ss, ff = map(int, value.split(":"))
                    binary_data = bytes([hh, mm, ss, ff])
                    
                    # Store in custom data for writing later
                    self.custom_data[offset] = binary_data
                except Exception as e:
                    self.logger.warning(f"Failed to parse SMPTE timecode: {value}, error: {str(e)}")
                    # If parsing fails, store as ASCII
                    self.custom_data[offset] = value.encode('ascii')
            else:
                # For all other timecodes, store as ASCII
                self.custom_data[offset] = value.encode('ascii')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting timecode: {str(e)}", exc_info=True)
            return False
    
    def rebuild(self, output_path: str, encrypt: bool = False, encryption_key: int = None) -> bool:
        """
        Rebuild the PTX file from components.
        
        Args:
            output_path: Path to save the rebuilt file
            encrypt: Whether to encrypt the file
            encryption_key: Encryption key (if not provided, AC240 default key 0x94 will be used)
            
        Returns:
            True if the file was rebuilt successfully, False otherwise
        """
        self.logger.info(f"Rebuilding PTX file to {output_path}")
        
        if not self.header_data:
            self.logger.error("Cannot rebuild: header data not loaded")
            return False
        
        try:
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            with open(output_path, "wb") as f:
                # Write the header
                f.write(self.header_data)
                current_offset = PTX_HEADER_SIZE
                
                # Calculate and update section offsets
                for section in self.sections:
                    section["offset"] = current_offset
                    
                    # Section header (16 bytes)
                    section_header = struct.pack("<I", section["type"])  # Type (4 bytes)
                    section_header += struct.pack("<I", section["size"])  # Size (4 bytes)
                    section_header += struct.pack("<I", 0)  # Flags (4 bytes, default to 0)
                    section_header += b'\0' * 4  # Reserved (4 bytes)
                    
                    # Write section header
                    f.write(section_header)
                    current_offset += PTX_SECTION_HEADER_SIZE
                    
                    # Write section data
                    f.write(section["data"])
                    current_offset += section["size"]
                
                # Apply custom data patches (timecodes, etc.)
                for offset, data in self.custom_data.items():
                    if offset < current_offset:
                        # Seek to the offset and write the data
                        f.seek(offset)
                        f.write(data)
                        # Return to the end of the file
                        f.seek(0, 2)
                    else:
                        self.logger.warning(f"Custom data at offset 0x{offset:08x} is beyond current file size, skipping")
                
                # Get the final file size
                self.output_size = f.tell()
                
                # Update the file size in the header if it has changed
                if self.output_size != struct.unpack("<I", self.header_data[12:16])[0]:
                    f.seek(12)
                    f.write(struct.pack("<I", self.output_size))
            
            # Encrypt the file if requested
            if encrypt:
                self.encrypt_file(output_path, output_path, encryption_key)
            
            self.logger.info(f"Successfully rebuilt PTX file: {self.output_size} bytes, {len(self.sections)} sections")
            return True
            
        except Exception as e:
            self.logger.error(f"Error rebuilding PTX file: {str(e)}", exc_info=True)
            return False
    
    def encrypt_file(self, input_path: str, output_path: str, encryption_key: int = None) -> bool:
        """
        Encrypt a PTX file using the AC240 encryption method.
        
        Args:
            input_path: Path to the file to encrypt
            output_path: Path to save the encrypted file
            encryption_key: Encryption key (if not provided, AC240 default key 0x94 will be used)
            
        Returns:
            True if the file was encrypted successfully, False otherwise
        """
        # Default to AC240 encryption key (0x94)
        if encryption_key is None:
            encryption_key = 0x94
        
        self.logger.info(f"Encrypting PTX file: {input_path} -> {output_path}")
        
        try:
            # Create a temporary file if input and output are the same
            temp_path = None
            if input_path == output_path:
                temp_path = output_path + ".tmp"
                output_path = temp_path
            
            with open(input_path, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    # Copy the first 16 bytes unchanged (header portion)
                    header = f_in.read(16)
                    f_out.write(header)
                    
                    # Update encryption type in the header
                    f_out.seek(16)
                    f_out.write(struct.pack("<I", 2298806321))  # AC240 encryption type
                    
                    # Continue from byte 20
                    f_in.seek(20)
                    f_out.seek(20)
                    
                    # Encrypt the rest of the file
                    while True:
                        chunk = f_in.read(4096)
                        if not chunk:
                            break
                        
                        # Apply XOR encryption
                        encrypted_chunk = bytes([b ^ encryption_key for b in chunk])
                        f_out.write(encrypted_chunk)
            
            # If we used a temporary file, replace the original with it
            if temp_path:
                # On Windows, we need to remove the original file first
                if os.path.exists(input_path):
                    os.remove(input_path)
                os.rename(temp_path, input_path)
            
            self.logger.info(f"Successfully encrypted PTX file with key 0x{encryption_key:02x}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error encrypting PTX file: {str(e)}", exc_info=True)
            return False 