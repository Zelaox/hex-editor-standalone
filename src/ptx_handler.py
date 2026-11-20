"""
PTX file handler for the HexEditor application.

This module provides functionality for parsing, analyzing and decrypting PTX files.
"""
import os
import logging
import struct
import binascii
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, BinaryIO, Union
import traceback
import threading

from src.logging_config import get_logger
from src.constants import (
    PTX_HEADER_SIZE, PTX_SECTION_HEADER_SIZE, PTX_KEY_OFFSETS, 
    PTX_ENCRYPTION_TYPES, PTX_SAMPLE_RATES, PTX_SECTION_TYPES,
    PTX_BIT_DEPTHS, PTX_HEADER_FIELDS,
    CHUNK_SIZE
)
from src.utils import FileCache
from src.services.ptx_parse_policy import (
    load_ptx_parse_policy,
    timecode_anchor_bytes,
    timecode_reference_offsets,
    timecode_regex_patterns,
)

# Get the logger for this module
logger = get_logger('ptx_handler')

PTX_LAYOUT_SESSION_TEXT = "session_text_header"
PTX_LAYOUT_AC240_DECRYPTED = "ac240_decrypted_body"
PTX_LAYOUT_LEGACY = "legacy_binary"
PTX_LAYOUT_UNKNOWN = "unknown"


def _decode_bit_prefix(data: bytes) -> str:
    end = data.find(b"\x00")
    if end < 0:
        end = len(data)
    return data[:end].decode("ascii", errors="ignore")


def _is_valid_smpte(value: str) -> bool:
    parts = value.split(":")
    if len(parts) not in (2, 3, 4):
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    if any(num < 0 for num in nums):
        return False
    if len(parts) == 4:
        hours, minutes, seconds, frames = nums
        return hours <= 23 and minutes <= 59 and seconds <= 59 and frames <= 99
    if len(parts) == 3:
        hours, minutes, seconds = nums
        return hours <= 23 and minutes <= 59 and seconds <= 59
    minutes, seconds = nums
    return minutes <= 59 and seconds <= 59


class PTXHeader:
    """Class representing a PTX file header."""

    def __init__(
        self,
        data: bytes,
        *,
        layout: str = PTX_LAYOUT_LEGACY,
        session_strings: Optional[List[str]] = None,
        body_encrypted: bool = False,
    ):
        self.layout = layout
        self.raw_prefix = data[:32]
        self.magic = data[0:4].decode("ascii", errors="ignore")
        self.bit_prefix = _decode_bit_prefix(data[1:18])
        self.session_strings = list(session_strings or [])
        self.body_encrypted = body_encrypted
        self.version = struct.unpack("<I", data[4:8])[0]
        self.flags = struct.unpack("<I", data[8:12])[0]
        self.size = struct.unpack("<I", data[12:16])[0]
        self.encryption_type = struct.unpack("<I", data[16:20])[0]
        self.reserved = data[20:32]

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "PTX header parsed: layout=%s magic=%r bit_prefix=%r body_encrypted=%s",
                self.layout,
                self.magic,
                self.bit_prefix,
                self.body_encrypted,
            )

    def is_valid(self) -> bool:
        if self.layout in (PTX_LAYOUT_SESSION_TEXT, PTX_LAYOUT_AC240_DECRYPTED, PTX_LAYOUT_LEGACY):
            return True
        if self.magic == "PTX\0" or self.magic == "PTX0":
            return True
        if self.magic.startswith("\x03") or self.magic.startswith("001"):
            logger.debug("Detected alternative PTX format with magic: %r", self.magic)
            return True
        return False

    def is_encrypted(self) -> bool:
        if self.layout == PTX_LAYOUT_SESSION_TEXT:
            return self.body_encrypted
        if self.layout == PTX_LAYOUT_AC240_DECRYPTED:
            return False
        return self.encryption_type != 0

    def get_encryption_info(self) -> Dict[str, Any]:
        if self.layout == PTX_LAYOUT_SESSION_TEXT:
            encryption_info = {
                "encrypted": self.body_encrypted,
                "type": None,
                "description": (
                    "Session metadata is cleartext; main body has no cleartext SMPTE anchors."
                    if self.body_encrypted
                    else "Session metadata is cleartext and SMPTE anchors were found in the body."
                ),
            }
        elif self.layout == PTX_LAYOUT_AC240_DECRYPTED:
            encryption_info = {
                "encrypted": False,
                "type": None,
                "description": (
                    "AC240-family layout with decrypted body; bytes 0x10-0x13 are not a verified encryption_type field."
                ),
            }
        else:
            encryption_info = {
                "encrypted": self.is_encrypted(),
                "type": self.encryption_type,
                "description": self._get_encryption_description(self.encryption_type),
            }
        logger.debug("Encryption info: %s", encryption_info)
        return encryption_info

    def _get_encryption_description(self, encryption_type: int) -> str:
        if encryption_type in PTX_ENCRYPTION_TYPES:
            return PTX_ENCRYPTION_TYPES[encryption_type]
        if encryption_type == 0:
            return "Not encrypted"
        return f"Unknown encryption type: {encryption_type}"

    def _misaligned_binary_fields(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "flags": f"0x{self.flags:08x}",
            "size": self.size,
            "encryption_type": self.encryption_type,
            "reserved": binascii.hexlify(self.reserved).decode("ascii"),
            "note": (
                "Bytes 0x00-0x1F were decoded as legacy uint32 PTXHeader fields. "
                "On AC240-family layouts these values are misaligned and must not be treated as verified facts."
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        encryption_info = self.get_encryption_info()
        if self.layout == PTX_LAYOUT_SESSION_TEXT:
            return {
                "layout": self.layout,
                "magic": self.magic,
                "session_bit_prefix": self.bit_prefix,
                "session_strings": self.session_strings,
                "body_encrypted": self.body_encrypted,
                "encryption_info": encryption_info,
                "misaligned_binary_fields": self._misaligned_binary_fields(),
            }
        if self.layout == PTX_LAYOUT_AC240_DECRYPTED:
            return {
                "layout": self.layout,
                "magic": self.magic,
                "session_bit_prefix": self.bit_prefix,
                "body_encrypted": False,
                "encryption_info": encryption_info,
                "misaligned_binary_fields": self._misaligned_binary_fields(),
            }
        return {
            "layout": self.layout,
            "magic": self.magic,
            "version": self.version,
            "flags": f"0x{self.flags:08x}",
            "size": self.size,
            "encryption_type": self.encryption_type,
            "encryption_info": encryption_info,
            "reserved": binascii.hexlify(self.reserved).decode("ascii"),
        }

class PTXSection:
    """Class representing a section in a PTX file."""
    
    def __init__(self, data: bytes, offset: int):
        """
        Initialize the PTX section from binary data.
        
        Args:
            data: The section data
            offset: The offset of this section in the file
        """
        self.offset = offset
        self.type = struct.unpack('<I', data[0:4])[0]
        self.size = struct.unpack('<I', data[4:8])[0]
        self.flags = struct.unpack('<I', data[8:12])[0]
        self.reserved = data[12:16]
        self.data_offset = offset + 16
        
        # Use debug level instead of info for section parsing
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"PTX section parsed at offset 0x{offset:08x}: type={self.type}, size={self.size}, flags={self.flags:08x}")
    
    def get_section_type_name(self) -> str:
        """
        Get the name of the section type.
        
        Returns:
            The name of the section type
        """
        # Use the section types from our constants
        if self.type in PTX_SECTION_TYPES:
            return PTX_SECTION_TYPES[self.type]
        return f"Unknown ({self.type})"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the section to a dictionary.
        
        Returns:
            Dictionary representation of the section
        """
        return {
            "offset": f"0x{self.offset:08x}",
            "type": self.type,
            "type_name": self.get_section_type_name(),
            "size": self.size,
            "flags": f"0x{self.flags:08x}",
            "data_offset": f"0x{self.data_offset:08x}",
            "reserved": binascii.hexlify(self.reserved).decode('ascii')
        }

class PTXFile:
    """Class for handling PTX files."""
    
    # Constants based on our PTX analysis findings
    KEY_OFFSETS = {
        0x00084058: "Timeline Start Marker",
        0x00084090: "Timecode Reference",
        0x0008418c: "Timecode Marker (00:01)",
        0x000846ec: "Timecode Marker (00:00:00:01)",
        0x00084a58: "Project Metadata",
        0x00084a70: "Timestamp Data"
    }
    
    # Known encryption types based on analysis
    ENCRYPTION_TYPES = {
        0: "Not encrypted",
        1: "Basic XOR encryption",
        2298806321: "AC240 XOR encryption (0x94)",
        3: "Custom encryption algorithm"
    }
    
    def __init__(self, file_path: str):
        """
        Initialize a PTX file handler.
        
        Args:
            file_path: Path to the PTX file
        """
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        
        # Use FileCache for efficient access
        self.file_cache = FileCache(file_path, CHUNK_SIZE, 10)
        
        # Initialize fields
        self.header = None
        self.sections = []
        self.timecodes = []
        self.metadata = {}
        
        # Create a lock for thread safety
        self.lock = threading.RLock()
        
        # Create a flag to track parsing state
        self.parsing_complete = False
        
        # Parse the header immediately
        self._parse_header()

    def get_summary(self) -> Dict[str, Any]:
        """Return a stable, JSON-safe analysis summary for desktop export."""
        with self.lock:
            return {
                "schema_version": 1,
                "source": {
                    "path": str(Path(self.file_path).resolve()),
                    "size": int(self.file_size),
                },
                "parsing_complete": bool(self.parsing_complete),
                "header": self.header.to_dict() if self.header is not None else None,
                "metadata": dict(self.metadata or {}),
                "timecodes": [dict(item) for item in self.timecodes or []],
                "sections": [section.to_dict() for section in self.sections or []],
                "counts": {
                    "sections": len(self.sections or []),
                    "timecodes": len(self.timecodes or []),
                    "metadata_fields": len(self.metadata or {}),
                },
                "provenance": {
                    "parser": "PTXFile",
                    "confidence": "heuristic",
                    "note": "PTX structures are reverse-engineered observations, not an authoritative format specification.",
                },
            }
        
    def _parse_header(self):
        """Parse the PTX file header."""
        try:
            header_data = self.file_cache.get_data(0, PTX_HEADER_SIZE)
            prefix = self.file_cache.get_data(0, min(512, self.file_size))
            body_sample = self.file_cache.get_data(0, self.file_size)
            layout, session_strings, body_encrypted = self._detect_layout(prefix, body_sample)

            self.header = PTXHeader(
                header_data,
                layout=layout,
                session_strings=session_strings,
                body_encrypted=body_encrypted,
            )

            logger.debug("PTX header parsed: %s", self.header.to_dict())
            return self.header.is_valid()
        except Exception as e:
            logger.error(f"Error parsing PTX header: {e}", exc_info=True)
            return False

    @staticmethod
    def _detect_layout(prefix: bytes, body_sample: bytes) -> Tuple[str, List[str], bool]:
        magic = prefix[:4]
        has_session_text = any(
            marker in prefix
            for marker in (b"Pro Tools", b"Release", b"Pro Tools Session File", b"Windows")
        )
        has_smpte_anchors = any(pattern in body_sample for pattern in timecode_anchor_bytes())

        if magic.startswith(b"\x03") or magic.decode("ascii", errors="ignore").startswith("\x03"):
            if has_session_text:
                return PTX_LAYOUT_SESSION_TEXT, PTXFile._extract_strings_from_bytes(prefix), not has_smpte_anchors
            if has_smpte_anchors:
                return PTX_LAYOUT_AC240_DECRYPTED, [], False
            return PTX_LAYOUT_SESSION_TEXT, PTXFile._extract_strings_from_bytes(prefix), True

        if magic in (b"PTX0", b"PTX\x00"):
            return PTX_LAYOUT_LEGACY, [], False

        return PTX_LAYOUT_UNKNOWN, [], False

    @staticmethod
    def _extract_strings_from_bytes(data: bytes, min_length: int = 4) -> List[str]:
        strings: List[str] = []
        current: List[str] = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
        if len(current) >= min_length:
            strings.append("".join(current))
        return strings
    
    def parse(self) -> bool:
        """
        Parse the PTX file structure.
        
        Returns:
            True if parsing was successful, False otherwise
        """
        with self.lock:
            try:
                # Check if parsing is already complete
                if self.parsing_complete:
                    return True
                
                # Validate the header
                if not self.header or not self.header.is_valid():
                    logger.error("Invalid PTX header")
                    return False
                
                # Parse the sections
                self.sections = self._parse_sections()
                
                # Extract timecodes and metadata in parallel
                timecode_thread = threading.Thread(target=self._extract_timecodes)
                metadata_thread = threading.Thread(target=self._extract_metadata)
                
                timecode_thread.start()
                metadata_thread.start()
                
                # Wait for threads to complete
                timecode_thread.join()
                metadata_thread.join()
                
                # Mark parsing as complete
                self.parsing_complete = True
                
                return True
            except Exception as e:
                logger.error(f"Error parsing PTX file: {e}", exc_info=True)
                return False
    
    def _parse_sections(self) -> List[PTXSection]:
        """
        Parse the sections in the PTX file.
        """
        try:
            if self.header and self.header.layout == PTX_LAYOUT_SESSION_TEXT and self.header.body_encrypted:
                logger.debug("Skipping section parse for encrypted session_text_header body")
                return []

            if self.header and self.header.layout in (PTX_LAYOUT_AC240_DECRYPTED, PTX_LAYOUT_SESSION_TEXT):
                sections = self._discover_sections_by_known_types()
                logger.debug("Found %s sections via known-type discovery", len(sections))
                return sections

            return self._parse_sections_legacy()
        except Exception as e:
            logger.error(f"Error parsing PTX sections: {e}", exc_info=True)
            return []

    def _discover_sections_by_known_types(self) -> List[PTXSection]:
        sections: List[PTXSection] = []
        occupied: List[Tuple[int, int]] = []
        offset = 0x1000
        max_sections = 20

        while offset + PTX_SECTION_HEADER_SIZE <= self.file_size and len(sections) < max_sections:
            section_data = self.file_cache.get_data(offset, PTX_SECTION_HEADER_SIZE)
            section = PTXSection(section_data, offset)

            if section.type in PTX_SECTION_TYPES:
                max_payload = self.file_size - section.data_offset
                if PTX_SECTION_HEADER_SIZE <= section.size <= max_payload:
                    end = section.data_offset + section.size
                    overlaps = any(not (end <= start or offset >= stop) for start, stop in occupied)
                    if not overlaps:
                        sections.append(section)
                        occupied.append((offset, end))
                        offset = end
                        continue

            offset += 4

        return sorted(sections, key=lambda item: item.offset)

    def _parse_sections_legacy(self) -> List[PTXSection]:
        sections = []
        offset = PTX_HEADER_SIZE
        max_sections = 500
        for _ in range(max_sections):
            if offset + PTX_SECTION_HEADER_SIZE > self.file_size:
                break

            section_data = self.file_cache.get_data(offset, PTX_SECTION_HEADER_SIZE)
            section = PTXSection(section_data, offset)

            if section.type not in PTX_SECTION_TYPES and section.size > self.file_size:
                break

            sections.append(section)
            offset += max(section.size, PTX_SECTION_HEADER_SIZE)

            if offset >= self.file_size:
                break

        logger.debug(f"Found {len(sections)} sections in PTX file")
        return sections
    
    def _extract_timecodes(self):
        """Extract timecodes from the PTX file."""
        try:
            timecodes: List[Dict[str, Any]] = []
            policy = load_ptx_parse_policy()
            reference_offsets = timecode_reference_offsets(policy=policy)

            if self.header and self.header.layout == PTX_LAYOUT_SESSION_TEXT and self.header.body_encrypted:
                prefix = self.file_cache.get_data(0, min(0x400, self.file_size))
                self._find_timecodes_in_chunk(prefix, 0, timecodes, strict_only=True, reference_offsets=reference_offsets)
                self.timecodes = sorted(timecodes, key=lambda tc: tc["offset"])
                logger.debug(
                    "Extracted %s header-only timecodes from encrypted session body (layout=%s scan_bytes=%s)",
                    len(self.timecodes),
                    self.header.layout,
                    min(0x400, self.file_size),
                )
                return

            if self.header and self.header.layout == PTX_LAYOUT_AC240_DECRYPTED:
                self._extract_anchor_timecodes(timecodes, reference_offsets=reference_offsets)

            if self.header and self.header.layout == PTX_LAYOUT_LEGACY:
                for ref_offset in sorted(reference_offsets):
                    if ref_offset >= self.file_size:
                        continue
                    data = self.file_cache.get_data(ref_offset, 16)
                    tc = self._parse_timecode(data, ref_offset, reference_offsets=reference_offsets)
                    if tc:
                        timecodes.append(tc)

            for section in self.sections:
                if section.size <= 0:
                    continue
                scan_end = min(section.data_offset + section.size, self.file_size)
                for offset in range(section.data_offset, scan_end, CHUNK_SIZE):
                    chunk_size = min(CHUNK_SIZE, scan_end - offset)
                    chunk = self.file_cache.get_data(offset, chunk_size)
                    self._find_timecodes_in_chunk(chunk, offset, timecodes, strict_only=True, reference_offsets=reference_offsets)

            if self.file_size > 0:
                for offset in range(0, self.file_size, CHUNK_SIZE):
                    chunk_size = min(CHUNK_SIZE, self.file_size - offset)
                    chunk = self.file_cache.get_data(offset, chunk_size)
                    self._find_timecodes_in_chunk(chunk, offset, timecodes, strict_only=True, reference_offsets=reference_offsets)

            deduped: Dict[int, Dict[str, Any]] = {}
            for item in sorted(timecodes, key=lambda tc: tc["offset"]):
                deduped[item["offset"]] = item
            self.timecodes = list(deduped.values())
            logger.debug(
                "Extracted %s timecodes from PTX file (layout=%s scan_bytes=%s)",
                len(self.timecodes),
                getattr(self.header, "layout", PTX_LAYOUT_UNKNOWN),
                self.file_size,
            )
        except Exception as e:
            logger.error(f"Error extracting timecodes: {e}", exc_info=True)
            self.timecodes = []

    def _extract_anchor_timecodes(self, timecodes: List[Dict[str, Any]], *, reference_offsets: set[int]) -> None:
        sample = self.file_cache.get_data(0, self.file_size)
        for pattern in timecode_anchor_bytes():
            start = 0
            while True:
                idx = sample.find(pattern, start)
                if idx < 0:
                    break
                value = pattern.decode("ascii", errors="ignore")
                if not any(tc["offset"] == idx for tc in timecodes):
                    timecodes.append(
                        {
                            "offset": idx,
                            "value": value,
                            "type": "Anchor Timecode",
                            "reference_point": idx in reference_offsets,
                        }
                    )
                start = idx + 1
    
    def _find_timecodes_in_chunk(
        self,
        chunk: bytes,
        base_offset: int,
        timecodes: List[Dict[str, Any]],
        *,
        strict_only: bool = False,
        reference_offsets: set[int] | None = None,
    ):
        offsets = reference_offsets if reference_offsets is not None else timecode_reference_offsets()
        patterns = timecode_regex_patterns()

        for pattern in patterns:
            for match in re.finditer(pattern, chunk):
                offset = base_offset + match.start()
                value = match.group(0).decode("ascii", errors="ignore")
                if strict_only and not _is_valid_smpte(value):
                    continue
                if any(tc["offset"] == offset for tc in timecodes):
                    continue
                timecode = {
                    "offset": offset,
                    "value": value,
                    "type": "Timecode",
                    "reference_point": offset in offsets,
                }
                if timecode["reference_point"]:
                    timecode["type"] = "Reference Timecode"
                timecodes.append(timecode)
    
    def _parse_timecode(self, data: bytes, offset: int, *, reference_offsets: set[int] | None = None) -> Optional[Dict[str, Any]]:
        """
        Parse a timecode from binary data.
        
        Args:
            data: The binary data
            offset: The offset of the data
            
        Returns:
            Dictionary with timecode information or None if not a valid timecode
        """
        try:
            offsets = reference_offsets if reference_offsets is not None else timecode_reference_offsets()
            # Try to decode as ASCII
            text = data.decode('ascii', errors='ignore')
            
            # Look for timecode patterns
            patterns = [
                r'(\d\d:\d\d:\d\d:\d\d)',  # HH:MM:SS:FF
                r'(\d\d:\d\d:\d\d)',       # HH:MM:SS
                r'(\d\d:\d\d)'             # MM:SS
            ]
            
            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    value = match.group(0)
                    if not _is_valid_smpte(value):
                        continue
                    timecode = {
                        'offset': offset,
                        'value': value,
                        'type': 'Timecode',
                        'reference_point': False
                    }
                    
                    if offset in offsets:
                        timecode['reference_point'] = True
                        timecode['type'] = 'Reference Timecode'
                    
                    return timecode
            
            return None
        except Exception as e:
            logger.error(f"Error parsing timecode at offset {offset}: {e}")
            return None
    
    def _extract_metadata(self):
        """Extract metadata from the PTX file."""
        try:
            metadata = {}
            
            # Extract basic file information
            metadata['file_path'] = self.file_path
            metadata['file_size'] = self.file_size
            
            # Add header information
            if self.header:
                metadata["header"] = self.header.to_dict()
                if self.header.layout == PTX_LAYOUT_SESSION_TEXT and self.header.session_strings:
                    metadata["session_strings"] = self.header.session_strings
                    for candidate in self.header.session_strings:
                        if "Session File" not in candidate and len(candidate) > 3:
                            metadata.setdefault("session_name", candidate)
                            break
            
            # Extract session name
            if self.sections and len(self.sections) > 1:
                # Check for session name in the second section (often metadata)
                section = self.sections[1]
                data = self.file_cache.get_data(section.data_offset, min(section.size, 1024))
                
                # Look for readable strings that might be session names
                strings = self._extract_readable_strings(data)
                if strings:
                    metadata['session_name'] = strings[0]
            
            # Extract sample rate
            for section in self.sections:
                if section.size >= 4:
                    data = self.file_cache.get_data(section.data_offset, 4)
                    for pattern, rate in PTX_SAMPLE_RATES.items():
                        if data.startswith(pattern):
                            metadata['sample_rate'] = rate
                            break
            
            # Extract bit depth
            for section in self.sections:
                if section.size >= 4:
                    data = self.file_cache.get_data(section.data_offset, 4)
                    for pattern, depth in PTX_BIT_DEPTHS.items():
                        if data.startswith(pattern):
                            metadata['bit_depth'] = depth
                            break
            
            # Extract encryption information
            if self.header:
                metadata['encryption'] = self.header.get_encryption_info()
            
            # Save the metadata
            self.metadata = metadata
            
            logger.debug(f"Extracted metadata with {len(metadata)} keys")
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}", exc_info=True)
            self.metadata = {}
    
    def _extract_readable_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """
        Extract readable strings from binary data.
        
        Args:
            data: The binary data
            min_length: Minimum length for a string to be considered valid
            
        Returns:
            List of readable strings
        """
        strings = []
        current = []
        
        for byte in data:
            # Check if the byte is a printable ASCII character
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                # End of string
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        # Add the last string if it's valid
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    def close(self):
        """Clean up resources."""
        if self.file_cache:
            self.file_cache.close()
            self.file_cache = None

    def extract_section_data(self, section_index: int, output_path: str | None = None):
        """Read one parsed section with strict bounds and optionally write it atomically."""
        with self.lock:
            if self.file_cache is None:
                raise RuntimeError("PTX file is closed")
            if not self.parsing_complete and not self.parse():
                raise ValueError("PTX file could not be parsed before section extraction")
            index = int(section_index)
            if index < 0 or index >= len(self.sections):
                raise IndexError(f"section index out of range: {index}")
            section = self.sections[index]
            data_length = int(section.size) - PTX_SECTION_HEADER_SIZE
            data_offset = int(section.data_offset)
            if data_length < 0:
                raise ValueError(f"section {index} is smaller than its section header")
            if data_offset < 0 or data_offset + data_length > self.file_size:
                raise ValueError(f"section {index} bounds exceed the PTX source")
            content = self.file_cache.get_data(data_offset, data_length)
            if len(content) != data_length:
                raise IOError(f"section {index} returned a short read")
            if output_path is None:
                return content

            destination = Path(output_path).expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp")
            try:
                with temporary.open("wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink()
            logger.debug("Extracted section %s to %s", index, destination)
            return str(destination)

    def extract_all(self, output_dir: str) -> Dict[str, str]:
        """
        Extract all sections of the PTX file to separate files.
        
        Args:
            output_dir: Directory to extract files to
            
        Returns:
            Dictionary mapping section names to output file paths
        """
        extracted_files = {}
        
        try:
            # Make sure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Make sure the file is parsed
            if not self.parsing_complete:
                self.parse()
            
            # Extract the header
            header_path = os.path.join(output_dir, "header.bin")
            with open(header_path, 'wb') as f:
                f.write(self.file_cache.get_data(0, PTX_HEADER_SIZE))
            extracted_files["Header"] = header_path
            
            # Extract each section
            for i, section in enumerate(self.sections):
                # Create a filename based on section type
                section_type = section.get_section_type_name()
                section_name = f"section_{i}_{section_type.replace(' ', '_').lower()}"
                section_path = os.path.join(output_dir, f"{section_name}.bin")
                
                # Extract the section data
                section_data = self.file_cache.get_data(section.data_offset, section.size - PTX_SECTION_HEADER_SIZE)
                
                # Write the section data to a file
                with open(section_path, 'wb') as f:
                    f.write(section_data)
                
                extracted_files[f"Section {i}: {section_type}"] = section_path
                
                logger.debug(f"Extracted section {i} to {section_path}")
            
            # Extract metadata to a JSON file
            metadata_path = os.path.join(output_dir, "metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(self.metadata, f, indent=4)
            extracted_files["Metadata"] = metadata_path
            
            # Extract timecodes to a text file
            if self.timecodes:
                timecodes_path = os.path.join(output_dir, "timecodes.txt")
                with open(timecodes_path, 'w') as f:
                    for tc in self.timecodes:
                        f.write(f"Offset: 0x{tc['offset']:08X}, Value: {tc['value']}, Type: {tc['type']}\n")
                extracted_files["Timecodes"] = timecodes_path
            
            logger.info(f"Extracted {len(extracted_files)} components from PTX file to {output_dir}")
            return extracted_files
            
        except Exception as e:
            logger.error(f"Error extracting PTX file: {e}", exc_info=True)
            return extracted_files

def detect_file_type(file_path: str) -> Optional[Union[PTXFile, Any]]:
    """
    Detect the type of file and return an appropriate handler.
    
    Args:
        file_path: Path to the file
        
    Returns:
        A file handler or None if the file type is not recognized
    """
    try:
        # Check the file extension
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.ptx':
            return PTXFile(file_path)

        from src.runtime.config import load_binary_dynamic_config
        from src.runtime.format_router import detect_format_plugin

        try:
            if detect_format_plugin(file_path, cfg=load_binary_dynamic_config()) == "ptx":
                return PTXFile(file_path)
        except Exception:
            pass

        return None
    except Exception as e:
        logger.error(f"Error detecting file type: {e}", exc_info=True)
        return None 
