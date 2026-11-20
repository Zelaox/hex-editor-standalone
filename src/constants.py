"""
Constants and configuration values for the HexEditor application.
"""

# File handling constants
CHUNK_SIZE = 256 * 1024  # Smaller 256KB chunks for more responsive loading
MAX_CACHED_CHUNKS = 30   # Keep more chunks in memory for smoother scrolling
VISIBLE_CHUNK_COUNT = 3  # Number of chunks to display at once for smooth scrolling

# Undo/Redo constants
MAX_UNDO_STEPS = 100

# Disassembly constants
MAX_INSTRUCTIONS = 10000

# Search constants
DEFAULT_SEARCH_TYPE = "text"
DEFAULT_CASE_SENSITIVE = False
DEFAULT_WHOLE_WORDS = False

# UI constants
DEFAULT_FONT_SIZE = 13
DEFAULT_FONT_FAMILY = "Consolas"
DEFAULT_HIGHLIGHT_COLOR = "lightblue"
BYTE_GROUP_SIZE = 4

# Display constants
HEX_TEXT_COLOR = "#E0E0E0"
OFFSET_COLOR = "#75B5AA"
ASCII_COLOR = "#FFCC66"

# General constants
APP_NAME = "HexEditor"
VERSION = "1.0.0"

# PTX file constants
PTX_HEADER_SIZE = 32
PTX_SECTION_HEADER_SIZE = 16

# Known PTX section types
PTX_SECTION_TYPES = {
    1531330650: "Primary Data Section",
    1159284524: "Metadata Section",
    13057: "Timing Section",
    2497877136: "Session Info",
    2308196969: "Audio Resources",
    28772: "Timeline Marker"
}

# Known PTX key offsets with detailed descriptions
PTX_KEY_OFFSETS = {
    0x00084058: "Timeline Start Marker (00:00:00:00)",
    0x00084090: "Timecode Reference (Primary)",
    0x0008418c: "Timecode Marker (00:01)",
    0x000846ec: "Timecode Marker (00:00:00:01)",
    0x00084a58: "Project Metadata (Session Name)",
    0x00084a70: "Timestamp Data (Session Creation)",
    0x00084e00: "Sample Rate Reference", 
    0x00085200: "Bit Depth Reference",
    0x00083b5c: "Track Count Marker",
    0x00083d34: "Audio Format Marker",
    0x00086444: "End Marker (Session End)",
    0x00087008: "Marker Reference Table",
    0x00087e50: "Media Pool Reference",
    0x0008790c: "Automation Data Start",
    0x00088180: "Plugin Data Reference",
    0x00088950: "Audio Fade Information",
    0x00089200: "Session Settings",
    0x00089854: "Region Reference Table"
}

# Timecode reference locations (18 key points)
PTX_TIMECODE_REFERENCES = [
    0x00084058,  # Start Timecode
    0x00084090,  # Primary Reference
    0x0008418c,  # 00:01 Mark
    0x000842b0,  # Ref #3
    0x00084320,  # Ref #4
    0x000844a8,  # Ref #5
    0x00084598,  # Ref #6
    0x000846ec,  # 00:00:00:01 Mark
    0x0008479c,  # Ref #8
    0x00084840,  # Ref #9
    0x00084910,  # Ref #10
    0x00084a58,  # Ref #11
    0x00084bd0,  # Ref #12
    0x00084c78,  # Ref #13
    0x00084d50,  # Ref #14
    0x00084e44,  # Ref #15
    0x00084f20,  # Ref #16
    0x00085008,  # Session End Timecode
]

# Known PTX encryption types with more detailed descriptions
PTX_ENCRYPTION_TYPES = {
    0: "Not encrypted",
    1: "Basic XOR encryption",
    2298806321: "AC240 XOR encryption (key: 0x94)",
    2: "AES-128 encryption",
    3: "Custom encryption algorithm",
    4: "Reserved encryption type"
}

# Common sample rates (in binary patterns) - enhanced with additional patterns
PTX_SAMPLE_RATES = {
    b'\x44\xac\x00\x00': 44100,  # 44.1 kHz
    b'\x80\xbb\x00\x00': 48000,  # 48 kHz
    b'\x00\x77\x01\x00': 96000,  # 96 kHz
    b'\x88\x58\x01\x00': 88200,  # 88.2 kHz
    b'\x00\xee\x02\x00': 192000  # 192 kHz
}

# Common bit depths with binary patterns
PTX_BIT_DEPTHS = {
    b'\x10\x00\x00\x00': 16,     # 16-bit
    b'\x18\x00\x00\x00': 24,     # 24-bit 
    b'\x20\x00\x00\x00': 32      # 32-bit
}

# PTX header field offsets
PTX_HEADER_FIELDS = {
    "magic": (0, 4),             # Magic number: 'PTX\0' or '\x03001'
    "version": (4, 8),           # Format version
    "flags": (8, 12),            # Flags
    "size": (12, 16),            # File size
    "encryption_type": (16, 20), # Encryption type
    "reserved": (20, 32)         # Reserved bytes
} 