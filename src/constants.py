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
