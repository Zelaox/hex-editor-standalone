"""
Utility functions for the HexEditor application.
"""
import re
import logging
import sys
import traceback
import os
import threading
import time
from typing import Optional, List, Tuple, Dict, Any, Set
from src.logging_config import setup_logging as configure_logging, log_exception, get_logger
from src.constants import BYTE_GROUP_SIZE

def setup_logging():
    """Set up logging for the application."""
    return configure_logging()

class FileCache:
    """
    Cache for efficient file access with background loading.
    Loads file data in chunks as needed and keeps recently accessed chunks in memory.
    """
    
    def __init__(self, file_path, chunk_size=1024*1024, max_cached_chunks=10):
        """
        Initialize the file cache.
        
        Args:
            file_path: Path to the file
            chunk_size: Size of each chunk in bytes
            max_cached_chunks: Maximum number of chunks to keep in memory
        """
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.max_cached_chunks = max_cached_chunks
        self.file_size = os.path.getsize(file_path)
        self.num_chunks = (self.file_size + chunk_size - 1) // chunk_size
        
        # Cache of loaded chunks {chunk_index: data}
        self.cache = {}
        self.cache_lock = threading.RLock()
        
        # LRU tracking for chunk eviction
        self.last_accessed = {}
        
        # Background loading
        self.background_chunks = set()
        self.loading_thread = None
        self.stop_loading = threading.Event()
        
        # Logger
        self.logger = get_logger('file_cache')
    
    def get_data(self, offset, size):
        """
        Get data from the file at the specified offset.
        
        Args:
            offset: Starting byte offset
            size: Number of bytes to read
            
        Returns:
            Bytes read from the file
        """
        if offset >= self.file_size:
            return b''
        
        # Adjust size if it goes beyond file end
        if offset + size > self.file_size:
            size = self.file_size - offset
        
        # Calculate which chunks are needed
        start_chunk = offset // self.chunk_size
        end_chunk = (offset + size - 1) // self.chunk_size
        
        # Load all necessary chunks
        result = b''
        for chunk_idx in range(start_chunk, end_chunk + 1):
            chunk_data = self._get_chunk(chunk_idx)
            
            # Calculate the portion of this chunk we need
            chunk_start = offset - (chunk_idx * self.chunk_size) if chunk_idx == start_chunk else 0
            chunk_end = ((offset + size) - (chunk_idx * self.chunk_size)) if chunk_idx == end_chunk else len(chunk_data)
            
            if chunk_end > len(chunk_data):
                chunk_end = len(chunk_data)
                
            if chunk_start < 0:
                chunk_start = 0
                
            result += chunk_data[chunk_start:chunk_end]
        
        # Start background loading of next chunks
        self._start_background_loading(end_chunk + 1, 3)
        
        return result
    
    def _get_chunk(self, chunk_idx):
        """
        Get a specific chunk, loading it if necessary.
        
        Args:
            chunk_idx: Index of the chunk to get
            
        Returns:
            The chunk data
        """
        if chunk_idx >= self.num_chunks:
            return b''
        
        with self.cache_lock:
            # Update access time for this chunk
            self.last_accessed[chunk_idx] = time.time()
            
            # Return from cache if available
            if chunk_idx in self.cache:
                return self.cache[chunk_idx]
            
            # Need to load the chunk
            chunk_offset = chunk_idx * self.chunk_size
            
            try:
                with open(self.file_path, 'rb') as f:
                    f.seek(chunk_offset)
                    chunk_data = f.read(self.chunk_size)
                    
                # Add to cache
                self.cache[chunk_idx] = chunk_data
                self._manage_cache_size()
                
                return chunk_data
            except Exception as e:
                self.logger.error(f"Error loading chunk {chunk_idx}: {e}")
                return b''
    
    def _manage_cache_size(self):
        """Remove least recently used chunks if cache exceeds maximum size."""
        if len(self.cache) <= self.max_cached_chunks:
            return
            
        # Find the least recently accessed chunks
        items = sorted(self.last_accessed.items(), key=lambda x: x[1])
        
        # Remove oldest chunks
        to_remove = len(self.cache) - self.max_cached_chunks
        for i in range(to_remove):
            if i < len(items):
                chunk_idx = items[i][0]
                with self.cache_lock:
                    if chunk_idx in self.cache:
                        del self.cache[chunk_idx]
                        del self.last_accessed[chunk_idx]
    
    def _start_background_loading(self, start_chunk, num_chunks):
        """
        Start background loading of chunks.
        
        Args:
            start_chunk: First chunk to load
            num_chunks: Number of chunks to load
        """
        # Add chunks to background loading queue
        chunks_to_load = set()
        for i in range(num_chunks):
            chunk_idx = start_chunk + i
            if chunk_idx < self.num_chunks and chunk_idx not in self.cache:
                chunks_to_load.add(chunk_idx)
        
        # Update background chunks set
        with self.cache_lock:
            self.background_chunks.update(chunks_to_load)
        
        # Start the loading thread if it's not already running
        if not self.loading_thread or not self.loading_thread.is_alive():
            self.stop_loading.clear()
            self.loading_thread = threading.Thread(target=self._background_loader)
            self.loading_thread.daemon = True
            self.loading_thread.start()
    
    def _background_loader(self):
        """Background thread to load chunks."""
        while not self.stop_loading.is_set():
            # Get the next chunk to load
            chunk_idx = None
            with self.cache_lock:
                if self.background_chunks:
                    chunk_idx = self.background_chunks.pop()
            
            if chunk_idx is not None:
                # Check if it's already in the cache
                with self.cache_lock:
                    if chunk_idx in self.cache:
                        continue
                
                # Load the chunk
                self._get_chunk(chunk_idx)
            else:
                # No more chunks to load, sleep briefly before checking again
                time.sleep(0.05)
                
                # If background chunks is still empty, exit
                with self.cache_lock:
                    if not self.background_chunks:
                        break
    
    def clear_cache(self):
        """Clear the entire cache."""
        with self.cache_lock:
            self.cache.clear()
            self.last_accessed.clear()
            self.background_chunks.clear()
            
    def stop_background_loading(self):
        """Stop any background loading."""
        if self.loading_thread and self.loading_thread.is_alive():
            self.stop_loading.set()
            self.loading_thread.join(1.0)  # Wait up to 1 second for thread to end
            
    def close(self):
        """Close the cache and release resources."""
        self.stop_background_loading()
        with self.cache_lock:
            self.cache.clear()
            self.last_accessed.clear()
            self.background_chunks.clear()

def bytes_to_hex_view(data: bytes, bytes_per_line: int = 16, base_offset: int = 0) -> str:
    """
    Convert binary data to a formatted hex view with improved readability.
    
    Args:
        data: The binary data to convert
        bytes_per_line: Number of bytes to display per line
        base_offset: Absolute file offset of the first byte in data
        
    Returns:
        A formatted string with hex representation
    """
    result = []
    origin = max(0, int(base_offset or 0))
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        
        # Format hex with extra spacing between groups for improved readability
        hex_groups = []
        for j in range(0, len(chunk), BYTE_GROUP_SIZE):
            group = chunk[j:j+BYTE_GROUP_SIZE]
            hex_groups.append(' '.join(f'{b:02X}' for b in group))
        
        hex_part = '  '.join(hex_groups)  # Double space between groups
        
        # Calculate padding to align the ASCII part
        # Each byte takes 2 chars + 1 space within group, and groups have extra space
        expected_hex_len = bytes_per_line * 3 + (bytes_per_line // BYTE_GROUP_SIZE - 1) * 1
        current_hex_len = len(hex_part)
        padding = ' ' * (expected_hex_len - current_hex_len)
        
        # ASCII representation
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        # Offset + hex + ascii with extra spacing for better readability
        line = f'{origin + i:08X}:  {hex_part}{padding}  |  {ascii_part}'
        result.append(line)
    
    return '\n'.join(result)

def hex_view_to_bytes(hex_content: str) -> bytes:
    """
    Convert a formatted hex view back to binary data.
    
    Args:
        hex_content: The formatted hex string
        
    Returns:
        The binary data
    """
    # Extract just the hex values, ignoring offsets and ASCII representation
    hex_only = []
    for line in hex_content.split('\n'):
        if ':' in line:
            # Extract the part between the colon and the pipe
            hex_part = line.split(':', 1)[1].split('|', 1)[0].strip()
            hex_only.append(hex_part)
    
    # Join all hex values and convert to bytes
    hex_str = ''.join(hex_only).replace(' ', '')
    
    # Convert hex string to bytes
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        logging.error(f"Error converting hex to bytes: {e}")
        return b''


def hex_view_to_bytes_strict(
    hex_content: str,
    expected_size: Optional[int] = None,
    base_offset: int = 0,
) -> bytes:
    """Parse an editor hex view and reject malformed, resized, or reordered data."""
    output = bytearray()
    expected_offset = max(0, int(base_offset or 0))
    for line_number, line in enumerate(hex_content.splitlines(), start=1):
        if not line.strip():
            continue
        if ':' not in line or '|' not in line:
            raise ValueError(f"Line {line_number} is not a valid hex-view row")
        offset_text, remainder = line.split(':', 1)
        try:
            displayed_offset = int(offset_text.strip(), 16)
        except ValueError as exc:
            raise ValueError(f"Line {line_number} has an invalid offset") from exc
        if displayed_offset != expected_offset:
            raise ValueError(
                f"Line {line_number} offset is 0x{displayed_offset:X}; expected 0x{expected_offset:X}"
            )
        hex_part = remainder.split('|', 1)[0]
        tokens = hex_part.split()
        if not tokens:
            raise ValueError(f"Line {line_number} contains no hexadecimal bytes")
        if len(tokens) > 16:
            raise ValueError(f"Line {line_number} contains more than 16 bytes")
        for token in tokens:
            if len(token) != 2 or re.fullmatch(r"[0-9A-Fa-f]{2}", token) is None:
                raise ValueError(f"Line {line_number} contains invalid byte {token!r}")
            output.append(int(token, 16))
        expected_offset += len(tokens)
    if expected_size is not None and len(output) != expected_size:
        raise ValueError(
            f"Edited view contains {len(output)} bytes; expected exactly {expected_size}. "
            "Inserting or deleting bytes is not supported."
        )
    return bytes(output)

def exception_hook(exc_type, exc_value, exc_traceback):
    """
    Custom exception hook to log unhandled exceptions.
    
    Args:
        exc_type: Exception type
        exc_value: Exception value
        exc_traceback: Exception traceback
    """
    # Log the exception
    log_exception(exc_type, exc_value, exc_traceback)
    
    # Format the exception
    error_msg = "".join(
        traceback.format_exception(exc_type, exc_value, exc_traceback)
    )
    
    # Print the exception to stderr
    print(error_msg, file=sys.stderr)

def is_valid_string(s: str, min_length: int = 4) -> bool:
    """
    Check if a string is valid (contains printable ASCII characters).
    
    Args:
        s: The string to check
        min_length: Minimum length for a valid string
        
    Returns:
        True if the string is valid, False otherwise
    """
    if len(s) < min_length:
        return False
    
    # Check if string contains mostly printable ASCII characters
    printable_count = sum(32 <= ord(c) <= 126 for c in s)
    return printable_count / len(s) >= 0.8

def format_bytes(data, bytes_per_line=16):
    """
    Format bytes as a hex string.
    
    Args:
        data: The bytes to format
        bytes_per_line: The number of bytes per line
        
    Returns:
        A formatted hex string
    """
    hex_dump = []
    ascii_dump = []
    
    for i, b in enumerate(data):
        # Add the hex representation
        hex_dump.append(f"{b:02X}")
        
        # Add the ASCII representation
        if 32 <= b <= 126:
            ascii_dump.append(chr(b))
        else:
            ascii_dump.append(".")
        
        # Add a space after each byte
        if (i + 1) % bytes_per_line != 0:
            hex_dump.append(" ")
        
        # Add a newline after each line
        if (i + 1) % bytes_per_line == 0:
            hex_dump.append("  ")
            hex_dump.append("".join(ascii_dump))
            hex_dump.append("\n")
            ascii_dump = []
    
    # Add any remaining ASCII characters
    if ascii_dump:
        # Calculate padding
        padding = " " * (3 * (bytes_per_line - len(ascii_dump)) - 1)
        hex_dump.append(padding)
        hex_dump.append("  ")
        hex_dump.append("".join(ascii_dump))
    
    return "".join(hex_dump)

def get_component_logger(component_name):
    """
    Get a logger for a specific component.
    
    Args:
        component_name: Name of the component
        
    Returns:
        Logger for the component
    """
    return get_logger(component_name) 
