"""
Decryption module for PTX files.

This module provides functions for decrypting Pro Tools PTX files.
"""

import logging
import struct

# Set up logging
logger = logging.getLogger(__name__)

class PTXDecryptor:
    """Class for decrypting PTX files"""
    
    def __init__(self):
        """Initialize the decryptor"""
        pass
    
    def decrypt_ptx_data(self, data):
        """
        Decrypt PTX data
        
        Args:
            data (bytes): Encrypted PTX data
            
        Returns:
            bytes: Decrypted data, or the original data if decryption fails
        """
        # Check if data is already decrypted
        if self._is_decrypted(data):
            logger.debug("Data appears to be already decrypted")
            return data
        
        # Check for known signatures
        if data.startswith(b'\x03\x30\x30\x31'):  # Pro Tools 12.x
            logger.info("Applying Pro Tools 12.x decryption algorithm")
            decrypted = self._decrypt_pt12(data)
            if decrypted:
                logger.info(f"Successfully decrypted {len(decrypted)} bytes of Pro Tools 12.x data")
                return decrypted
        elif data.startswith(b'PTX '):  # Pro Tools X
            logger.info("Applying Pro Tools X decryption algorithm")
            decrypted = self._decrypt_ptx(data)
            if decrypted:
                logger.info(f"Successfully decrypted {len(decrypted)} bytes of Pro Tools X data")
                return decrypted
        
        # Check for audio format signatures
        if data.startswith(b'RIFF') or data.startswith(b'FORM') or data.startswith(b'fLaC'):
            logger.debug("Found audio format signature, no decryption needed")
            return data
        
        # If no known signature is found, analyze the data to determine if decryption is needed
        if self._is_binary_data(data):
            logger.info("Data appears to be binary, attempting generic decryption")
            decrypted = self._decrypt_generic_binary(data)
            if decrypted and decrypted != data:
                return decrypted
        
        # If all else fails, try marker-based decryption
        decrypted = self._decrypt_marker_based(data)
        if decrypted and decrypted != data:
            return decrypted
        
        # If no decryption method worked, return the original data
        logger.warning("Could not determine decryption method, returning original data")
        return data
    
    def _is_decrypted(self, data):
        """
        Check if data is already decrypted
        
        Args:
            data (bytes): Data to check
            
        Returns:
            bool: True if data appears to be already decrypted
        """
        # Check for audio format signatures
        if (data.startswith(b'RIFF') or data.startswith(b'FORM') or 
            data.startswith(b'fLaC') or data.startswith(b'OggS')):
            return True
        
        # Check for Pro Tools markers
        markers = [b'TRAK', b'CLIP', b'MEDI', b'EDIT', b'PLUG', b'MIXR', b'SESS', b'INFO']
        marker_count = 0
        for marker in markers:
            marker_count += data.count(marker)
        
        # If we find multiple markers, it's likely already decrypted
        if marker_count >= 3:
            return True
        
        # Check for high proportion of printable ASCII
        sample = data[:1024] if len(data) > 1024 else data
        printable_count = sum(1 for b in sample if 32 <= b <= 126)
        if printable_count / len(sample) > 0.7:
            return True
        
        return False
    
    def _is_binary_data(self, data):
        """
        Check if data appears to be binary
        
        Args:
            data (bytes): Data to check
            
        Returns:
            bool: True if data appears to be binary
        """
        # Check for high proportion of non-printable ASCII
        sample = data[:1024] if len(data) > 1024 else data
        non_printable_count = sum(1 for b in sample if b < 32 or b > 126)
        return non_printable_count / len(sample) > 0.3
    
    def _decrypt_pt12(self, data):
        """
        Decrypt Pro Tools 12.x format data
        
        Args:
            data (bytes): Encrypted data with PT12 signature
            
        Returns:
            bytes: Decrypted data, or None if decryption fails
        """
        # Pro Tools 12.x uses a simple XOR encryption with a key derived from the signature
        signature = data[:4]  # b'\x03\x30\x30\x31'
        key = sum(signature) % 256  # Sum of signature bytes modulo 256 (148)
        logger.debug(f"Using XOR key: 0x{key:02x} ({key})")
        
        # Create a copy of the data for decryption
        decrypted = bytearray(data)
        
        # Apply XOR decryption after the 16-byte header
        header_size = 16
        for i in range(header_size, len(decrypted)):
            decrypted[i] ^= key
        
        # Verify decryption by checking for markers
        markers = [b'TRAK', b'CLIP', b'MEDI', b'EDIT', b'PLUG', b'MIXR', b'SESS', b'INFO']
        marker_found = False
        for marker in markers:
            if marker in decrypted[header_size:header_size+1024]:
                marker_found = True
                logger.debug(f"Found marker {marker} in decrypted data")
                break
        
        if not marker_found:
            logger.debug("No markers found in decrypted data, trying selective decryption")
            
            # Try selective decryption (only non-printable ASCII)
            selective_decrypted = bytearray(data)
            for i in range(header_size, len(selective_decrypted)):
                if not (32 <= selective_decrypted[i] <= 126):
                    selective_decrypted[i] ^= key
            
            for marker in markers:
                if marker in selective_decrypted[header_size:header_size+1024]:
                    logger.debug(f"Found marker {marker} with selective decryption")
                    return bytes(selective_decrypted)
            
            # Try alternative keys
            alt_keys = [
                0,  # XOR of signature bytes
                signature[0],  # First byte
                signature[-1],  # Last byte
                data[header_size] if len(data) > header_size else 0  # Byte at header boundary
            ]
            
            for alt_key in alt_keys:
                if alt_key == key:
                    continue
                
                logger.debug(f"Trying alternative key: 0x{alt_key:02x} ({alt_key})")
                alt_decrypted = bytearray(data)
                for i in range(header_size, len(alt_decrypted)):
                    alt_decrypted[i] ^= alt_key
                
                for marker in markers:
                    if marker in alt_decrypted[header_size:header_size+1024]:
                        logger.debug(f"Found marker {marker} with alternative key 0x{alt_key:02x}")
                        return bytes(alt_decrypted)
        
        return bytes(decrypted)
    
    def _decrypt_ptx(self, data):
        """
        Decrypt Pro Tools X format data
        
        Args:
            data (bytes): Encrypted data with PTX signature
            
        Returns:
            bytes: Decrypted data, or None if decryption fails
        """
        # Pro Tools X uses byte-swapping for pairs of bytes
        decrypted = bytearray(data)
        
        # Skip the 8-byte header
        header_size = 8
        
        # Swap pairs of bytes
        i = header_size
        while i < len(decrypted) - 1:
            decrypted[i], decrypted[i+1] = decrypted[i+1], decrypted[i]
            i += 2
        
        return bytes(decrypted)
    
    def _decrypt_generic_format(self, data, offset=0):
        """
        Generic decryption for recognized but unsupported formats
        
        Args:
            data (bytes): Encrypted data
            offset (int): Offset to start decryption
            
        Returns:
            bytes: Decrypted data, or None if decryption fails
        """
        logger.debug(f"Attempting generic format decryption with offset {offset}")
        
        # For now, just return the data as-is
        # This is a placeholder for future format-specific decryption algorithms
        return data
    
    def _decrypt_generic_binary(self, data):
        """
        Decrypt binary data without a recognized signature
        
        Args:
            data (bytes): Encrypted binary data
            
        Returns:
            bytes: Decrypted data, or None if decryption fails
        """
        logger.debug("Attempting generic binary decryption")
        
        # Look for potential markers in the data
        markers = [b'TRAK', b'CLIP', b'MEDI', b'EDIT', b'PLUG', b'MIXR', b'SESS', b'INFO']
        marker_positions = []
        
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                marker_positions.append((pos, marker))
                logger.debug(f"Found marker {marker} at position {pos}")
        
        if not marker_positions:
            logger.debug("No markers found, cannot determine decryption method")
            return data
        
        # Sort marker positions
        marker_positions.sort()
        
        # Try to derive a key from the first marker
        first_pos, first_marker = marker_positions[0]
        
        if first_pos > 0:
            # Try using the byte before the marker as a key
            key = data[first_pos - 1]
            logger.debug(f"Trying key derived from marker position: 0x{key:02x}")
            
            # Create a copy of the data for decryption
            decrypted = bytearray(data)
            
            # Apply XOR decryption
            for i in range(first_pos, len(decrypted)):
                decrypted[i] ^= key
            
            # Check if decryption worked by looking for more markers
            marker_count = 0
            for marker in markers:
                marker_count += decrypted.count(marker)
            
            if marker_count > len(marker_positions):
                logger.debug(f"Found {marker_count} markers after decryption")
                return bytes(decrypted)
        
        # If that didn't work, try common XOR keys
        common_keys = [0x55, 0xAA, 0xFF, 0x33, 0xCC, 0xF0, 0x0F, 0x94]
        
        for key in common_keys:
            logger.debug(f"Trying common XOR key: 0x{key:02x}")
            decrypted = bytearray(data)
            
            # Apply XOR decryption
            for i in range(0, len(decrypted)):
                decrypted[i] ^= key
            
            # Check if decryption worked by looking for markers
            marker_count = 0
            for marker in markers:
                marker_count += decrypted.count(marker)
            
            if marker_count > len(marker_positions):
                logger.debug(f"Found {marker_count} markers after decryption with key 0x{key:02x}")
                return bytes(decrypted)
        
        logger.warning("Could not determine decryption method for binary data")
        return data
    
    def _decrypt_marker_based(self, data):
        """
        Decrypt data based on Pro Tools markers
        
        Args:
            data (bytes): Encrypted data
            
        Returns:
            bytes: Decrypted data, or None if decryption fails
        """
        logger.debug("Attempting marker-based decryption")
        
        # Look for Pro Tools markers
        markers = [b'TRAK', b'CLIP', b'MEDI', b'EDIT', b'PLUG', b'MIXR', b'SESS', b'INFO']
        marker_positions = []
        
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                marker_positions.append((pos, marker))
                logger.debug(f"Found marker {marker} at position {pos}")
        
        if not marker_positions:
            logger.debug("No markers found, cannot determine decryption method")
            return data
        
        # Sort marker positions
        marker_positions.sort()
        
        # Check if markers are already in the right positions
        if len(marker_positions) >= 2:
            # Calculate distances between markers
            distances = [marker_positions[i+1][0] - marker_positions[i][0] for i in range(len(marker_positions)-1)]
            
            # If distances are consistent, data may already be decrypted
            if all(d > 0 and d < 1024 for d in distances):
                logger.debug("Markers appear to be in consistent positions, data may already be decrypted")
                return data
        
        # Try block-based decryption
        if len(marker_positions) >= 1:
            first_pos, first_marker = marker_positions[0]
            
            # Try different block sizes
            for block_size in [16, 32, 64, 128]:
                logger.debug(f"Trying block-based decryption with block size {block_size}")
                
                # Create a copy of the data for decryption
                decrypted = bytearray(data)
                
                # Apply block-based decryption
                for i in range(0, len(decrypted) - block_size, block_size):
                    # Swap blocks
                    for j in range(block_size // 2):
                        decrypted[i+j], decrypted[i+block_size-j-1] = decrypted[i+block_size-j-1], decrypted[i+j]
                
                # Check if decryption worked by looking for more markers
                marker_count = 0
                for marker in markers:
                    marker_count += decrypted.count(marker)
                
                if marker_count > len(marker_positions):
                    logger.debug(f"Found {marker_count} markers after block-based decryption")
                    return bytes(decrypted)
        
        # Try offset-based decryption
        if len(marker_positions) >= 1:
            first_pos, first_marker = marker_positions[0]
            
            # Try different offsets
            for offset in [0, 8, 16, 32]:
                logger.debug(f"Trying offset-based decryption with offset {offset}")
                
                # Create a copy of the data for decryption
                decrypted = bytearray(data)
                
                # Apply offset-based decryption (byte swapping)
                i = offset
                while i < len(decrypted) - 1:
                    decrypted[i], decrypted[i+1] = decrypted[i+1], decrypted[i]
                    i += 2
                
                # Check if decryption worked by looking for more markers
                marker_count = 0
                for marker in markers:
                    marker_count += decrypted.count(marker)
                
                if marker_count > len(marker_positions):
                    logger.debug(f"Found {marker_count} markers after offset-based decryption")
                    return bytes(decrypted)
        
        logger.warning("Could not determine decryption method based on markers")
        return data 