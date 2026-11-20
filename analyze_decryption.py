#!/usr/bin/env python
"""
Script to analyze PTX files and determine the decryption key pattern.
"""
import os
import sys
import binascii
import argparse

def analyze_key_pattern(original_file, decrypted_file, block_size=64, max_blocks=10):
    """
    Analyze the original and decrypted files to identify the decryption key pattern.
    
    Args:
        original_file: Path to the original encrypted file
        decrypted_file: Path to the decrypted file
        block_size: Size of blocks to analyze (default: 64 bytes)
        max_blocks: Maximum number of blocks to analyze (default: 10)
    
    Returns:
        The identified decryption key pattern
    """
    # Check if files exist
    if not os.path.exists(original_file):
        print(f"Error: Original file {original_file} does not exist")
        return None
    
    if not os.path.exists(decrypted_file):
        print(f"Error: Decrypted file {decrypted_file} does not exist")
        return None
    
    # Open both files
    with open(original_file, 'rb') as f_orig, open(decrypted_file, 'rb') as f_decr:
        # Read the header (first 32 bytes)
        header_orig = f_orig.read(32)
        header_decr = f_decr.read(32)
        
        print("==== Header Analysis ====")
        print(f"Original header: {binascii.hexlify(header_orig).decode()}")
        print(f"Decrypted header: {binascii.hexlify(header_decr).decode()}")
        
        # Check if the headers are the same
        if header_orig == header_decr:
            print("Headers match - no decryption applied to the header")
        else:
            print("Headers differ - analyzing differences")
            for i, (b_orig, b_decr) in enumerate(zip(header_orig, header_decr)):
                if b_orig != b_decr:
                    xor_val = b_orig ^ b_decr
                    print(f"Offset {i}: {hex(b_orig)} ^ {hex(b_decr)} = {hex(xor_val)}")
        
        print("\n==== Data Analysis ====")
        # Reset file pointers to start from file beginning
        f_orig.seek(0)
        f_decr.seek(0)
        
        # Analyze multiple blocks throughout the file
        key_patterns = []
        block_index = 0
        
        while block_index < max_blocks:
            # Skip to the next block
            block_pos = 32 + (block_index * block_size)
            
            f_orig.seek(block_pos)
            f_decr.seek(block_pos)
            
            block_orig = f_orig.read(block_size)
            block_decr = f_decr.read(block_size)
            
            # Break if we've reached the end of either file
            if not block_orig or not block_decr:
                break
            
            print(f"\nBlock {block_index} (Offset 0x{block_pos:08x}):")
            
            # Calculate XOR differences (potential key)
            key_block = bytes(b_orig ^ b_decr for b_orig, b_decr in zip(block_orig, block_decr))
            key_patterns.append(key_block)
            
            print(f"Original: {binascii.hexlify(block_orig[:16]).decode()}...")
            print(f"Decrypted: {binascii.hexlify(block_decr[:16]).decode()}...")
            print(f"XOR key:   {binascii.hexlify(key_block[:16]).decode()}...")
            
            # Check for pattern
            if all(b == key_block[0] for b in key_block):
                print(f"Consistent single-byte XOR key detected: 0x{key_block[0]:02x}")
            else:
                # Check for repeating patterns
                for pattern_length in range(1, min(17, len(key_block))):
                    pattern = key_block[:pattern_length]
                    matches = True
                    
                    for i in range(0, len(key_block) - pattern_length, pattern_length):
                        if key_block[i:i+pattern_length] != pattern:
                            matches = False
                            break
                    
                    if matches:
                        print(f"Repeating key pattern detected: {binascii.hexlify(pattern).decode()}")
                        break
            
            block_index += 1
        
        # Final key pattern analysis
        if key_patterns:
            print("\n==== Key Pattern Summary ====")
            
            # Check if all blocks have the same pattern
            first_pattern = key_patterns[0]
            consistent = True
            
            for pattern in key_patterns[1:]:
                if pattern != first_pattern[:len(pattern)]:
                    consistent = False
                    break
            
            if consistent:
                # Find the smallest repeating unit
                for i in range(1, len(first_pattern) + 1):
                    pattern = first_pattern[:i]
                    if len(first_pattern) % len(pattern) == 0:
                        is_repeating = True
                        for j in range(0, len(first_pattern), len(pattern)):
                            if first_pattern[j:j+len(pattern)] != pattern:
                                is_repeating = False
                                break
                        
                        if is_repeating:
                            print(f"Consistent key pattern found: {binascii.hexlify(pattern).decode()}")
                            return pattern
            else:
                print("Inconsistent key patterns detected across file blocks.")
                # Check for single-byte consistency
                if all(p[0] == first_pattern[0] for p in key_patterns):
                    print(f"First byte is consistent: 0x{first_pattern[0]:02x}")
                    return bytes([first_pattern[0]])
    
    return None

def main():
    parser = argparse.ArgumentParser(description="Analyze PTX files to determine decryption key pattern")
    parser.add_argument("original", help="Path to the original encrypted file")
    parser.add_argument("decrypted", help="Path to the decrypted file")
    parser.add_argument("-b", "--block-size", type=int, default=64, help="Size of blocks to analyze")
    parser.add_argument("-m", "--max-blocks", type=int, default=10, help="Maximum number of blocks to analyze")
    
    args = parser.parse_args()
    
    key_pattern = analyze_key_pattern(args.original, args.decrypted, args.block_size, args.max_blocks)
    
    if key_pattern:
        print("\nDetected Key Pattern:")
        print(f"Hex: {binascii.hexlify(key_pattern).decode()}")
        print(f"Length: {len(key_pattern)} bytes")
        
        # If single byte, show decimal value
        if len(key_pattern) == 1:
            print(f"Decimal value: {key_pattern[0]}")
    else:
        print("\nUnable to determine consistent key pattern.")

if __name__ == "__main__":
    main() 