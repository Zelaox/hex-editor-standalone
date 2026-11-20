import os
import filecmp
import hashlib
import sys

def compare_files(file1, file2, verbose=False):
    # Check if files exist
    if not os.path.exists(file1):
        print(f"Error: File {file1} does not exist")
        return False
    if not os.path.exists(file2):
        print(f"Error: File {file2} does not exist")
        return False
    
    # Compare file sizes
    size1 = os.path.getsize(file1)
    size2 = os.path.getsize(file2)
    
    if verbose:
        print(f"File sizes: {file1}={size1} bytes, {file2}={size2} bytes")
    
    # Are they identical?
    identical = filecmp.cmp(file1, file2, shallow=False)
    
    if verbose:
        print(f"Files are identical: {identical}")
    else:
        print(f"RESULT: {'MATCH' if identical else 'DIFFERENT'}")
    
    # If not identical and verbose mode, show details
    if not identical and verbose:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            header1 = f1.read(32)
            header2 = f2.read(32)
            
            print(f"\nHeader comparison (first 32 bytes):")
            print(f"File 1 header: {header1.hex()}")
            print(f"File 2 header: {header2.hex()}")
            print(f"Headers match: {header1 == header2}")
            
            # Compute byte differences in first 64 bytes
            f1.seek(0)
            f2.seek(0)
            data1 = f1.read(64)
            data2 = f2.read(64)
            
            print("\nByte-by-byte comparison (first 64 bytes):")
            for i, (b1, b2) in enumerate(zip(data1, data2)):
                if b1 != b2:
                    print(f"Offset {i}: {b1} ({hex(b1)}) != {b2} ({hex(b2)})")
            
            # Compute full file hashes
            f1.seek(0)
            f2.seek(0)
            hash1 = hashlib.md5(f1.read()).hexdigest()
            hash2 = hashlib.md5(f2.read()).hexdigest()
            
            print(f"\nMD5 hashes:")
            print(f"{file1}: {hash1}")
            print(f"{file2}: {hash2}")
    
    return identical

if __name__ == "__main__":
    verbose_mode = "-v" in sys.argv or "--verbose" in sys.argv
    
    # Remove verbose flags from argv if present
    if "-v" in sys.argv:
        sys.argv.remove("-v")
    if "--verbose" in sys.argv:
        sys.argv.remove("--verbose")
    
    # Get file paths from arguments or use defaults
    if len(sys.argv) > 2:
        file1, file2 = sys.argv[1], sys.argv[2]
    else:
        file1, file2 = "ac240_test3_decrypted.ptx", "ac240_decrypted.ptx"
        
    compare_files(file1, file2, verbose=verbose_mode) 