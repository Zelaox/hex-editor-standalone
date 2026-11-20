# PTX Rebuilder Documentation

The PTX Rebuilder is a comprehensive tool for rebuilding, restructuring, and modifying Pro Tools Session Exchange (PTX) files. This document outlines the capabilities and usage of the PTX rebuilder module and its command-line interface.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Using the Module](#using-the-module)
4. [Command-Line Interface](#command-line-interface)
5. [Examples](#examples)
6. [Advanced Usage](#advanced-usage)
7. [Encryption and Decryption](#encryption-and-decryption)
8. [Troubleshooting](#troubleshooting)

## Overview

The PTX Rebuilder enables you to:

- Load and parse PTX file components from an extracted directory
- Load and parse a source PTX file
- Modify header fields, timecodes, and sections
- Add, replace, or remove sections
- Rebuild and restructure PTX files
- Encrypt or decrypt PTX files using various encryption methods

## Key Features

- **Component-Based Rebuilding**: Build a PTX file from individual extracted components
- **Source-Based Rebuilding**: Use an existing PTX file as a source for rebuilding
- **Structural Modifications**: Modify the structure of a PTX file by adding, removing, or replacing sections
- **Header Modification**: Change header fields such as magic number, version, and flags
- **Timecode Editing**: Change timecode values at specific offsets
- **Encryption Support**: Built-in support for AC240 XOR encryption (0x94 key)
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Using the Module

The PTX Rebuilder module can be used programmatically in your Python code:

```python
from src.ptx_rebuilder import PTXRebuilder

# Create a rebuilder from components
rebuilder = PTXRebuilder(components_dir="extracted_components")

# Or create a rebuilder from a source file
rebuilder = PTXRebuilder(source_ptx="source.ptx")

# Modify header fields
rebuilder.set_header_field("version", 1)

# Modify timecodes
rebuilder.set_timecode(0x84058, "01:00:00:00", "SMPTE", True)

# Add a new section
section_data = b"This is a custom section"
rebuilder.add_section(section_data, 1531330650)  # Primary Data Section

# Replace an existing section
rebuilder.replace_section(0, new_data=b"Modified section data")

# Rebuild the file
rebuilder.rebuild("output.ptx", encrypt=False)

# Encrypt a file
rebuilder.encrypt_file("input.ptx", "encrypted.ptx", encryption_key=0x94)
```

## Command-Line Interface

The PTX Rebuilder comes with a command-line interface (`ptx_rebuild_cli.py`) for easy access to its features:

```
python ptx_rebuild_cli.py [COMMAND] [OPTIONS]
```

### Commands

- `rebuild`: Rebuild a PTX file from components or a source file
- `encrypt`: Encrypt a PTX file
- `decrypt`: Decrypt a PTX file
- `modify`: Make specific modifications to a PTX file

### Common Options

- `--verbose`, `-v`: Enable verbose logging
- `--help`, `-h`: Show help message

### Rebuild Command Options

```
python ptx_rebuild_cli.py rebuild [OPTIONS]
```

Options:
- `--components`, `-c`: Directory containing extracted components
- `--source`, `-s`: Source PTX file to rebuild from
- `--output`, `-o`: Output file path (required)
- `--encrypt`, `-e`: Encrypt the output file
- `--header`, `-H`: Modify header field (format: field=value)
- `--timecode`, `-t`: Modify timecode (format: offset=value[,type][,ref])

### Encrypt Command Options

```
python ptx_rebuild_cli.py encrypt [INPUT] [OUTPUT] [OPTIONS]
```

Options:
- `--key`, `-k`: Encryption key (default: 0x94 for AC240)

### Decrypt Command Options

```
python ptx_rebuild_cli.py decrypt [INPUT] [OUTPUT] [OPTIONS]
```

Options:
- `--key`, `-k`: Decryption key (default: 0x94 for AC240)
- `--force`, `-f`: Force decryption even if file appears unencrypted

### Modify Command Options

```
python ptx_rebuild_cli.py modify [OPTIONS]
```

Options:
- `--input`, `-i`: Input PTX file (required)
- `--output`, `-o`: Output modified file (required)
- `--encrypt`, `-e`: Encrypt the output file
- `--header`, `-H`: Modify header field (format: field=value)
- `--timecode`, `-t`: Modify timecode (format: offset=value[,type][,ref])

## Examples

### Rebuilding from Components

Extract a PTX file and then rebuild it:

```bash
# First, extract components using the PTX analyzer
python test_ptx_features.py my_session.ptx

# Then, rebuild the PTX file from extracted components
python ptx_rebuild_cli.py rebuild --components test_output --output rebuilt.ptx
```

### Modifying a Source File

Rebuild a source file with modifications:

```bash
python ptx_rebuild_cli.py rebuild --source source.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
```

### Changing Header Fields

Modify the version field in the header:

```bash
python ptx_rebuild_cli.py modify --input source.ptx --output modified.ptx --header version=2
```

### Multiple Modifications

Apply multiple modifications at once:

```bash
python ptx_rebuild_cli.py modify --input source.ptx --output modified.ptx \
  --header version=2 \
  --header flags=0 \
  --timecode 0x84058=01:00:00:00 \
  --timecode 0x84090=00:01:00:00,SMPTE,true
```

### Encrypting and Decrypting

Encrypt a PTX file:

```bash
python ptx_rebuild_cli.py encrypt source.ptx encrypted.ptx
```

Decrypt an encrypted PTX file:

```bash
python ptx_rebuild_cli.py decrypt encrypted.ptx decrypted.ptx
```

Encrypt with a custom key:

```bash
python ptx_rebuild_cli.py encrypt source.ptx encrypted.ptx --key 123
```

## Advanced Usage

### Working with Header Fields

The PTX header contains the following fields:

- `magic`: Magic number or identifier (4 bytes)
- `version`: Format version (4 bytes)
- `flags`: Flags (4 bytes)
- `size`: File size (4 bytes)
- `encryption_type`: Encryption type (4 bytes)
- `reserved`: Reserved bytes (12 bytes)

Example of setting multiple header fields:

```bash
python ptx_rebuild_cli.py modify --input source.ptx --output modified.ptx \
  --header magic=PTX0 \
  --header version=2 \
  --header flags=0 \
  --header encryption_type=0
```

### Working with Timecodes

Timecodes can be set at specific offsets using the following format:

```
offset=value[,type][,ref]
```

Where:
- `offset`: Offset in the file (can be hex with 0x prefix)
- `value`: Timecode value (e.g., "00:00:01:00" for SMPTE)
- `type`: Timecode type (optional, e.g., "SMPTE", "SMPTE (Binary)", "Decimal")
- `ref`: Whether this is a reference timecode (optional, "true"/"false")

Example:

```bash
python ptx_rebuild_cli.py modify --input source.ptx --output modified.ptx \
  --timecode 0x84058=01:00:00:00,SMPTE,true \
  --timecode 0x84090=00:01:00:00
```

## Encryption and Decryption

The PTX Rebuilder supports several encryption methods, with AC240 XOR encryption (key 0x94) being the most common for PTX files.

### Encryption Types

The encryption type is stored in the header at offset 16-20:

- `0`: Not encrypted
- `1`: Basic XOR encryption
- `2298806321` (0x88F80D01): AC240 XOR encryption (key 0x94)
- `2`: AES-128 encryption (not implemented)
- `3`: Custom encryption algorithm (not implemented)

### XOR Encryption/Decryption

XOR encryption is its own inverse, so the same key is used for both encryption and decryption:

```bash
# Encrypt
python ptx_rebuild_cli.py encrypt source.ptx encrypted.ptx --key 0x94

# Decrypt
python ptx_rebuild_cli.py decrypt encrypted.ptx decrypted.ptx --key 0x94
```

## Troubleshooting

### Common Issues

1. **Missing header file**: Ensure that the components directory contains a `header.bin` file.
2. **Invalid section data**: Check that section files are named properly (e.g., `section_0_primary_data_section.bin`).
3. **Invalid offsets**: When setting timecodes, ensure the offset is within the file's size.
4. **Encryption errors**: Verify that the correct encryption key is being used.

### Verbose Logging

Enable verbose logging for more detailed information:

```bash
python ptx_rebuild_cli.py rebuild --components test_output --output rebuilt.ptx --verbose
```

### Checking Log Files

The rebuilder writes logs to the `logs` directory. Check the log files for detailed information:

```
logs/ptx_rebuilder.log       # Module logs
logs/ptx_rebuilder_cli.log   # CLI logs
```

---

This documentation provides an overview of the PTX Rebuilder's capabilities. For more information or assistance, refer to the source code or contact the project maintainers. 