# Hex Editor with PTX Analysis & Rebuilding

A specialized hex editor with advanced PTX file analysis and rebuilding capabilities. This tool allows users to analyze Pro Tools Session Exchange (PTX) files, extract valuable information including timecodes, metadata, and session structure, and rebuild or modify PTX files.

## Quick Start

Run the main hex editor application:
```
python main.py
```

Use the standalone PTX analyzer:
```
python test_ptx_features.py [PTX_FILE] [OPTIONS]
```

Use the PTX rebuilder:
```
python ptx_rebuild_cli.py [COMMAND] [OPTIONS]
```

Unified PTX parser/converter pipeline (config + `data/` SSOT):

**GUI (double-click):** `Start-PtxPipeline.bat` in this folder.

**CLI:**
```
python scripts/ptx_pipeline.py run --spec-file tests/fixtures/ptx_pipeline/archive_bind_spec.json
python scripts/ptx_pipeline.py export --graph-artifact-dir <graph_run_dir> --format ptx
```

Policy: `config/ptx_pipeline_policy.json`, `config/ptx_converter_policy.json` (CPR/Studio One default **disabled**).

## Features

- **Browser storage forensics**: shared CLI/MCP services and a desktop evidence viewer for bounded SQLite/WAL, LevelDB/Snappy, JSON and schema-less Protobuf analysis, with isolated workers, source mappings, deterministic replay and existing LearnerDB indexing. See [supported behavior and limitations](docs/BROWSER_STORAGE_FORENSICS.md); marker findings are not verified messages or decryption.
- **Protected text recovery / live DOM import**: current-user Windows DPAPI storage and an in-memory viewer for bounded text candidates or explicitly acquired loaded-chat observations. The one-shot loopback importer does not control the browser, send chats, access browser keys or claim complete message history. [Usage and limits](docs/BROWSER_STORAGE_FORENSICS.md#protected-text-recovery-and-loaded-dom-import).
- **Explicit readable local export**: `binary_message_export` writes unencrypted HTML/TXT/JSON and bounded local media framing candidates from explicitly named source runs/copies. No official Snapchat export, network fetch or complete-history claim. [Privacy warning and usage](docs/BROWSER_STORAGE_FORENSICS.md#explicit-local-plaintext-export--hex-editor-only).

- Coverage-complete, evidence-driven full-file decode orchestration with registry-loaded proof providers, compatible candidate composition, reversible materialization, explicit unresolved coverage, strict plaintext extraction, and canonical lossless ASCII round-trip. No case-specific offsets, strings, keys, hashes, filenames, or scopes are embedded in runtime logic.
- Unresolved-byte ownership and dependency inference with a schema-validated Binary Semantic Graph, deterministic offset/relationship queries, proof-gated coverage classification, reversible candidates, converter/parser handoffs, MCP tools and Binary Inspector status. Unsupported relationships fail closed as unresolved.

- **Hex Editing**: Search, navigation, and fixed-size byte replacement with atomic large-file saving
- **PTX Analysis**: Specialized tools for working with Pro Tools PTX files
- **Timecode Extraction**: Identify and navigate between timecode reference points
- **Multiple Output Formats**: Export analysis results in TXT, XML, or JSON formats
- **Decryption Support**: Decrypt encrypted PTX files (AC240 format)
- **PTX Rebuilding**: Rebuild PTX files from components or modify existing files
- **Encryption/Decryption**: Command-line tools for encrypting and decrypting PTX files

## PTX Analysis Tool

For detailed PTX file analysis, use the standalone test script:

```
python test_ptx_features.py [PTX_FILE] [OPTIONS]
```

Options:
- `--format=FORMAT` - Output format: text, xml, or json (default: text)
- `--output=FILE` - Output file path for xml or json format
- `--help`, `-h` - Show help message

Example (export as XML):
```
python test_ptx_features.py my_session.ptx --format=xml --output=results.xml
```

Example (export as JSON):
```
python test_ptx_features.py my_session.ptx --format=json --output=results.json
```

## PTX Rebuilder Tool

The PTX rebuilder provides tools for rebuilding, modifying, and encrypting/decrypting PTX files:

```
python ptx_rebuild_cli.py [COMMAND] [OPTIONS]
```

Commands:
- `rebuild` - Rebuild a PTX file from components or a source file
- `encrypt` - Encrypt a PTX file using XOR encryption
- `decrypt` - Decrypt an encrypted PTX file
- `modify` - Make specific modifications to a PTX file

Examples:

Rebuild from components:
```
python ptx_rebuild_cli.py rebuild --components test_output --output rebuilt.ptx
```

Rebuild from source with modifications:
```
python ptx_rebuild_cli.py rebuild --source source.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
```

Encrypt a file:
```
python ptx_rebuild_cli.py encrypt input.ptx output.ptx
```

Decrypt a file:
```
python ptx_rebuild_cli.py decrypt input.ptx output.ptx
```

Modify a specific timecode:
```
python ptx_rebuild_cli.py modify --input input.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
```

## Timecode Navigation

The hex editor provides specialized navigation for PTX timecodes:

- Press `Ctrl+Right` to navigate to the next timecode
- Press `Ctrl+Left` to navigate to the previous timecode
- Press `Ctrl+Shift+Right` to navigate to the next reference timecode
- Press `Ctrl+Shift+Left` to navigate to the previous reference timecode

The status bar will display timecode information when navigating.

## Documentation

See [PTX_ANALYZER.md](PTX_ANALYZER.md) for detailed documentation on the PTX file format and analysis capabilities.

See [PTX_REBUILDER.md](PTX_REBUILDER.md) for documentation on the PTX rebuilding capabilities.

## Requirements

- Python 3.7+
- PyQt5
- Additional dependencies in requirements.txt

## License

This tool is provided for educational and interoperability purposes. 
