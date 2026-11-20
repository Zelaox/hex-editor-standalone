# Universal Hex Editor for AI Agents

A **standalone** binary workspace for humans and **AI agents**: bounded file access, structured analysis, reversible edits, and **58 MCP/CLI tools** on a single contract.

- **Desktop GUI** — interactive hex editing  
- **CLI** — `scripts/hex_tool_cli.py`  
- **MCP stdio** — `scripts/hex_mcp_server.py` for Cursor, UVE/TRIAGE/RE, or any MCP client  

No host application required. Configure workspace roots explicitly; tools fail closed outside allowlists.

[STANDALONE.md](STANDALONE.md) · [docs/EXTERNAL_INTEGRATION.md](docs/EXTERNAL_INTEGRATION.md)

## Quick start

```powershell
.\install.ps1 -WithMcp
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe scripts\hex_tool_cli.py list
```

## What agents get

| Capability | Notes |
|------------|--------|
| **File I/O** | Info, ranged read/decode, search, patch, write (bounded) |
| **Semantic graph** | Full decode, unresolved inference, record families, scopes |
| **Diff & snapshots** | BinarySnapshot parse/diff, workspace unpack |
| **PE** | Analysis, bounded disasm, execution trace helpers |
| **Representations** | Hex/text/integer sweeps, falsification, pseudocode routing |
| **Desktop bridge** | Optional owned GUI + inbox commands |

## Verification

```powershell
.\install.ps1 -WithMcp -WithTests
.\.venv\Scripts\python.exe -m pytest tests/test_standalone_interfaces.py -q
```

Expect **58** tools and **4** interface tests passing.

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/README.md](docs/README.md) | Feature index |
| [docs/BINARY_DIFF_VIEW.md](docs/BINARY_DIFF_VIEW.md) | Diff / compatibility |

## Open source & collaboration

This repository is **public and open source** under the [Apache License 2.0](LICENSE).

**English:** Anyone may **clone, download, use, modify, fork, and contribute**. Pull requests, issues, and discussions are welcome. You keep your own copyright on contributions; the license governs redistribution.

**Svenska:** Projektet är **öppen källkod**. **Vem som helst** kan ladda ner, använda, ändra, fork:a och **samarbeta** — välkommen med pull requests och issues.

```powershell
git clone https://github.com/Zelaox/hex-editor-standalone.git
```

## Requirements

Python 3.10+, PyQt5 — see `requirements.txt`, `requirements-mcp.txt`.