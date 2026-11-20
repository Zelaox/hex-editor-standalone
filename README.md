# Universal Hex Editor for AI Agents

A **standalone** binary workspace for humans and **AI agents**: bounded file access, structured analysis, reversible edits, and **68 MCP/CLI tools** on a single contract—without tying you to one file format or one host application.

- **Desktop GUI** for interactive inspection and editing  
- **CLI** (`hex_tool_cli.py`) for scripts and CI  
- **MCP stdio** (`hex_mcp_server.py`) for Cursor, custom agents, UVE/TRIAGE/RE, or any MCP client  

No AI Lab, no shared lab database, no implicit tokenization or mystery paths—configure workspace roots explicitly and fail closed.

See [STANDALONE.md](STANDALONE.md) for install, and [docs/EXTERNAL_INTEGRATION.md](docs/EXTERNAL_INTEGRATION.md) for how hosts attach optionally.

## Quick start

**Install (Windows):**

```powershell
.\install.ps1 -WithMcp
```

**GUI:**

```powershell
.\.venv\Scripts\python.exe main.py
```

**List tools (agent / shell):**

```powershell
.\.venv\Scripts\python.exe scripts/hex_tool_cli.py list
```

**Run one tool:**

```powershell
.\.venv\Scripts\python.exe scripts/hex_tool_cli.py run binary_file_info --param path=C:\path\to\file.bin
```

**MCP server (stdio, for agents):**

```powershell
.\.venv\Scripts\python.exe scripts/hex_mcp_server.py
```

Set `HEX_EDITOR_WORKSPACE_CONFIG` to a JSON file with `allowed_roots` so tools only touch paths you allow.

## What agents get

| Capability | Notes |
|------------|--------|
| **File bounds & integrity** | SHA-256, size, mmap-safe ranges, workspace validation |
| **Binary semantic graph** | Offsets, relationships, unresolved bytes, proof-gated claims |
| **Diff & waterfall** | Cross-snapshot compare without filename magic |
| **Snapshots & artifacts** | Content-addressed runs under `data/` (local, gitignored) |
| **PE / structure** | PE snapshots, bounded disassembly, execution trace helpers |
| **Desktop bridge** | Optional owned GUI process + inbox commands (`hexeditor_tools.desktop`) |
| **Full decode / transforms** | Registry-driven; no hardcoded case offsets in core paths |

PTX, CPR, and session-specific pipelines are **optional format modules**—not the product definition. Enable them via config when you need that domain.

## Release verification

```powershell
.\install.ps1 -WithMcp -WithTests
.\.venv\Scripts\python.exe -m pytest tests/test_standalone_interfaces.py -q
```

Expect **68** tools, MCP round-trip, CLI from an external cwd, and GUI `open` acknowledgment—without Lab on `PYTHONPATH`.

## Documentation map

| Doc | Topic |
|-----|--------|
| [STANDALONE.md](STANDALONE.md) | Install surfaces, env vars |
| [docs/EXTERNAL_INTEGRATION.md](docs/EXTERNAL_INTEGRATION.md) | UVE, TRIAGE, RE, MCP hosts |
| [docs/README.md](docs/README.md) | Deep feature index |
| [docs/BINARY_DIFF_VIEW.md](docs/BINARY_DIFF_VIEW.md) | Diff / compatibility |
| [PTX_ANALYZER.md](PTX_ANALYZER.md) | *Optional* Pro Tools PTX format notes |
| [PTX_REBUILDER.md](PTX_REBUILDER.md) | *Optional* PTX rebuild CLI |

## Optional: PTX / session formats

If you work with Pro Tools session exchange (PTX) or related converters, use the dedicated scripts and policies—same MCP tools where registered, same workspace rules:

```powershell
python scripts/ptx_pipeline.py --help
python ptx_rebuild_cli.py --help
```

Do not treat the repo as “PTX-only”; most tools are format-agnostic binary operations.

## Requirements

- Python 3.10+ recommended (3.14 tested in standalone gate)
- PyQt5 for GUI
- See `requirements.txt`, `requirements-mcp.txt`, `requirements-dev.txt`

## License

Provided for education, interoperability, and agent-assisted reverse engineering with explicit policy bounds. Use responsibly on data you are allowed to analyze.