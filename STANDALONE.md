# Hex Editor — standalone distribution

This tree is the **standalone** Hex Editor application. It does not require AI Lab, UVE, TRIAGE, RE, or any other host.

**UVE / TRIAGE / RE may still use Hex Editor** when you want: spawn MCP or CLI from a verification run, point probes at the same tool contracts, and tear the host down without breaking the editor. See [External integration](docs/EXTERNAL_INTEGRATION.md).

## Install

From this directory (Windows PowerShell):

```powershell
.\install.ps1 -WithMcp -WithTests
```

Creates `.venv/`, installs runtime + MCP + dev test dependencies.

Minimal runtime only:

```powershell
.\install.ps1
```

## Run

| Surface | Command |
|---------|---------|
| GUI | `.\.venv\Scripts\python.exe main.py` |
| PTX pipeline GUI | `Start-PtxPipeline.bat` |
| CLI tools | `.\.venv\Scripts\python.exe scripts/hex_tool_cli.py list` |
| MCP (stdio) | `.\.venv\Scripts\python.exe scripts/hex_mcp_server.py` |

Workspace roots are controlled by `config/workspace_roots.json` and optional `HEX_EDITOR_WORKSPACE_CONFIG` (local file, not committed).

## Verification gate (release)

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_standalone_interfaces.py -q
```

Expect **79** registered MCP/CLI tools, stdio round-trip, and owned desktop command delivery with **no** `AI_LAB_ROOT` and **no** Lab MCP package on `PYTHONPATH`.

## What is not bundled

- Private regression bundles (`config/hex_regression_fixtures.json`, `config/ptx_plaintext_calibration.json` entries cleared)
- AI Lab LLM routing (`config/llm_config.json` empty agents)
- Runtime artifacts under `data/` and `logs/` (gitignored)

Configure local fixtures explicitly when you need private calibration sessions.