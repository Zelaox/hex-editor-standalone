# Documentation index

Standalone Hex Editor — public docs only (no host lab required).

## Start here

| Document | Purpose |
|----------|---------|
| [../README.md](../README.md) | Overview, quick start, verification |
| [../STANDALONE.md](../STANDALONE.md) | Install, layout, MCP/CLI/GUI |
| [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md) | Optional UVE / MCP / desktop bridge |
| [BINARY_DIFF_VIEW.md](BINARY_DIFF_VIEW.md) | Snapshot diff and compatibility |

## Entry points

| Surface | Path |
|---------|------|
| Desktop GUI | `main.py` |
| CLI | `scripts/hex_tool_cli.py` |
| MCP stdio | `scripts/hex_mcp_server.py` |

## Configuration

Policy and registry JSON live under [`config/`](../config/). Tool allowlists: [`config/hex_editor.json`](../config/hex_editor.json).

## Verification

```powershell
.\install.ps1 -WithMcp -WithTests
.\.venv\Scripts\python.exe -m pytest tests/test_standalone_interfaces.py -q
```

Expect **58** registered tools and **4** interface tests passing.