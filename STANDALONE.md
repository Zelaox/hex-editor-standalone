# Hex Editor — standalone for agents and humans

This repository is a **universal hex / binary editor** you can run alone. AI agents reach it through **MCP stdio** or **CLI**; humans use the **PyQt GUI**.

It does **not** require AI Lab, UVE, TRIAGE, or RE. Those systems may **optionally** spawn this checkout as a child process when verifying or orchestrating work. See [External integration](docs/EXTERNAL_INTEGRATION.md).

## Install

```powershell
.\install.ps1 -WithMcp -WithTests   # agents + tests
.\install.ps1 -WithMcp              # agents
.\install.ps1                       # GUI/runtime only
```

## Surfaces (pick one or more)

| Surface | Command |
|---------|---------|
| **GUI** | `.\.venv\Scripts\python.exe main.py` |
| **CLI** | `.\.venv\Scripts\python.exe scripts/hex_tool_cli.py list` |
| **MCP stdio** | `.\.venv\Scripts\python.exe scripts/hex_mcp_server.py` |
| **Optional desktop bridge** | `main.py --lab-bridge <runtime_dir>` |

Workspace paths: `config/workspace_roots.json` or `HEX_EDITOR_WORKSPACE_CONFIG`.

## Agent contract

- **79 tools** in catalog; schemas validated in `tests/test_standalone_interfaces.py`
- Fail-closed paths, no host database, no Lab MCP package import
- Optional format pipelines (e.g. PTX) via config—not required for core binary tools

## Release gate

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_standalone_interfaces.py -q
```

## What we do not ship publicly

- Private regression bundles (cleared in `config/hex_regression_fixtures.json`, etc.)
- Populated `llm_config.json` agents
- Your `data/` or `logs/` trees (gitignored)