# External hosts: UVE, TRIAGE, RE, AI Lab, or any MCP client

Hex Editor is a **standalone application**. Nothing in AI Lab, UVE, TRIAGE, or RE is required for it to install, run, or serve tools.

Those systems may **optionally attach** when you want unified verification or agent workflows. The dependency direction is always:

```text
[optional host: UVE / TRIAGE / RE / AI Lab / Cursor MCP]
        │  stdio MCP, CLI subprocess, or desktop inbox
        ▼
[Hex Editor checkout]  ← owns GUI, services, config, artifacts
```

Hex Editor does **not** call back into a host. It does **not** load Lab controllers, Lab databases, or Lab MCP packages at startup.

## Integration surfaces (pick any)

| Surface | Host uses | Hex Editor provides |
|---------|-----------|---------------------|
| **MCP stdio** | Spawn `scripts/hex_mcp_server.py` with `cwd` = checkout | 79 tools, JSON schemas, bounded file access |
| **CLI** | `scripts/hex_tool_cli.py list` / `run <tool>` | Same contracts as MCP, no server process |
| **Desktop bridge** | Write JSON commands to `data/runtime/hex_editor/inbox/` (or `--lab-bridge` runtime dir) | GUI applies `open` / related commands via `hexeditor_tools.desktop` |
| **Direct GUI** | User double-clicks `main.py` | Full editor; no host |

Environment variables the host may set (optional):

- `HEX_EDITOR_ROOT` — must point at this checkout if the process cwd is elsewhere.
- `HEX_EDITOR_WORKSPACE_CONFIG` — JSON file listing `allowed_roots` for tool file access (fail-closed).

`AI_LAB_ROOT` is **not** read by standalone services. Tests set it to a non-existent path to prove the app still works.

## UVE / TRIAGE / RE (verification-only)

Typical pattern:

1. UVE (or TRIAGE) provisions a clean workspace and synthetic fixtures.
2. It spawns Hex Editor MCP or CLI as a **child process** of the verification run.
3. Probes assert tool list, schema, read-only bounds, GUI ack, or pipeline receipts.
4. Hex Editor keeps running even if UVE is absent.

UVE does not need to ship Hex Editor source inside the Lab repo; it only needs a path to this checkout and `install.ps1`.

Example MCP host fragment (conceptual):

```json
{
  "command": "<venv>/python.exe",
  "args": ["-B", "scripts/hex_mcp_server.py"],
  "cwd": "<hex-editor-checkout>",
  "env": {
    "HEX_EDITOR_WORKSPACE_CONFIG": "<uve-run>/workspace.local.json"
  }
}
```

## AI Lab (optional, not special-cased)

AI Lab can use the same three surfaces. Historically some docs say “AI Lab MCP”; in standalone builds that means **any MCP host**, including Lab, UVE harnesses, or Cursor.

Optional GUI live bridge: start `main.py --lab-bridge <runtime_dir>` only when a host actively drops inbox commands. Without the flag, the editor is a normal desktop app.

## Release gate

`tests/test_standalone_interfaces.py` proves:

- 79 tools enabled and schema-valid
- CLI works from a foreign directory without Lab on `PYTHONPATH`
- MCP stdio round-trip
- Owned desktop process accepts an `open` command

That gate is what publishers and UVE should treat as the standalone contract.