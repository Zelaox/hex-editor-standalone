# Hex Editor — Project documentation

> **Product:** Universal hex editor for **AI agents** (MCP + CLI) and humans (GUI). Any MCP host may optionally attach — see [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md). No AI Lab, UVE, or lab database is required at runtime.

## Overview

PyQt5 binary workspace: bounded reads and writes, semantic graphs, representation sweeps, deterministic snapshots, diff, and **58** MCP/CLI tools on one contract. The public standalone build focuses on **format-agnostic** hex/binary work plus a **PE** format plugin for static image graphs, disassembly, and optional bounded execution tracing.

| Doc | Topic |
|-----|--------|
| [../README.md](../README.md) | Quick start |
| [../STANDALONE.md](../STANDALONE.md) | Install and release gate |
| [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md) | Optional hosts (UVE, Cursor MCP, inbox bridge) |
| [BINARY_DIFF_VIEW.md](BINARY_DIFF_VIEW.md) | Snapshot diff / waterfall compatibility |

## Requirements

- Python 3.10+
- PyQt5, `pefile`, `capstone` — see `requirements.txt` and `requirements-mcp.txt`

```powershell
.\install.ps1 -WithMcp -WithTests
```

## Surfaces

| Surface | Command |
|---------|---------|
| **GUI** | `python main.py` |
| **CLI** | `python scripts/hex_tool_cli.py list` |
| **MCP stdio** | `python scripts/hex_mcp_server.py` |
| **Desktop bridge (optional)** | `python main.py --lab-bridge <runtime_dir>` |

Open a file at startup:

```powershell
python main.py --open "C:\path\to\file.bin"
```

Tool hosts use the same contracts as MCP via `scripts/hex_tool_cli.py run <tool> ...`. Workspace allowlists: `config/workspace_roots.json` or `HEX_EDITOR_WORKSPACE_CONFIG`.

---

## Desktop GUI features

### Hex editing

- Hex and ASCII views with policy-driven forensic overlay layers (incremental refresh — no full-document replace on each update).
- **Full-file** load (`hex_view_mode: full`) or **viewport** mode for large files (`hex_view_mode: auto` + thresholds in `config/ui_policy.json`).
- Edits tracked by absolute byte offset across cached chunks; undo/redo.
- Atomic in-place save and Save As without rebuilding from the visible window only.
- File-change monitoring with optional reload prompt.

### Search and navigation

- Full-file raw-byte search with absolute-offset results (text, hex, `0x` offset jump, bookmarks).
- Opening a result scrolls to and selects the exact byte in the grouped hex view.

### Docks and inspectors

- **File structure** — source summary, record families, preserved regions, knowledge metrics (policy-driven).
- **Text Inspector** — RAW, transform preview, materialized, and semantic modes; debounced async preview; export full-file preview when policy allows.
- **Binary Inspector** — coverage, anchors, unknown regions, record families, representation, semantic graph, unresolved inference (visibility-gated refresh).
- **Runtime Overview** — session inspector + binary waterfall tables from the active `BinarySnapshot`.
- **Pseudocode** — region-routed structural/decompiler output with bidirectional hex sync.
- **Disassembly** — Capstone-backed worker for PE; semantic pseudocode fallback for other binaries per policy.
- **Search results**, bookmarks, symbols — navigation from lists to offsets.

### PE-oriented GUI behavior

- Background **BinarySnapshot** analysis for PE images when the binary inspector or runtime overview docks need data.
- **Tools → Binary Snapshot…** — dialog for snapshot metadata, forensic context, workspace export hooks, and offset navigation.
- Disassembly and binary snapshot menus enable when the format router reports `pe`.

### Presentation

- Application-wide dark mode for menus, docks, tables, and inspectors.
- Layout persistence (`config/ui_policy.json` → `desktop_persistence`, `dock_defaults`).

---

## Binary runtime (PE plugin)

- **Format router** (`src/runtime/format_router.py`) — PE suffixes and `MZ` sniff; storage headers via `config/format_detect_registry.json`.
- **BinarySnapshot** graph — nodes, edges, coverage, anchors, unknown regions, record families (`src/plugins/pe/`, `src/runtime/snapshot.py`).
- **Semantic validation** before promotion (`src/parsing/semantic_validator.py`).
- **Workspace unpack/reload** — manifest-backed artifacts (`src/services/binary_workspace.py`).
- **Three-level diff** — exact / structural / incompatible (`src/services/binary_snapshot_diff.py`, `config/binary_diff_policy.json`).
- **Waterfall payload** — shared contract for GUI tables and MCP (`src/services/binary_runtime.py`).

See [BINARY_DIFF_VIEW.md](BINARY_DIFF_VIEW.md) for compatibility classes and what the diff service actually measures.

---

## Representation and decode rails

- **Representation convert / sweep** — hex, text, integer, float, BCD, bitfield, interpreter signals (`binary_representation_*` tools, `config/representation_policy.json`).
- **Decoder candidates & value interpret** — registry-driven families (`config/binary_decoders.json`, `config/value_interpreter_policy.json`).
- **Representation falsification** — mechanically classifies hypotheses as supported, falsified, or inconclusive; never promotes parser facts.
- **Parser learning** — quarantined artifacts only; promotion through verified profiles (`binary_parser_learning_*`).
- **Transform scope / alternate scope / iterative scope** — proof runs with checkpoints, gates, and resume (`binary_*_scope_*`).
- **Local transform** — record-family XOR materialization with byte budgets (`binary_local_transform_*`).
- **Record families** — discovery and verification E2E (`binary_record_family_*`).
- **Full decode** — lossless ASCII rail with resume (`binary_full_decode_*`).
- **Unresolved inference** — ownership proofs, binary semantic graph, bounded query (`binary_unresolved_inference_*`, `binary_semantic_graph_query`).
- **Candidate lineage** — resolve and verify chains (`binary_candidate_lineage_*`).
- **Pseudocode** — region map, render, offset/selection mapping (`binary_pseudocode_*`, `config/region_routing_policy.json`).

### Learned plaintext profiles

Transform scoring can compare candidate bytes with locally learned plaintext profiles. Types, byte classes, token grammar, budgets, and library location are declared in `config/plaintext_profile_policy.json` — not embedded in parser code. Profiles store histograms and fingerprints only (no raw source paths in the library). Gemma packets receive scores and deltas; mechanical promotion gates remain authoritative.

### Learning DB

SQLite index for cross-run metadata (hashes, run status, candidates, parser coverage). Payloads stay on disk under `artifact_root`.

- Policy: `config/learning_db_policy.json`
- Registry: `config/learning_db_registry.json`
- Default DB: `learning_db_root` in `config/hex_editor.json`
- Sync: `scripts/learning_db_sync.py --inspect`
- Service: `src/services/learning_db/`

---

## PE execution (confirmation-gated)

| Tool | Role |
|------|------|
| `pe_execution_preflight` | Policy check before run |
| `pe_execution_run` | Requires `confirmed=true`; produces trace artifact |
| `pe_execution_get_trace` | Read bounded trace from saved artifact |
| `pe_execution_merge_view` | Merge static snapshot with runtime trace |

Sandbox/restricted modes are policy-defined; subprocess execution is trusted-only unless a real isolation backend is configured (`config/pe_execution_policy.json`).

---

## MCP / CLI tool catalog (58)

Enabled names come from `config/hex_editor.json` → `enabled_operations`. Grouped by role:

**Inspection & I/O**

- `binary_file_info`, `binary_read_range`, `binary_decode_range`, `binary_search`
- `binary_patch_range`, `binary_write_file` (write tools — confirmation rules apply)

**Representation**

- `binary_representation_convert`, `binary_region_representation_sweep`, `binary_decoder_candidates`, `binary_value_interpret`
- `binary_representation_workspace_sweep`, `binary_representation_falsify`

**Proof pipelines** (run / inspect / verify / resume where listed)

- `binary_parser_learning_*`
- `binary_transform_scope_*`
- `binary_alternate_scope_*` (includes `resume`)
- `binary_iterative_scope_*`
- `binary_local_transform_*`
- `binary_record_family_*`
- `binary_full_decode_*` (includes `resume`)
- `binary_unresolved_inference_*` (includes `resume`)

**PE & pseudocode**

- `pe_analyze`, `disasm_readonly`
- `binary_pseudocode_region_map`, `binary_pseudocode_render`, `binary_pseudocode_offset_for_line`, `binary_pseudocode_range_for_selection`

**Snapshots & workspaces**

- `binary_snapshot_parse`, `binary_snapshot_diff`
- `binary_unpack_workspace`, `binary_workspace_verify_integrity`
- `export_binary_analysis`

**Graph & lineage**

- `binary_semantic_graph_query`
- `binary_candidate_lineage_resolve`, `binary_candidate_lineage_verify`

**Desktop bridge**

- `hex_editor_open_desktop`, `hex_editor_desktop_status`

List live tools:

```powershell
python scripts/hex_tool_cli.py list
```

Schemas are validated in `tests/test_standalone_interfaces.py`.

---

## Architecture map

### Entry & GUI

| Path | Role |
|------|------|
| `main.py` | Desktop entry, logging, optional `--open`, `--lab-bridge` |
| `src/app.py` | Controller: loads, search, docks, snapshot workers, forensic context |
| `src/ui.py` | Main window, docks, menus, layout persistence |
| `src/hex_editor.py` | Chunk cache, edits, overlays, monitoring |

### Services (GUI-independent)

| Path | Role |
|------|------|
| `src/services/binary_inspection.py` | Bounded file facts, read, search |
| `src/services/binary_runtime.py` | Snapshot analyze entry, waterfall payload |
| `src/services/pe_analysis.py` | PE structured analyze |
| `src/services/disasm_analysis.py` | Entry disassembly |
| `src/services/representation_*` | Sweep, falsify, workspace |
| `src/services/transform_engine.py` | Crypto transform trials (generic calibration in `config/crypto_*.json`) |
| `src/services/*_scope/`, `full_decode/`, `unresolved_inference/` | Proof E2E rails |
| `hexeditor_tools/` | MCP catalog, CLI, desktop manager, investigation breakdown |

### Config SSOT

All budgets, registries, and thresholds live under `config/*.json`. Code loads policy paths from manifests — no magic paths in services.

---

## Verification

```powershell
.\install.ps1 -WithMcp -WithTests
python -m pytest tests/test_standalone_interfaces.py -q
```

Expect **58** tools and **4** interface tests (catalog schemas, CLI from foreign cwd, MCP stdio, desktop `open` ack).

---

## Safety

Keep an untouched copy of any source binary. Bounded tools refuse paths outside workspace config. Write and artifact-export tools require explicit confirmation flags where documented. Parser and decrypt **claims** stay in `model_hypotheses` until byte-backed gates pass — see `hexeditor_tools/evidence.py` epistemic rules.

## License & collaboration

Licensed under the [Apache License 2.0](../LICENSE). Anyone may download, modify, and collaborate on this project. **Vem som helst** kan ladda ner, ändra och samarbeta — fork och pull requests välkomna.