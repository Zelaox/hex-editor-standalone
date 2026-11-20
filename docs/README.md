# Hex Editor — Project Documentation

> **Product framing:** Universal hex editor for **AI agents** (MCP + CLI) and humans (GUI). UVE, TRIAGE, RE, Lab, or any MCP client may **optionally** attach — see [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md). Older “AI Lab” wording means an optional host, not a dependency.

## Overview

This project is a PyQt5 binary workspace: bounded reads/writes, semantic graphs, diffs, snapshots, and MCP tools. The public standalone build is **format-agnostic** hex/binary analysis (PE and registered plugins).

## Learned plaintext byte profiles

Transform scoring and the PTX dynamic key hunt can compare candidate bytes with locally learned plaintext profiles. The reference types, byte classes, token grammar, budgets, score weights, match threshold, and library location are declared in `config/plaintext_profile_policy.json`; format keywords are not embedded in parser code.

Profiles are built only from explicitly selected or policy-discovered files. Discovery can cover every suffix and groups references by suffix without embedding a format list in code. Generated runtime data and configured cache directories are excluded to prevent the library from learning itself. The persisted library contains normalized byte histograms, byte-class ratios, UTF-8 validity, SHA-256 token and byte-sequence fingerprints, and source hashes/sizes/suffixes. Sequence lengths, stride, retained fingerprint count, recursion, directory exclusions, and grouping are policy settings. It does not store source paths, filenames, raw tokens, or raw sequences. Gemma receives only the best profile ID, component scores, total similarity, and before/after delta. This evidence can rank a transform candidate but cannot by itself set `key_verified`, `keys_found`, or `promote_allowed`; the existing mechanical structure and consistency gates remain authoritative.

The generated local library is stored below the AI Lab runtime-data root configured by policy. Rebuild it when reference data changes instead of adding new literals to parsers.

## Learning DB (cross-run memory index)

The hex editor maintains a **config-driven SQLite learning index** for decode/parser runs. Binary payloads and manifests stay on disk in the artifact store; the DB stores queryable metadata only (hashes, run status, candidate states, findings, parser observations).

- Policy: `config/learning_db_policy.json` — table definitions, sync behavior, query limits, DB path source
- Registry: `config/learning_db_registry.json` — indexer field maps from artifact JSON into DB rows (no hardcoded offsets, paths, or thresholds in Python)
- DB location: `learning_db_root` in AI Lab `config/hex_editor.json` (default `data/runtime/hex_editor/learning_db/learning.sqlite`)
- Auto-index: enabled when `sync.on_run_complete` is true — `full_decode`, `record_family`, `local_transform`, and `parser_learning` runs index themselves on completion
- Backfill: `python scripts/learning_db_sync.py --inspect`
- Query API: `src/services/learning_db/` — `query_runs_for_source`, `query_candidates_for_source`, `inspect_learning_db`, `sync_learning_db`

Parser rule promotion still flows through the verified parser-learning rail and declarative parser profile registries; the learning DB does not auto-promote facts.

The project has three main surfaces:

1. The interactive hex editor started by `main.py`.
2. PTX analysis and rebuilding command-line tools.
3. The `ptx_converter` package for parsing and converting session data.

## Requirements

- Python 3.7 or newer
- PyQt5 5.15 or newer
- `pefile`
- `capstone`

Install the declared dependencies from the project root:

```powershell
python -m pip install -r requirements.txt
```

## Starting the application

From the project root:

```powershell
python main.py
```

`main.py` changes the working directory to the project root, creates `logs` when necessary, configures logging, and starts `src.app.main()`.

Open a file at startup:

```powershell
python main.py --open "C:\path\to\session.ptx"
```

When AI Lab is running, `/hex-editor` provides application health, read-only analysis, and desktop launch controls. AI Lab tool calls use the GUI-independent services under `src/services/`; they do not automate Qt widgets.

## Main features

- Hex and ASCII views of binary files with policy-driven forensic overlay layers (incremental — no full-document replace on refresh).
- Full-file hex load (`hex_view_mode: full`) with native Qt scroll.
- Large files switch automatically to viewport rendering (`hex_view_mode: auto`) using thresholds in `config/ui_policy.json` (`hex_viewport_file_bytes`, `hex_viewport_document_lines`) so 10 MB+ files avoid building a full hex document.
- Fixed-size byte edits tracked by absolute offset across visible chunks.
- Atomic in-place and Save As writes for large files without rebuilding from the visible window.
- Full-file raw-byte search with absolute-offset results, including text that crosses rendered line boundaries. The Search box accepts ordinary text, whitespace-separated hex bytes, explicit `text:` / `hex:` prefixes, or a `0x...` offset for direct navigation. Opening a result scrolls to and selects its exact byte in the grouped hex view. Bookmarks, comments, undo, and redo infrastructure are also available.
- Application-wide dark mode for menus, docks, tabs, tables, headers, form controls, buttons, inspectors, and disabled states.
- File-change monitoring.
- Binary extraction and disassembly views.
- The existing Disassemble worker routes non-PE binaries to a policy-driven Semantic Pseudocode fallback. A matching verified Binary Semantic Graph selects evidence-bound source ranges without displaying graph bookkeeping. Policy maps `verified_plaintext` to strict escaped text literals and keeps decoded, preserved and unresolved binary classes as exact byte initializers; without a graph it emits offset-addressed unresolved bytes. Full view emits every byte (`0` policy limits mean unlimited) and wraps initializers using a configured line width. It does not invent field meanings or claim data is executable code.
- Text Inspector provides policy-registered RAW, TRANSFORM PREVIEW, MATERIALIZED and SEMANTIC modes for the current selection/cursor window. Preview/materialized data is accepted only from a verified identity-matched full-decode candidate; semantic mode composes verified plaintext with explicit binary/unresolved placeholders from a matching graph. Missing evidence stays unavailable instead of triggering guessed transforms, and `Go to source bytes` returns to the inspected offset.
- PTX file detection, background parsing, timecode discovery, and highlighted PTX structures.
- PTX section and metadata extraction.
- Immutable PTX runtime snapshots with raw↔parsed provenance and explicit unknown coverage.
- Unified **BinarySnapshot** runtime for PTX and PE/EXE via format plugins (`src/runtime/`, `src/plugins/ptx/`, `src/plugins/pe/`).
- PTX full-byte coverage pass with content-derived anchors, repeated record-family candidates, explicit unknown-region feature profiles, deterministic coverage summaries, and policy-bounded sequence sampling.
- Registry-driven M12 representation falsification consumes cached or on-demand `RepresentationBrief` artifacts and classifies decoder/signal hypotheses as supported, falsified, or inconclusive. It never promotes parser or decrypt facts.
- Representation/interpreter dispatch, transform scheduling and candidate finalization resolve registry hooks and metadata. Repeating-XOR periods are evidence-ranked within configured inference bounds. Missing inference, scheduler, finalizer or tool-budget policy fails loudly; no runtime fallback candidate list or synthetic key is substituted.
- Session Inspector and Binary Inspector tabs driven by the same snapshot model.
- **Tools → Binary Snapshot…** dialog: view snapshot metadata, Gemma/investigation runs, probe ledger, best rejected, derived windows, transform diff / scope evidence, and export workspace or JSON.
- Policy-budgeted dynamic key hunt with optional advisory Gemma hypotheses and mechanical-only verification.
- PE static image graph (sections, imports, exports, entry/disasm) and a separate confirmation-gated runtime layer. Sandbox/restricted modes are non-executing until a real isolation backend is registered; local subprocess execution is trusted-only.
- Deterministic binary workspace unpack/reload and three-level snapshot diff services.
- Binary Waterfall compatibility gate: direct diff for exact layouts, segment alignment for structural matches, and no automatic diff for incompatible snapshots.
- Binary Waterfall and Binary Inspector consume the same anchors, unknown regions, record families, coverage summary, and snapshot ID; neither UI surface creates parser facts.
- PTX analysis export to text, JSON, and XML.
- Desktop JSON export uses a versioned, JSON-safe PTX summary and atomically replaces the selected report file.
- Desktop section extraction validates every parsed range against the PTX source and atomically writes numerically named section files.
- PTX rebuilding, modification, encryption, and decryption utilities.

Always keep an untouched copy of a source binary. Editing, decrypting, or rebuilding undocumented binary formats can produce files that the originating application cannot open.

## Architecture

### Application entry and GUI

- `main.py` — desktop entry point and logging bootstrap.
- `src/app.py` — application controller. Connects UI actions, editor operations, PTX handling, search, extraction, and disassembly.
- `src/ui.py` — main-window widgets, menus, toolbars, docks, dialogs, and persisted UI settings.
- `src/hex_editor.py` — file cache integration, visible chunk rendering, editing state, navigation, highlighting, and file monitoring.

### Binary services

- `src/search.py` — background raw-byte search with absolute file offsets and result highlighting.
- `src/disassembler.py` — disassembly worker and symbol/string results.
- `src/extractor.py` — extraction of binary structures and related outputs.
- `src/utils.py` — hex conversion, caching, logging helpers, and shared utilities.
- `src/constants.py` — editor limits, chunk sizes, colors, and shared constants.
- `src/services/binary_inspection.py` — bounded file facts, reads, and chunk-safe byte search.
- `src/services/contracts.py` — JSON-serializable findings and analysis results.
- `src/services/ptx_analysis.py` — structured PTX analysis with explicit heuristic provenance.
- `src/services/artifact_store.py` — staged output, manifests, hashes, and source-preservation checks.
- `src/services/ptx_artifacts.py` — managed analysis export and safe PTX section extraction.
- `src/services/ptx_runtime_analysis.py` — backward-compatible re-export over unified binary runtime.
- `src/services/binary_runtime.py` — format-routed `analyze_binary_snapshot`, waterfall payload, semantic validation.
- `src/services/binary_workspace.py` — deterministic manifest-backed unpack/reload for PTX and PE.
- `src/services/binary_snapshot_diff.py` — raw, parsed, and runtime graph diff.
- `src/snapshot_controller.py` — immutable snapshot lifecycle for Binary Inspector.
- `src/binary_inspector_widget.py` — format-driven static/runtime PyQt inspector dock.
- `src/plugins/pe/dynamic_execution.py` — policy-gated PE launch orchestrator (never called from parser).
- `src/services/ptx_workspace.py` — legacy PTX workspace alias; prefer `binary_workspace`.
- `src/services/ptx_session_diff.py` — legacy PTX diff alias; prefer `binary_snapshot_diff`.

### PTX crypto / decrypt services

- `src/services/ptx_crypto_analysis.py` — two-stage XOR sweep, AES-128-ECB trial lane, cheap/stage2 scoring.
- `src/services/ptx_crypto_primitives.py` — `xor_apply`, AES-128-ECB, entropy, SHA256 (pure Python).
- `src/services/ptx_crypto_config.py` — loads calibration thresholds and probe windows from lab fixture.
- `src/services/ptx_key_discovery.py` — decrypt key probe entry point (AI Lab MCP `ptx_probe_decrypt_keys`).
- `src/services/ptx_promotion_gate.py` — mechanical promotion (`score ≠ keys_found`).
- `src/services/ptx_transform_evidence.py` — before/after, preserve, reference diff evidence.
- `src/services/ptx_auto_decrypt.py` — materialize decrypted `.ptx` beside source snapshot.
- `src/services/ptx_desktop_decrypt.py` — desktop confirmation path: exhaustive bounded probe, mechanical promotion gate, then atomic output to the user-selected destination.
- `src/services/ptx_scoring_regions.py` — body probe windows, excluded cleartext regions.

**Documentation:**

- [PTX XOR & AES (current behavior)](PTX_XOR_AES_CRYPTO.md)
- [Binary Waterfall Diff View — measurements and interpretation](BINARY_DIFF_VIEW.md)
- [Binary Diff View — debug guide (config-driven triage, no case literals)](diff_view/debug.md)
- [Binary transform inference engine (plan)](plans/binary_transform_inference_engine/plan.md) — registry-driven expansion; **NO HARDCODE, config under `Hex editor/config/`**

### PTX GUI / CLI / legacy scripts

- `src/ptx_handler.py` — PTX detection, parsing, sections, timecodes, and file-specific operations used by the GUI.
- `test_ptx_features.py` — analysis-oriented CLI/test driver with text, JSON, and XML output.
- `ptx_rebuild_cli.py` — command-line entry for rebuild, modify, encrypt, and decrypt operations.
- `src/ptx_rebuilder.py` — PTX reconstruction implementation used by project code.
- `decrypt_ptx.py`, `auto_detect_key.py`, and `analyze_decryption.py` — experimental decryption and key-analysis utilities.
- `extract_binary_data.py`, `extract_key_offsets.py`, `extract_timecodes.py`, `find_metadata.py`, and `search_strings.py` — targeted forensic extraction utilities.

### Session converter

The `ptx_converter` package is a second application surface:

- `ptx_converter/core/parser.py` — session parsing.
- `ptx_converter/core/decryption.py` — decryption support.
- `ptx_converter/core/application.py` — converter orchestration.
- `ptx_converter/core/cli.py` — converter CLI.
- `ptx_converter/formats/` — target/session format adapters.
- `ptx_converter/gui/main_window.py` — converter GUI.

Run its module entry point from the project root:

```powershell
python -m ptx_converter
```

## Runtime data flow

For the desktop editor, the main flow is:

```text
main.py
  -> logging setup
  -> src.app.HexEditorApp
  -> src.ui.HexEditorMainWindow
  -> src.hex_editor.HexEditor
  -> file-type detection
  -> optional PTX parsing/extraction/decryption
  -> GUI views and exported artifacts
```

Opening a file creates a cached file reader, loads the initial visible chunks, detects whether the file is PTX, and starts PTX parsing in a background thread when applicable. Saving reinitializes the extractor and file handler so the displayed structure reflects the saved file.

### Editing and saving large files

The editor records changed bytes as absolute file-offset patches. Before leaving a visible range or saving, it strictly parses the hexadecimal byte column and requires the byte count to remain unchanged. Edits made in separate windows remain in the patch map until save or undo.

Saving copies the complete source to a temporary file in the destination directory, applies contiguous changed-byte runs, verifies the original file size, flushes the file, and atomically replaces the destination. Save As preserves the original source. If the source changed outside the editor after loading, saving is refused until reload.

Insertion and deletion are intentionally unsupported; this editor currently performs fixed-size byte replacement only. Invalid hex, changed row offsets, and resized views are rejected. The ASCII column is a display aid—make edits in the hexadecimal byte column.

## PTX analyzer

Basic analysis:

```powershell
python test_ptx_features.py session.ptx
```

JSON export:

```powershell
python test_ptx_features.py session.ptx --format=json --output=analysis.json
```

XML export:

```powershell
python test_ptx_features.py session.ptx --format=xml --output=analysis.xml
```

See the root-level `PTX_ANALYZER.md` for format-specific notes and analyzer details.

## PTX rebuilder

Inspect command help before operating on important data:

```powershell
python ptx_rebuild_cli.py --help
```

Examples:

```powershell
python ptx_rebuild_cli.py rebuild --components test_output --output rebuilt.ptx
python ptx_rebuild_cli.py rebuild --source source.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
python ptx_rebuild_cli.py decrypt input.ptx output.ptx
python ptx_rebuild_cli.py encrypt input.ptx output.ptx
python ptx_rebuild_cli.py modify --input input.ptx --output modified.ptx --timecode 0x84058=01:00:00:00
```

See the root-level `PTX_REBUILDER.md` for the detailed rebuild contract.

## Testing

The repository contains both focused loader tests and larger PTX feature/rebuilder tests:

```powershell
python test_load_ptx.py
python test_ptx_features.py
python test_ptx_rebuilder.py
```

AI Lab integration and large-save regression tests:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest tests\hex_editor -q
```

Some tests use sample PTX files or create binary output. Run them against copies and review their command-line defaults before execution.

## Generated files and logs

New AI Lab output operations write to `data/artifacts/hex_editor/<operation-id>/` in the Lab root. They do not add new exports to the Hex Editor source directory. See `docs/ARTIFACT_INVENTORY.md` for classification of historical files already present here.

- `logs/` contains GUI, editor, extractor, search, disassembler, rebuilder, and debug logs.
- `test_output/` contains test analysis output and extracted binary fragments.
- `sections/`, `ptx_sections/`, `ac240_decrypted_sections/`, and `full_extraction/` contain extracted data.
- Root-level `*_report.json`, `*_report.txt`, `ptx_results.*`, rebuilt PTX files, and analysis reports are generated or research artifacts.

Do not treat generated analysis, inferred offsets, encryption keys, or reconstructed structures as authoritative format specifications without independent verification.

## Development guidance

- Keep UI orchestration in `src/app.py` and binary transformations in focused service modules.
- Perform expensive parsing, searching, and disassembly outside the GUI thread.
- Preserve deterministic offsets and provenance in exported analysis.
- Never overwrite the only copy of a source file in tests or experiments.
- Add regression fixtures for every newly understood PTX structure.
- Distinguish verified PTX facts from heuristic detections in output and documentation.
- Avoid committing logs, caches, extracted binaries, rebuilt sessions, and large sample files unless they are intentional test fixtures.

## Known caveats

- PTX is not treated here as a fully documented, stable public format; several operations are heuristic or experimental.
- The codebase contains overlapping historical scripts and newer `src` implementations. Confirm which entry point owns a behavior before refactoring it.
- Encryption/decryption routines must be validated against known-good files.
- The application currently contains TODOs around recent-file handling and some context-menu actions.
- Fixed-size replacements can be saved at large file sizes; byte insertion and deletion remain unsupported.
- Large recursive output folders and binary samples should remain separate from source documentation and unit-test fixtures.
- AI Lab registers bounded inspection, PTX runtime analysis, advisory key hunt, runtime diff, and confirmed unpack tools. Decrypted materialization still requires a separate explicit confirmation path.
- AI Lab additionally registers `ptx_full_coverage_analyze`, `ptx_unknown_region_inspect`, and `ptx_structural_experiment_diff` as read-only evidence tools. Full workspaces use schema version 2 and export coverage, anchors, record families, experiment index, content-addressed unknown blocks, and the canonical snapshot.
- Multi-turn semantic scope search is available through `binary_iterative_scope_run`, `binary_iterative_scope_inspect`, and `binary_iterative_scope_verify`. The service verifies both input identities, derives lost/gained/retained spans from configured detectors, composes evidence-referenced scopes, keeps a multi-objective Pareto frontier, checkpoints every turn, and writes experimental candidates under `data/artifacts/hex_editor/iterative_scope_runs/`. `scripts/iterative_scope_gemma_live.py` lets Gemma rank only the mechanically eligible frontier class; the model cannot introduce ranges, keys, candidates, promotion, or decryption authority.
- Evidence-driven local transform regimes are available through `binary_local_transform_run`, `binary_local_transform_inspect`, and `binary_local_transform_verify`. Transform families, parameter domains, sweep thresholds, record-family independence, materialization budgets, semantic analyzers, and validation gates come from `config/local_transform_policy.json` and `config/local_transform_registry.json`. The service composes source-to-parent lineage per span, materializes only evidence-supported repeated records, and emits chained logs, checkpoints, descriptors, overlays, and experimental candidates under `data/artifacts/hex_editor/local_transform_runs/`. `scripts/local_transform_gemma_live.py` constrains Gemma to ranking mechanically eligible candidate numbers; it cannot add transform parameters, offsets, scopes, promotion, or decryption claims.
- Coverage-complete full-file decoding is implemented in `src/services/full_decode/` and exposed through `scripts/full_decode_e2e.py` plus `binary_full_decode_run`, `binary_full_decode_inspect`, `binary_full_decode_verify`, and `binary_full_decode_resume`. Registered proof providers are composed only when their byte proposals are compatible. Every byte is classified as verified plaintext, verified decoded binary, preserved binary, or unresolved; outputs include an immutable candidate, inverse patch, proof spans, full coverage, strict plaintext corpus, canonical lossless ASCII, semantic ASCII report, chained events, and verification gates. Runtime behavior is controlled by `config/full_decode_policy.json` and `config/full_decode_registry.json`; case-specific strings, offsets, filenames, hashes, keys, and scopes are forbidden.
- `scripts/full_decode_gemma_live.py` lets the configured Gemma endpoint rank an existing verified full-decode candidate through `config/grammars/full_decode_advisory.gbnf`. Attempts, the model-safe packet, accepted action, authority status, and digest are persisted under `data/artifacts/hex_editor/full_decode_gemma_live/`; the model cannot submit bytes, offsets, scopes, transform parameters, keys, promotion, or decryption claims.
- `scripts/live_investigation_e2e.py` runs the registered full-decode measurements as a bounded multi-turn closure. Record-family transform consistency is checked independently for each family, so compatible families may use different mechanically observed lanes; an inconsistent family is rejected without aborting the run. Gemma output uses the configured GBNF when the active llama runtime accepts it and falls back to unconstrained generation only for a runtime grammar-parser error; the same packet-ID validator remains authoritative in both paths.
- Unresolved-byte ownership inference is implemented in `src/services/unresolved_inference/`, driven by `config/unresolved_inference_policy.json` and `config/unresolved_inference_registry.json`. `scripts/unresolved_inference_e2e.py` and the `binary_unresolved_inference_*` MCP tools verify a partial full-decode run, derive topology/context/boundary/representation/dependency evidence, compile ownership proofs and a typed Binary Semantic Graph, emit deterministic indexes/queries/diffs plus converter/parser handoffs, and leave unsupported spans unresolved. `binary_semantic_graph_query` provides bounded offset and relationship traversal. The Binary Inspector discovers the newest verified matching graph only while its dock is visible and provides vertical non-overflowing navigation, a status banner, policy-colored truth states, state filtering, node/edge exploration, selected-node relationships, ownership proofs and byte-offset navigation. Its empty state includes an `Analyze current file` recovery action. When both Binary Inspector and PTX Metadata are closed, snapshot/forensic workers are not started; PTX Metadata may request the shared lightweight snapshot while graph discovery remains gated by Binary Inspector visibility.
- The desktop **Decrypt PTX** action never guesses and writes directly: without a mechanically promoted candidate it creates no output, and it never overwrites the loaded source.
- Dynamic session discovery currently classifies generic strings and preserves everything else as unknown; verified PTX-specific track/clip/region profiles still require independently evidenced registry rules.

## Related documentation

- `README.md` — original project quick start.
- `docs/BINARY_DIFF_VIEW.md` — authoritative guide to Binary Waterfall Diff, including the current single-snapshot GUI boundary, pairwise compatibility, sequence metrics, alignment, raw identity, parsed nodes, graph/signals, and current limitations.
- `docs/diff_view/debug.md` — config-driven felsökningsguide för Binary Diff View; kör `scripts/diff_view_debug.py` med `config/diff_view_debug_policy.json`.
- `docs/PTX_XOR_AES_CRYPTO.md` — current XOR/AES decrypt probe behavior (`src/services/`).
- `docs/plans/binary_transform_inference_engine/plan.md` — transform engine roadmap (Hex Editor config SSOT).
- `docs/plans/parser_learning_feedback_rail/plan.md` — in-progress evidence-driven parser-learning, validation and promotion rail (core E2E verified; production publish not yet exercised).
- `docs/plans/xor_transform_scope_and_gate_proof/plan.md` — planned evidence-derived XOR scope, preserve-region and promotion-gate proof with bounded checkpointed probes.
- `docs/plans/record_family_materialization_loop/plan.md` — proposed evidence-driven path from repeated plaintext observations through boundary/framing proof, held-out record-family validation, reversible family-scoped materialization, Pareto composition, parser-learning handoff, and verified unknown-coverage reduction.
- `docs/plans/full_file_decode_to_plaintext_ascii/plan.md` — active whole-file E2E roadmap and verified implementation status for coverage accounting, provider composition, reversible materialization, strict plaintext extraction, canonical lossless ASCII, semantic reporting, and zero-unresolved completion gates.
- `docs/plans/unresolved_byte_ownership_and_dependency_inference/plan.md` — implemented NO-HARDCODE E2E rail and verified live status for unresolved topology, boundary/representation/dependency inference, ownership proofs, reversible candidates and a typed Binary Semantic Graph; unsupported ownership remains explicitly unresolved.
- `docs/plans/binary_semantic_pseudocode_view/plan.md` — Whole E2E NO-HARDCODE plan with the first non-PE worker-to-Pseudocode-dock semantic rendering slice implemented; structured navigation, richer typed IR and strict visibility-driven generation remain planned.
- `docs/plans/scope_aware_transform_preview_view/plan.md` — Whole E2E NO-HARDCODE plan with its first four-mode Text Inspector implementation verified; on-demand descriptor-chain replay, length-changing mappings, conflict overlays and virtualized full-file export remain planned.
- `docs/plans/gui_forensic_visibility/plan.md` — planned GUI wiring for timecodes, anchors, waterfall, and investigation probe visibility (NO HARDCODE; config-driven `ui_policy.json`).
- `config/iterative_scope_policy.json`, `config/iterative_scope_registry.json`, and `schemas/iterative_scope_run.schema.json` — implemented multi-turn scope policy, runtime hooks, objectives, model boundary, artifact contract, and stop conditions.
- `config/local_transform_policy.json`, `config/local_transform_registry.json`, and `schemas/local_transform_run.schema.json` — implemented local-regime discovery, record-family aggregation, lineage-safe materialization, semantic gates, model boundary, artifact contract, and logging policy.
- `data/investigations/ac240_943d8d8ba0808469__ad8a1cd7dd0f476a/plan.md` — planned key-hunt/probe improvements derived from the AC240 full-coverage investigation (NO HARDCODE).
- `PTX_ANALYZER.md` — PTX analyzer documentation.
- `PTX_REBUILDER.md` — PTX rebuilder documentation.
- `MINIMAL_LOGGING_README.md` — logging behavior.
- `ptx_analysis_conclusion.md`, `ptx_decryption_findings.md`, and `summary_findings.md` — historical research findings that should be read as project evidence, not guaranteed format truth.
