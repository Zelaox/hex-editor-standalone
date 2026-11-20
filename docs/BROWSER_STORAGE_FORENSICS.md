# Browser storage forensics

The existing Hex Editor CLI, MCP tools, desktop evidence viewer and IP Catcher bridge share `src/services/browser_forensics/`. The storage engine analyzes explicitly selected **saved evidence copies**. A separate operator-assisted loopback importer can accept text observed through the authorized browser UI. Neither path uses session cookies, recovers credentials, accesses hidden browser state or automatically decrypts messages.

## Supported structure and explicit limits

| Input | Implemented | Limits |
|---|---|---|
| SQLite | Raw b-tree/serial-field reader, overflow spans, WITHOUT ROWID, validated committed WAL overlay | Unknown/encrypted databases and rollback journals are not decoded. A live-copy snapshot is not assumed consistent. |
| LevelDB SSTable | Footer/block handles, CRC32C, restart/prefix records, internal sequence/deletion, Snappy, record pagination | Unknown codecs/versions and malformed stores remain partial/unsupported. Parsing a table is not full Chromium IndexedDB semantics. |
| LevelDB log / MANIFEST / CURRENT | Checksummed fragments, WriteBatch, supported VersionEdit tags, pointer grammar | No automatic repair, replay of the complete store version set, or inference of missing files. |
| JSON | Strict UTF-8 parsing, duplicate/nonfinite rejection, bounded traversal, configured field classification | Source mapping is honestly `block-level`, not a guessed token offset. Values are omitted. |
| Protobuf | Bounded wire fields and exact byte ranges | Requires an explicit `format_hint: "protobuf"`; without an app schema the status is `protobuf_candidate`. Length-delimited bytes are not guessed to be message text. |
| Chromium IndexedDB/V8 (optional protected recovery) | Bounded typed keys, object-store values, selected V8/Blink envelopes/types and Snappy wrappers | Not all serialization tags/versions are supported. External-blob references are identified, not automatically joined. Explicit blobs remain unbound candidates. |
| Opaque / unsupported blobs | Source hash and explicit unsupported coverage | No blanket claim that these contain encrypted data; no private-key or message claim from marker names. |

`messaging-markers-v1` is an explicitly selected, versioned marker profile, not a complete Messenger/Snapchat decoder. Its encodings and key/value locations live in policy. LevelDB occurrences are `marker_occurrence` / `carved` with a candidate type; matching an identity field does not prove the presence of a usable private key. Overlapping names are not separate message identities. `verified_message_count` is fixed at zero in this implementation's result schema.

## Configuration, not case constants

- `config/browser_forensics_policy.json`: validated budgets, worker deployment, profile rules, fuzz campaign and companion requirements.
- `config/format_detect_registry.json`: content signatures, probes and parser handlers; existing PE/PTX routing remains in place. Header routing avoids sending SQLite to a native PE parser; full storage grammar runs in isolation.
- `schemas/browser_forensics_{spec,policy,result}.schema.json`: input, policy and masked output contracts.
- `config/learning_db_{policy,registry}.json`: existing LearnerDB storage and registry-declared forensic index mappings.
- `config/pseudocode_navigation_policy.json`: evidence-viewer labels and highlight theme.
- AI Lab `config/hex_editor.json` and workspace-root configuration: enabled operations, LearnerDB root and allowed paths.

No capture ID, account ID, source hash, machine evidence path or expected finding count is embedded in the general parser. Wire-format constants belong to the relevant grammar. Worker distro/interpreter paths are deployment configuration, not inferred from evidence.

## Isolation prerequisites

The current backend is Linux `bubblewrap`; Windows invokes the distribution selected by `worker.wsl_distribution`. It requires a working WSL distribution, its configured Python (3.10+), `bubblewrap`, `libseccomp.so.2`, and namespace support. Native Linux uses the same backend directly. This service also requires Python 3.10+ on the host and `jsonschema` (already declared in Hex Editor requirements).

The launcher clears the environment, uses an unprivileged UID/GID, drops capabilities, unshares namespaces, exposes only runtime libraries/code/assigned copies read-only, and permits writes only to its scratch/output. Seccomp denies configured process, network, mount and tracing operations. CPU, memory, output/file size, process and wall-time limits are enforced; the wall watchdog kills the sandbox process group. Failure to establish the backend does **not** trigger an unrestricted fallback.

On this workstation, `bubblewrap` was installed in the configured WSL distribution for verification. Configure deployment explicitly on another workstation. The analysis identity pins parser Python files, forensic schemas, policy/registry snapshots, actual worker Python binary and sandbox executable hashes. This is not a signed chain of custody or an attestation of the entire OS/kernel/library installation.

## Create an input specification

Paths inside `files` are relative to `input_root`. Supply already acquired copies, including available sidecars. Hashes may be supplied by the acquisition manifest; otherwise the engine computes them before staging and checks them again afterwards. `acquired_at` and `origin` are optional evidence metadata: leave them unknown rather than inventing them from filenames.

```json
{
  "schema_version": 1,
  "case_id": "operator-selected-case",
  "capture_id": "operator-selected-acquisition",
  "input_root": "<absolute allowlisted acquisition directory>",
  "snapshot_state": "best_effort",
  "selection": {"rule": "explicit"},
  "profiles": ["messaging-markers-v1"],
  "files": [
    {"path": "store/CURRENT", "store_id": "store"},
    {"path": "store/MANIFEST-000001", "store_id": "store"},
    {"path": "store/table.ldb", "store_id": "store"}
  ]
}
```

The names above are illustrative, not runtime defaults. Include only files that actually exist; the engine rejects path escapes and hash mismatches. `snapshot_state: "consistent"` is an operator claim supported by the acquisition method, not something SHA-256 proves.

## Existing CLI

Run from the Hex Editor directory. Assign the PowerShell variables to your actual, allowlisted paths first; these examples deliberately contain no workstation/capture constants.

```powershell
python .\scripts\hex_tool_cli.py list
python .\scripts\hex_tool_cli.py describe binary_forensic_analyze
python .\scripts\hex_tool_cli.py run binary_format_detect --param "path=$analysisFile"
python .\scripts\hex_tool_cli.py run binary_forensic_analyze --param "spec_path=$specFile" --param "output_workspace=$outputFolder" --param confirmed=true
python .\scripts\hex_tool_cli.py run binary_forensic_inspect --param "run_path=$runFolder"
python .\scripts\hex_tool_cli.py run binary_forensic_verify --param "run_path=$runFolder" --param "input_root=$acquisitionRoot"
python .\scripts\hex_tool_cli.py run binary_forensic_replay --param "run_path=$runFolder" --param "input_root=$acquisitionRoot" --param "output_workspace=$replayOutput" --param confirmed=true
python .\scripts\hex_tool_cli.py run binary_learning_db_inspect
```

Ten new operations are registered: `binary_format_detect`, `binary_forensic_analyze`, `binary_forensic_inspect`, `binary_forensic_verify`, `binary_forensic_replay`, `binary_forensic_resolve`, `binary_forensic_open_finding`, `binary_learning_db_inspect`, `binary_message_recover`, `binary_message_export`. The validated CLI registry contains 74 enabled tools in this checkout. `describe` is authoritative for individual parameters/effects. Export/replay/recovery require `confirmed=true`; inspection/verification do not create a run. Existing CLI exit code 2 means an invocation error or returned `ok=false`; exit 0/`ok=true` is **not** a completeness claim. Always inspect `status`, coverage, limits and index status.

Each run has a unique output directory containing `manifest.json`, canonical masked `result.json`, saved `policy.json`/`registry.json`, hash-linked `events.jsonl` and escaped `report.html`. Verification covers the normalized result, policy/registry, manifest journal and optionally current sources. HTML is a presentation, not an integrity-sealed evidence artifact; the desktop viewer regenerates it from verified result data. The journal is an integrity check, not tamper-proof storage: archive or externally sign trusted digests if your custody process requires it. Existing evidence and earlier runs are never rewritten.

For a paginated SSTable, `binary_forensic_inspect` returns `continuations[]`. Create a **new** spec with the matching source hash and the returned file's `record_cursor`; retain companion inputs. Analyze that spec to a new run. Record ordinals/sequences and logical/version identities preserve the page boundaries. This does not automatically merge runs or claim all pages were read.

Replay verifies originals and saved artifacts, reuses the saved policy/registry, rejects an incompatible current build and writes a new run. It compares the entire normalized digest. Different input/output roots are supported when the relative source names and hashes match. Timestamps/run IDs/absolute roots/indexing times are outside the normalized result. LearnerDB hints are not consulted during parsing, so changing that index cannot silently change replay. A digest match for `partial`/`budget_exhausted` only reproduces that incomplete outcome; it is not proof of complete coverage.

## LearnerDB

The existing database gains registry-declared `forensic_runs` and `forensic_acquisitions` plus scoped masked finding references. Indexing verifies saved artifacts first, is idempotent and reports failures separately from parsing. It stores no raw cookies, message bodies or key values. Content hashes are identifiers, not anonymization of guessable secrets.

```powershell
python .\scripts\learning_db_sync.py --inspect-only
python .\scripts\learning_db_sync.py --forensic-root "$outputFolder"
```

`--inspect-only` opens a checkpointed database read-only/immutable, without initialization, migration, sync or DB creation. A nonempty WAL returns `requires_checkpointed_snapshot`; it does not checkpoint your live DB. `--forensic-root` is an explicit **writing** backfill from verified saved runs. Existing `--inspect` still performs sync first. The Python read-only query supports case filtering on case-scoped tables; this local index is not a substitute for multi-user access control.

## Desktop finding ↔ hex navigation

Use the **Forensic records and evidence** menu action (label is policy-controlled), then open a saved run. The records tab contains files, records, fields and individual source spans; the report tab contains typed finding links. Clicking a field resolves and verifies the run, case, current source hashes and bounds before emitting ranges. Selecting a segment chooses which physical file/range to open. Hex-cursor changes can select related fields in the loaded evidence viewer.

Uncompressed fields/log fragments/SQLite overflow chains retain physical spans. Snappy/prefix-reconstructed keys use contributing **block-level** spans where exact original-byte correspondence cannot be asserted; logical block/field offsets remain in the record locator. WAL overlay retains source DB/WAL identity. Modified sources or stale mappings are rejected. HTML cannot issue arbitrary filesystem/shell commands; only registered finding identities are resolved. The viewer supports the implemented transform types, not an arbitrary multi-codec provenance graph or an unrestricted decrypted-byte viewer.

## IP Catcher bridge

In the collector checkout, `forensic_hex_bridge.py --case-id <case> --lab-root <lab> [--capture <capture>]` generates an explicit spec and calls the same CLI service. Config/schema are `config/hex_forensics.json` and `config/hex_forensics.schema.json`. Lab root is explicit, configured/environment-provided or resolved upwards; there is no fixed drive fallback. `latest` follows the declared inventory; `pinned` follows the pinned file and is not silently replaced by latest. The inventory digest is retained when available.

The three existing `scripts/hex_*live_capture.py` / `hex_forensics_full.py` entrypoints delegate to this bridge. The former helper implementations are retained as legacy, not the supported canonical path. The new path never promotes generic ASCII previews to messages. Separate crypto discovery writes redacted, versioned output rather than overwriting earlier evidence. Historical unredacted files are not automatically rewritten/deleted.

## Verification and release boundaries

- `tests/test_browser_forensics.py`: synthetic format validation/corruption, Snappy, log fragments, SQLite overflow/WAL/WITHOUT ROWID, inside-block pagination, redaction, worker enforcement, replay/relocation, tamper rejection, LearnerDB idempotence/read-only behavior and GUI report/field navigation.
- Existing CLI, desktop, region routing, LearnerDB and pseudocode-navigation suites remain part of regression verification.
- Collector `tests/test_forensic_hex_bridge.py` covers generic discovery, redaction, root fail-closed behavior and inventory-driven latest selection.
- `scripts/browser_forensics_fuzz.py --synthetic-corpus <directory-of-approved-bin-seeds> --output <campaign-directory>` runs the configured deterministic, Python branch-coverage-guided campaign **inside isolation**. It records seed/corpus hashes, coverage, policy/registry/build digests and sanitized blockers; minimized reproducers use content-hash filenames. No production capture is automatically used as a corpus.

The default fuzz CLI adds the recovery policy's V8-value and IndexedDB-key harnesses to the nine storage harnesses, for eleven total. Native ASan/UBSan are **not run**; these are Python storage readers, and the span harness does not prove the entire GUI/resolver correct. Completing a bounded fuzz campaign does not prove absence of parser bugs.

## Protected text recovery and loaded-DOM import

`binary_message_recover` uses the existing confirmed CLI/MCP workflow on an explicit saved-file spec. Its worker performs bounded Chromium IndexedDB/V8 decoding and strict saved-JSON inspection under the same isolation. `config/browser_message_recovery_policy.json` declares supported versions, field aliases, budgets, saved-DOM profiles and the existing LearnerDB indexer. Unknown serialization forms fail closed. `_encryptedContent` objects are not promoted to plaintext; identity/hash markers are not decryption keys. An explicit file role `blob` allows bounded unbound-value inspection, not an invented parent-record association.

```powershell
python .\scripts\hex_tool_cli.py run binary_message_recover --param "spec_path=$specFile" --param "output_workspace=$outputFolder" --param confirmed=true
python .\scripts\browser_message_viewer.py --run-path "$runFolder" --case-id "$caseId"
```

Protected recovery outputs store raw candidate text and the live observation envelope only in `private.dpapi`, sealed for the current Windows user. `summary.json` is masked; `identity.json` and saved policies bind the protected payload, source identity and configuration. The viewer verifies case, digests and DPAPI authentication, then renders escaped text in memory with links disabled. On non-Windows hosts protection fails closed. This is not a separate password vault, administrator isolation, a signed custody system or guaranteed memory erasure. A separately confirmed readable export intentionally writes plaintext as described below. Existing historical exports are not rewritten/deleted.

For explicitly authorized live UI reading, start the one-shot **local importer**:

```powershell
python .\scripts\browser_live_capture.py --output-workspace "$outputFolder" --case-id "$caseId"
```

It prints a temporary loopback URL using an OS-assigned port and random capability, accepts an observation through its form, seals it locally and exits after one success or the configured timeout. It requires the exact same origin and Host, bounds the request and sets no-store/CSP headers. There is no remote listener, browser-debugging connection, credential access, network scraper or automatic unread-chat navigation. The script uses the existing workspace-root bootstrap/allowlist, not a fixed drive. `--no-index` disables automatic indexing; otherwise the existing LearnerDB sync policy applies. Only masked run references enter the existing DB.

The observation contract is schema version 1 with `profile_id`, canonical `profile_digest`, exact `url`, matching `conversation_id`, an operator-checked `conversation_label`, timezone-aware `observed_at` and `groups` (arrays of rows). A row contains only `text_parts`, `sender` and `timestamp`; missing row-level metadata must be `null`. The source URL and conversation label remain inside DPAPI, not the summary. Selectors, origins, route grammar and budgets live in the validated `config/browser_live_dom_profile.json`. Selector changes require a new reviewed profile revision; changed or missing DOM structure must not trigger a whole-page/sidebar fallback. The importer validates the submitted envelope, not whether a human/browser supplied genuine DOM; acquisition trust remains explicit.

Use only authorized, observed message containers. Each text part is a **`live_dom_text_observation`**, never a server-verified message. Ordinal locators refer to the protected DOM observation, not invented file-byte offsets. Duplicate visible text is preserved at separate positions. A pasted transcript inside a bubble remains one body. Sender/time are not inherited from nearby bubbles; reactions, attachments, deleted/expired content, unloaded history and unsupported structures are not recovered by this path. No automatic all-chat crawling, pagination or complete-history claim is made. The older saved-DOM export path remains `saved_dom_text_candidate`, as it may include UI labels or wrongly associated threads.

`tests/test_message_recovery.py` covers bounded V8/IDB decoding, invalid input, crypto non-promotion, DPAPI/case/tamper, masked LearnerDB indexing and the shared viewer. `tests/test_live_dom.py` covers live scope/profile validation, unknown metadata, duplicate/pasted text, safe HTML, sealed artifacts and loopback CSRF rejection. A real browser-form import was also checked end to end; its count is evidence-specific, not a runtime expectation.

## Explicit local plaintext export — Hex Editor only

`binary_message_export` is an opt-in **unencrypted** artifact export through the existing CLI/MCP. It does not use the official account export, contact Snapchat, open unread Snaps, extract credentials or change the default DPAPI storage. Anyone with filesystem access to the new output can read it. Do not place this directory in a shared/cloud-synced folder unless that disclosure is intended.

Create an export spec with explicit source run directories and each run's required original case scope. An export may combine explicitly named cases; it never auto-discovers private runs or silently changes their case IDs. Set `include_candidates` explicitly. An optional `media_spec_path` points to an ordinary saved-copy input spec.

```json
{
  "schema_version": 1,
  "case_id": "operator-selected-readable-export",
  "include_candidates": true,
  "runs": [{"run_path": "<absolute allowlisted sealed run>", "case_id": "<that run's original case>"}],
  "media_spec_path": "<optional absolute allowlisted saved-copy spec>"
}
```

```powershell
python .\scripts\hex_tool_cli.py describe binary_message_export
python .\scripts\hex_tool_cli.py run binary_message_export --param "spec_path=$exportSpec" --param "output_workspace=$outputFolder" --param confirmed=true
```

A new `readable-history-<random-id>` directory contains escaped/CSP-restricted `index.html`, UTF-8 `history.txt`, `history.json`, separate `candidates.json`, `media.json`, optional content-hash-named media files, saved policy and a hash manifest. `history` means loaded UI **observations**, not server-verified messages; saved DOM/structured/unbound-blob candidates stay in the separate unverified section. Duplicate candidate identities retain source-run references. Unknown sender/time is not guessed. `verify_readable` checks manifest/artifact/policy digests, not an external signature or historical completeness. The manifest links existing LearnerDB-indexed source runs; it does not insert raw text/media into that database.

`config/browser_readable_export_policy.json` and its schema declare statuses, budgets, media signatures/extensions/MIME types and parser routing. The isolated worker searches the explicit copies and recognized Chromium Snappy wrapping for bounded PNG/JPEG/WebP/MP4 framing candidates. PNG CRCs/structure, JPEG marker bounds, WebP RIFF bounds and supported MP4 boxes are checked. This is **not codec decoding**, proof of message association, decryption, support for every image/video format, archive/HEIC/WebM/GIF recovery or reconstruction of missing fragments. Media remains `framed_media_candidate`, with an unassigned conversation. No network URL is fetched. Unknown/encrypted/missing media is not replaced with fabricated content.

`scripts/browser_local_inventory.py` builds a new explicit, content-hash-deduplicated saved-copy spec from CLI `--include` patterns. Aliased copies remain in the inventory; selected roots, case/capture and output directory are supplied by the operator. It does not copy a running browser profile or repair stores. Its `--heap-pattern` annotates selected supported heap copies, but normal inventory/file budgets still apply; oversized files are reported as skipped rather than silently increasing limits.

Recovery additionally supports bounded V8 object references, including cyclic/shared supported objects and views of supported buffers. Reference leaves are not recursively expanded. A **separately enabled** `heap` recovery policy plus explicit `format_hint: "v8_heap_snapshot"` permits compact-array parsing/validation of a saved V8 heap graph. Only profile-declared property relationships can form structured text candidates; loose strings, arbitrary browser secrets, sliced strings and unlinked media are not promoted. Supported concatenated strings are reconstructed from their explicit first/second graph edges within depth/text budgets. Non-string supported identity objects receive explicitly labeled `heap-node-reference` locators, never invented service/account IDs. Heap node/edge locators are block-level provenance, not guessed byte offsets. Unknown schema/targets, malformed graphs and budgets fail closed; sanitized grammar/exception codes are retained. This subset is not a general memory or app-protocol decoder.

`binary_message_recover` accepts optional allowlisted `policy_path` and `recovery_policy_path` for explicit, validated per-case resource/schema settings. Case policies are saved and hashed with the run; changing a budget does not disable CPU/memory/wall/network constraints. `tests/test_readable_export.py` covers opt-in, candidate/observation separation, graph relationships, isolation, image/container framing, escaping, bounds and tamper. Existing V8 branch-guided fuzzing covers the extended reference reader; heap/media currently have bounded synthetic acceptance tests, not sustained coverage-guided campaigns or native sanitizers.

Remaining plan work: full Chromium IndexedDB key/value/V8 and external-blob semantics, versioned application message schemas, complete store-version reconstruction and rollback-journal support, automated pagination aggregation/cross-capture semantic diffs, acquisition consistency receipts from the collector, a general transform-artifact graph/derived-byte viewer, signed custody storage and broader native/sustained fuzzing. These are not advertised as completed or replaced with decryption guesses.
