"""Register Hex Editor tools with the central Tool Registry."""

from __future__ import annotations

from src.project import project_root

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from hexeditor_tools import api as hex_editor_tools

logger = logging.getLogger("mcp.services.hex_editor_tools_registration")

_READ_TAGS = [
    "hex",
    "binary",
    "read-only",
    "capability:binary_inspection",
    "effect:evidence_read",
]
_WRITE_TAGS = [
    "hex",
    "binary",
    "capability:binary_write",
    "effect:reversible_mutation",
]
_ARTIFACT_TAGS = [
    "hex",
    "binary",
    "capability:artifact_export",
    "effect:reversible_mutation",
]


def _definitions() -> Dict[str, Dict[str, Any]]:
    path = {"type": "string", "required": True, "description": "Allowlisted binary file path."}
    return {
        "binary_file_info": {
            "description": "Read file identity, SHA-256, size, and a 32-byte binary prefix.",
            "parameters": {"path": path},
            "function": hex_editor_tools.binary_file_info,
            "tags": _READ_TAGS,
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_read_range": {
            "description": "Read a bounded binary range as hex and printable ASCII (maximum 1 MiB).",
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": False, "default": 0},
                "length": {"type": "integer", "required": False, "default": 65536},
            },
            "function": hex_editor_tools.binary_read_range,
            "tags": _READ_TAGS,
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_decode_range": {
            "description": (
                "Decode a bounded binary range as text with forensic encodings "
                "(UTF-8, ASCII, Latin-1, UTF-16). Returns decoded text, hex, binary, and Base64."
            ),
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": False, "default": 0},
                "length": {"type": "integer", "required": False, "default": 65536},
                "encoding": {"type": "string", "required": False, "default": "utf-8"},
                "errors": {"type": "string", "required": False, "default": "strict"},
            },
            "function": hex_editor_tools.binary_decode_range,
            "tags": _READ_TAGS,
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_representation_convert": {
            "description": "Lossless conversion between bytes and hex, binary, decimal, or base64 representations.",
            "parameters": {
                "direction": {
                    "type": "string",
                    "required": True,
                    "description": "to_bytes (parse text into bytes) or from_bytes (render bytes as text).",
                },
                "format_id": {"type": "string", "required": True, "description": "hex, binary, decimal, or base64."},
                "payload": {"type": "string", "required": True, "description": "Input string or spaced hex for from_bytes."},
            },
            "function": hex_editor_tools.binary_representation_convert,
            "tags": _READ_TAGS + ["capability:binary_representation"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_region_representation_sweep": {
            "description": "Run the full representation brief sweep (hex, text, integer, float, BCD, bitfield, interpreter signals) on a file range.",
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": False, "default": 0},
                "length": {"type": "integer", "required": False, "description": "Omit or use zero to resolve the configured representation tool budget."},
            },
            "function": hex_editor_tools.binary_region_representation_sweep,
            "tags": _READ_TAGS + ["capability:binary_representation"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_decoder_candidates": {
            "description": "Return registry-driven decoder candidates for a bounded binary range.",
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": False, "default": 0},
                "length": {"type": "integer", "required": False, "description": "Omit or use zero to resolve the configured representation tool budget."},
                "decoder_ids": {
                    "type": "string",
                    "required": False,
                    "description": "Optional comma-separated decoder family ids.",
                },
            },
            "function": hex_editor_tools.binary_decoder_candidates,
            "tags": _READ_TAGS + ["capability:binary_representation"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_value_interpret": {
            "description": "Run mechanical value interpreter signals over decoder candidates for a bounded range.",
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": False, "default": 0},
                "length": {"type": "integer", "required": False, "description": "Omit or use zero to resolve the configured representation tool budget."},
                "pattern_ids": {
                    "type": "string",
                    "required": False,
                    "description": "Optional comma-separated interpreter pattern ids.",
                },
            },
            "function": hex_editor_tools.binary_value_interpret,
            "tags": _READ_TAGS + ["capability:binary_representation"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_representation_workspace_sweep": {
            "description": "Sweep unknown regions in an exported binary workspace and cache RepresentationBrief artifacts.",
            "parameters": {
                "workspace_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to exported binary-unpack workspace root.",
                },
                "region_id": {"type": "string", "required": False, "description": "Optional single region id."},
                "force": {"type": "boolean", "required": False, "default": False},
            },
            "function": hex_editor_tools.binary_representation_workspace_sweep,
            "tags": _READ_TAGS + ["capability:binary_representation", "capability:binary_runtime_analysis"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_representation_falsify": {
            "description": "Mechanically support, falsify, or leave inconclusive registry-derived hypotheses from an unknown region RepresentationBrief; never promotes parser or decrypt facts.",
            "parameters": {
                "path": path,
                "region_id": {"type": "string", "required": True, "description": "Content-addressed unknown region id."},
                "workspace_path": {"type": "string", "required": False, "description": "Optional exported workspace containing a cached RepresentationBrief."}
            },
            "function": hex_editor_tools.binary_representation_falsify,
            "tags": _READ_TAGS + ["capability:binary_representation", "capability:mechanical_falsification"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_parser_learning_run": {
            "description": "Aggregate M10-M12 workspace evidence into quarantined record/field/relation parser candidates and validate policy-owned cross-file gates; never publishes profiles.",
            "parameters": {
                "workspace_paths_json": {"type": "string", "required": True, "description": "JSON array of exported binary workspace paths."},
                "output_workspace": {"type": "string", "required": True},
                "format_plugin": {"type": "string", "required": True},
                "base_profile_id": {"type": "string", "required": True},
                "promotion_profile_id": {"type": "string", "required": False},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_parser_learning_run,
            "tags": _ARTIFACT_TAGS + ["capability:parser_learning", "capability:mechanical_falsification"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_parser_learning_inspect": {
            "description": "Read a parser-learning run, validation gates, and bounded Gemma advisory packet.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_parser_learning_inspect,
            "tags": _READ_TAGS + ["capability:parser_learning"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_transform_scope_run": {
            "description": "Run a confirmed bounded evidence-derived transform scope proof with preserve checks, gate breakdown, checkpoint and structured logs; never mutates source or active registries.",
            "parameters": {
                "path": path,
                "output_workspace": {"type": "string", "required": True},
                "candidate_hex": {"type": "string", "required": True},
                "boundary_hint": {"type": "integer", "required": True},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_transform_scope_run,
            "tags": _ARTIFACT_TAGS + ["capability:transform_scope", "capability:mechanical_falsification"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_transform_scope_inspect": {
            "description": "Read transform scope hypotheses, exact gate breakdown and run status.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_transform_scope_inspect,
            "tags": _READ_TAGS + ["capability:transform_scope"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_transform_scope_verify": {
            "description": "Verify that every artifact referenced by a transform scope run exists and its run schema is valid.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_transform_scope_verify,
            "tags": _READ_TAGS + ["capability:transform_scope"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_alternate_scope_run": {
            "description": "Run confirmed evidence-driven alternate-scope and boundary probes with independent-window, parser, preserve and header gates.",
            "parameters": {
                "path": path,
                "output_workspace": {"type": "string", "required": True},
                "candidate_hex": {"type": "string", "required": True},
                "boundary_hint": {"type": "integer", "required": True},
                "previous_run": {"type": "string", "required": False},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_alternate_scope_run,
            "tags": _ARTIFACT_TAGS + ["capability:alternate_scope", "capability:boundary_inference", "capability:mechanical_falsification"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_alternate_scope_inspect": {
            "description": "Read alternate-scope progress, gate summary and verified run state.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_alternate_scope_inspect,
            "tags": _READ_TAGS + ["capability:alternate_scope", "capability:boundary_inference"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_alternate_scope_verify": {
            "description": "Verify alternate-scope schemas, artifacts, digests, safe paths and chained event logs.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_alternate_scope_verify,
            "tags": _READ_TAGS + ["capability:alternate_scope"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_alternate_scope_resume": {
            "description": "Resume a verified alternate-scope checkpoint; terminal checkpoints execute no new descriptors.",
            "parameters": {"run_path": {"type": "string", "required": True}, "confirmed": {"type": "boolean", "required": True}},
            "function": hex_editor_tools.binary_alternate_scope_resume,
            "tags": _ARTIFACT_TAGS + ["capability:alternate_scope"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_iterative_scope_run": {
            "description": "Run confirmed multi-turn semantic scope composition with lineage, Pareto validation, checkpoints and experimental candidate artifacts.",
            "parameters": {
                "source_path": path,
                "alternative_path": {"type": "string", "required": True, "description": "Allowlisted alternative candidate path."},
                "output_workspace": {"type": "string", "required": True},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_iterative_scope_run,
            "tags": _ARTIFACT_TAGS + ["capability:iterative_scope", "capability:semantic_regression", "capability:mechanical_falsification"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_iterative_scope_inspect": {
            "description": "Read verified multi-turn frontier, semantic lost/gained/retained overlays and run status.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_iterative_scope_inspect,
            "tags": _READ_TAGS + ["capability:iterative_scope", "capability:semantic_regression"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_iterative_scope_verify": {
            "description": "Verify iterative-scope schema, input lineage, safe artifact paths and chained event log.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_iterative_scope_verify,
            "tags": _READ_TAGS + ["capability:iterative_scope"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_local_transform_run": {
            "description": "Run confirmed evidence-driven local transform discovery, record-family aggregation, lineage-safe materialization and semantic validation.",
            "parameters": {
                "source_path": path,
                "parent_path": {"type": "string", "required": True, "description": "Allowlisted parent candidate whose lineage will be composed per materialized span."},
                "output_workspace": {"type": "string", "required": True},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_local_transform_run,
            "tags": _ARTIFACT_TAGS + ["capability:local_transform", "capability:record_family", "capability:semantic_regression"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_local_transform_inspect": {
            "description": "Read a verified local-transform run, record families, frontier and advisory model packet.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_local_transform_inspect,
            "tags": _READ_TAGS + ["capability:local_transform", "capability:record_family"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_local_transform_verify": {
            "description": "Verify local-transform schema, input lineage, safe artifact paths and chained event log.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_local_transform_verify,
            "tags": _READ_TAGS + ["capability:local_transform"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_record_family_run": {
            "description": "Run confirmed repeated-plaintext seed discovery, boundary and holdout proof, reversible family-scoped materialization, Pareto composition, Finding Ledger and parser/coverage handoff.",
            "parameters": {
                "source_path": path,
                "parent_path": {"type": "string", "required": True, "description": "Allowlisted equal-sized parent candidate used for reversible lineage-safe materialization."},
                "output_workspace": {"type": "string", "required": True},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_record_family_run,
            "tags": _ARTIFACT_TAGS + ["capability:record_family", "capability:boundary_inference", "capability:parser_learning", "capability:semantic_regression"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_record_family_inspect": {
            "description": "Read verified record families, training/holdout occurrences, boundary proofs, Pareto frontier and byte overlays.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_record_family_inspect,
            "tags": _READ_TAGS + ["capability:record_family", "capability:boundary_inference"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_record_family_verify": {
            "description": "Verify record-family schemas, source/parent identities, safe artifact paths and chained event log.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_record_family_verify,
            "tags": _READ_TAGS + ["capability:record_family"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_full_decode_run": {
            "description": "Run confirmed coverage-complete decode composition, reversible candidate materialization, strict plaintext extraction and canonical lossless ASCII export.",
            "parameters": {
                "source_path": path,
                "parent_path": {"type": "string", "required": True, "description": "Allowlisted equal-sized parent candidate."},
                "output_workspace": {"type": "string", "required": True},
                "confirmed": {"type": "boolean", "required": True}
            },
            "function": hex_editor_tools.binary_full_decode_run,
            "tags": _ARTIFACT_TAGS + ["capability:full_decode", "capability:record_family", "capability:ascii_export"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_full_decode_inspect": {
            "description": "Read full-decode coverage, proof provider, gates, overlays and ASCII export paths.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_full_decode_inspect,
            "tags": _READ_TAGS + ["capability:full_decode", "capability:ascii_export"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_full_decode_verify": {
            "description": "Verify full-decode schemas, input identities, artifact confinement, event chain and byte-exact ASCII round-trip.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_full_decode_verify,
            "tags": _READ_TAGS + ["capability:full_decode"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_full_decode_resume": {
            "description": "Resume a verified full-decode checkpoint; terminal verified runs execute no duplicate work.",
            "parameters": {"run_path": {"type": "string", "required": True}, "confirmed": {"type": "boolean", "required": True}},
            "function": hex_editor_tools.binary_full_decode_resume,
            "tags": _ARTIFACT_TAGS + ["capability:full_decode"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_unresolved_inference_run": {
            "description": "Run confirmed unresolved-byte ownership, dependency inference and Binary Semantic Graph compilation over a verified full-decode run.",
            "parameters": {"full_decode_run_path": {"type": "string", "required": True}, "output_workspace": {"type": "string", "required": True}, "confirmed": {"type": "boolean", "required": True}},
            "function": hex_editor_tools.binary_unresolved_inference_run,
            "tags": _ARTIFACT_TAGS + ["capability:unresolved_inference", "capability:binary_semantic_graph"],
            "effect": "reversible_mutation", "visibility": "public",
        },
        "binary_unresolved_inference_inspect": {
            "description": "Inspect ownership proofs, coverage, gates, graph summary and overlays from an unresolved-inference run.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_unresolved_inference_inspect,
            "tags": _READ_TAGS + ["capability:unresolved_inference", "capability:binary_semantic_graph"], "effect": "evidence_read", "visibility": "public",
        },
        "binary_unresolved_inference_verify": {
            "description": "Verify unresolved-inference schemas, identities, artifact confinement, event chain and Binary Semantic Graph integrity.",
            "parameters": {"run_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.binary_unresolved_inference_verify,
            "tags": _READ_TAGS + ["capability:unresolved_inference"], "effect": "evidence_read", "visibility": "public",
        },
        "binary_unresolved_inference_resume": {
            "description": "Resume a verified unresolved-inference checkpoint without duplicating terminal work.",
            "parameters": {"run_path": {"type": "string", "required": True}, "confirmed": {"type": "boolean", "required": True}},
            "function": hex_editor_tools.binary_unresolved_inference_resume,
            "tags": _ARTIFACT_TAGS + ["capability:unresolved_inference"], "effect": "reversible_mutation", "visibility": "public",
        },
        "binary_semantic_graph_query": {
            "description": "Run a bounded deterministic offset or relationship query over a verified Binary Semantic Graph artifact.",
            "parameters": {"graph_path": {"type": "string", "required": True}, "operation": {"type": "string", "required": True}, "node_id": {"type": "string", "required": False}, "offset": {"type": "integer", "required": False, "default": -1}, "maximum_depth": {"type": "integer", "required": False, "default": 1}, "maximum_results": {"type": "integer", "required": False, "default": 4096}},
            "function": hex_editor_tools.binary_semantic_graph_query,
            "tags": _READ_TAGS + ["capability:binary_semantic_graph"], "effect": "evidence_read", "visibility": "public",
        },
        "binary_candidate_lineage_resolve": {
            "description": "Resolve verified candidate lineage across full-decode, unresolved-inference, record-family and materialization rails for a file identity.",
            "parameters": {"source_sha256": {"type": "string", "required": False}, "file_path": {"type": "string", "required": False}},
            "function": hex_editor_tools.binary_candidate_lineage_resolve,
            "tags": _READ_TAGS + ["capability:candidate_lineage"], "effect": "evidence_read", "visibility": "public",
        },
        "binary_candidate_lineage_verify": {
            "description": "Verify cross-rail hash consistency and upstream linkage for a resolved candidate lineage packet.",
            "parameters": {"source_sha256": {"type": "string", "required": False}, "file_path": {"type": "string", "required": False}},
            "function": hex_editor_tools.binary_candidate_lineage_verify,
            "tags": _READ_TAGS + ["capability:candidate_lineage"], "effect": "evidence_read", "visibility": "public",
        },
        "binary_search": {
            "description": "Search an allowlisted binary for hex, UTF-8, or ASCII bytes.",
            "parameters": {
                "path": path,
                "query": {"type": "string", "required": True},
                "encoding": {"type": "string", "required": False, "default": "hex"},
                "max_matches": {"type": "integer", "required": False, "default": 200},
            },
            "function": hex_editor_tools.binary_search,
            "tags": _READ_TAGS,
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_analyze": {
            "description": "Analyze a PTX file read-only; inferred structures are labeled heuristic.",
            "parameters": {"path": path},
            "function": hex_editor_tools.ptx_analyze,
            "tags": _READ_TAGS + ["capability:ptx_analysis"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "pe_analyze": {
            "description": "Analyze a PE (.exe/.dll) read-only via pefile; labels stay heuristic.",
            "parameters": {"path": path},
            "function": hex_editor_tools.pe_analyze,
            "tags": _READ_TAGS + ["capability:pe_analysis"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "disasm_readonly": {
            "description": "Bounded Capstone disassembly at PE entry point (read-only).",
            "parameters": {
                "path": path,
                "max_instructions": {"type": "integer", "required": False, "default": 96},
            },
            "function": hex_editor_tools.disasm_readonly,
            "tags": _READ_TAGS + ["capability:pe_disasm"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_probe_decrypt_keys": {
            "description": "Bounded read-only XOR key probe for PTX — returns key candidates until keys_found.",
            "parameters": {
                "path": path,
                "sample_offset": {"type": "integer", "required": False, "default": 16},
                "sample_length": {"type": "integer", "required": False, "default": 4096},
                "key_cursor": {"type": "integer", "required": False, "default": 0},
                "key_batch": {"type": "integer", "required": False, "default": 32},
                "include_known": {"type": "boolean", "required": False, "default": True},
                "materialize_confirmed": {"type": "boolean", "required": False, "default": False},
            },
            "function": hex_editor_tools.ptx_probe_decrypt_keys,
            "tags": _READ_TAGS + ["capability:ptx_key_probe"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_runtime_analyze": {
            "description": "Build an immutable provenance-linked PTX runtime snapshot.",
            "parameters": {"path": path},
            "function": hex_editor_tools.ptx_runtime_analyze,
            "tags": _READ_TAGS + ["capability:ptx_runtime_analysis"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_dynamic_key_hunt": {
            "description": "Run a policy-budgeted mechanical PTX key hunt; model hypotheses are advisory only.",
            "parameters": {"path": path, "checkpoint_path": {"type": "string", "required": False}},
            "function": hex_editor_tools.ptx_dynamic_key_hunt,
            "tags": _READ_TAGS + ["capability:ptx_dynamic_key_hunt"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_runtime_diff": {
            "description": "Compare two PTX files at raw, parsed, and runtime graph levels.",
            "parameters": {"left_path": path, "right_path": path},
            "function": hex_editor_tools.ptx_runtime_diff,
            "tags": _READ_TAGS + ["capability:ptx_runtime_diff"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_full_coverage_analyze": {
            "description": "Build a policy-driven PTX snapshot with complete byte coverage, anchors, record families, and unknown-region features.",
            "parameters": {"path": path},
            "function": hex_editor_tools.ptx_full_coverage_analyze,
            "tags": _READ_TAGS + ["capability:ptx_runtime_analysis", "capability:binary_full_coverage"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_unknown_region_inspect": {
            "description": "Inspect one content-addressed unknown PTX region from the current full-coverage snapshot.",
            "parameters": {
                "path": path,
                "region_id": {"type": "string", "required": True},
                "workspace_path": {"type": "string", "required": False},
            },
            "function": hex_editor_tools.ptx_unknown_region_inspect,
            "tags": _READ_TAGS + ["capability:binary_full_coverage"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_structural_experiment_diff": {
            "description": "Compare a compatible PTX baseline/variant using a one-change experiment manifest; inferred fields remain candidates.",
            "parameters": {"left_path": path, "right_path": path, "manifest_path": {"type": "string", "required": True}},
            "function": hex_editor_tools.ptx_structural_experiment_diff,
            "tags": _READ_TAGS + ["capability:ptx_runtime_diff", "capability:binary_full_coverage"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "ptx_unpack_runtime": {
            "description": "Export a deterministic provenance-preserving PTX runtime workspace.",
            "parameters": {"path": path, "confirmed": {"type": "boolean", "required": True}},
            "function": hex_editor_tools.ptx_unpack_runtime,
            "tags": _ARTIFACT_TAGS + ["capability:ptx_runtime_analysis"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_pseudocode_region_map": {
            "description": "Return the coalesced region-routed pseudocode map for an allowlisted binary.",
            "parameters": {"path": path},
            "function": hex_editor_tools.binary_pseudocode_region_map,
            "tags": _READ_TAGS + ["capability:pseudocode_routing"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_pseudocode_render": {
            "description": "Render region-routed pseudocode artifacts (region map, text, coalescence audit) under artifact_root.",
            "parameters": {
                "path": path,
                "output_root": {"type": "string", "required": False, "default": ""},
            },
            "function": hex_editor_tools.binary_pseudocode_render,
            "tags": _READ_TAGS + ["capability:pseudocode_routing", "capability:artifact_export"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_pseudocode_offset_for_line": {
            "description": "Map a pseudocode line number to a source byte offset using the region-routed source map.",
            "parameters": {
                "path": path,
                "line_number": {"type": "integer", "required": True},
            },
            "function": hex_editor_tools.binary_pseudocode_offset_for_line,
            "tags": _READ_TAGS + ["capability:pseudocode_routing"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_pseudocode_range_for_selection": {
            "description": "Map a pseudocode line selection to disjoint file byte ranges and an anchor offset for scrolling.",
            "parameters": {
                "path": path,
                "start_line": {"type": "integer", "required": True},
                "end_line": {"type": "integer", "required": False, "default": 0},
            },
            "function": hex_editor_tools.binary_pseudocode_range_for_selection,
            "tags": _READ_TAGS + ["capability:pseudocode_routing"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_snapshot_parse": {
            "description": "Build a bounded immutable BinarySnapshot for PTX or PE without launching a target.",
            "parameters": {"path": path},
            "function": hex_editor_tools.binary_snapshot_parse,
            "tags": _READ_TAGS + ["capability:binary_runtime_analysis"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_snapshot_diff": {
            "description": "Compare compatible BinarySnapshots using exact or structurally aligned Waterfall lanes; incompatible layouts are blocked.",
            "parameters": {"left_path": path, "right_path": path},
            "function": hex_editor_tools.binary_snapshot_diff,
            "tags": _READ_TAGS + ["capability:binary_runtime_diff"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "binary_unpack_workspace": {
            "description": "Export a confirmed deterministic PTX/PE BinarySnapshot workspace.",
            "parameters": {
                "path": path,
                "confirmed": {"type": "boolean", "required": True},
                "include_representation_sweep": {
                    "type": "boolean",
                    "required": False,
                    "default": False,
                    "description": "When true, run representation brief sweeps for unknown regions during export.",
                },
            },
            "function": hex_editor_tools.binary_unpack_workspace,
            "tags": _ARTIFACT_TAGS + ["capability:binary_runtime_analysis"],
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_workspace_verify_integrity": {
            "description": "Verify manifest integrity for an exported binary workspace directory.",
            "parameters": {
                "workspace_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to exported binary-unpack workspace root.",
                }
            },
            "function": hex_editor_tools.binary_workspace_verify_integrity,
            "tags": _READ_TAGS + ["capability:binary_runtime_analysis"],
            "effect": "evidence_read",
            "visibility": "private",
            "owner_agent": "hex_editor_integration",
        },
        "pe_execution_preflight": {
            "description": "Resolve configured PE execution policy and backend without launching the target.",
            "parameters": {"path": path, "mode": {"type": "string", "required": False}},
            "function": hex_editor_tools.pe_execution_preflight,
            "tags": _READ_TAGS + ["capability:pe_execution_preflight"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "pe_execution_run": {
            "description": "Run a PE only after explicit confirmation using the configured execution backend and limits.",
            "parameters": {"path": path, "confirmed": {"type": "boolean", "required": True}, "mode": {"type": "string", "required": False}},
            "function": hex_editor_tools.pe_execution_run,
            "tags": ["hex", "binary", "capability:pe_dynamic_execution", "effect:irreversible_external"],
            "effect": "irreversible_external",
            "visibility": "private",
            "owner_agent": "hex_editor_integration",
        },
        "pe_execution_get_trace": {
            "description": "Read bounded runtime trace from saved execution artifact (no relaunch).",
            "parameters": {
                "runtime_snapshot_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to runtime_snapshot.json from a prior confirmed execution.",
                }
            },
            "function": hex_editor_tools.pe_execution_get_trace,
            "tags": _READ_TAGS + ["capability:pe_dynamic_execution"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "pe_execution_merge_view": {
            "description": "Merge static PE graph with saved runtime artifact (read-only).",
            "parameters": {
                "path": path,
                "runtime_snapshot_path": {"type": "string", "required": True},
            },
            "function": hex_editor_tools.pe_execution_merge_view,
            "tags": _READ_TAGS + ["capability:pe_dynamic_execution"],
            "effect": "evidence_read",
            "visibility": "public",
        },
        "export_binary_analysis": {
            "description": "Create a managed analysis artifact in the Lab artifact store.",
            "parameters": {
                "path": path,
                "confirmed": {"type": "boolean", "required": True},
            },
            "function": hex_editor_tools.export_binary_analysis,
            "tags": _ARTIFACT_TAGS,
            "effect": "reversible_mutation",
            "visibility": "private",
            "owner_agent": "hex_editor_integration",
        },
        "extract_ptx_artifacts": {
            "description": "Extract bounded PTX sections into a managed artifact directory.",
            "parameters": {
                "path": path,
                "confirmed": {"type": "boolean", "required": True},
            },
            "function": hex_editor_tools.extract_ptx_artifacts,
            "tags": _ARTIFACT_TAGS + ["capability:ptx_analysis"],
            "effect": "reversible_mutation",
            "visibility": "private",
            "owner_agent": "hex_editor_integration",
        },
        "binary_patch_range": {
            "description": "Apply a fixed-size in-place binary patch at an offset (maximum 1 MiB).",
            "parameters": {
                "path": path,
                "offset": {"type": "integer", "required": True},
                "data_hex": {
                    "type": "string",
                    "required": True,
                    "description": "Even-length hex string; patch length must not change file size.",
                },
                "confirmed": {"type": "boolean", "required": True},
            },
            "function": hex_editor_tools.binary_patch_range,
            "tags": _WRITE_TAGS,
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "binary_write_file": {
            "description": "Create or replace an allowlisted binary file from hex bytes (maximum 50 MiB).",
            "parameters": {
                "path": path,
                "data_hex": {
                    "type": "string",
                    "required": True,
                    "description": "Even-length hex string for the full file payload.",
                },
                "confirmed": {"type": "boolean", "required": True},
            },
            "function": hex_editor_tools.binary_write_file,
            "tags": _WRITE_TAGS,
            "effect": "reversible_mutation",
            "visibility": "public",
        },
        "hex_editor_open_desktop": {
            "description": "Launch the desktop Hex Editor GUI and optionally open an allowlisted file live.",
            "parameters": {
                "path": {
                    "type": "string",
                    "required": False,
                    "description": "Optional allowlisted file to open in the desktop editor.",
                },
                "turn_id": {"type": "string", "required": False},
            },
            "function": hex_editor_tools.hex_editor_open_desktop,
            "tags": [
                "hex",
                "binary",
                "capability:desktop_launch",
                "capability:binary_inspection",
                "effect:irreversible_external",
            ],
            "effect": "irreversible_external",
            "visibility": "public",
        },
        "hex_editor_desktop_status": {
            "description": "Report whether the desktop Hex Editor is running and which file is open.",
            "parameters": {},
            "function": hex_editor_tools.hex_editor_desktop_status,
            "tags": [
                "hex",
                "binary",
                "capability:desktop_launch",
                "effect:evidence_read",
            ],
            "effect": "evidence_read",
            "visibility": "public",
        },
    }


def register_hex_editor_tools(tool_registry) -> int:
    registered = 0
    for name, definition in _definitions().items():
        result = tool_registry.register_tool(
            name=name,
            description=definition["description"],
            module_path="hexeditor_tools.api",
            function_name=name,
            parameters=definition["parameters"],
            return_type="Dict[str, Any]",
            author="hex_editor_integration",
            tags=definition["tags"],
            version="1.0.0",
            function_obj=definition["function"],
            visibility=definition.get("visibility", "public"),
            owner_agent=definition.get("owner_agent"),
            agent_id="hex_editor_integration",
            purpose="Bounded binary inspection through the application-owned workspace allowlist.",
            timestamp=datetime.now(timezone.utc).isoformat(),
            effect=definition.get("effect", "unknown"),
            result_kind="artifact_mutation" if definition.get("effect") == "reversible_mutation" else "tool_evidence",
        )
        if result.get("success"):
            registered += 1
        else:
            logger.warning("Failed to register %s: %s", name, result.get("message"))
    return registered
