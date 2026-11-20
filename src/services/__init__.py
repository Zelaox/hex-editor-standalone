"""GUI-independent Hex Editor services."""

from .binary_inspection import binary_file_info, binary_read_range, binary_search
from .binary_operations import binary_patch_range, binary_write_file
from .binary_runtime import analyze_binary_snapshot, binary_waterfall_payload
from .binary_snapshot_diff import diff_binary_snapshots
from .binary_compatibility import assess_snapshot_compatibility, load_binary_diff_policy
from .binary_workspace import export_binary_workspace, load_binary_workspace
from .disasm_analysis import disasm_pe_entry
from .pe_analysis import analyze_pe
from .ptx_analysis import analyze_ptx
from .ptx_key_discovery import probe_ptx_decrypt_keys
from .ptx_artifacts import export_analysis, extract_ptx_sections
from .ptx_dynamic_key_hunt import load_key_hunt_policy, run_dynamic_key_hunt
from .ptx_desktop_decrypt import decrypt_ptx_with_verified_probe
from .ptx_runtime_analysis import analyze_ptx_runtime
from .ptx_session_diff import diff_snapshots
from .ptx_workspace import export_runtime_workspace, load_runtime_workspace
from .text_encoding import analyze_bytes, binary_decode_range
from .representation_registry import load_representation_policy, load_representation_bundle
from .binary_representation import convert_representation
from .binary_decoders import run_decoder_candidates
from .value_interpreter import interpret_candidates
from .representation_sweep import sweep_region, sweep_region_features, write_representation_brief_cache, load_representation_brief_cache
from .representation_falsification import falsify_representation_brief, load_falsification_policy
from .representation_workspace import sweep_unknown_regions_in_workspace
from .plaintext_profiles import build_plaintext_profile, load_plaintext_profile_library, score_plaintext_profiles, update_plaintext_profile_library
from .ptx_full_coverage import load_full_coverage_policy
from .ptx_experiment_ledger import load_experiment_manifest, structural_experiment_diff
from .parser_learning import build_gemma_packet, load_parser_learning_bundle, promote_profile_transaction, run_parser_learning, validate_candidates, validate_gemma_actions
from .transform_scope import load_scope_bundle, resume_transform_scope_proof, run_transform_scope_proof, verify_scope_run
from .alternate_scope import build_alternate_scope_model_packet, inspect_alternate_scope_run, load_alternate_scope_bundle, materialize_gemma_scope_candidate, resume_alternate_scope_run, run_alternate_scope_proof, validate_model_actions, verify_alternate_scope_run
from .record_family import build_record_family_model_packet, inspect_record_family_run, run_record_family_e2e, validate_record_family_model_action, verify_record_family_run
from .full_decode import build_full_decode_model_packet, decode_lossless_ascii, encode_lossless_ascii, inspect_full_decode_run, resume_full_decode_run, run_full_decode_e2e, validate_full_decode_model_action, verify_full_decode_run
from .unresolved_inference import build_unresolved_model_packet, inspect_unresolved_inference_run, query_binary_semantic_graph, resume_unresolved_inference_run, run_unresolved_inference_e2e, validate_unresolved_model_action, verify_unresolved_inference_run
from .preserved_binary_inference import (
    build_preserved_model_packet,
    inspect_preserved_binary_inference_run,
    run_preserved_binary_inference_e2e,
    validate_preserved_model_action,
    verify_preserved_binary_inference_run,
)
from .candidate_lineage import (
    candidate_graph_impact,
    resolve_candidate_lineage,
    verify_candidate_lineage_chain,
)
from .learning_db import (
    ensure_learning_db_schema,
    inspect_learning_db,
    load_learning_db_bundle,
    query_candidates_for_source,
    query_learning_db,
    query_runs_for_source,
    sync_learning_db,
)

__all__ = [
    "binary_file_info",
    "binary_read_range",
    "binary_search",
    "binary_patch_range",
    "binary_write_file",
    "analyze_pe",
    "disasm_pe_entry",
    "analyze_ptx",
    "probe_ptx_decrypt_keys",
    "export_analysis",
    "extract_ptx_sections",
    "analyze_ptx_runtime",
    "analyze_binary_snapshot",
    "binary_waterfall_payload",
    "load_key_hunt_policy",
    "run_dynamic_key_hunt",
    "decrypt_ptx_with_verified_probe",
    "diff_snapshots",
    "diff_binary_snapshots",
    "assess_snapshot_compatibility",
    "load_binary_diff_policy",
    "export_runtime_workspace",
    "load_runtime_workspace",
    "export_binary_workspace",
    "load_binary_workspace",
    "analyze_bytes",
    "binary_decode_range",
    "load_representation_policy",
    "load_representation_bundle",
    "convert_representation",
    "run_decoder_candidates",
    "interpret_candidates",
    "sweep_region",
    "sweep_region_features",
    "write_representation_brief_cache",
    "load_representation_brief_cache",
    "falsify_representation_brief",
    "load_falsification_policy",
    "sweep_unknown_regions_in_workspace",
    "build_plaintext_profile",
    "load_plaintext_profile_library",
    "score_plaintext_profiles",
    "update_plaintext_profile_library",
    "load_full_coverage_policy",
    "load_experiment_manifest",
    "structural_experiment_diff",
    "build_gemma_packet",
    "load_parser_learning_bundle",
    "promote_profile_transaction",
    "run_parser_learning",
    "validate_candidates",
    "validate_gemma_actions",
    "load_scope_bundle",
    "run_transform_scope_proof",
    "verify_scope_run",
    "resume_transform_scope_proof",
    "load_alternate_scope_bundle",
    "run_alternate_scope_proof",
    "inspect_alternate_scope_run",
    "verify_alternate_scope_run",
    "resume_alternate_scope_run",
    "validate_model_actions",
    "build_alternate_scope_model_packet",
    "materialize_gemma_scope_candidate",
    "run_record_family_e2e",
    "inspect_record_family_run",
    "verify_record_family_run",
    "build_record_family_model_packet",
    "validate_record_family_model_action",
    "run_full_decode_e2e",
    "inspect_full_decode_run",
    "verify_full_decode_run",
    "resume_full_decode_run",
    "build_full_decode_model_packet",
    "validate_full_decode_model_action",
    "encode_lossless_ascii",
    "decode_lossless_ascii",
    "run_unresolved_inference_e2e",
    "inspect_unresolved_inference_run",
    "verify_unresolved_inference_run",
    "resume_unresolved_inference_run",
    "query_binary_semantic_graph",
    "build_unresolved_model_packet",
    "validate_unresolved_model_action",
    "run_preserved_binary_inference_e2e",
    "inspect_preserved_binary_inference_run",
    "verify_preserved_binary_inference_run",
    "build_preserved_model_packet",
    "validate_preserved_model_action",
    "resolve_candidate_lineage",
    "verify_candidate_lineage_chain",
    "candidate_graph_impact",
    "ensure_learning_db_schema",
    "inspect_learning_db",
    "load_learning_db_bundle",
    "query_candidates_for_source",
    "query_learning_db",
    "query_runs_for_source",
    "sync_learning_db",
]
