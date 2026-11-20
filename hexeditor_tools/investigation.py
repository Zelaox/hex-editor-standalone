"""Local evidence-based investigation breakdown; no external controller authority."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
from hexeditor_tools.evidence import EPISTEMIC_RULES, compile_epistemic_state_from_binary_info, compile_epistemic_state_from_ptx_analysis, session_handoff_epistemic_template

SCOPE_ID = 'hex_investigation_readonly'

LEGACY_SCOPE_ID = 'binary_investigation_readonly'

PIPELINE_ID = 'hex_investigation_tools'

_PE_SUFFIXES = {'.exe', '.dll', '.sys', '.scr'}

_BARE_INVESTIGATION_FILE_RE = re.compile('\\b[\\w.-]+\\.(?:ptx|exe|dll|sys|scr|bin|dat|raw|hex)\\b', re.I)

def _finding_value(analysis: Mapping[str, Any], label: str) -> Any:
    for finding in analysis.get('findings') or []:
        if str(finding.get('label') or finding.get('kind') or '') == label:
            return finding.get('value')
    return None

def compile_investigation_breakdown(analysis: Mapping[str, Any], path: str, *, user_message: str='', operation: str='analyze_readonly') -> Dict[str, Any]:
    """
    Compile milestone breakdown from analyzer output — SSOT for hex investigation scope.

    Runner, verifier, chat prompt, and session handoff all read this structure.
    """
    suffix = Path(path).suffix.lower()
    is_ptx_plugin = suffix == '.ptx'
    is_pe_plugin = suffix in _PE_SUFFIXES
    checks = _finding_value(analysis, 'consistency_checks') or []
    check_codes = {str(item.get('code') or '') for item in checks if isinstance(item, dict)}
    wants_plan = _looks_like_plan_request(user_message)
    wants_decrypt_keys = is_ptx_plugin and _looks_like_decrypt_key_hunt(user_message)
    wants_full_coverage = is_ptx_plugin and _looks_like_full_coverage(user_message, analysis)
    milestones: List[Dict[str, Any]] = [{'id': 'M1', 'title': 'Establish verified baseline (size, SHA256, prefix bytes)', 'status': 'ready', 'operation': 'inspect_readonly', 'blocking_verify_tokens': ['structured_result'], 'advisory_verify_tokens': ['verified_facts_populated'], 'notes': 'Populate verified_facts only from binary_file_info — no format claims.'}, {'id': 'M2', 'title': 'Targeted byte read at claimed offset', 'status': 'pending', 'operation': 'read_range', 'blocking_verify_tokens': ['bounded_read', 'byte_evidence_present'], 'advisory_verify_tokens': ['read_within_bounds'], 'notes': 'Use binary_read_range; add hex windows to verified_facts.'}, {'id': 'M3', 'title': 'Pattern / magic search with bounded matches', 'status': 'pending', 'operation': 'search_bytes', 'blocking_verify_tokens': ['match_list_bounded'], 'advisory_verify_tokens': [], 'notes': 'Match offsets go to verified_facts; meaning stays in model_hypotheses.'}]
    if is_ptx_plugin:
        from src.services.ptx_crypto_config import resolve_crypto_case as resolve_calibration_case
        source = dict(analysis.get('source') or {})
        has_calibration = resolve_calibration_case(path, sha256=str(source.get('sha256') or ''), file_size=int(source.get('size') or 0)) is not None
        m4_blocking = ['byte_evidence_present']
        if has_calibration:
            m4_blocking.append('ptx_parser_calibrated')
        milestones.extend([{'id': 'M4', 'title': 'PTX plugin: run ptx_analyze — parser output → model_hypotheses only', 'status': 'ready' if analysis.get('ok') else 'pending', 'operation': 'ptx_analyze', 'plugin': 'ptx', 'blocking_verify_tokens': m4_blocking, 'advisory_verify_tokens': ['encryption_claim_calibrated'], 'notes': 'encryption_type, encrypted=true, sections, timecodes → model_hypotheses with confidence low/heuristic — never verified_facts.'}, {'id': 'M5', 'title': 'PTX plugin: reconcile parser fields against byte evidence', 'status': 'ready' if check_codes else 'pending', 'operation': 'read_range', 'plugin': 'ptx', 'blocking_verify_tokens': [], 'advisory_verify_tokens': ['header_hypothesis_consistent', 'timecode_hypothesis_consistent'], 'notes': 'If header.size ≠ file size, report misaligned decode — not corruption.'}])
        if wants_decrypt_keys:
            milestones.extend([{'id': 'M7', 'title': 'PTX decrypt: probe XOR key candidates (read-only)', 'status': 'pending', 'operation': 'ptx_probe_decrypt_keys', 'plugin': 'ptx', 'blocking_verify_tokens': ['structured_result', 'transform_evidence_present', 'promote_allowed_true', 'decrypt_candidate_promoted', 'artifact_sha_changed'], 'advisory_verify_tokens': ['keys_found_or_continue'], 'notes': 'Call ptx_probe_decrypt_keys until promotion gate passes or sweep exhausted.'}, {'id': 'M8', 'title': 'PTX decrypt: validate key on second sample window', 'status': 'pending', 'operation': 'ptx_probe_decrypt_keys', 'plugin': 'ptx', 'blocking_verify_tokens': ['structured_result', 'transform_evidence_present', 'cross_window_validation', 'artifact_sha_matches_reference_or_structural'], 'advisory_verify_tokens': [], 'notes': 'Re-probe with fixture m8_probe_window; identity artifact must fail.'}, {'id': 'M9', 'title': 'PTX decrypt: stop condition — promoted key or exhausted sweep', 'status': 'pending', 'operation': 'ptx_probe_decrypt_keys', 'plugin': 'ptx', 'blocking_verify_tokens': ['decrypt_hunt_complete'], 'advisory_verify_tokens': [], 'notes': 'Do not end investigation while promotion gate fails and sweep has cursor headroom.'}])
    elif is_pe_plugin:
        milestones.extend([{'id': 'M4', 'title': 'PE plugin: run pe_analyze — pefile labels → model_hypotheses only', 'status': 'ready' if analysis.get('ok') else 'pending', 'operation': 'pe_analyze', 'plugin': 'pe', 'blocking_verify_tokens': ['byte_evidence_present'], 'advisory_verify_tokens': [], 'notes': 'Sections, imports, exports, entry RVA → hypotheses until byte-backed.'}, {'id': 'M5', 'title': 'PE plugin: bounded entry disassembly (Capstone)', 'status': 'pending', 'operation': 'disasm_readonly', 'plugin': 'pe', 'blocking_verify_tokens': ['structured_result'], 'advisory_verify_tokens': [], 'notes': 'Instructions at entry RVA are verified observations; meaning stays hypothetical.'}])
    else:
        milestones.append({'id': 'M4', 'title': 'Form format hypothesis from bytes (no plugin)', 'status': 'pending', 'operation': 'read_range', 'blocking_verify_tokens': [], 'advisory_verify_tokens': ['format_hypothesis_stated'], 'notes': 'Optional future plugins (PE, etc.) attach here — not hardcoded slugs.'})
    milestones.append({'id': 'M6', 'title': 'Next concrete byte-level action', 'status': 'pending', 'operation': operation, 'blocking_verify_tokens': [], 'advisory_verify_tokens': ['next_step_actionable'], 'notes': 'End each turn with {operation, offset, length|query} for the following turn.'})
    if wants_full_coverage:
        milestones.extend([{'id': 'M10', 'title': 'Full coverage: inspect one unknown region (bounded)', 'status': 'pending', 'operation': 'ptx_unknown_region_inspect', 'plugin': 'ptx', 'blocking_verify_tokens': ['structured_result'], 'advisory_verify_tokens': [], 'notes': 'One unknown region per turn; cursor persisted in checkpoint.'}, {'id': 'M11', 'title': 'Full coverage: structural experiment diff summary', 'status': 'pending', 'operation': 'ptx_structural_experiment_diff', 'plugin': 'ptx', 'blocking_verify_tokens': ['structured_result'], 'advisory_verify_tokens': [], 'notes': 'Experiment ledger delta only — skip when no experiment manifest exists.'}, {'id': 'M12', 'title': 'Representation: mechanically falsify region hypotheses', 'status': 'pending', 'operation': 'binary_representation_falsify', 'plugin': 'ptx', 'blocking_verify_tokens': ['structured_result'], 'advisory_verify_tokens': [], 'notes': 'Consumes the cached/on-demand RepresentationBrief. Outcomes are supported, falsified, or inconclusive; promotion remains disabled.'}])
    epistemic_state = _compile_epistemic_state(analysis, path)
    source = dict(analysis.get('source') or {})
    decrypt_state = {}
    if wants_decrypt_keys:
        from hexeditor_tools.key_hunt import build_decrypt_hunt_contract_state
        decrypt_state = build_decrypt_hunt_contract_state(None, goal_text=user_message)
    breakdown = {'schema_version': 1, 'contract_revision': 3, 'scope_id': SCOPE_ID, 'scope_kind': 'hex_investigation', 'legacy_scope_id': LEGACY_SCOPE_ID, 'target_path': str(path), 'target_sha256': str(source.get('sha256') or ''), 'target_suffix': suffix.lstrip('.'), 'engine': 'hex_editor_operation_contract', 'format_plugin': 'ptx' if is_ptx_plugin else 'pe' if is_pe_plugin else None, 'milestones': milestones, 'required_verify_tokens': ['structured_result', 'byte_evidence_present'], 'semantic_verify_tokens': ['verified_facts_populated', 'encryption_claim_calibrated', 'parser_claim_not_in_verified_facts'], 'epistemic_state': epistemic_state, 'session_handoff_template': {**session_handoff_epistemic_template(), 'current_milestone': 'M1', 'verified_facts': epistemic_state.get('verified_facts') or [], 'model_hypotheses': epistemic_state.get('model_hypotheses') or []}, 'model_directive': _model_directive(wants_plan=wants_plan, wants_decrypt_keys=wants_decrypt_keys), 'consistency_summary': [str(item.get('message') or '') for item in checks if isinstance(item, dict) and item.get('message')][:8]}
    if decrypt_state:
        breakdown['decrypt_key_hunt'] = decrypt_state
    return breakdown

def _compile_epistemic_state(analysis: Mapping[str, Any], path: str) -> Dict[str, Any]:
    suffix = Path(path).suffix.lower()
    byte_evidence = _finding_value(analysis, 'byte_evidence') or []
    if suffix == '.ptx' and analysis.get('ok'):
        return compile_epistemic_state_from_ptx_analysis(analysis, byte_evidence=byte_evidence)
    if suffix in _PE_SUFFIXES and analysis.get('ok') and (str(analysis.get('operation') or '') in {'pe_analyze', 'disasm_readonly'}):
        if str(analysis.get('operation') or '') == 'disasm_readonly':
            from hexeditor_tools.evidence import compile_epistemic_state_from_disasm
            return compile_epistemic_state_from_disasm(analysis)
        from hexeditor_tools.evidence import compile_epistemic_state_from_pe_analysis
        return compile_epistemic_state_from_pe_analysis(analysis, byte_evidence=byte_evidence)
    if analysis.get('operation') == 'binary_file_info' or analysis.get('prefix_hex') is not None:
        return compile_epistemic_state_from_binary_info(analysis)
    source = analysis.get('source') or {}
    if source:
        return compile_epistemic_state_from_binary_info({'ok': True, 'source': source, 'prefix_hex': analysis.get('prefix_hex')})
    return compile_epistemic_state_from_binary_info({'ok': True, 'source': {}})

def _looks_like_decrypt_key_hunt(text: str) -> bool:
    try:
        from hexeditor_tools.key_hunt import looks_like_decrypt_key_hunt_goal
        return looks_like_decrypt_key_hunt_goal(text)
    except Exception:
        return False

def _looks_like_plan_request(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    markers = ('plan', 'breakdown', 'milestones', 'next step', 'work auto', 'automate', 'how do we crack', 'how do we decrypt', 'gör en plan', 'planera', 'nästa steg')
    return any((marker in low for marker in markers))

def _looks_like_full_coverage(text: str, analysis: Mapping[str, Any]) -> bool:
    if not text and (not analysis):
        return False
    low = (text or '').lower()
    markers = ('full coverage', 'full-coverage', 'unpack workspace', 'workspace export', 'binary-unpack', 'full_coverage')
    if any((marker in low for marker in markers)):
        return True
    if analysis.get('full_coverage') is True:
        return True
    summary = dict(analysis.get('coverage_summary') or {})
    return bool(summary.get('coverage_complete'))

def _model_directive(*, wants_plan: bool, wants_decrypt_keys: bool=False) -> str:
    lines = ['You are investigating a binary file using the hex engine (read/search/patch) plus optional format plugins.', '', 'Hard epistemic rules:', f'- {EPISTEMIC_RULES}', '- verified_facts: bytes_at + value + source (e.g. bytes 0x10-0x13 = a5 b3 c2 1d).', '- model_hypotheses: interpreted_as + confidence (e.g. encryption_type field, confidence: low).', '- NEVER write encrypted=true to verified_facts because a parser said so.', '- NEVER claim corruption from regex timecodes without byte-backed reasoning.', '- PTX parser JSON is a hypothesis surface — not proof.', '', 'Keep going across turns: end with one concrete {operation, offset, length|query}.']
    if wants_decrypt_keys:
        lines.extend(['', 'Decrypt key hunt (mandatory until complete):', '- Use ptx_probe_decrypt_keys repeatedly until keys_found=true.', '- If keys_found=false, follow recommended_next.key_cursor on the next tool call.', '- When keys_found=true, paste the auto-decrypted markdown link from chat_ui_links in your reply.', '- Report key_hex only in model_hypotheses until validated on a second window.', '- Do NOT stop after ptx_analyze alone — the hunt is incomplete without keys_found.'])
    if wants_plan:
        lines.append('The user asked for a plan: respond with the milestone breakdown, then analyze M1 using verified_facts vs model_hypotheses sections.')
    else:
        lines.append('Summarize verified_facts and model_hypotheses separately, then advance one milestone.')
    return '\n'.join(lines)

def apply_completed_milestones(breakdown: Mapping[str, Any], completed: Sequence[str]) -> Dict[str, Any]:
    """Mark milestones done after runner executes mechanical steps."""
    done = {str(item) for item in completed}
    updated = dict(breakdown)
    milestones = []
    for milestone in breakdown.get('milestones') or []:
        if not isinstance(milestone, dict):
            milestones.append(milestone)
            continue
        item = dict(milestone)
        mid = str(item.get('id') or '')
        if mid in done:
            item['status'] = 'done'
        elif item.get('status') == 'ready' and mid not in done:
            item['status'] = 'ready'
        milestones.append(item)
    updated['milestones'] = milestones
    return updated
