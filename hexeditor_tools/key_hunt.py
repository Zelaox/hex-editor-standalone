"""Application-owned probe state, with no shared chat or dataset state."""
from __future__ import annotations
import json, logging, re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from src.project import project_root

_DECRYPT_GOAL_RE = re.compile('\\b(?:decrypt|decryption|dekryptera|nyckel|key|crack|kracka|hitta\\s+(?:nyckeln|nycklar|dekrypteringsnyckel\\w*)|find\\s+(?:the\\s+)?(?:decrypt(?:ion)?\\s+)?key)\\b', re.I)

logger = logging.getLogger(__name__)

_LAB_ROOT = project_root()

_FIXTURE_PATH = _LAB_ROOT / 'config' / 'crypto_cases.json'

def looks_like_decrypt_key_hunt_goal(text: str) -> bool:
    if not text or not text.strip():
        return False
    return bool(_DECRYPT_GOAL_RE.search(text))

DEFAULT_TURNS = 40

def _hex_editor_root() -> Path:
    return _LAB_ROOT

def _import_probe_phase_config():
    import sys
    hex_root = _hex_editor_root()
    if str(hex_root) not in sys.path:
        sys.path.insert(0, str(hex_root))
    from src.services.probe_phase_config import initial_probe_phase, milestone_probe_params, next_probe_phase
    return (initial_probe_phase, milestone_probe_params, next_probe_phase)

def new_hunt_state(*, target_path: str, goal_text: str, turn_id: str='') -> Dict[str, Any]:
    try:
        initial_probe_phase, _, _ = _import_probe_phase_config()
        first_phase = initial_probe_phase()
    except Exception:
        first_phase = 'xor_l2_sweep'
    return {'target_path': str(target_path), 'goal_text': str(goal_text), 'established_turn_id': str(turn_id or ''), 'turns_remaining': DEFAULT_TURNS, 'keys_found': False, 'best_key_hex': '', 'last_key_cursor': 0, 'phase': 'probe', 'probe_phase_id': first_phase, 'phases_completed': [], 'promotion_evidence': {}}

def apply_probe_to_hunt(hunt: Dict[str, Any], probe_result: Mapping[str, Any]) -> Dict[str, Any]:
    updated = dict(hunt)
    probe_phase_before = str(updated.get('probe_phase_id') or '')
    cursor_before = int(updated.get('last_key_cursor') or 0)
    phases_before = list(updated.get('phases_completed') or [])
    promotion = dict(probe_result.get('promotion_evidence') or {})
    transform_evidence = dict(probe_result.get('transform_evidence') or promotion.get('transform_evidence') or {})
    promoted = bool(probe_result.get('keys_found')) and bool(promotion.get('promoted'))
    verdict = dict(transform_evidence.get('evidence_verdict') or {})
    if verdict:
        promoted = promoted and bool(verdict.get('promote_allowed'))
    if promoted:
        updated['keys_found'] = True
        updated['best_key_hex'] = str(probe_result.get('best_key_hex') or '')
        updated['promotion_evidence'] = promotion
        updated['transform_evidence'] = transform_evidence
        updated['phase'] = 'promoted'
        links = probe_result.get('chat_ui_links') or {}
        if links:
            updated['decrypted_path'] = str(links.get('decrypted_path') or '')
            updated['decrypted_chat_url'] = str(links.get('url') or '')
            updated['decrypted_markdown_link'] = str(links.get('markdown_link') or '')
            updated['source_snapshot_path'] = str(links.get('source_snapshot_path') or '')
            updated['source_markdown_link'] = str(links.get('source_markdown_link') or '')
            updated['artifact_folder'] = str(links.get('artifact_folder') or '')
    else:
        recommended = probe_result.get('recommended_next') or {}
        if recommended.get('key_cursor') is not None:
            updated['last_key_cursor'] = int(recommended.get('key_cursor') or 0)
        elif probe_result.get('next_key_cursor') is not None:
            updated['last_key_cursor'] = int(probe_result.get('next_key_cursor') or 0)
        phase_id = str(probe_result.get('probe_phase_id') or updated.get('probe_phase_id') or '')
        phases_completed = list(updated.get('phases_completed') or [])
        phase_done = bool(probe_result.get('phase_exhausted')) or probe_result.get('next_key_cursor') is None
        expected_next = phase_id
        try:
            _, _, next_probe_phase_fn = _import_probe_phase_config()
            expected_next = str(next_probe_phase_fn(phases_completed) or phase_id)
        except Exception:
            pass
        if phase_done and phase_id:
            if phase_id == expected_next and phase_id not in phases_completed:
                phases_completed.append(phase_id)
            elif phase_id not in phases_completed and phase_id != expected_next:
                logger.warning('probe phase out of order: result=%s expected_next=%s completed=%s', phase_id, expected_next, phases_completed)
        updated['phases_completed'] = phases_completed
        updated['probe_phase_id'] = phase_id
        if transform_evidence:
            updated['transform_evidence'] = transform_evidence
        try:
            _, _, next_probe_phase_fn = _import_probe_phase_config()
            next_phase = next_probe_phase_fn(phases_completed)
        except Exception:
            next_phase = None
        sweep_limit = int(probe_result.get('sweep_key_limit') or 256)
        if next_phase:
            updated['phase'] = 'probe'
            updated['probe_phase_id'] = next_phase
            updated['last_key_cursor'] = 0
        elif phase_done and (not next_phase):
            updated['phase'] = 'exhausted'
            start = int(probe_result.get('key_cursor') or updated.get('last_key_cursor') or 0)
            batch = int(probe_result.get('key_batch') or sweep_limit)
            updated['last_key_cursor'] = max(int(updated.get('last_key_cursor') or 0), min(sweep_limit, start + batch))
        elif int(updated.get('last_key_cursor') or 0) >= sweep_limit:
            updated['phase'] = 'exhausted'
    logger.info('hex hunt apply_probe probe_phase_before=%s probe_phase_after=%s cursor_before=%s cursor_after=%s phase_exhausted=%s phases_completed=%s hunt_phase=%s', probe_phase_before, updated.get('probe_phase_id'), cursor_before, updated.get('last_key_cursor'), bool(probe_result.get('phase_exhausted')), updated.get('phases_completed'), updated.get('phase'))
    return updated

def build_decrypt_hunt_contract_state(hunt: Optional[Mapping[str, Any]], *, goal_text: str='') -> Dict[str, Any]:
    record = dict(hunt or {})
    if not record and looks_like_decrypt_key_hunt_goal(goal_text):
        record = new_hunt_state(target_path='', goal_text=goal_text)
    if not record:
        return {}
    return {'phase': str(record.get('phase') or 'probe'), 'last_key_cursor': int(record.get('last_key_cursor') or 0), 'keys_found': bool(record.get('keys_found')), 'best_key_hex': str(record.get('best_key_hex') or ''), 'turns_remaining': int(record.get('turns_remaining') or DEFAULT_TURNS), 'promotion_evidence': dict(record.get('promotion_evidence') or {}), 'probe_phase_id': str(record.get('probe_phase_id') or ''), 'phases_completed': list(record.get('phases_completed') or [])}
