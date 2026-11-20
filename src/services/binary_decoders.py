"""Registry-driven decoder orchestration (Layer B)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.representation_registry import load_decoder_registry, resolve_decoder_callable


def run_decoder_candidates(
    data: bytes,
    *,
    policy: Optional[Mapping[str, Any]] = None,
    decoder_ids: Optional[Sequence[str]] = None,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    bundle = load_decoder_registry(dict(policy) if policy else None)
    active_policy = dict(bundle["policy"])
    budgets = dict(active_policy.get("budgets") or {})
    max_candidates = int(budgets["max_decoder_candidates"])
    allowed = {str(value) for value in decoder_ids} if decoder_ids else None
    candidates: List[Dict[str, Any]] = []
    for family in bundle["enabled_families"]:
        family_id = str(family.get("id") or "")
        if allowed is not None and family_id not in allowed:
            continue
        decode = resolve_decoder_callable(family)
        result = decode(data, policy=active_policy, family=family, offset=offset)
        if isinstance(result, dict):
            candidates.append(result)
        elif isinstance(result, list):
            candidates.extend(item for item in result if isinstance(item, dict))
        if len(candidates) >= max_candidates:
            break
    return candidates[:max_candidates]
