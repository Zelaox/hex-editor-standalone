"""Confirmed desktop PTX decrypt through the mechanical promotion gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.services.ptx_auto_decrypt import materialize_ptx_decrypt_to_path
from src.services.ptx_key_discovery import probe_ptx_decrypt_keys


def decrypt_ptx_with_verified_probe(source: str | Path, destination: str | Path) -> Dict[str, Any]:
    resolved = Path(source).expanduser().resolve()
    target = Path(destination).expanduser().resolve()
    probe = probe_ptx_decrypt_keys(resolved, exhaustive=True, include_known=True, materialize_confirmed=False)
    promotion = dict(probe.get("promotion_evidence") or {})
    if not probe.get("ok"):
        return {"ok": False, "status": "probe_failed", "error": probe.get("error") or "PTX key probe failed", "probe": probe}
    if not probe.get("keys_found") or not promotion.get("promoted"):
        return {"ok": False, "status": "no_verified_candidate", "error": "No mechanically verified decrypt candidate passed the promotion gate.", "probe": probe}
    key_hex = str(probe.get("best_key_hex") or "")
    algorithm = str(probe.get("best_algorithm") or "")
    transform_start = int(probe.get("xor_start_offset") or probe.get("sample_offset") or 0)
    result = materialize_ptx_decrypt_to_path(resolved, target, key_hex, algorithm=algorithm, transform_start=transform_start)
    return {**result, "status": "materialized" if result.get("ok") else "materialize_failed", "promotion_evidence": promotion}
