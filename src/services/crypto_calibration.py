"""Load transform crypto calibration from Hex editor config."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.transform_registry import hex_editor_root, merge_crypto_defaults


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _fixture_path() -> Path:
    return _lab_root() / "config" / "crypto_cases.json"


@lru_cache(maxsize=1)
def load_crypto_calibration() -> Dict[str, Any]:
    fixture = _fixture_path()
    if not fixture.is_file():
        return {"cases": [], "defaults": merge_crypto_defaults()}
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    lab_defaults = dict(payload.get("crypto_defaults") or {})
    merged_defaults = merge_crypto_defaults(lab_defaults)
    return {
        "cases": list(payload.get("cases") or []),
        "defaults": merged_defaults,
    }


def resolve_crypto_case(
    path: str | Path,
    *,
    sha256: str = "",
    file_size: int = 0,
) -> Optional[Dict[str, Any]]:
    resolved = Path(path).expanduser().resolve()
    name = resolved.name.lower()
    digest = str(sha256 or "").lower()
    for case in load_crypto_calibration().get("cases") or []:
        if not isinstance(case, dict):
            continue
        rel = str(case.get("path") or "")
        fixture_name = Path(rel).name.lower()
        if fixture_name and fixture_name == name:
            return dict(case)
        expected_size = int(case.get("file_size") or 0)
        if expected_size and file_size and expected_size == file_size and fixture_name == name:
            return dict(case)
        ref_sha = str((case.get("decrypt") or {}).get("expected_sha256") or "").lower()
        if ref_sha and digest and digest.startswith(ref_sha[:16]):
            return dict(case)
    return None


def crypto_defaults() -> Dict[str, Any]:
    defaults = dict(load_crypto_calibration().get("defaults") or {})
    if not defaults:
        defaults = merge_crypto_defaults()
    return defaults


def probe_pipeline_config(defaults: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    base = dict(crypto_defaults().get("probe_pipeline") or {})
    if defaults:
        base.update(dict(defaults.get("probe_pipeline") or {}))
    merged = merge_crypto_defaults({"probe_pipeline": base})
    return dict(merged.get("probe_pipeline") or {})


def sweep_limits_config(defaults: Optional[Mapping[str, Any]] = None) -> Dict[str, int]:
    pipeline = probe_pipeline_config(defaults)
    sweep_limit = max(1, int(pipeline.get("sweep_key_limit") or 256))
    single_limit = max(1, min(int(pipeline.get("sweep_single_byte_limit") or 256), sweep_limit))
    return {
        "sweep_key_limit": sweep_limit,
        "sweep_single_byte_limit": single_limit,
    }


def case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    needle = str(case_id or "").strip()
    if not needle:
        return None
    for case in load_crypto_calibration().get("cases") or []:
        if isinstance(case, dict) and str(case.get("id") or "") == needle:
            return dict(case)
    return None


def probe_windows_for_case(case: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if case:
        windows = list((case.get("decrypt") or {}).get("probe_windows") or [])
        if windows:
            return [dict(item) for item in windows if isinstance(item, dict)]
    defaults = crypto_defaults()
    return list(defaults.get("probe_windows") or [])


def reference_sha256_for_case(case: Optional[Mapping[str, Any]]) -> str:
    if not case:
        return str(crypto_defaults().get("reference_sha256") or "")
    return str((case.get("decrypt") or {}).get("expected_sha256") or "")


def known_keys_for_case(case: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    keys: List[Dict[str, Any]] = []
    if case:
        decrypt = dict(case.get("decrypt") or {})
        key_hex = str(decrypt.get("key_hex") or "").strip()
        if key_hex:
            keys.append(
                {
                    "name": str(decrypt.get("algorithm") or "fixture_xor"),
                    "key_hex": key_hex,
                    "provenance": "calibration fixture decrypt.key_hex",
                    "algorithm": str(decrypt.get("algorithm") or "xor_single_byte"),
                }
            )
        for item in decrypt.get("known_keys") or []:
            if isinstance(item, dict) and item.get("key_hex"):
                keys.append(dict(item))
    for item in crypto_defaults().get("known_keys") or []:
        if isinstance(item, dict) and item.get("key_hex"):
            keys.append(dict(item))
    dedup: Dict[str, Dict[str, Any]] = {}
    for item in keys:
        dedup[str(item.get("key_hex") or "").lower()] = item
    return list(dedup.values())


def config_root() -> Path:
    return hex_editor_root() / "config"
