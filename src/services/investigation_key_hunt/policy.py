"""Load investigation key hunt policy from config SSOT."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


def _config_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "investigation_key_hunt_policy.json"


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / "investigation_key_hunt_policy.schema.json"


def _canonical_digest(value: Any) -> str:
    import hashlib

    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_investigation_key_hunt_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _config_path()
    policy = json.loads(target.read_text(encoding="utf-8-sig"))
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"investigation key hunt policy invalid: {errors[0].message}")
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("unsupported investigation key hunt policy schema version")
    modes = set(policy.get("window_source_modes") or [])
    default_mode = str(policy.get("default_window_source") or "")
    if default_mode not in modes:
        raise ValueError("investigation key hunt default_window_source is not registered")
    required_budgets = ("max_probe_seconds", "default_key_batch", "max_unknown_regions", "max_ledger_events", "max_sweep_keys_per_run")
    budgets = dict(policy.get("budgets") or {})
    missing = [name for name in required_budgets if name not in budgets]
    if missing:
        raise ValueError(f"investigation key hunt policy missing budgets: {missing}")
    derivation = dict(policy.get("window_derivation") or {})
    required_derivation = (
        "case_evidence_roles",
        "exclude_unknown_roles",
        "max_printable_ratio_for_cipher_sample",
        "min_entropy_for_unknown_region",
        "min_window_length",
        "default_window_length",
        "prefer_case_evidence_first",
    )
    missing_derivation = [name for name in required_derivation if name not in derivation]
    if missing_derivation:
        raise ValueError(f"investigation key hunt policy missing window_derivation: {missing_derivation}")
    return {**policy, "policy_digest": _canonical_digest(policy), "policy_path": str(target)}
