"""Orchestrate representation sweep and RepresentationBrief emission."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from src.services.binary_decoders import run_decoder_candidates
from src.services.binary_representation import (
    bytes_to_base64,
    bytes_to_binary,
    bytes_to_decimal,
    bytes_to_hex,
)
from src.services.representation_registry import load_representation_policy
from src.services.value_interpreter import interpret_candidates


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), default=str) + "\n").encode("utf-8")


def sweep_region(
    data: bytes,
    *,
    offset: int = 0,
    policy: Optional[Mapping[str, Any]] = None,
    include_binary_decimal: bool | None = None,
) -> Dict[str, Any]:
    active_policy = dict(policy or load_representation_policy())
    budgets = dict(active_policy.get("budgets") or {})
    max_region = int(budgets["max_region_bytes"])
    if len(data) > max_region:
        data = data[:max_region]
        truncated = True
    else:
        truncated = False

    gemma_packet = dict(active_policy.get("gemma_packet") or {})
    show_binary_decimal = (
        include_binary_decimal
        if include_binary_decimal is not None
        else bool(gemma_packet.get("include_binary_decimal"))
    )

    representation: Dict[str, Any] = {
        "hex": bytes_to_hex(data, policy=active_policy),
        "base64": bytes_to_base64(data),
    }
    if show_binary_decimal:
        representation["binary"] = bytes_to_binary(data, policy=active_policy)
        representation["decimal"] = bytes_to_decimal(data, policy=active_policy)

    decoder_candidates = run_decoder_candidates(data, policy=active_policy, offset=offset)
    interpreter_signals = interpret_candidates(data, decoder_candidates, policy=active_policy)

    text_candidates = [item for item in decoder_candidates if item.get("kind") == "text"]
    integer_candidates = [item for item in decoder_candidates if item.get("kind") == "integer"]
    float_candidates = [item for item in decoder_candidates if item.get("kind") == "float"]

    brief: Dict[str, Any] = {
        "schema_version": 1,
        "operation": "representation_brief",
        "offset": int(offset),
        "length": len(data),
        "truncated": truncated,
        "representation": representation,
        "text_candidates": text_candidates,
        "integer_candidates": integer_candidates,
        "float_candidates": float_candidates,
        "decoder_candidates": decoder_candidates,
        "interpreter_signals": interpreter_signals,
        "features": {
            "entropy": round(_entropy(data), 6),
            "byte_count": len(data),
            "printable_ratio": round(
                sum(1 for value in data if 32 <= value <= 126 or value in (9, 10, 13)) / max(1, len(data)),
                6,
            ),
            "null_ratio": round(data.count(0) / max(1, len(data)), 6),
        },
    }
    return brief


def sweep_region_features(data: bytes, *, policy: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Compatibility wrapper for ptx_full_coverage.scan_region_features."""
    brief = sweep_region(data, offset=0, policy=policy, include_binary_decimal=False)
    features = dict(brief.get("features") or {})
    integer = next((item for item in brief.get("decoder_candidates") or [] if item.get("kind") == "integer"), None)
    numeric_candidates = []
    if integer:
        for item in integer.get("values") or []:
            numeric_candidates.append(
                {
                    "width": item.get("width"),
                    "byte_order": item.get("byte_order"),
                    "first_value": item.get("value"),
                }
            )
            if len(numeric_candidates) >= 1:
                break
    features["numeric_candidates"] = numeric_candidates
    features["interpreter_signals"] = list(brief.get("interpreter_signals") or [])
    features["representation_brief_digest"] = hashlib.sha256(_canonical_json(brief)).hexdigest()
    return features


def write_representation_brief_cache(
    workspace: str | Path,
    region_id: str,
    brief: Mapping[str, Any],
) -> Dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    regions_dir = root / "representation" / "regions"
    regions_dir.mkdir(parents=True, exist_ok=True)
    target = regions_dir / f"{region_id}.json"
    encoded = _canonical_json(dict(brief))
    target.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    index_path = root / "representation" / "index.json"
    index = {}
    if index_path.is_file():
        index = json.loads(index_path.read_text(encoding="utf-8"))
    entries = dict(index.get("entries") or {})
    entries[str(region_id)] = {"path": str(target.relative_to(root)), "sha256": digest}
    index_payload = {"schema_version": 1, "entries": entries}
    index_path.write_bytes(_canonical_json(index_payload))
    return {"ok": True, "region_id": region_id, "path": str(target), "sha256": digest}


def load_representation_brief_cache(workspace: str | Path, region_id: str) -> Dict[str, Any] | None:
    root = Path(workspace).expanduser().resolve()
    index_path = root / "representation" / "index.json"
    if not index_path.is_file():
        return None
    index = json.loads(index_path.read_text(encoding="utf-8"))
    entry = dict((index.get("entries") or {}).get(str(region_id)) or {})
    rel = entry.get("path")
    if not rel:
        return None
    target = root / str(rel)
    if not target.is_file():
        return None
    return json.loads(target.read_text(encoding="utf-8"))
