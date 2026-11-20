"""Fixed-width IEEE float decoder candidates."""

from __future__ import annotations

import math
import struct
from typing import Any, Dict, List, Mapping


def _byte_order_prefix(value: str) -> str:
    normalized = str(value or "").lower()
    if normalized in {"little", "le"}:
        return "<"
    if normalized in {"big", "be"}:
        return ">"
    raise ValueError(f"unsupported byte order: {value}")


def _decode_float(width: int, byte_order: str, chunk: bytes) -> float:
    prefix = _byte_order_prefix(byte_order)
    if width == 4:
        return struct.unpack(f"{prefix}f", chunk)[0]
    if width == 8:
        return struct.unpack(f"{prefix}d", chunk)[0]
    raise ValueError(f"unsupported float width: {width}")


def decode_float_candidates(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    sweep = dict(policy.get("float_sweep") or {})
    budgets = dict(policy.get("budgets") or {})
    plausibility = dict(policy.get("plausibility") or {})
    max_values = int(budgets["max_float_values_per_candidate"])
    finite_required = bool(plausibility.get("float_finite_required"))
    abs_max = float(plausibility["float_abs_max"])
    abs_min = float(plausibility["float_abs_min"])
    values: List[Dict[str, Any]] = []
    for width in [int(value) for value in sweep.get("widths") or []]:
        for byte_order in sweep.get("byte_orders") or []:
            order = str(byte_order)
            index = 0
            emitted = 0
            while index + width <= len(data) and emitted < max_values:
                chunk = data[index : index + width]
                numeric = _decode_float(width, order, chunk)
                finite = math.isfinite(numeric)
                plausible = finite and abs_min <= abs(numeric) <= abs_max
                if finite_required and not finite:
                    plausible = False
                values.append(
                    {
                        "offset": offset + index,
                        "width": width,
                        "byte_order": order,
                        "value": numeric,
                        "finite": finite,
                        "plausible": plausible,
                        "hex": chunk.hex(),
                    }
                )
                index += width
                emitted += 1
    return {
        "decoder_id": str(family["id"]),
        "kind": "float",
        "valid": bool(values),
        "values": values,
    }
