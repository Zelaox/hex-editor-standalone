"""Fixed-width integer decoder candidates."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _byte_order_name(value: str) -> str:
    normalized = str(value or "").lower()
    if normalized in {"little", "le"}:
        return "little"
    if normalized in {"big", "be"}:
        return "big"
    raise ValueError(f"unsupported byte order: {value}")


def decode_integer_candidates(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    sweep = dict(policy.get("integer_sweep") or {})
    budgets = dict(policy.get("budgets") or {})
    max_values = int(budgets["max_integer_values_per_candidate"])
    widths = [int(value) for value in sweep.get("widths") or []]
    byte_orders = [_byte_order_name(value) for value in sweep.get("byte_orders") or []]
    signed_variants = [bool(value) for value in sweep.get("signed_variants") or []]
    values: List[Dict[str, Any]] = []
    for width in widths:
        if width < 1 or width > 8:
            continue
        for byte_order in byte_orders:
            for signed in signed_variants:
                index = 0
                emitted = 0
                while index + width <= len(data) and emitted < max_values:
                    chunk = data[index : index + width]
                    numeric = int.from_bytes(chunk, byte_order, signed=signed)
                    values.append(
                        {
                            "offset": offset + index,
                            "width": width,
                            "byte_order": byte_order,
                            "signed": signed,
                            "value": numeric,
                            "hex": chunk.hex(),
                        }
                    )
                    index += width
                    emitted += 1
    return {
        "decoder_id": str(family["id"]),
        "kind": "integer",
        "valid": bool(values),
        "values": values,
    }
