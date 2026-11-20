"""Packed and unpacked BCD decoder candidates."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _nibble_valid(value: int) -> bool:
    return 0 <= value <= 9


def decode_bcd_packed_candidates(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    sweep = dict(policy.get("bcd_sweep") or {})
    budgets = dict(policy.get("budgets") or {})
    max_values = int(budgets.get("max_bcd_values_per_candidate") or budgets["max_integer_values_per_candidate"])
    values: List[Dict[str, Any]] = []
    for index, byte in enumerate(data):
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        valid = _nibble_valid(high) and _nibble_valid(low)
        if not valid and not sweep.get("include_invalid"):
            continue
        values.append(
            {
                "offset": offset + index,
                "high_digit": high,
                "low_digit": low,
                "decimal_string": f"{high}{low}" if valid else None,
                "valid": valid,
                "hex": f"{byte:02x}",
            }
        )
        if len(values) >= max_values:
            break
    return {
        "decoder_id": str(family["id"]),
        "kind": "bcd",
        "layout": "packed",
        "valid": any(item.get("valid") for item in values),
        "values": values,
    }


def decode_bcd_unpacked_candidates(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    budgets = dict(policy.get("budgets") or {})
    max_values = int(budgets.get("max_bcd_values_per_candidate") or budgets["max_integer_values_per_candidate"])
    values: List[Dict[str, Any]] = []
    for index, byte in enumerate(data):
        digit = byte & 0x0F
        valid = _nibble_valid(digit) and byte >> 4 == 0
        if not valid:
            continue
        values.append({"offset": offset + index, "digit": digit, "valid": True, "hex": f"{byte:02x}"})
        if len(values) >= max_values:
            break
    return {
        "decoder_id": str(family["id"]),
        "kind": "bcd",
        "layout": "unpacked",
        "valid": bool(values),
        "values": values,
    }
