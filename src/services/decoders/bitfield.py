"""Config-driven bitfield extraction decoder."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def decode_bitfield_candidates(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    sweep = dict(policy.get("bitfield_sweep") or {})
    fields = list(sweep.get("fields") or [])
    if not fields:
        return {"decoder_id": str(family["id"]), "kind": "bitfield", "valid": False, "fields": []}
    values: List[Dict[str, Any]] = []
    for field in fields:
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "")
        byte_index = int(field.get("byte_index") or 0)
        bit_offset = int(field.get("bit_offset") or 0)
        width_bits = int(field.get("width_bits") or 0)
        if not name or width_bits <= 0 or byte_index >= len(data):
            continue
        byte_value = data[byte_index]
        mask = (1 << width_bits) - 1
        extracted = (byte_value >> bit_offset) & mask
        values.append(
            {
                "name": name,
                "byte_index": byte_index,
                "bit_offset": bit_offset,
                "width_bits": width_bits,
                "value": extracted,
                "hex": f"{byte_value:02x}",
                "absolute_offset": offset + byte_index,
            }
        )
    return {
        "decoder_id": str(family["id"]),
        "kind": "bitfield",
        "valid": bool(values),
        "fields": values,
    }
