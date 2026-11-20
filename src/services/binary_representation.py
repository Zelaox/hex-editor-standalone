"""Layer A — lossless binary representation transforms."""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, Mapping

from src.services.representation_registry import RepresentationRegistryError, load_representation_policy


def _format_params(policy: Mapping[str, Any]) -> Dict[str, Any]:
    formats = dict(policy.get("formats") or {})
    if not formats:
        raise RepresentationRegistryError("representation policy missing formats")
    return formats


def bytes_to_hex(data: bytes, *, policy: Mapping[str, Any] | None = None) -> str:
    cfg = dict(_format_params(dict(policy or load_representation_policy()))["hex"])
    group_size = int(cfg["group_size"])
    separator = str(cfg.get("separator") or " ")
    if group_size < 1:
        raise RepresentationRegistryError("hex.group_size must be positive")
    hex_str = data.hex(separator)
    if group_size == 1:
        return hex_str
    parts = hex_str.split(separator)
    grouped = [separator.join(parts[index : index + group_size]) for index in range(0, len(parts), group_size)]
    return separator.join(grouped)


def hex_to_bytes(payload: str, *, policy: Mapping[str, Any] | None = None) -> bytes:
    del policy
    cleaned = re.sub(r"\s+", "", str(payload or ""))
    if not cleaned:
        raise ValueError("hex payload must not be empty")
    if len(cleaned) % 2:
        raise ValueError("hex payload must contain an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("hex payload is not valid hexadecimal") from exc


def bytes_to_binary(data: bytes, *, policy: Mapping[str, Any] | None = None) -> str:
    cfg = dict(_format_params(dict(policy or load_representation_policy()))["binary"])
    bit_width = int(cfg["bit_width"])
    separator = str(cfg.get("separator") or " ")
    if bit_width != 8:
        raise RepresentationRegistryError("only 8-bit binary groups are supported")
    return separator.join(f"{value:0{bit_width}b}" for value in data)


def binary_to_bytes(payload: str, *, policy: Mapping[str, Any] | None = None) -> bytes:
    del policy
    cleaned = re.sub(r"\s+", "", str(payload or ""))
    if not cleaned:
        raise ValueError("binary payload must not be empty")
    if len(cleaned) % 8:
        raise ValueError("binary payload bit length must be a multiple of 8")
    if any(ch not in "01" for ch in cleaned):
        raise ValueError("binary payload contains non-binary characters")
    return bytes(int(cleaned[index : index + 8], 2) for index in range(0, len(cleaned), 8))


def bytes_to_decimal(data: bytes, *, policy: Mapping[str, Any] | None = None) -> str:
    cfg = dict(_format_params(dict(policy or load_representation_policy()))["decimal"])
    separator = str(cfg.get("separator") or " ")
    return separator.join(str(value) for value in data)


def decimal_to_bytes(payload: str, *, policy: Mapping[str, Any] | None = None) -> bytes:
    cfg = dict(_format_params(dict(policy or load_representation_policy()))["decimal"])
    separator = str(cfg.get("separator") or " ")
    parts = [part for part in str(payload or "").split(separator) if part]
    if not parts:
        raise ValueError("decimal payload must not be empty")
    values = []
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"decimal payload contains non-integer token: {part}")
        value = int(part)
        if value < 0 or value > 255:
            raise ValueError(f"decimal byte out of range: {value}")
        values.append(value)
    return bytes(values)


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(payload: str) -> bytes:
    cleaned = str(payload or "").strip()
    if not cleaned:
        raise ValueError("base64 payload must not be empty")
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        raise ValueError("base64 payload is not valid") from exc


def convert_representation(
    *,
    direction: str,
    format_id: str,
    payload: str | bytes,
    policy: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    active_policy = dict(policy or load_representation_policy())
    format_id = str(format_id or "").lower()
    direction = str(direction or "").lower()
    if direction not in {"to_bytes", "from_bytes"}:
        raise ValueError("direction must be to_bytes or from_bytes")

    if direction == "from_bytes":
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError("from_bytes requires bytes payload")
        data = bytes(payload)
        if format_id == "hex":
            result = bytes_to_hex(data, policy=active_policy)
        elif format_id == "binary":
            result = bytes_to_binary(data, policy=active_policy)
        elif format_id == "decimal":
            result = bytes_to_decimal(data, policy=active_policy)
        elif format_id == "base64":
            result = bytes_to_base64(data)
        else:
            raise ValueError(f"unsupported representation format: {format_id}")
        return {"ok": True, "operation": "binary_representation_convert", "format_id": format_id, "direction": direction, "result": result}

    if not isinstance(payload, str):
        raise ValueError("to_bytes requires string payload")
    if format_id == "hex":
        data = hex_to_bytes(payload, policy=active_policy)
    elif format_id == "binary":
        data = binary_to_bytes(payload, policy=active_policy)
    elif format_id == "decimal":
        data = decimal_to_bytes(payload, policy=active_policy)
    elif format_id == "base64":
        data = base64_to_bytes(payload)
    else:
        raise ValueError(f"unsupported representation format: {format_id}")
    return {
        "ok": True,
        "operation": "binary_representation_convert",
        "format_id": format_id,
        "direction": direction,
        "byte_count": len(data),
        "result_hex": bytes_to_hex(data, policy=active_policy),
    }
