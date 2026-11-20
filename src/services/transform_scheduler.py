"""Family scheduling by registry priority and classifier hints."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def schedule_families(
    registry: Mapping[str, Any],
    *,
    classifier: Mapping[str, Any] | None = None,
    include_byte_transforms: bool = False,
    include_infer_xor: bool = False,
    include_extended_crypto: bool = False,
) -> List[Dict[str, Any]]:
    enabled = list(registry.get("enabled_families") or [])
    skip_crypto = bool((classifier or {}).get("skip_crypto_lanes"))
    options = {
        "include_byte_transforms": bool(include_byte_transforms),
        "include_infer_xor": bool(include_infer_xor),
        "include_extended_crypto": bool(include_extended_crypto),
    }
    scheduled: List[Dict[str, Any]] = []
    for family in enabled:
        scheduler = dict(family.get("scheduler") or {})
        if not scheduler:
            raise ValueError(f"transform family {family.get('id')} missing scheduler metadata")
        if not bool(scheduler.get("direct_schedule")):
            continue
        if skip_crypto and str(scheduler.get("category") or "") == "crypto":
            continue
        required_option = scheduler.get("requires_option")
        if required_option is not None and str(required_option) not in options:
            raise ValueError(f"transform family {family.get('id')} references unknown scheduler option")
        if required_option is not None and not options[str(required_option)]:
            continue
        scheduled.append(dict(family))
    return scheduled
