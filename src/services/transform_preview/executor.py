"""In-memory replay and registry-dispatched transform preview execution."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Sequence

from src.services.transform_preview.contracts import PreviewDescriptor
from src.services.transform_preview.registry import dispatch_preview_step, is_preview_safe, load_transform_preview_registry


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replay_materialization_scopes(
    *,
    opened_slice: bytes,
    parent_slice: bytes,
    source_slice: bytes,
    descriptors: Sequence[PreviewDescriptor],
    identity_role: str,
    range_offset: int,
) -> tuple[bytes, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Replay verified materialization scopes in memory without mutating files."""
    output = bytearray(opened_slice)
    steps: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []

    for descriptor in descriptors:
        offset = int(descriptor["offset"])
        length = int(descriptor["length"])
        local_start = offset - range_offset
        local_end = local_start + length
        if local_start < 0 or local_end > len(output):
            diagnostics.append({"code": "scope_out_of_range", "descriptor_id": descriptor.get("descriptor_id")})
            continue
        before = bytes(output[local_start:local_end])
        if identity_role == "parent":
            replacement = source_slice[local_start:local_end]
            output[local_start:local_end] = replacement
            after = bytes(replacement)
        else:
            after = before
        steps.append(
            {
                "step_id": (descriptor.get("steps") or [{}])[0].get("step_id"),
                "descriptor_id": descriptor.get("descriptor_id"),
                "offset": offset,
                "length": length,
                "input_digest": _digest(before),
                "output_digest": _digest(after),
                "identity_role": identity_role,
                "operation": "materialize_scope",
            }
        )
        if identity_role == "source" and parent_slice:
            parent_piece = parent_slice[local_start:local_end]
            if parent_piece and before != parent_piece:
                diagnostics.append(
                    {
                        "code": "source_scope_differs_from_parent_baseline",
                        "descriptor_id": descriptor.get("descriptor_id"),
                        "offset": offset,
                    }
                )

    return bytes(output), steps, diagnostics


def execute_descriptor_chain(
    *,
    opened_slice: bytes,
    parent_slice: bytes,
    source_slice: bytes,
    descriptors: Sequence[PreviewDescriptor],
    identity_role: str,
    range_offset: int,
    source_sha: str,
    maximum_chain_depth: int,
    registry: Mapping[str, Any] | None = None,
) -> tuple[bytes, List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Execute descriptor steps via registry hooks and materialization replay."""
    registry_cfg = dict(registry or load_transform_preview_registry())
    output = bytearray(opened_slice)
    steps: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    step_mappings: List[Dict[str, Any]] = []

    for descriptor in descriptors:
        offset = int(descriptor["offset"])
        length = int(descriptor["length"])
        local_start = offset - range_offset
        local_end = local_start + length
        if local_start < 0 or local_end > len(output):
            diagnostics.append({"code": "scope_out_of_range", "descriptor_id": descriptor.get("descriptor_id")})
            continue
        chain_steps = list(descriptor.get("steps") or [])[: max(1, int(maximum_chain_depth))]
        region = bytes(output[local_start:local_end])
        parent_region = parent_slice[local_start:local_end] if parent_slice else region
        source_region = source_slice[local_start:local_end] if source_slice else region

        for step in chain_steps:
            operation = str(step.get("operation") or "materialize_scope")
            family_id = str(step.get("family_id") or "materialization")
            before = bytes(region)
            try:
                if operation == "materialize_scope" or family_id in {"materialization", "record-family-proof"}:
                    if identity_role == "parent":
                        region = bytes(source_region)
                    meta = {"operation": "materialize_scope", "length_relation": "one_to_one"}
                elif is_preview_safe(registry_cfg, family_id):
                    region, meta = dispatch_preview_step(
                        family_id=family_id,
                        data=region,
                        step=step,
                        source_sha=source_sha,
                        registry=registry_cfg,
                    )
                else:
                    diagnostics.append({"code": "preview_hook_not_safe", "family_id": family_id, "descriptor_id": descriptor.get("descriptor_id")})
                    continue
            except Exception as exc:
                diagnostics.append(
                    {
                        "code": "preview_step_failed",
                        "family_id": family_id,
                        "descriptor_id": descriptor.get("descriptor_id"),
                        "detail": str(exc),
                    }
                )
                continue

            relation = str(meta.get("length_relation") or "one_to_one")
            mapping_kind = "one_to_one" if relation == "one_to_one" and len(region) == len(before) else "block"
            step_mappings.append(
                {
                    "kind": mapping_kind,
                    "source_offset": offset,
                    "source_length": len(before),
                    "output_offset": local_start,
                    "output_length": len(region),
                    "step_id": str(step.get("step_id") or ""),
                    "exact": mapping_kind == "one_to_one",
                    "length_relation": relation,
                }
            )
            steps.append(
                {
                    "step_id": step.get("step_id"),
                    "descriptor_id": descriptor.get("descriptor_id"),
                    "family_id": family_id,
                    "offset": offset,
                    "length": length,
                    "input_digest": _digest(before),
                    "output_digest": _digest(region),
                    "identity_role": identity_role,
                    "operation": operation,
                }
            )

        if len(region) == local_end - local_start:
            output[local_start:local_end] = region
        else:
            diagnostics.append(
                {
                    "code": "length_changing_scope_unmapped_in_slice",
                    "descriptor_id": descriptor.get("descriptor_id"),
                    "source_length": local_end - local_start,
                    "output_length": len(region),
                }
            )

    return bytes(output), steps, diagnostics, step_mappings


def verify_inverse_replay(
    *,
    output_slice: bytes,
    parent_slice: bytes,
    inverse_entries: Sequence[Mapping[str, Any]],
    range_offset: int,
) -> Dict[str, Any]:
    restored = bytearray(output_slice)
    for item in reversed(list(inverse_entries)):
        offset = int(item["offset"])
        length = int(item["length"])
        local_start = offset - range_offset
        local_end = local_start + length
        if local_start < 0 or local_end > len(restored):
            continue
        restored[local_start:local_end] = bytes.fromhex(str(item["bytes_hex"]))
    ok = bytes(restored) == parent_slice
    return {"ok": ok, "operation": "inverse_replay_verify"}
