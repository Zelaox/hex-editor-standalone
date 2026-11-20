"""Bounded chain_recipe — only explicit registry-declared chains."""

from __future__ import annotations

import importlib
from typing import Any, Callable, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _materialize_fn(module_path: str) -> Callable[..., bytes]:
    module = importlib.import_module(module_path)
    func = getattr(module, "materialize", None)
    if not callable(func):
        raise ValueError(f"{module_path}.materialize not callable")
    return func


def _compose_materializers(ctx: TransformProbeContext, steps: List[str]) -> Callable[[bytes], bytes]:
    families_by_id = dict(ctx.registry.get("families_by_id") or {})
    fns: List[Callable[[TransformProbeContext, Mapping[str, Any]], bytes]] = []
    for step_id in steps:
        family = families_by_id.get(step_id) or {}
        module_path = str((family.get("impl") or {}).get("module") or "")
        if not module_path:
            continue
        mat = _materialize_fn(module_path)
        fns.append(mat)

    def apply_chain(data: bytes) -> bytes:
        temp_ctx = TransformProbeContext(
            raw=data,
            case=ctx.case,
            defaults=ctx.defaults,
            pipeline=ctx.pipeline,
            xor_start=0,
            reference_sha=ctx.reference_sha,
            source_sha=ctx.source_sha,
            anchors=ctx.anchors,
            body_windows=ctx.body_windows,
            reference_bytes=ctx.reference_bytes,
            crypto_case_id=ctx.crypto_case_id,
            classifier=ctx.classifier,
            registry=ctx.registry,
        )
        current = data
        for index, step_id in enumerate(steps):
            family = families_by_id.get(step_id) or {}
            stub = {"algorithm": step_id, "key_hex": "00", "parameters": {}}
            mat = _materialize_fn(str((family.get("impl") or {}).get("module") or ""))
            current = mat(temp_ctx, stub)
            temp_ctx = TransformProbeContext(
                raw=current,
                case=ctx.case,
                defaults=ctx.defaults,
                pipeline=ctx.pipeline,
                xor_start=0,
                reference_sha=ctx.reference_sha,
                source_sha=ctx.source_sha,
                anchors=ctx.anchors,
                body_windows=ctx.body_windows,
                reference_bytes=ctx.reference_bytes,
                crypto_case_id=ctx.crypto_case_id,
                classifier=ctx.classifier,
                registry=ctx.registry,
            )
        return current

    return apply_chain


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    recipes = list(ctx.registry.get("chain_recipes") or [])
    results: List[Dict[str, Any]] = []
    for recipe in recipes:
        if not recipe.get("enabled"):
            continue
        steps = [str(s) for s in recipe.get("steps") or []]
        if not steps:
            continue
        recipe_id = str(recipe.get("id") or "")
        transform_fn = _compose_materializers(ctx, steps)

        def body_transform(data: bytes, fn: Callable[[bytes], bytes] = transform_fn) -> bytes:
            prefix = ctx.raw[: ctx.xor_start]
            if data != ctx.raw[ctx.xor_start :]:
                return fn(data)
            transformed = fn(ctx.raw)
            return transformed[ctx.xor_start :]

        results.append(
            score_transform_windows(
                ctx,
                transform_fn=lambda data, fn=transform_fn: (
                    fn(ctx.raw)[ctx.xor_start :] if len(data) > 0 else data
                ),
                profile_name="byte_arith",
                name=f"chain_{recipe_id}",
                algorithm="chain_recipe",
                key_hex=recipe_id,
                provenance=f"registry chain_recipe steps={steps}",
                parameters={"chain_id": recipe_id, "steps": steps, "transform_regions": [{"start": ctx.xor_start}]},
            )
        )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    params = dict(candidate.get("parameters") or {})
    steps = [str(s) for s in params.get("steps") or []]
    if not steps:
        return ctx.raw
    fn = _compose_materializers(ctx, steps)
    return fn(ctx.raw)


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
