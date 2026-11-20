"""Compression detection transform hook."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.behavior_classifier import classify_binary
from src.services.transforms.base import TransformProbeContext


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    classification = classify_binary(ctx.raw, defaults=ctx.defaults, transform_start=ctx.xor_start)
    if not classification.get("is_compressed"):
        return []
    return [
        {
            "name": "compression_detect",
            "algorithm": "compression_detect",
            "key_hex": "",
            "score": 1 if classification.get("decompression_success") else 0,
            "cheap_only": True,
            "provenance": "behavior_classifier magic_scan",
            "parameters": {
                "decompression_success": classification.get("decompression_success"),
                "recommended_action": classification.get("recommended_action"),
            },
            "classifier": classification,
        }
    ]


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    return ctx.raw


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
