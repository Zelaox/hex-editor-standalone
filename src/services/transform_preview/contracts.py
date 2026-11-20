"""Transform preview contracts — descriptors, spans, mappings."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, TypedDict


class PreviewStep(TypedDict, total=False):
    step_id: str
    family_id: str
    operation: str
    offset: int
    length: int
    input_digest: str
    output_digest: str


class PreviewDescriptor(TypedDict, total=False):
    schema_version: int
    descriptor_id: str
    source_sha256: str
    parent_sha256: str
    offset: int
    length: int
    scope_id: str
    proof_id: str
    provider_id: str
    steps: List[PreviewStep]
    truth_state: str
    mapping_kind: Literal["one_to_one", "block"]
    conflict_group: str


class PreviewSpan(TypedDict, total=False):
    offset: int
    length: int
    presentation_class: str
    descriptor_id: str
    truth_state: str
    conflict_group: str


class PreviewMapping(TypedDict, total=False):
    kind: str
    source_offset: int
    source_length: int
    output_offset: int
    output_length: int
    step_id: str
    presentation_class: str
    exact: bool


class PartitionResult(TypedDict, total=False):
    spans: List[PreviewSpan]
    descriptors: List[PreviewDescriptor]
    conflicts: List[Dict[str, Any]]
    gaps: List[PreviewSpan]
