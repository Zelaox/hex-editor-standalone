"""Policy-driven full-byte PTX coverage and discovery helpers."""

from __future__ import annotations

import hashlib
import json
import math
import bisect
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def load_full_coverage_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _lab_root() / "config" / "ptx_full_coverage_policy.json"
    policy = json.loads(target.read_text(encoding="utf-8"))
    required = {"schema_version", "policy_id", "revision", "analysis_budget", "feature_scan", "anchor_discovery", "coverage", "gemma_packet"}
    if int(policy.get("schema_version") or 0) != 1 or required - set(policy):
        raise ValueError("invalid PTX full coverage policy")
    return policy


def _id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(raw).hexdigest()[:24]}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def scan_region_features(data: bytes, policy: Mapping[str, Any]) -> Dict[str, Any]:
    feature_scan = dict(policy.get("feature_scan") or {})
    representation_policy_path = feature_scan.get("representation_policy_path")
    if feature_scan.get("use_representation_sweep"):
        from src.services.representation_registry import load_representation_policy
        from src.services.representation_sweep import sweep_region_features as _sweep_features

        rep_policy = load_representation_policy(representation_policy_path) if representation_policy_path else None
        swept = _sweep_features(data, policy=rep_policy)
        swept["sequence_sampling"] = {"delegated_to": "representation_sweep", "deterministic": True}
        swept["top_sequence_hashes"] = []
        return swept

    cfg = dict(policy["feature_scan"])
    sequences: Counter[str] = Counter()
    stride = max(1, int(cfg["sequence_stride"]))
    for width_value in cfg["sequence_lengths"]:
        width = int(width_value)
        positions = max(0, len(data) - width + 1)
        max_samples = max(1, int(cfg["max_sequence_samples_per_region"]))
        effective_stride = max(stride, math.ceil(positions / max_samples))
        for offset in range(0, positions, effective_stride):
            sequences[hashlib.sha256(data[offset:offset + width]).hexdigest()] += 1
    numeric = []
    for width_value in cfg["numeric_widths"]:
        width = int(width_value)
        if len(data) < width:
            continue
        for byte_order in cfg["byte_order"]:
            numeric.append({"width": width, "byte_order": str(byte_order), "first_value": int.from_bytes(data[:width], str(byte_order), signed=False)})
    return {
        "entropy": round(_entropy(data), 6),
        "byte_count": len(data),
        "printable_ratio": round(sum(1 for value in data if 32 <= value <= 126 or value in (9, 10, 13)) / max(1, len(data)), 6),
        "null_ratio": round(data.count(0) / max(1, len(data)), 6),
        "top_sequence_hashes": [{"sha256": key, "count": count} for key, count in sequences.most_common(int(cfg["top_sequences_per_region"]))],
        "sequence_sampling": {"configured_stride": stride, "maximum_samples_per_length": int(cfg["max_sequence_samples_per_region"]), "deterministic": True},
        "numeric_candidates": numeric,
    }


def build_anchors(nodes: Sequence[Mapping[str, Any]], source_size: int, policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    cfg = dict(policy["anchor_discovery"])
    include = {str(value) for value in cfg["include_kinds"]}
    grouped: Dict[tuple[str, str], List[Mapping[str, Any]]] = defaultdict(list)
    for node in nodes:
        if str(node.get("kind")) in include:
            grouped[(str(node.get("kind")), str(node.get("label")))].append(node)
    anchors = []
    for (kind, label), occurrences in sorted(grouped.items()):
        family_id = _id("anchor-family", {"kind": kind, "value_sha256": hashlib.sha256(label.encode("utf-8")).hexdigest()})
        for node in occurrences:
            for span in node.get("source_ranges") or []:
                offset, length = int(span["offset"]), int(span["length"])
                before, after = int(cfg["context_bytes_before"]), int(cfg["context_bytes_after"])
                context_start = max(0, offset - before)
                context_end = min(source_size, offset + length + after)
                anchors.append({"anchor_id": _id("anchor", {"node": node.get("id"), "offset": offset, "length": length}), "family_id": family_id, "node_id": node.get("id"), "kind": kind, "span": {"offset": offset, "length": length}, "context_span": {"offset": context_start, "length": context_end - context_start}, "occurrence_count": len(occurrences), "evidence_level": "verified"})
    return anchors[: int(policy["analysis_budget"]["max_anchors"])]


def build_record_families(anchors: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    minimum = int(policy["anchor_discovery"]["minimum_occurrences_for_family"])
    groups: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for anchor in anchors:
        groups[str(anchor["family_id"])].append(anchor)
    return [{"family_id": family_id, "kind": "repeated_anchor_context", "anchor_ids": [str(item["anchor_id"]) for item in items], "support": len(items), "evidence_level": "candidate"} for family_id, items in sorted(groups.items()) if len(items) >= minimum]


def partition_coverage(source_size: int, spans: Iterable[Mapping[str, Any]], policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    events: Dict[int, Dict[str, List[tuple[str, tuple[str, ...]]]]] = defaultdict(lambda: {"start": [], "end": []})
    points = {0, source_size}
    for item in spans:
        start = max(0, int(item.get("offset", 0)))
        end = min(source_size, start + max(0, int(item.get("length", 0))))
        if end <= start:
            continue
        descriptor = (str(item.get("class") or "inferred"), tuple(str(value) for value in item.get("node_ids") or []))
        events[start]["start"].append(descriptor)
        events[end]["end"].append(descriptor)
        points.update((start, end))
    ordered = sorted(points)
    unknown_class = str(policy["coverage"]["unknown_class"])
    result = []
    active: Counter[tuple[str, tuple[str, ...]]] = Counter()
    for start, end in zip(ordered, ordered[1:]):
        for descriptor in events[start]["end"]:
            active[descriptor] -= 1
            if active[descriptor] <= 0:
                del active[descriptor]
        for descriptor in events[start]["start"]:
            active[descriptor] += 1
        classes = sorted({descriptor[0] for descriptor in active})
        node_ids = sorted({node for descriptor in active for node in descriptor[1]})
        result.append({"offset": start, "length": end - start, "class": classes[0] if len(classes) == 1 else ("overlap" if classes else unknown_class), "classes": classes or [unknown_class], "node_ids": node_ids})
    return result


def build_unknown_regions(data: bytes, coverage: Sequence[Mapping[str, Any]], anchors: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    unknown_class = str(policy["coverage"]["unknown_class"])
    result = []
    sorted_anchors = sorted(anchors, key=lambda anchor: int(anchor["span"]["offset"]))
    anchor_offsets = [int(anchor["span"]["offset"]) for anchor in sorted_anchors]
    for item in coverage:
        if item.get("class") != unknown_class:
            continue
        offset, length = int(item["offset"]), int(item["length"])
        position = bisect.bisect_left(anchor_offsets, offset)
        neighbors = sorted_anchors[max(0, position - 1):min(len(sorted_anchors), position + 1)]
        result.append({"region_id": _id("unknown", {"source": hashlib.sha256(data).hexdigest(), "offset": offset, "length": length}), "span": {"offset": offset, "length": length}, "classification": unknown_class, "features": scan_region_features(data[offset:offset + length], policy), "neighbor_anchor_ids": [str(anchor["anchor_id"]) for anchor in neighbors], "confidence": "unknown"})
    return result[: int(policy["analysis_budget"]["max_unknown_regions"])]


def coverage_summary(source_size: int, coverage: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    totals: Counter[str] = Counter()
    for item in coverage:
        totals[str(item["class"])] += int(item["length"])
    return {"source_bytes": source_size, "covered_bytes": sum(totals.values()), "coverage_complete": sum(totals.values()) == source_size, "bytes_by_class": dict(sorted(totals.items())), "ratio_by_class": {key: value / max(1, source_size) for key, value in sorted(totals.items())}}
