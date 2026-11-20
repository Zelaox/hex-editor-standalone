"""Build raw region maps from routing policy and format detection."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .format_detect import detect_format
from .policies import load_format_detect_registry, load_region_routing_policy


@dataclass
class RegionSpan:
    offset: int
    length: int
    region_class: str
    producer_id: str
    format_plugin: str
    confidence: float
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _producer_for_class(routing: Mapping[str, Any], region_class: str) -> str:
    classes = dict(routing.get("region_classes") or {})
    entry = dict(classes.get(region_class) or {})
    producer = str(entry.get("producer_id") or "")
    if not producer:
        raise ValueError(f"region_routing_policy missing producer for class: {region_class}")
    return producer


def _fill_gaps(regions: List[RegionSpan], *, file_size: int, routing: Mapping[str, Any], format_plugin: str, confidence: float) -> List[RegionSpan]:
    if file_size <= 0:
        return regions
    ordered = sorted(regions, key=lambda item: item.offset)
    filled: List[RegionSpan] = []
    cursor = 0
    unknown_producer = _producer_for_class(routing, "unknown_data")
    for region in ordered:
        if region.offset > cursor:
            filled.append(
                RegionSpan(
                    offset=cursor,
                    length=region.offset - cursor,
                    region_class="unknown_data",
                    producer_id=unknown_producer,
                    format_plugin=format_plugin,
                    confidence=confidence,
                    meta={"strategy": "gap_fill"},
                )
            )
        filled.append(region)
        cursor = max(cursor, region.offset + region.length)
    if cursor < file_size:
        filled.append(
            RegionSpan(
                offset=cursor,
                length=file_size - cursor,
                region_class="unknown_data",
                producer_id=unknown_producer,
                format_plugin=format_plugin,
                confidence=confidence,
                meta={"strategy": "gap_fill"},
            )
        )
    return filled


def _pe_section_regions(path: Path, *, routing: Mapping[str, Any], format_plugin: str, confidence: float, file_size: int) -> List[RegionSpan]:
    import pefile

    from .policies import load_decompiler_policy

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories()
    dec = load_decompiler_policy(routing=routing)
    exec_names = {str(name) for name in dec.get("section_characteristics_executable") or []}
    regions: List[RegionSpan] = []
    max_regions = int(dec.get("max_executable_regions") or 16)
    for index, section in enumerate(pe.sections):
        if len(regions) >= max_regions and bool(section.Characteristics & 0x20000000):
            break
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace") or f"section_{index}"
        offset = int(section.PointerToRawData)
        length = int(section.SizeOfRawData)
        if length <= 0:
            continue
        is_exec = bool(section.Characteristics & 0x20000000)
        if is_exec:
            region_class = "executable_code"
            producer = _producer_for_class(routing, "executable_code")
        else:
            region_class = "structured_data"
            producer = _producer_for_class(routing, "structured_data")
        regions.append(
            RegionSpan(
                offset=offset,
                length=length,
                region_class=region_class,
                producer_id=producer,
                format_plugin=format_plugin,
                confidence=confidence,
                meta={"pe_section": name, "characteristics": hex(int(section.Characteristics)), "exec_hint": list(exec_names)},
            )
        )
    regions.sort(key=lambda item: item.offset)
    return _fill_gaps(regions, file_size=file_size, routing=routing, format_plugin=format_plugin, confidence=confidence)


def _whole_file_region(
    size: int,
    *,
    region_class: str,
    producer_id: str,
    format_plugin: str,
    confidence: float,
) -> List[RegionSpan]:
    if size <= 0:
        return []
    return [
        RegionSpan(
            offset=0,
            length=size,
            region_class=region_class,
            producer_id=producer_id,
            format_plugin=format_plugin,
            confidence=confidence,
            meta={"strategy": "whole_file"},
        )
    ]


def classify_raw_regions(path: Path, *, routing: Optional[Mapping[str, Any]] = None) -> List[RegionSpan]:
    routing_policy = dict(routing or load_region_routing_policy())
    registry = load_format_detect_registry(routing=routing_policy)
    resolved = path.expanduser().resolve()
    size = resolved.stat().st_size if resolved.is_file() else 0
    plugin, detected_class, confidence = detect_format(
        resolved,
        registry=registry,
        prefix_bytes=int(routing_policy.get("prefix_read_bytes") or 4096),
    )
    strategy = str((routing_policy.get("plugin_region_strategies") or {}).get(plugin) or "whole_file_unknown")
    if strategy == "pe_sections" and plugin == "pe":
        fail_mode = str(routing_policy.get("pe_sections_fail") or "")
        try:
            regions = _pe_section_regions(
                resolved,
                routing=routing_policy,
                format_plugin=plugin,
                confidence=confidence,
                file_size=size,
            )
            if not regions:
                raise ValueError("pe_sections produced zero regions")
            return regions
        except Exception as exc:
            if fail_mode == "fail_closed":
                return [
                    RegionSpan(
                        offset=0,
                        length=size,
                        region_class="unknown_data",
                        producer_id=_producer_for_class(routing_policy, "unknown_data"),
                        format_plugin=plugin,
                        confidence=confidence,
                        meta={"strategy": "pe_sections_error", "error": str(exc)},
                    )
                ]
            return _whole_file_region(
                size,
                region_class="unknown_data",
                producer_id=_producer_for_class(routing_policy, "unknown_data"),
                format_plugin=plugin,
                confidence=confidence,
            )

    if strategy == "whole_file_structural":
        producer = _producer_for_class(routing_policy, "structured_data")
        return _whole_file_region(
            size,
            region_class="structured_data",
            producer_id=producer,
            format_plugin=plugin,
            confidence=confidence,
        )

    producer = _producer_for_class(routing_policy, detected_class if detected_class in (routing_policy.get("region_classes") or {}) else "unknown_data")
    region_class = detected_class if detected_class in (routing_policy.get("region_classes") or {}) else "unknown_data"
    return _whole_file_region(size, region_class=region_class, producer_id=producer, format_plugin=plugin, confidence=confidence)
