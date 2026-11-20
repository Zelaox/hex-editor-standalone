"""Region producers: decompiler, structural plugins, unknown fallback."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .policies import load_decompiler_policy, load_decompiler_registry, load_rtf_parser_registry
from .region_map import RegionSpan
from .semantic_fallback import render_semantic_fallback_for_region


def _byte_initializer(chunk: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in chunk)


def _apply_pseudocode_template(template: str, *, region_index: int, offset: int) -> str:
    return (
        template.replace("{region_index}", str(region_index))
        .replace("{offset:X}", f"{offset:X}")
        .replace("{offset}", str(offset))
    )


def _apply_instruction_template(
    template: str,
    *,
    virtual_address: int,
    file_offset: int,
    mnemonic: str,
    operands: str,
    size: int,
) -> str:
    return (
        template.replace("{virtual_address:X}", f"{int(virtual_address):X}")
        .replace("{virtual_address}", str(int(virtual_address)))
        .replace("{file_offset:X}", f"{int(file_offset):X}")
        .replace("{file_offset}", str(int(file_offset)))
        .replace("{mnemonic}", str(mnemonic))
        .replace("{operands}", str(operands))
        .replace("{size}", str(int(size)))
        .replace("{address:X}", f"{int(virtual_address):X}")
        .replace("{address}", str(int(virtual_address)))
    )


def _graph_lines_for_region(path: Path, data: bytes, region: RegionSpan, *, ir_policy: Mapping[str, Any]) -> List[str] | None:
    graph_cfg = dict(ir_policy.get("graph_adapter") or {})
    if not bool(graph_cfg.get("enabled")):
        return None
    try:
        from src.services.semantic_pseudocode import load_semantic_pseudocode_policy, render_semantic_graph

        rel = str(graph_cfg.get("semantic_policy_path") or "config/semantic_pseudocode_policy.json")
        policy_path = Path(rel)
        if not policy_path.is_absolute():
            policy_path = Path(__file__).resolve().parents[3] / rel
        policy = load_semantic_pseudocode_policy(policy_path)
        from src.services.semantic_pseudocode import _verified_graph_for_path

        graph = _verified_graph_for_path(path, policy)
        if graph is None:
            return None
        filtered_nodes = []
        region_end = region.offset + region.length
        for node in graph.get("nodes") or []:
            attrs = dict(node.get("attributes") or {})
            if "offset" not in attrs or "length" not in attrs:
                continue
            off = int(attrs["offset"])
            length = int(attrs["length"])
            if off >= region.offset and off + length <= region_end:
                filtered_nodes.append(node)
        if not filtered_nodes:
            return None
        subgraph = {"graph_id": graph.get("graph_id"), "nodes": filtered_nodes}
        return render_semantic_graph(subgraph, source_bytes=data, policy=policy)
    except Exception:
        return None


def produce_unknown_region(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    ir_policy: Mapping[str, Any] | None = None,
    routing: Mapping[str, Any] | None = None,
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str]:
    if (region.meta or {}).get("strategy") == "pe_sections_error":
        error = str((region.meta or {}).get("error") or "pe_sections failed")
        return [
            f"/* pe_sections_error @ 0x{region.offset:X}[{region.length}] */",
            f"semantic_binary pe_routing_error {{",
            f"    inconclusive string error = {error!r};",
            "}",
        ]
    if routing is not None:
        semantic_lines = render_semantic_fallback_for_region(
            path, data, region, routing=routing, merge_policy=merge_policy
        )
        if semantic_lines:
            return semantic_lines
    if ir_policy is not None:
        graph_lines = _graph_lines_for_region(path, data, region, ir_policy=ir_policy)
        if graph_lines:
            return [f"/* unknown_data graph_adapter @ 0x{region.offset:X}[{region.length}] */"] + graph_lines
    start = region.offset
    end = min(len(data), region.offset + region.length)
    chunk = data[start:end]
    lines = [
        f"/* unknown_data producer @ 0x{start:X}[{len(chunk)}] confidence={region.confidence} */",
        f"semantic_binary unresolved_region_{start:X} {{",
    ]
    step = 16
    for rel in range(0, len(chunk), step):
        piece = chunk[rel : rel + step]
        lines.append(f"    unresolved byte data_0x{start + rel:X}[{len(piece)}] = {{ {_byte_initializer(piece)} }};")
    lines.append("}")
    return lines


def produce_structural_region(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    routing: Mapping[str, Any] | None = None,
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str]:
    plugin = str(region.format_plugin or "unknown")
    text_heavy = dict((routing or {}).get("text_heavy_plugins") or {})
    if plugin in text_heavy and str((text_heavy.get(plugin) or {}).get("structural_module") or "") == "semantic_fallback":
        if routing is not None:
            semantic_lines = render_semantic_fallback_for_region(
                path, data, region, routing=routing, merge_policy=merge_policy
            )
            if semantic_lines:
                return semantic_lines
    if plugin == "rtf":
        from src.plugins.rtf.structural_pseudocode import produce_structural_lines

        registry = load_rtf_parser_registry()
        lines, painted = produce_structural_lines(data, offset=region.offset, length=region.length, registry=registry)
        unpainted = _unparsed_tail(
            path,
            data,
            region,
            painted_ranges=[(region.offset + a, region.offset + b) for a, b in painted],
            routing=routing,
            merge_policy=merge_policy,
        )
        return lines + unpainted
    if plugin == "pe":
        from src.plugins.pe.structural_pseudocode import produce_pe_structural_lines

        pe_cfg = dict(text_heavy.get("pe") or {})
        section_name = str((region.meta or {}).get("pe_section") or "pe")
        return produce_pe_structural_lines(
            path,
            region_offset=int(region.offset),
            region_length=int(region.length),
            section_name=section_name,
            pe_plugin_cfg=pe_cfg,
        )
    if plugin == "ptx":
        from .ptx_structural import produce_ptx_structural_lines

        ptx_cfg = dict(text_heavy.get("ptx") or {})
        return produce_ptx_structural_lines(
            path,
            data,
            region_offset=int(region.offset),
            region_length=int(region.length),
            ptx_plugin_cfg=ptx_cfg,
        )
    return produce_unknown_region(path, data, region, routing=routing, merge_policy=merge_policy)


def _unparsed_tail(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    painted_ranges: Sequence[Tuple[int, int]],
    routing: Mapping[str, Any] | None = None,
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str]:
    start = region.offset
    end = min(len(data), region.offset + region.length)
    lines: List[str] = []
    cursor = start
    ordered = sorted(painted_ranges)
    for range_start, range_end in ordered:
        if range_start > cursor:
            lines.extend(
                produce_unknown_region(
                    path,
                    data,
                    RegionSpan(cursor, range_start - cursor, "unknown_data", "unknown", region.format_plugin, region.confidence),
                    routing=routing,
                    merge_policy=merge_policy,
                )
            )
        cursor = max(cursor, range_end)
    if cursor < end:
        lines.extend(
            produce_unknown_region(
                path,
                data,
                RegionSpan(cursor, end - cursor, "unknown_data", "unknown", region.format_plugin, region.confidence),
                routing=routing,
                merge_policy=merge_policy,
            )
        )
    return lines


def produce_decompiler_region(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    routing: Mapping[str, Any],
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str]:
    dec_policy = load_decompiler_policy(routing=routing)
    registry = load_decompiler_registry(decompiler_policy=dec_policy)
    templates = dict(registry.get("pseudocode_templates") or {})
    header = str(templates.get("function_header") or "verified void region_entry_{region_index}() {{")
    instr_tpl = str(templates.get("instruction_line") or "    /* 0x{address:X} */ {mnemonic} {operands};")
    footer = str(templates.get("function_footer") or "}")

    try:
        import pefile
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except ImportError as exc:
        return [f"/* decompiler unavailable: {exc} */"] + produce_unknown_region(
            path, data, region, routing=routing, merge_policy=merge_policy
        )

    pe = pefile.PE(str(path), fast_load=True)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    md.detail = False
    meta = dict(region.meta or {})
    section_hint = str(meta.get("pe_section") or "")
    if not section_hint:
        for nested in meta.get("coalesced_from") or []:
            nested_meta = dict((nested or {}).get("meta") or {})
            section_hint = str(nested_meta.get("pe_section") or "")
            if section_hint:
                break
    region_end = min(len(data), int(region.offset) + int(region.length))
    file_start = int(region.offset)
    if file_start >= region_end:
        return [f"/* executable_code decompiler region empty @ 0x{file_start:X} */"]

    def _pe_file_slices(start: int, end: int):
        cursor = start
        while cursor < end:
            matched = False
            for candidate in pe.sections:
                raw_start = int(candidate.PointerToRawData)
                raw_size = int(candidate.SizeOfRawData)
                if raw_size <= 0:
                    continue
                raw_end = raw_start + raw_size
                if raw_start <= cursor < raw_end:
                    chunk_end = min(end, raw_end)
                    rva = int(candidate.VirtualAddress) + (cursor - raw_start)
                    va = int(pe.OPTIONAL_HEADER.ImageBase) + rva
                    name = candidate.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                    yield cursor, chunk_end - cursor, va, name
                    cursor = chunk_end
                    matched = True
                    break
            if not matched:
                break

    limit = int(dec_policy.get("max_instructions_per_region") or 96)
    lines = [
        f"/* executable_code decompiler region section={section_hint or 'file_offset'} file_offset=0x{file_start:X}[{region_end - file_start}] */",
        _apply_pseudocode_template(header, region_index=int(region.offset), offset=int(region.offset)),
    ]
    if bool(dec_policy.get("include_cfg_comment")):
        lines.append("    /* CFG: linear bounded scan — basic blocks not lifted in this slice */")
    count = 0
    for slice_start, slice_len, base_va, slice_section in _pe_file_slices(file_start, region_end):
        if slice_section and not section_hint:
            lines.append(f"    /* pe_section={slice_section} */")
        code = data[slice_start : slice_start + slice_len]
        for address, size, mnemonic, op_str in md.disasm_lite(code, base_va):
            if count >= limit:
                lines.append(f"    /* instruction budget reached ({limit}) */")
                break
            insn_file_offset = slice_start + (int(address) - base_va)
            lines.append(
                _apply_instruction_template(
                    instr_tpl,
                    virtual_address=int(address),
                    file_offset=insn_file_offset,
                    mnemonic=str(mnemonic),
                    operands=str(op_str),
                    size=int(size),
                )
            )
            count += 1
        if count >= limit:
            break
    if count == 0:
        return [f"/* executable_code decompiler produced zero instructions @ 0x{file_start:X} */"]
    lines.append(footer)
    return lines


def produce_region_lines(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    routing: Mapping[str, Any],
    ir_policy: Mapping[str, Any] | None = None,
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str]:
    if region.producer_id == "decompiler":
        return produce_decompiler_region(path, data, region, routing=routing, merge_policy=merge_policy)
    if region.producer_id == "structural":
        return produce_structural_region(path, data, region, routing=routing, merge_policy=merge_policy)
    return produce_unknown_region(path, data, region, ir_policy=ir_policy, routing=routing, merge_policy=merge_policy)


def decompiler_sub_source_entries(
    body_lines: Sequence[str],
    *,
    region: RegionSpan,
    line_start: int,
) -> List[Dict[str, Any]]:
    import re

    entries: List[Dict[str, Any]] = []
    file_pattern = re.compile(r"file=0x([0-9A-Fa-f]+)")
    va_pattern = re.compile(r"va=0x([0-9A-Fa-f]+)")
    for index, line in enumerate(body_lines):
        file_match = file_pattern.search(line)
        if not file_match:
            continue
        file_offset = int(file_match.group(1), 16)
        va_match = va_pattern.search(line)
        entry: Dict[str, Any] = {
            "ir_id": f"{region.offset:X}-insn-{index}",
            "line_start": line_start + index,
            "line_end": line_start + index,
            "file_offset": file_offset,
            "offset": file_offset,
            "length": 1,
            "producer_id": "decompiler",
        }
        if va_match:
            entry["virtual_address"] = int(va_match.group(1), 16)
            entry["coordinate_hint"] = "virtual_address_display"
        entries.append(entry)
    return entries
