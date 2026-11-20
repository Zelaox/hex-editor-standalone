"""PE image runtime graph from pefile + provenance ranges."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Mapping

from src.plugins.pe.disasm_regions import build_entry_disasm_nodes
from src.plugins.pe.rva_map import rva_to_file_offset, section_coverage
from src.runtime.byte_source import ByteSource
from src.runtime.config import load_binary_dynamic_config, load_parser_registry
from src.runtime.snapshot import SCHEMA_VERSION, BinarySnapshot, GraphEdge, GraphNode, SourceRange, stable_node_id


def _registry_digest(registry: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(registry, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _pe_suffixes(cfg: Mapping[str, Any]) -> set[str]:
    return {str(item).lower() for item in cfg.get("pe_suffixes") or []}


def _structure_file_offset(structure: Any) -> int:
    """Return a pefile structure's source offset through its public API."""
    getter = getattr(structure, "get_file_offset", None)
    if not callable(getter):
        return 0
    return max(0, int(getter()))


def build_pe_snapshot(source: ByteSource, *, policy: Mapping[str, Any] | None = None) -> BinarySnapshot:
    cfg = dict(policy or load_binary_dynamic_config())
    registry = load_parser_registry("pe")
    registry_revision = str(registry.get("revision") or cfg.get("registry_revision") or "generic-discovery-v1")
    data = source.bytes()
    source_sha = str(source.identity["sha256"])
    path = Path(str(source.identity.get("path") or ""))
    suffix = path.suffix.lower() if path.name else str(source.identity.get("suffix") or "")
    if suffix and suffix not in _pe_suffixes(cfg) and data[:2] != b"MZ":
        raise ValueError("PE plugin requires PE suffix or MZ header")

    try:
        import pefile
    except ImportError as exc:
        raise RuntimeError(f"pefile not available: {exc}") from exc

    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    optional = pe.OPTIONAL_HEADER
    entry_rva = int(optional.AddressOfEntryPoint)
    image_base = int(optional.ImageBase)
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

    image_id = stable_node_id("pe_image", source_sha, 0, min(len(data), 64))
    nodes.append(
        GraphNode(
            image_id,
            "pe_image",
            path.name or "pe_image",
            (SourceRange(0, min(len(data), 512)),),
            1.0,
            "pe.dos_header",
            attributes={"machine": int(pe.FILE_HEADER.Machine), "image_base": image_base, "subsystem": int(optional.Subsystem)},
        )
    )

    sections: List[Dict[str, Any]] = []
    for section in pe.sections[:64]:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        info = {
            "name": name,
            "virtual_address": int(section.VirtualAddress),
            "virtual_size": int(section.Misc_VirtualSize),
            "raw_size": int(section.SizeOfRawData),
            "raw_pointer": int(section.PointerToRawData),
        }
        sections.append(info)
        raw_ptr = int(info["raw_pointer"])
        raw_size = int(info["raw_size"])
        if raw_ptr >= 0 and raw_size > 0 and raw_ptr + raw_size <= len(data):
            sid = stable_node_id("section", source_sha, raw_ptr, raw_size, rva=int(info["virtual_address"]))
            nodes.append(
                GraphNode(
                    sid,
                    "section",
                    name,
                    (SourceRange(raw_ptr, raw_size, rva=int(info["virtual_address"])),),
                    0.95,
                    "pe.section_table",
                    attributes=info,
                )
            )
            eid = stable_node_id("edge", source_sha, raw_ptr, raw_size)
            edges.append(GraphEdge(eid, "contains", image_id, sid, 0.95, ("pe.section_table",)))

    entry_map = rva_to_file_offset(entry_rva, sections)
    if entry_map:
        file_off, section_name = entry_map
        eid = stable_node_id("entry", source_sha, file_off, 16, rva=entry_rva)
        nodes.append(
            GraphNode(
                eid,
                "entry_point",
                f"entry@{hex(entry_rva)}",
                (SourceRange(file_off, min(64, len(data) - file_off), rva=entry_rva),),
                0.9,
                "pe.optional_header.AddressOfEntryPoint",
                attributes={"entry_rva": entry_rva, "section": section_name},
            )
        )
        edges.append(GraphEdge(stable_node_id("edge", source_sha, file_off, 1), "entry_in", image_id, eid, 0.9, ("pe.entry",)))
        if path.is_file():
            nodes.extend(build_entry_disasm_nodes(path, source_sha, image_id, edges, cfg))

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:32]:
            dll = entry.dll.decode("utf-8", errors="replace")
            mid = stable_node_id("import_module", source_sha, 0, 0, rva=0)
            # module node uses import descriptor range when available
            mod_off = _structure_file_offset(getattr(entry, "struct", entry))
            nodes.append(
                GraphNode(
                    stable_node_id("import_module", source_sha, mod_off, 8),
                    "import_module",
                    dll,
                    (SourceRange(max(0, mod_off), 8),),
                    0.75,
                    "pe.import_directory",
                    attributes={"dll": dll},
                )
            )
            for imp in (entry.imports or [])[:32]:
                if imp.name:
                    label = f"{dll}.{imp.name.decode('utf-8', errors='replace')}"
                elif imp.ordinal is not None:
                    label = f"{dll}.#{imp.ordinal}"
                else:
                    continue
                iid = stable_node_id("import_symbol", source_sha, int(imp.address or 0), 4)
                nodes.append(
                    GraphNode(
                        iid,
                        "import_symbol",
                        label,
                        (SourceRange(0, 0),),
                        0.7,
                        "pe.import_directory",
                        attributes={"dll": dll, "ordinal": getattr(imp, "ordinal", None)},
                    )
                )
                edges.append(
                    GraphEdge(
                        stable_node_id("edge", source_sha, int(imp.address or 0), 4),
                        "declares_import",
                        stable_node_id("import_module", source_sha, mod_off, 8),
                        iid,
                        0.7,
                        ("pe.import_directory",),
                    )
                )

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in (pe.DIRECTORY_ENTRY_EXPORT.symbols or [])[:64]:
            if not exp.name:
                continue
            name = exp.name.decode("utf-8", errors="replace")
            xid = stable_node_id("export_symbol", source_sha, int(exp.address or 0), 4)
            nodes.append(
                GraphNode(
                    xid,
                    "export_symbol",
                    name,
                    (SourceRange(0, 0),),
                    0.75,
                    "pe.export_directory",
                    attributes={"rva": int(exp.address or 0)},
                )
            )
            edges.append(
                GraphEdge(stable_node_id("edge", source_sha, int(exp.address or 0), 8), "exports_symbol", image_id, xid, 0.75, ("pe.export_directory",))
            )

    coverage = section_coverage(sections, file_size=len(data))
    for item in coverage:
        item["node_ids"] = [n.id for n in nodes if n.kind == "section" and any(r.offset == item["offset"] for r in n.source_ranges)]

    mapped = sum(int(item["length"]) for item in coverage)
    signals = {
        "profile_id": str(registry.get("default_profile_id") or ""),
        "machine": int(pe.FILE_HEADER.Machine),
        "optional_header_magic": int(optional.Magic),
        "file_size": len(data),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "section_count": len(sections),
        "coverage_ratio": mapped / len(data) if data else 0.0,
        "entry_rva": entry_rva,
        "entry_resolved": bool(entry_map),
        "graph_consistent": True,
    }
    digest = _registry_digest(registry)
    snapshot_id = BinarySnapshot.compute_snapshot_id(
        source_sha256=source_sha,
        format_plugin="pe",
        registry_revision=registry_revision,
        payload={"nodes": [asdict(n) for n in nodes], "coverage": coverage},
    )
    diagnostics: List[Dict[str, Any]] = []
    if not entry_map:
        diagnostics.append({"code": "entry_section_unresolved", "severity": "advisory", "message": "Entry RVA did not map to a file span."})
    return BinarySnapshot(
        SCHEMA_VERSION,
        snapshot_id,
        "pe",
        dict(source.identity),
        registry_revision,
        digest,
        tuple(nodes),
        tuple(edges),
        tuple(coverage),
        tuple(diagnostics),
        signals,
    )


def analyze_pe_path(path: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_binary_dynamic_config())
    resolved = Path(path).expanduser().resolve()
    if resolved.suffix.lower() not in _pe_suffixes(cfg):
        raise ValueError("PE plugin requires PE suffix")
    max_bytes = int(cfg.get("max_source_bytes", 268435456))
    source = ByteSource.from_path(resolved, max_bytes=max_bytes)
    snapshot = build_pe_snapshot(source, policy=cfg)
    return {"ok": True, "operation": "binary_snapshot_parse", "format_plugin": "pe", "snapshot": snapshot.to_dict()}
