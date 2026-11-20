"""Bounded entry disasm nodes linked to static PE graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping

from src.runtime.config import load_binary_dynamic_config
from src.runtime.snapshot import GraphEdge, GraphNode, SourceRange, stable_node_id


def build_entry_disasm_nodes(
    path: Path,
    source_sha: str,
    image_id: str,
    edges: List[GraphEdge],
    cfg: Mapping[str, Any],
) -> List[GraphNode]:
    from src.services.disasm_analysis import disasm_pe_entry

    default_limit = int(cfg.get("disasm_max_instructions_default", 96))
    result = disasm_pe_entry(path, max_instructions=default_limit)
    if not result.get("ok"):
        return []
    instructions = []
    for finding in result.get("findings") or []:
        if str(finding.get("label") or finding.get("kind") or "") == "disasm_entry":
            instructions = list((finding.get("value") or {}).get("instructions") or [])
            break
    nodes: List[GraphNode] = []
    region_id = stable_node_id("code_region", source_sha, 0, default_limit)
    nodes.append(
        GraphNode(
            region_id,
            "code_region",
            "entry_disasm",
            (SourceRange(0, 0),),
            0.8,
            "pe.disasm_entry",
            attributes={"instruction_count": len(instructions), "evidence_class": "static"},
        )
    )
    edges.append(GraphEdge(stable_node_id("edge", source_sha, 0, 2), "disasm_span_of", image_id, region_id, 0.8, ("capstone",)))
    for index, ins in enumerate(instructions[:default_limit]):
        iid = stable_node_id("instruction", source_sha, index, 1)
        nodes.append(
            GraphNode(
                iid,
                "instruction",
                str(ins.get("mnemonic") or "ins"),
                (SourceRange(0, 0),),
                0.85,
                "pe.disasm_entry",
                attributes={"address": ins.get("address"), "operands": ins.get("operands"), "observation": "hypothesis"},
            )
        )
        edges.append(GraphEdge(stable_node_id("edge", source_sha, index, 3), "contains", region_id, iid, 0.85, ("capstone",)))
    return nodes
