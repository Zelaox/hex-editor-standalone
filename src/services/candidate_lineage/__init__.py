"""Unified candidate lineage discovery across forensic rails."""

from __future__ import annotations

from src.services.candidate_lineage.discover import discover_materialization_for_identity, discover_verified_run_for_rail
from src.services.candidate_lineage.graph_bridge import (
    candidate_graph_impact,
    full_decode_from_lineage,
    graph_path_from_lineage,
    unresolved_inference_from_lineage,
)
from src.services.candidate_lineage.present import (
    present_lineage_candidate_rows,
    present_lineage_hash_rows,
    present_lineage_overview_rows,
    present_lineage_rail_rows,
)
from src.services.candidate_lineage.resolve import resolve_candidate_lineage
from src.services.candidate_lineage.verify_chain import verify_candidate_lineage_chain

__all__ = [
    "candidate_graph_impact",
    "discover_materialization_for_identity",
    "discover_verified_run_for_rail",
    "full_decode_from_lineage",
    "graph_path_from_lineage",
    "unresolved_inference_from_lineage",
    "present_lineage_candidate_rows",
    "present_lineage_hash_rows",
    "present_lineage_overview_rows",
    "present_lineage_rail_rows",
    "resolve_candidate_lineage",
    "verify_candidate_lineage_chain",
]
