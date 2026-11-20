"""Region-routed pseudocode: decompiler, structural plugins, unknown fallback."""

from .core import (
    build_region_map_document,
    offset_for_pseudocode_line,
    range_for_pseudocode_selection,
    render_region_routed_bundle,
    render_region_routed_pseudocode_for_path,
    run_region_routed_pseudocode_job,
)
from .navigation import line_for_offset, offset_for_line, ranges_for_selection
from .policies import load_region_routing_policy

__all__ = [
    "build_region_map_document",
    "line_for_offset",
    "load_region_routing_policy",
    "offset_for_line",
    "offset_for_pseudocode_line",
    "range_for_pseudocode_selection",
    "ranges_for_selection",
    "render_region_routed_bundle",
    "render_region_routed_pseudocode_for_path",
    "run_region_routed_pseudocode_job",
]
