"""Transform preview — RAW, preview, materialized and semantic presentation."""

from __future__ import annotations

from src.services.transform_preview.config import load_transform_preview_policy
from src.services.transform_preview.export import export_full_file_preview
from src.services.transform_preview.inspect import _verified_run, inspect_transform_preview, iter_full_file_preview, map_output_offset_to_source
from src.services.transform_preview.overlays import build_transform_preview_overlay_spans

__all__ = [
    "build_transform_preview_overlay_spans",
    "export_full_file_preview",
    "inspect_transform_preview",
    "iter_full_file_preview",
    "load_transform_preview_policy",
    "map_output_offset_to_source",
    "_verified_run",
]
