"""Shared binary runtime kernel — ByteSource, BinarySnapshot, format routing."""

from .byte_source import ByteSource
from .config import load_binary_dynamic_config, load_execution_policy, resolve_execution_policy
from .format_router import detect_format_plugin, route_format_plugin
from .interval_index import IntervalIndex
from .snapshot import BinarySnapshot, GraphEdge, GraphNode, SourceRange, stable_node_id

__all__ = [
    "BinarySnapshot",
    "ByteSource",
    "GraphEdge",
    "GraphNode",
    "IntervalIndex",
    "SourceRange",
    "detect_format_plugin",
    "load_binary_dynamic_config",
    "load_execution_policy",
    "resolve_execution_policy",
    "route_format_plugin",
    "stable_node_id",
]
