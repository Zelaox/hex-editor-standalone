"""Bidirectional file-offset interval index for snapshot nodes."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping


class IntervalIndex:
    def __init__(self, nodes: Iterable[Mapping[str, Any]]):
        self._by_node: Dict[str, List[Mapping[str, Any]]] = {}
        self._by_offset: List[tuple[int, int, str]] = []
        for node in nodes:
            node_id = str(node.get("id") or "")
            for item in node.get("source_ranges") or []:
                offset = int(item.get("offset", -1))
                length = int(item.get("length", -1))
                if offset < 0 or length <= 0:
                    continue
                self._by_node.setdefault(node_id, []).append(item)
                self._by_offset.append((offset, offset + length, node_id))
        self._by_offset.sort()

    def nodes_for_range(self, offset: int, length: int) -> List[str]:
        end = offset + length
        hits: List[str] = []
        for start, stop, node_id in self._by_offset:
            if stop <= offset:
                continue
            if start >= end:
                break
            hits.append(node_id)
        return sorted(set(hits))

    def ranges_for_node(self, node_id: str) -> List[Mapping[str, Any]]:
        return list(self._by_node.get(node_id) or [])
