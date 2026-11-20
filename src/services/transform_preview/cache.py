"""Content-addressed preview cache."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from typing import Any, Dict, Mapping, MutableMapping, Optional


def cache_key(*, source_sha256: str, mode: str, offset: int, length: int, policy: Mapping[str, Any]) -> str:
    payload = {
        "source_sha256": str(source_sha256),
        "mode": str(mode),
        "offset": int(offset),
        "length": int(length),
        "policy_id": str(policy.get("policy_id") or ""),
        "policy_revision": int(policy.get("revision") or 0),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PreviewCache:
    def __init__(self, *, max_entries: int) -> None:
        self._max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        value = self._entries.get(str(key))
        if value is None:
            return None
        self._entries.move_to_end(str(key))
        return dict(value)

    def put(self, key: str, value: Mapping[str, Any]) -> None:
        self._entries[str(key)] = dict(value)
        self._entries.move_to_end(str(key))
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        self._entries.clear()


_GLOBAL: Optional[PreviewCache] = None


def shared_preview_cache(policy: Mapping[str, Any]) -> PreviewCache:
    global _GLOBAL
    cache_cfg = dict(policy.get("cache") or {})
    if not cache_cfg.get("enabled", True):
        return PreviewCache(max_entries=1)
    max_entries = int(cache_cfg.get("max_entries") or 256)
    if _GLOBAL is None or _GLOBAL._max_entries != max_entries:
        _GLOBAL = PreviewCache(max_entries=max_entries)
    return _GLOBAL
