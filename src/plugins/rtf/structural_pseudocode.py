"""Registry-driven RTF structural pseudocode producer."""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple


def _load_registry() -> Dict[str, Any]:
    hex_root = Path(__file__).resolve().parents[2]
    lab_root = hex_root.parent
    path = lab_root / "config" / "rtf_parser_profiles" / "registry.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing RTF parser registry: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _escape_c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _scan_groups(data: bytes, destinations: Sequence[str]) -> List[Tuple[int, int, str]]:
    text = data.decode("latin-1", errors="replace")
    found: List[Tuple[int, int, str]] = []
    for dest in destinations:
        pattern = re.compile(r"\{\\(" + re.escape(str(dest)) + r")", re.IGNORECASE)
        for match in pattern.finditer(text):
            start = match.start()
            depth = 0
            end = start
            for idx in range(start, len(text)):
                char = text[idx]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx + 1
                        break
            if end > start:
                found.append((start, end - start, str(dest)))
    found.sort(key=lambda item: item[0])
    return found


def _header_fields(text: str, control_words: Sequence[str]) -> List[str]:
    lines: List[str] = []
    for word in control_words:
        token = str(word)
        match = re.search(r"\\" + re.escape(token) + r"(-?\d+)?", text)
        if not match:
            continue
        value = match.group(1)
        if value is None:
            lines.append(f"    verified bool header_{token} = true;")
        else:
            lines.append(f"    verified int header_{token} = {value};")
    return lines


def produce_structural_lines(
    data: bytes,
    *,
    offset: int,
    length: int,
    registry: Mapping[str, Any] | None = None,
) -> Tuple[List[str], List[Tuple[int, int]]]:
    """Return pseudocode lines and parsed byte ranges (relative to slice)."""
    reg = dict(registry or _load_registry())
    chunk = data[offset : offset + length]
    text = chunk.decode("latin-1", errors="replace")
    destinations = [str(item) for item in reg.get("known_group_destinations") or []]
    header_words = [str(item) for item in reg.get("header_control_words") or []]

    lines = [
        f"verified struct RTFDocument region_0x{offset:X} {{",
        f"    verified size_t span_length = {length}U;",
    ]
    lines.extend(_header_fields(text[: min(len(text), 512)], header_words))

    painted: List[Tuple[int, int]] = []
    groups = _scan_groups(chunk, destinations)
    for index, (group_offset, group_len, dest) in enumerate(groups):
        painted.append((group_offset, group_offset + group_len))
        snippet = chunk[group_offset : group_offset + min(group_len, 96)]
        preview = snippet.decode("latin-1", errors="replace")
        preview = preview.replace("\r", " ").replace("\n", " ")
        lines.append(f"    verified group {dest}_group_{index} @ 0x{offset + group_offset:X}[{group_len}] = {_escape_c_string(preview)};")

    if not groups:
        lines.append("    inconclusive string header_probe = " + _escape_c_string(text[: min(120, len(text))]) + ";")

    lines.append("}")
    return lines, painted
