"""Storage detection consumes the editor's existing format registry."""
from __future__ import annotations

try:
    from . import parsers
except ImportError:  # Minimal sandbox runs these stdlib-only modules as scripts.
    import parsers


def detect_bytes(data, registry, budget, hint=""):
    candidates = []
    for rule in registry.get("storage_rules", []):
        if rule.get("requires_hint") and hint != rule["id"]:
            continue
        if hint and hint != rule["id"]:
            continue
        if rule.get("prefix_hex") and not data.startswith(bytes.fromhex(rule["prefix_hex"])):
            continue
        if rule.get("footer_hex") and not data.endswith(bytes.fromhex(rule["footer_hex"])):
            continue
        try:
            if getattr(parsers, rule["probe"])(data, budget):
                candidates.append({k: rule[k] for k in ("id", "parser", "region_class", "confidence")})
        except (parsers.ParseError, ValueError, UnicodeError, RecursionError, OverflowError):
            continue
    return {"format_id": candidates[0]["id"] if candidates else "unknown", "candidates": candidates}


def detect_storage_header(path, registry):
    """Fixed-size byte comparisons only; full grammar validation stays in sandbox."""
    from pathlib import Path
    source = Path(path)
    with source.open("rb") as stream:
        prefix = stream.read(registry["header_read_bytes"])
        stream.seek(max(0, source.stat().st_size-registry["footer_read_bytes"]))
        footer = stream.read(registry["footer_read_bytes"])
    for rule in registry.get("storage_rules", []):
        if rule.get("prefix_hex") and prefix.startswith(bytes.fromhex(rule["prefix_hex"])):
            return rule["id"]
        if rule.get("footer_hex") and footer.endswith(bytes.fromhex(rule["footer_hex"])):
            return rule["id"]
    return None
