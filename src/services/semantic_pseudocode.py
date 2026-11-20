"""Evidence-preserving C-like presentation for non-executable binary data."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_semantic_pseudocode_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "semantic_pseudocode_policy.json"
    policy = json.loads(target.read_text(encoding="utf-8"))
    schema = json.loads((_root() / "schemas" / "semantic_pseudocode_policy.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"semantic pseudocode policy invalid: {errors[0].message}")
    return policy


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identifier(value: Any, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_]", "_", str(value or "")).strip("_")
    if not text:
        text = fallback
    if text[0].isdigit():
        text = f"node_{text}"
    return text


def _literal(value: Any, maximum: int) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    if maximum > 0 and len(encoded) > maximum:
        return json.dumps(encoded[: max(0, maximum - 3)] + "...", ensure_ascii=True)
    return encoded


def _range_for(node: Mapping[str, Any]) -> tuple[int, int] | None:
    attributes = dict(node.get("attributes") or {})
    if "offset" not in attributes or "length" not in attributes:
        return None
    try:
        offset, length = int(attributes["offset"]), int(attributes["length"])
    except (TypeError, ValueError):
        return None
    return (offset, length) if offset >= 0 and length >= 0 else None


def _byte_initializer(data: bytes) -> str:
    return ", ".join(f"0x{value:02X}" for value in data)


def _decode_text(data: bytes, renderer: Mapping[str, Any]) -> tuple[str, str] | None:
    errors = str(renderer["text_decode_errors"])
    for encoding in map(str, renderer["text_encodings"]):
        try:
            return data.decode(encoding, errors=errors), encoding
        except (LookupError, UnicodeDecodeError):
            continue
    return None


def _load_plaintext_tiers_policy(cfg: Mapping[str, Any]) -> Dict[str, Any]:
    from src.services.semantic_plaintext_tiers import load_semantic_plaintext_tiers_policy

    tiers_cfg = dict(cfg.get("plaintext_tiers") or {})
    policy_path = tiers_cfg.get("policy_path")
    if not policy_path:
        raise ValueError("semantic pseudocode policy missing plaintext_tiers.policy_path")
    path = Path(str(policy_path))
    if not path.is_absolute():
        path = (_root() / path).resolve()
    return load_semantic_plaintext_tiers_policy(path)


def _render_decoded_plaintext_line(
    text: str,
    *,
    encoding: str,
    offset: int,
    renderer: Mapping[str, Any],
    tiers_policy: Mapping[str, Any],
    identifier_suffix: str = "",
) -> List[str]:
    from src.services.semantic_plaintext_tiers import (
        classify_plaintext_tier,
        tier_presentation,
        verified_printable_bytes_comment,
    )

    tier_id = classify_plaintext_tier(text, policy=tiers_policy)
    presentation = tier_presentation(tier_id, policy=tiers_policy)
    name = f"span_0x{offset:X}{identifier_suffix}"
    literal = _literal(text, int(renderer["maximum_value_characters"]))
    lines = [
        f"    {presentation['truth_state']} {presentation['presentation_label']} const char {name}[] = {literal};"
    ]
    if tier_id == "verified_printable_bytes":
        lines.append(f"    /* {verified_printable_bytes_comment(policy=tiers_policy)} */")
    return lines


def render_semantic_graph(
    graph: Mapping[str, Any],
    *,
    source_bytes: bytes,
    policy: Mapping[str, Any] | None = None,
) -> List[str]:
    cfg = dict(policy or load_semantic_pseudocode_policy())
    renderer = dict(cfg["renderer"])
    tiers_policy = _load_plaintext_tiers_policy(cfg)
    admitted = set(map(str, renderer["admitted_truth_states"]))
    maximum_nodes = int(renderer["maximum_nodes"])
    renderable_types = set(map(str, renderer["renderable_range_node_types"]))
    type_priority = {name: index for index, name in enumerate(map(str, renderer["range_node_type_priority"]))}
    nodes = [
        node for node in graph.get("nodes") or []
        if str(node.get("truth_state") or "") in admitted
        and str(node.get("node_type") or "") in renderable_types
        and _range_for(node) is not None
    ]
    nodes.sort(key=lambda node: (_range_for(node), type_priority.get(str(node.get("node_type") or ""), len(type_priority)), str(node.get("node_id") or "")))
    unique_nodes = []
    seen_ranges = set()
    for node in nodes:
        source_range = _range_for(node)
        if source_range in seen_ranges:
            continue
        seen_ranges.add(source_range)
        unique_nodes.append(node)
    nodes = unique_nodes
    truncated = maximum_nodes > 0 and len(nodes) > maximum_nodes
    if maximum_nodes > 0:
        nodes = nodes[:maximum_nodes]
    lines = [
        "/* Semantic pseudocode: evidence view, not recovered source code. */",
        f"semantic_binary {_identifier(graph.get('graph_id'), 'graph')} {{",
    ]
    for node in nodes:
        node_type = _identifier(node.get("node_type"), "BinarySpan")
        node_name = _identifier(node.get("node_id"), "node")
        truth = str(node.get("truth_state") or "unknown")
        source_range = _range_for(node)
        offset, length = source_range
        available = source_bytes[offset:offset + length] if offset <= len(source_bytes) else b""
        raw_limit = int(renderer["maximum_raw_bytes_per_span"])
        classification_value = str((node.get("attributes") or {}).get("class") or "")
        classification = _identifier(classification_value, node_type)
        presentation = str((renderer.get("coverage_class_renderers") or {}).get(classification_value) or "bytes")
        lines.append(f"    /* {truth}; bytes(0x{offset:X}, {length}) */")
        if presentation == "text":
            text_limit = int(renderer["maximum_text_bytes_per_span"])
            text_bytes = available[:text_limit] if text_limit > 0 else available
            decoded = _decode_text(text_bytes, renderer)
            if decoded is not None and len(available) == length:
                text, encoding = decoded
                lines.extend(
                    _render_decoded_plaintext_line(
                        text,
                        encoding=encoding,
                        offset=offset,
                        renderer=renderer,
                        tiers_policy=tiers_policy,
                        identifier_suffix=f"_{node_name}",
                    )
                )
                if len(available) > len(text_bytes):
                    lines.append(f"    /* {len(available) - len(text_bytes)} more text bytes omitted by policy */")
                continue
            lines.append("    /* declared plaintext could not be decoded under the configured strict encodings; showing bytes */")
        shown = available[:raw_limit] if raw_limit > 0 else available
        lines.append(f"    {truth} byte {classification}_{node_name}[{length}] = {{")
        line_width = int(renderer["byte_initializer_line_bytes"])
        for line_offset in range(0, len(shown), line_width):
            suffix = "," if line_offset + line_width < len(shown) else ""
            lines.append(f"        {_byte_initializer(shown[line_offset:line_offset + line_width])}{suffix}")
        if len(available) > len(shown):
            lines.append(f"        /* {len(available) - len(shown)} more source bytes omitted by policy */")
        if len(available) != length:
            lines.append("        /* source range exceeds the loaded file */")
        lines.append("    };")
    if truncated:
        lines.append(f"    /* nodes truncated by policy: {len(graph.get('nodes') or []) - maximum_nodes} */")
    lines.append("}")
    return lines


def _verified_graph_for_path(path: Path, policy: Mapping[str, Any]) -> Mapping[str, Any] | None:
    discovery_cfg = dict(policy["discovery"])
    from src.services.candidate_lineage import discover_verified_run_for_rail

    source_sha = _sha256(path)
    discovery = discover_verified_run_for_rail(
        str(discovery_cfg["rail_id"]),
        source_sha,
        scan_limit=int(discovery_cfg["scan_limit"]),
    )
    if not discovery.get("verified"):
        return None
    inspected = dict(discovery.get("inspected") or {})
    graph_path = Path(str((inspected.get("artifacts") or {}).get("semantic_graph") or ""))
    if not graph_path.is_file():
        return None
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    if not bool((graph.get("validation") or {}).get("valid")):
        return None
    return graph


def _fallback_banner(*, policy: Mapping[str, Any]) -> str:
    from src.services.ui_policy import load_ui_policy

    panel = dict((load_ui_policy().get("panels") or {}).get("pseudocode_fallback") or {})
    text = str(panel.get("banner") or "").strip()
    if not text:
        raise ValueError("ui policy missing panels.pseudocode_fallback.banner")
    return text


def _full_decode_plaintext_segments(file_path: Path, cfg: Mapping[str, Any]) -> List[Dict[str, Any]]:
    from src.gui_evidence_presenter import discover_full_decode_run
    from src.services.ui_policy import load_ui_policy

    ui_policy = load_ui_policy()
    scan_limit = int((ui_policy.get("load_budgets") or {}).get(str(cfg.get("full_decode_discovery", {}).get("scan_limit_policy_key") or "scope_run_scan_limit")) or 256)
    source_sha = _sha256(file_path)
    inspected = discover_full_decode_run(source_sha, scan_limit=scan_limit)
    segments = list((inspected.get("coverage") or {}).get("segments") or [])
    return [dict(item) for item in segments if str(item.get("class") or "") == "verified_plaintext"]


def _render_plaintext_clusters(data: bytes, cfg: Mapping[str, Any], *, tiers_policy: Mapping[str, Any]) -> List[str]:
    from src.services.plaintext_runs import discover_printable_runs, discover_repeated_digest_clusters
    from src.services.semantic_plaintext_tiers import classify_cluster_tier, tier_presentation

    cluster_cfg = dict(cfg.get("plaintext_clusters") or {})
    minimum = int(cluster_cfg.get("minimum_occurrences") or 2)
    maximum_clusters = int(cluster_cfg.get("maximum_clusters") or 0)
    maximum_occurrences = int(cluster_cfg.get("maximum_occurrences_per_cluster") or 0)
    include_printable = bool(
        cluster_cfg.get("include_verified_printable_bytes_clusters", cluster_cfg.get("include_printable_representation_clusters"))
    )
    render_dialect = str(cluster_cfg.get("render_dialect") or "c_struct")
    if render_dialect != "c_struct":
        raise ValueError(f"unsupported plaintext cluster render dialect: {render_dialect}")

    runs = discover_printable_runs(data)
    clusters = discover_repeated_digest_clusters(runs, minimum_occurrences=minimum)
    selected: List[tuple[int, Dict[str, Any], str]] = []
    for index, cluster in enumerate(clusters):
        preview = str(cluster.get("preview") or "")
        cluster_tier = classify_cluster_tier(preview, policy=tiers_policy)
        if cluster_tier != "repeated_semantic_cluster" and not include_printable:
            continue
        selected.append((index + 1, cluster, cluster_tier))
        if maximum_clusters > 0 and len(selected) >= maximum_clusters:
            break

    if not selected:
        return []

    lines: List[str] = [
        "    struct byte_span {",
        "        uint64_t offset;",
        "        uint32_t length;",
        "    };",
        "    struct repeated_plaintext_cluster {",
        "        uint32_t occurrence_count;",
        "        uint32_t span_length;",
        "        const char *preview;",
        "    };",
        "    /* repeated digest clusters — mechanical candidates, not typed record families */",
    ]
    preview_limit = int(dict(cfg["renderer"]).get("maximum_value_characters") or 0)
    for cluster_index, cluster, cluster_tier in selected:
        preview = str(cluster.get("preview") or "")
        preview_literal = _literal(preview, preview_limit)
        spans = list(cluster.get("spans") or [])
        span_length = int(spans[0]["length"]) if spans else 0
        presentation = tier_presentation(cluster_tier, policy=tiers_policy)
        lines.append(
            f"    /* cluster_{cluster_index}: {presentation['truth_state']} {presentation['presentation_label']} */"
        )
        lines.append(f"    struct repeated_plaintext_cluster cluster_{cluster_index} = {{")
        lines.append(f"        .occurrence_count = {int(cluster['occurrence_count'])}U,")
        lines.append(f"        .span_length = {span_length}U,")
        lines.append(f"        .preview = {preview_literal},")
        lines.append("    };")
        listed = spans
        omitted = 0
        if maximum_occurrences > 0 and len(listed) > maximum_occurrences:
            omitted = len(listed) - maximum_occurrences
            listed = listed[:maximum_occurrences]
        lines.append(f"    struct byte_span cluster_{cluster_index}_occurrences[{len(listed)}] = {{")
        for occurrence_index, span in enumerate(listed):
            offset = int(span.get("offset") or 0)
            length = int(span.get("length") or 0)
            suffix = "," if occurrence_index + 1 < len(listed) else ""
            lines.append(f"        {{ .offset = 0x{offset:X}ULL, .length = {length}U }}{suffix}")
        lines.append("    };")
        if omitted > 0:
            lines.append(f"    /* cluster_{cluster_index}: {omitted} more occurrences omitted by policy */")
    return lines


def _render_unresolved_tail(data: bytes, renderer: Mapping[str, Any], *, painted_ranges: List[tuple[int, int]]) -> List[str]:
    maximum = int(renderer["maximum_fallback_bytes"])
    chunk_size = int(renderer["fallback_chunk_bytes"])
    shown = data[:maximum] if maximum > 0 else data
    lines: List[str] = []
    for offset in range(0, len(shown), chunk_size):
        end = min(len(shown), offset + chunk_size)
        if any(not (end <= start or offset >= stop) for start, stop in painted_ranges):
            continue
        chunk = shown[offset:end]
        lines.append(f"    unresolved byte data_0x{offset:X}[{len(chunk)}] = {{ {_byte_initializer(chunk)} }};")
    if len(data) > len(shown):
        lines.append(f"    /* {len(data) - len(shown)} more source bytes omitted by policy */")
    return lines


def _discover_structural_findings_path(path: Path, cfg: Mapping[str, Any]) -> Path | None:
    section = dict(cfg.get("structural_findings") or {})
    if not section.get("enabled"):
        return None
    source_sha = _sha256(path)
    rail_id = str(section.get("source_rail") or "")
    mode = str(section.get("discovery") or "")
    if mode == "learning_db" and rail_id:
        from src.services.learning_db import discover_rail_run_via_learning_db

        discovery = discover_rail_run_via_learning_db(rail_id, source_sha)
        if not discovery:
            return None
        artifacts = dict((discovery.get("run") or {}).get("artifacts") or {})
        manifest = artifacts.get("forensic_bundle_manifest")
        if manifest:
            candidate = Path(str(manifest)).resolve().parent / "findings.json"
            if candidate.is_file():
                return candidate
        bundle_root = artifacts.get("forensic_bundle")
        if bundle_root:
            candidate = Path(str(bundle_root)) / "findings.json"
            if candidate.is_file():
                return candidate
    return None


def _render_semantic_fallback_body(
    path: Path,
    data: bytes,
    cfg: Mapping[str, Any],
    *,
    range_offset: int = 0,
    range_length: int | None = None,
) -> List[str]:
    """Clusters + plaintext segments + unresolved tail for a byte range (full file when range covers all)."""
    file_size = len(data)
    span_end = file_size if range_length is None else min(file_size, range_offset + int(range_length))
    span_start = max(0, int(range_offset))
    if span_start >= span_end:
        return ["semantic_binary unresolved_source {", "}"]

    graph = _verified_graph_for_path(path, cfg)
    if graph is not None and span_start == 0 and span_end == file_size:
        return render_semantic_graph(graph, source_bytes=data, policy=cfg)
    if not bool((cfg.get("fallback") or {}).get("render_unresolved_file")):
        raise ValueError("no verified semantic graph matches the source")

    renderer = dict(cfg["renderer"])
    tiers_policy = _load_plaintext_tiers_policy(cfg)
    lines = [
        f"/* {_fallback_banner(policy=cfg)} */",
        "semantic_binary unresolved_source {",
    ]
    findings_path = _discover_structural_findings_path(path, cfg)
    if findings_path is not None:
        from src.services.forensic_bundle import render_structural_pseudocode_lines

        structural_lines = render_structural_pseudocode_lines(findings_path, data, policy=cfg)
        if structural_lines:
            lines.append("    /* structural preserved prefixes */")
            lines.extend(f"    {line}" for line in structural_lines)
    painted_ranges: List[tuple[int, int]] = []
    for segment in _full_decode_plaintext_segments(path, cfg):
        offset = int(segment.get("offset") or 0)
        length = max(1, int(segment.get("length") or 1))
        seg_end = offset + length
        if seg_end <= span_start or offset >= span_end:
            continue
        chunk = data[offset:offset + length]
        decoded = _decode_text(chunk, renderer)
        if decoded is None:
            lines.append(f"    /* verified_plaintext at 0x{offset:X}[{length}] failed strict decode; bytes omitted */")
            continue
        text, encoding = decoded
        lines.extend(
            _render_decoded_plaintext_line(
                text,
                encoding=encoding,
                offset=offset,
                renderer=renderer,
                tiers_policy=tiers_policy,
            )
        )
        painted_ranges.append((offset, offset + length))

    slice_data = data[span_start:span_end]
    cluster_lines = _render_plaintext_clusters(slice_data, cfg, tiers_policy=tiers_policy)
    if cluster_lines:
        if span_start != 0:
            cluster_lines = [
                re.sub(
                    r"0x([0-9A-Fa-f]+)ULL",
                    lambda match: f"0x{int(match.group(1), 16) + span_start:X}ULL",
                    line,
                )
                for line in cluster_lines
            ]
        lines.extend(cluster_lines)

    tail_painted = [
        (max(start, span_start) - span_start, min(stop, span_end) - span_start)
        for start, stop in painted_ranges
        if stop > span_start and start < span_end
    ]
    tail_lines = _render_unresolved_tail(slice_data, renderer, painted_ranges=tail_painted)
    if span_start != 0:
        tail_lines = [
            re.sub(
                r"data_0x([0-9A-Fa-f]+)",
                lambda match: f"data_0x{int(match.group(1), 16) + span_start:X}",
                line,
            )
            for line in tail_lines
        ]
    lines.extend(tail_lines)
    lines.append("}")
    return lines


def render_semantic_fallback_for_byte_range(
    file_path: str | Path,
    *,
    offset: int = 0,
    length: int | None = None,
    policy: Mapping[str, Any] | None = None,
) -> List[str]:
    cfg = dict(policy or load_semantic_pseudocode_policy())
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise ValueError("semantic pseudocode source is not a file")
    data = path.read_bytes()
    return _render_semantic_fallback_body(path, data, cfg, range_offset=offset, range_length=length)


def render_semantic_pseudocode_for_path(
    file_path: str | Path,
    *,
    policy: Mapping[str, Any] | None = None,
) -> List[str]:
    """Render a verified graph, or coverage/plaintext clusters plus honest unresolved bytes."""
    cfg = dict(policy or load_semantic_pseudocode_policy())
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise ValueError("semantic pseudocode source is not a file")
    data = path.read_bytes()
    return _render_semantic_fallback_body(path, data, cfg, range_offset=0, range_length=len(data))
