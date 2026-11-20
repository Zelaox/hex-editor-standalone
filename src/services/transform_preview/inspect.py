"""Main transform preview inspect entrypoint."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping

from src.services.transform_preview.cache import cache_key, shared_preview_cache
from src.services.transform_preview.composite import assemble_composite_text
from src.services.transform_preview.config import load_transform_preview_policy
from src.services.transform_preview.executor import execute_descriptor_chain, replay_materialization_scopes, verify_inverse_replay
from src.services.transform_preview.mapping import aggregate_mapping, compose_chain_mappings, mappings_for_spans, reject_unmapped_length_change
from src.services.transform_preview.resolver import partition_range


def _identity(path: Path) -> Dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": path.stat().st_size}


def _candidate_path(inspected: Mapping[str, Any], run: Mapping[str, Any] | None = None) -> Path | None:
    run_artifacts = dict((run or {}).get("artifacts") or {})
    candidates = [
        (inspected.get("candidate") or {}).get("artifact_path"),
        (inspected.get("candidate") or {}).get("path"),
        (inspected.get("exports") or {}).get("candidate"),
        (inspected.get("artifacts") or {}).get("candidate"),
        run_artifacts.get("candidate"),
    ]
    for value in candidates:
        if value and Path(str(value)).is_file():
            return Path(str(value)).resolve()
    return None


def _discover_lineage(rail: str, source_sha: str, scan_limit: int) -> Dict[str, Any]:
    from src.services.candidate_lineage import discover_verified_run_for_rail

    result = discover_verified_run_for_rail(rail, source_sha, scan_limit=scan_limit)
    return dict(result) if result.get("verified") else {}


def _hydrate_preview_context(discovery: Mapping[str, Any]) -> Dict[str, Any]:
    if not discovery:
        return {}
    run = dict(discovery.get("run") or {})
    inspected = dict(discovery.get("inspected") or {})
    artifacts = dict(run.get("artifacts") or {})
    inspected = {
        **inspected,
        "artifacts": {**dict(inspected.get("artifacts") or {}), **artifacts},
        "run": run,
        "run_root": str(inspected.get("run_root") or run.get("run_root") or ""),
    }
    return {
        "verified": True,
        "run": run,
        "inspected": inspected,
        "candidate_path": _candidate_path(inspected, run),
        "matched_role": str(discovery.get("matched_role") or ""),
    }


def _verified_run(rail: str, source_sha: str, scan_limit: int) -> Dict[str, Any]:
    discovery = _discover_lineage(rail, source_sha, scan_limit)
    ctx = _hydrate_preview_context(discovery)
    return dict(ctx.get("inspected") or {}) if ctx else {}


def _decode(data: bytes, encodings: list[str]) -> tuple[str, str] | None:
    for encoding in encodings:
        try:
            return data.decode(encoding, errors="strict"), encoding
        except (LookupError, UnicodeDecodeError):
            continue
    return None


def _semantic_text(graph: Mapping[str, Any], data: bytes, offset: int, policy: Mapping[str, Any]) -> tuple[str, str]:
    end = offset + len(data)
    segments = []
    for node in graph.get("nodes") or []:
        if str(node.get("node_type") or "") != "CoverageSegment":
            continue
        attributes = dict(node.get("attributes") or {})
        start, length = int(attributes.get("offset") or 0), int(attributes.get("length") or 0)
        stop = start + length
        if stop <= offset or start >= end:
            continue
        local_start, local_stop = max(start, offset), min(stop, end)
        segments.append((local_start, local_stop, str(attributes.get("class") or "unresolved")))
    segments.sort(key=lambda item: (item[0], item[1], item[2]))
    rows = []
    cursor = offset
    for local_start, local_stop, classification in segments:
        if local_start > cursor:
            rows.append(str(policy["unresolved_placeholder"]).format(offset_hex=f"0x{cursor:X}", length=local_start - cursor))
        if local_stop <= cursor:
            continue
        local_start = max(local_start, cursor)
        piece = data[local_start - offset : local_stop - offset]
        decoded = _decode(piece, list(map(str, policy["text_encodings"]))) if classification == "verified_plaintext" else None
        if decoded:
            rows.append(decoded[0])
        else:
            template = policy["unresolved_placeholder"] if classification == "unresolved" else policy["binary_placeholder"]
            rows.append(str(template).format(offset_hex=f"0x{local_start:X}", length=len(piece), classification=classification))
        cursor = local_stop
    if cursor < end:
        rows.append(str(policy["unresolved_placeholder"]).format(offset_hex=f"0x{cursor:X}", length=end - cursor))
    return "\n".join(rows), "semantic_graph"


def _identity_role(opened_sha: str, inspected: Mapping[str, Any], *, opened_path: Path | None = None) -> str:
    run = dict(inspected.get("run") or {})
    if not run:
        candidate = dict(inspected.get("candidate") or {})
        source_sha = str(candidate.get("source_sha256") or "")
        parent_sha = str(candidate.get("parent_sha256") or "")
        parent_path = ""
    else:
        source_sha = str((run.get("source") or {}).get("sha256") or "")
        parent_sha = str((run.get("parent") or {}).get("sha256") or "")
        parent_path = str((run.get("parent") or {}).get("path") or "")
    if opened_path is not None and parent_path:
        try:
            if opened_path.resolve() == Path(parent_path).expanduser().resolve():
                return "parent"
        except OSError:
            pass
    if opened_sha == source_sha:
        return "source"
    if opened_sha == parent_sha:
        return "parent"
    output_sha = str((inspected.get("candidate") or {}).get("output_sha256") or "")
    if output_sha and opened_sha == output_sha:
        return "candidate"
    return "unknown"


def _truth_state_for_mode(mode: str, state: str) -> str:
    if mode == "raw":
        return "RAW · SOURCE"
    if mode == "materialized":
        return "MATERIALIZED · VERIFIED CANDIDATE" if state == "verified_candidate" else f"MATERIALIZED · {state.upper()}"
    if mode == "semantic":
        return "SEMANTIC · VERIFIED FIELD" if state == "verified_graph" else f"SEMANTIC · {state.upper()}"
    if state == "verified_preview":
        return "PREVIEW · VERIFIED"
    if state == "source_only":
        return "PREVIEW · SOURCE ONLY"
    if state == "verified_candidate":
        return "PREVIEW · VERIFIED CANDIDATE"
    if state == "unavailable":
        return "PREVIEW · UNAVAILABLE"
    return f"PREVIEW · {state.upper()}"


def inspect_transform_preview(
    source_path: str | Path,
    *,
    offset: int,
    length: int,
    mode: str,
    policy: Mapping[str, Any] | None = None,
    use_cache: bool = True,
) -> Dict[str, Any]:
    cfg = dict(policy or load_transform_preview_policy())
    registered = {str(item["id"]) for item in cfg["modes"]}
    if mode not in registered:
        raise ValueError("unregistered transform preview mode")
    path = Path(source_path).expanduser().resolve()
    identity = _identity(path)
    offset = max(0, int(offset))
    length = max(0, min(int(length), identity["size"] - offset))
    key = cache_key(source_sha256=identity["sha256"], mode=mode, offset=offset, length=length, policy=cfg)
    if use_cache and dict(cfg.get("cache") or {}).get("enabled", True):
        cached = shared_preview_cache(cfg).get(key)
        if cached is not None:
            return dict(cached)

    raw = path.read_bytes()[offset : offset + length]
    selected, provider, state = raw, "source", "source"
    diagnostics: list[str] = []
    chain_steps: list[dict] = []
    conflicts: list[dict] = []
    composite_spans: list[dict] = []
    composite_rows: list[dict] = []
    coverage_gaps: list[dict] = []
    chain_mappings: list[dict] = []
    mapping: dict = {
        "kind": "one_to_one",
        "source_offset": offset,
        "source_length": len(raw),
        "output_offset": 0,
        "output_length": len(raw),
        "segments": [],
    }
    file_lineage = {"opened_sha256": identity["sha256"], "matched_role": "source", "lineage_sha256": identity["sha256"]}

    if mode == "materialized":
        ctx = _hydrate_preview_context(_discover_lineage(str(cfg["verified_candidate_rail"]), identity["sha256"], int(cfg["scan_limit"])))
        candidate = ctx.get("candidate_path") if ctx else None
        inspected = dict(ctx.get("inspected") or {}) if ctx else {}
        if candidate is None:
            state = "unavailable"
            diagnostics.append("no_verified_materialized_candidate")
        else:
            selected = candidate.read_bytes()[offset : offset + length]
            provider = str(candidate)
            state = "verified_candidate"
            file_lineage["matched_role"] = _identity_role(identity["sha256"], inspected, opened_path=path)
            composite_spans = [
                {
                    "offset": offset,
                    "length": length,
                    "presentation_class": "materialized_plaintext",
                    "truth_state": "verified",
                }
            ]

    elif mode == "transform_preview":
        discovery = _discover_lineage(str(cfg["verified_candidate_rail"]), identity["sha256"], int(cfg["scan_limit"]))
        ctx = _hydrate_preview_context(discovery)
        if not ctx:
            state = "unavailable"
            diagnostics.append("no_verified_preview_lineage")
        else:
            inspected = dict(ctx["inspected"])
            run = dict(ctx["run"])
            candidate = ctx.get("candidate_path")
            source_sha = str((run.get("source") or {}).get("sha256") or (inspected.get("candidate") or {}).get("source_sha256") or "")
            parent_sha = str((run.get("parent") or {}).get("sha256") or (inspected.get("candidate") or {}).get("parent_sha256") or "")
            file_lineage["lineage_sha256"] = source_sha or parent_sha or identity["sha256"]
            file_lineage["matched_role"] = _identity_role(identity["sha256"], inspected, opened_path=path)
            partition = partition_range(
                inspected=inspected,
                source_sha256=source_sha,
                parent_sha256=parent_sha,
                range_offset=offset,
                range_length=length,
                scope_sources=list(cfg.get("scope_sources") or []),
            )
            composite_spans = list(partition.get("spans") or [])
            conflicts = list(partition.get("conflicts") or [])
            descriptors = list(partition.get("descriptors") or [])
            parent_bytes = b""
            source_bytes = b""
            if candidate is not None:
                source_bytes = candidate.read_bytes()[offset : offset + length]
            parent_path = str((run.get("parent") or {}).get("path") or "")
            if parent_path and Path(parent_path).is_file():
                parent_bytes = Path(parent_path).read_bytes()[offset : offset + length]
            elif file_lineage["matched_role"] == "parent":
                parent_bytes = raw
            if descriptors:
                selected, chain_steps, replay_diag, chain_mappings = execute_descriptor_chain(
                    opened_slice=raw,
                    parent_slice=parent_bytes or raw,
                    source_slice=source_bytes or raw,
                    descriptors=descriptors,
                    identity_role=file_lineage["matched_role"],
                    range_offset=offset,
                    source_sha=identity["sha256"],
                    maximum_chain_depth=int(cfg.get("maximum_chain_depth") or 1),
                )
                diagnostics.extend(str(item.get("code") or item) for item in replay_diag)
                provider = "descriptor_replay"
                state = "verified_preview"
            else:
                selected = raw
                provider = "source"
                state = "source_only"
                diagnostics.append("no_verified_preview_descriptor_for_scope")
            inverse_entries = []
            artifacts = dict(inspected.get("artifacts") or {})
            inverse_path = Path(str(artifacts.get("inverse") or ""))
            if not inverse_path.is_file() and candidate is not None:
                inverse_path = candidate.parent / "inverse.json"
            if inverse_path.is_file() and descriptors:
                inverse_entries = json.loads(inverse_path.read_text(encoding="utf-8"))
                replay_check = verify_inverse_replay(
                    output_slice=selected,
                    parent_slice=parent_bytes or raw,
                    inverse_entries=inverse_entries,
                    range_offset=offset,
                )
                if not replay_check.get("ok"):
                    diagnostics.append("inverse_replay_mismatch")
            if descriptors and not reject_unmapped_length_change(
                source_length=len(raw),
                output_length=len(selected),
                chain_mappings=chain_mappings,
            ):
                diagnostics.append("length_change_without_block_mapping")
            span_mappings = mappings_for_spans(spans=composite_spans, range_offset=offset, range_length=length)
            mapping = aggregate_mapping(
                compose_chain_mappings(span_mappings, chain_mappings),
                range_offset=offset,
                output_length=len(selected),
            )

    decoded = _decode(selected, list(map(str, cfg["text_encodings"])))
    text = decoded[0] if decoded else str(cfg["binary_placeholder"]).format(offset_hex=f"0x{offset:X}", length=len(selected), classification="binary")
    encoding = decoded[1] if decoded else None

    if mode == "semantic":
        discovery = _discover_lineage(str(cfg["semantic_graph_rail"]), identity["sha256"], int(cfg["scan_limit"]))
        ctx = _hydrate_preview_context(discovery)
        inspected = dict(ctx.get("inspected") or {}) if ctx else {}
        graph_path = Path(str((inspected.get("artifacts") or {}).get("semantic_graph") or ""))
        if graph_path.is_file():
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            text, provider = _semantic_text(graph, raw, offset, cfg)
            state = "verified_graph"
        else:
            state = "unavailable"
            diagnostics.append("no_verified_semantic_graph")

    if mode in {"transform_preview", "materialized"} and composite_spans:
        text, composite_rows, coverage_gaps = assemble_composite_text(
            raw=raw,
            output=selected,
            spans=composite_spans,
            conflicts=conflicts,
            policy=cfg,
            range_offset=offset,
        )

    result = {
        "operation": "transform_preview_inspect",
        "mode": mode,
        "state": state,
        "truth_state": _truth_state_for_mode(mode, state),
        "source_sha256": identity["sha256"],
        "offset": offset,
        "length": length,
        "raw_bytes": raw,
        "output_bytes": selected,
        "decoded_text": text,
        "encoding": encoding,
        "provider": provider,
        "source_output_mapping": mapping,
        "diagnostics": diagnostics,
        "source_mutated": False,
        "chain_steps": chain_steps,
        "conflicts": conflicts,
        "composite_spans": composite_spans,
        "composite_rows": composite_rows,
        "coverage_gaps": coverage_gaps,
        "file_lineage": file_lineage,
    }
    if use_cache and dict(cfg.get("cache") or {}).get("enabled", True):
        shared_preview_cache(cfg).put(key, result)
    return result


def iter_full_file_preview(
    source_path: str | Path,
    *,
    mode: str,
    policy: Mapping[str, Any] | None = None,
) -> Iterator[Dict[str, Any]]:
    cfg = dict(policy or load_transform_preview_policy())
    export_cfg = dict(cfg.get("full_file_export") or {})
    page_bytes = int(export_cfg.get("page_bytes") or 0)
    max_total = int(export_cfg.get("max_total_bytes") or 0)
    if page_bytes <= 0 or max_total <= 0:
        raise ValueError("full_file_export requires page_bytes and max_total_bytes")
    path = Path(source_path).expanduser().resolve()
    size = min(_identity(path)["size"], max_total)
    cursor = 0
    while cursor < size:
        chunk = min(page_bytes, size - cursor)
        yield inspect_transform_preview(path, offset=cursor, length=chunk, mode=mode, policy=cfg)
        cursor += chunk


def map_output_offset_to_source(mapping: Mapping[str, Any], output_offset: int) -> Dict[str, Any]:
    local = int(output_offset) - int(mapping.get("output_offset") or 0)
    for segment in mapping.get("segments") or []:
        out_start = int(segment.get("output_offset") or 0)
        out_len = int(segment.get("output_length") or 0)
        if out_start <= local < out_start + out_len:
            delta = local - out_start
            if segment.get("exact") and str(segment.get("kind") or "") == "one_to_one":
                return {
                    "source_offset": int(segment.get("source_offset") or 0) + delta,
                    "exact": True,
                    "kind": segment.get("kind"),
                }
            return {
                "source_offset": int(segment.get("source_offset") or 0),
                "source_length": int(segment.get("source_length") or 0),
                "exact": False,
                "kind": segment.get("kind"),
            }
    return {"source_offset": int(mapping.get("source_offset") or 0) + local, "exact": False, "kind": "unknown"}
