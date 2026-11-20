"""Compile disjoint forensic knowledge byte metrics from artifact rails."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Sequence

from jsonschema import Draft202012Validator

_TAG_UNOWNED = 0
_TAG_OWNED = 1
_TAG_STRUCTURAL = 2
_TAG_SEMANTIC = 3


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def load_forensic_knowledge_metrics_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).resolve() if path else _root() / "config" / "forensic_knowledge_metrics_policy.json"
    policy = _read(target)
    required = {
        "schema_version",
        "policy_id",
        "revision",
        "display_decimal_places",
        "display_labels",
        "structural_admission",
        "semantic_admission",
        "inputs",
    }
    if set(policy) != required or int(policy["schema_version"]) != 1:
        raise ValueError("invalid forensic knowledge metrics policy")
    return {"policy": policy, "policy_path": str(target), "policy_digest": _digest(policy)}


def _percent(bytes_value: int, file_size: int, places: int) -> float:
    if file_size <= 0:
        return 0.0
    return round(100.0 * bytes_value / file_size, places)


def _mark_range(tags: MutableMapping[int, int], start: int, end: int, tag: int) -> None:
    lo, hi = max(0, start), end
    for index in range(lo, hi):
        if tag == _TAG_SEMANTIC:
            tags[index] = _TAG_SEMANTIC
        elif tag == _TAG_STRUCTURAL and tags.get(index, _TAG_UNOWNED) != _TAG_SEMANTIC:
            tags[index] = _TAG_STRUCTURAL
        elif tag == _TAG_OWNED and tags.get(index, _TAG_UNOWNED) == _TAG_UNOWNED:
            tags[index] = _TAG_OWNED


def _structural_byte_ranges(
    proofs: Sequence[Mapping[str, Any]],
    representations: Sequence[Mapping[str, Any]],
    dependencies: Mapping[str, Any],
    admission: Mapping[str, Any],
) -> List[tuple[int, int]]:
    gate_id = str(admission["ownership_gate_id"])
    gate_value = str(admission["ownership_gate_value"])
    edge_type = str(admission["dependency_edge_type"])
    dep_state = str(admission["dependency_state"])
    structural_spans = {
        str(item["span_id"])
        for item in proofs
        if str((item.get("gate_statuses") or {}).get(gate_id)) == gate_value
    }
    verified_deps = {
        str(item["source_span_id"])
        for item in dependencies.get("edges") or []
        if str(item.get("edge_type")) == edge_type and str(item.get("state")) == dep_state
    }
    targets = structural_spans & verified_deps
    ranges: List[tuple[int, int]] = []
    for representation in representations:
        if str(representation.get("span_id")) not in targets:
            continue
        offset = int(representation["offset"])
        width = int(representation["width"])
        ranges.append((offset, offset + width))
    return ranges


def _semantic_byte_ranges(
    source: bytes,
    coverage: Mapping[str, Any],
    tiers_policy: Mapping[str, Any],
    admission: Mapping[str, Any],
) -> List[tuple[int, int]]:
    from src.services.semantic_plaintext_tiers import classify_plaintext_tier

    allowed_classes = {str(item) for item in admission["coverage_classes"]}
    allowed_tiers = {str(item) for item in admission["presentation_tiers"]}
    ranges: List[tuple[int, int]] = []
    for segment in coverage.get("segments") or []:
        if str(segment.get("class")) not in allowed_classes:
            continue
        start = int(segment["offset"])
        end = start + int(segment["length"])
        chunk = source[start:end]
        text = None
        for encoding in ("utf-8", "ascii", "latin-1"):
            try:
                text = chunk.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            continue
        tier_id = classify_plaintext_tier(text, policy=tiers_policy)
        if str(tier_id) not in allowed_tiers:
            continue
        ranges.append((start, end))
    return ranges


def compile_knowledge_coverage(
    *,
    source: bytes,
    full_decode_coverage: Mapping[str, Any],
    preserved_overlay: Mapping[str, Any] | None = None,
    preserved_proofs: Sequence[Mapping[str, Any]] | None = None,
    preserved_representations: Sequence[Mapping[str, Any]] | None = None,
    preserved_dependencies: Mapping[str, Any] | None = None,
    full_decode_run_id: str | None = None,
    preserved_inference_run_id: str | None = None,
    policy_path: str | Path | None = None,
) -> Dict[str, Any]:
    bundle = load_forensic_knowledge_metrics_policy(policy_path)
    policy = bundle["policy"]
    file_size = int(full_decode_coverage.get("file_size") or len(source))
    if file_size != len(source):
        raise ValueError("knowledge metrics file_size mismatch with source bytes")
    if file_size <= 0:
        raise ValueError("knowledge metrics require non-empty source")

    overlay_segments = list((preserved_overlay or {}).get("segments") or [])
    overlay_by_id = {str(item["segment_id"]): item for item in overlay_segments}

    tags: Dict[int, int] = {index: _TAG_UNOWNED for index in range(file_size)}

    for segment in full_decode_coverage.get("segments") or []:
        start = int(segment["offset"])
        end = start + int(segment["length"])
        klass = str(segment.get("class"))
        if klass == "unresolved":
            continue
        if klass == "preserved_binary":
            overlay = overlay_by_id.get(str(segment.get("segment_id")))
            if overlay and str(overlay.get("ownership_state")) == "unowned":
                continue
        _mark_range(tags, start, end, _TAG_OWNED)

    if preserved_proofs and preserved_representations and preserved_dependencies:
        for start, end in _structural_byte_ranges(
            preserved_proofs,
            preserved_representations,
            preserved_dependencies,
            policy["structural_admission"],
        ):
            _mark_range(tags, start, end, _TAG_STRUCTURAL)

    from src.services.semantic_plaintext_tiers import load_semantic_plaintext_tiers_policy
    from src.services.semantic_pseudocode import load_semantic_pseudocode_policy

    pseudo_policy = load_semantic_pseudocode_policy()
    tiers_path = pseudo_policy["plaintext_tiers"]["policy_path"]
    tiers_policy = load_semantic_plaintext_tiers_policy(
        (_root() / tiers_path).resolve() if not Path(str(tiers_path)).is_absolute() else tiers_path
    )
    for start, end in _semantic_byte_ranges(source, full_decode_coverage, tiers_policy, policy["semantic_admission"]):
        _mark_range(tags, start, end, _TAG_SEMANTIC)

    counts = {
        _TAG_UNOWNED: 0,
        _TAG_OWNED: 0,
        _TAG_STRUCTURAL: 0,
        _TAG_SEMANTIC: 0,
    }
    for tag in tags.values():
        counts[tag] = counts.get(tag, 0) + 1

    semantic_coverage_bytes = counts[_TAG_SEMANTIC]
    structural_only_bytes = counts[_TAG_STRUCTURAL]
    owned_but_unlabeled_bytes = counts[_TAG_OWNED]
    unowned_bytes = counts[_TAG_UNOWNED]
    verified_plaintext_bytes = int((full_decode_coverage.get("summary") or {}).get("verified_plaintext") or 0)

    if semantic_coverage_bytes + structural_only_bytes + owned_but_unlabeled_bytes + unowned_bytes != file_size:
        raise ValueError("knowledge metrics disjoint partition failed")

    places = int(policy["display_decimal_places"])
    owned_total = file_size - unowned_bytes
    result = {
        "schema_version": 1,
        "file_size": file_size,
        "semantic_coverage_bytes": semantic_coverage_bytes,
        "structural_only_bytes": structural_only_bytes,
        "owned_but_unlabeled_bytes": owned_but_unlabeled_bytes,
        "unowned_bytes": unowned_bytes,
        "verified_plaintext_bytes": verified_plaintext_bytes,
        "percentages": {
            "byte_ownership": _percent(owned_total, file_size, places),
            "structural_knowledge": _percent(structural_only_bytes, file_size, places),
            "semantic_knowledge": _percent(semantic_coverage_bytes, file_size, places),
            "plaintext_readable": _percent(verified_plaintext_bytes, file_size, places),
        },
        "policy_digest": bundle["policy_digest"],
        "inputs": {
            "full_decode_run_id": full_decode_run_id,
            "preserved_inference_run_id": preserved_inference_run_id,
            "parser_learning_handoff_digest": None,
        },
        "evidence_refs": [],
    }
    errors = list(Draft202012Validator(_read(_root() / "schemas" / "forensic_knowledge_coverage.schema.json")).iter_errors(result))
    if errors:
        raise ValueError(f"knowledge coverage schema failure: {errors[0].message}")
    return result


def compile_knowledge_coverage_from_runs(
    full_decode_run_path: str | Path,
    preserved_run_path: str | Path | None = None,
    *,
    policy_path: str | Path | None = None,
) -> Dict[str, Any]:
    from src.services.full_decode import verify_full_decode_run

    fd_path = Path(full_decode_run_path).resolve()
    fd_run = _read(fd_path / "run.json" if fd_path.is_dir() else fd_path)
    if not verify_full_decode_run(fd_path if fd_path.name == "run.json" else fd_path / "run.json").get("ok"):
        raise ValueError("full-decode run failed verification")
    source_path = Path(str(fd_run["source"]["path"]))
    source = source_path.read_bytes()
    coverage = _read(Path(fd_run["artifacts"]["coverage"]))
    overlay = proofs = representations = dependencies = None
    preserved_id = None
    if preserved_run_path:
        pr_path = Path(preserved_run_path).resolve()
        pr_run = _read(pr_path / "run.json" if pr_path.is_dir() else pr_path)
        from src.services.preserved_binary_inference import verify_preserved_binary_inference_run

        if not verify_preserved_binary_inference_run(pr_path if pr_path.name == "run.json" else pr_path / "run.json").get("ok"):
            raise ValueError("preserved run failed verification")
        preserved_id = str(pr_run["run_id"])
        artifacts = pr_run["artifacts"]
        overlay = _read(Path(artifacts["ownership_overlay"]))
        proofs = _read(Path(artifacts["ownership_proofs"]))
        representations = _read(Path(artifacts["representations"]))
        dependencies = _read(Path(artifacts["dependency_graph"]))
    elif int(coverage.get("summary", {}).get("preserved_binary") or 0) and policy_path is None:
        bundle = load_forensic_knowledge_metrics_policy()
        if bool(bundle["policy"]["inputs"]["require_preserved_run_when_preserved_bytes"]):
            raise ValueError("preserved run required when preserved_binary bytes exist")
    return compile_knowledge_coverage(
        source=source,
        full_decode_coverage=coverage,
        preserved_overlay=overlay,
        preserved_proofs=proofs,
        preserved_representations=representations,
        preserved_dependencies=dependencies,
        full_decode_run_id=str(fd_run["run_id"]),
        preserved_inference_run_id=preserved_id,
        policy_path=policy_path,
    )


def discover_knowledge_coverage_path(source_sha256: str) -> str | None:
    if not source_sha256:
        return None
    try:
        from src.services.learning_db import discover_rail_run_via_learning_db

        discovery = discover_rail_run_via_learning_db("preserved_binary_inference", source_sha256)
        if not discovery:
            return None
        run = discovery.get("run") or {}
        artifacts = run.get("artifacts") or {}
        bundle_path = artifacts.get("forensic_bundle_metrics")
        if bundle_path and Path(bundle_path).is_file():
            return str(Path(bundle_path).resolve())
        bundle_dir = artifacts.get("forensic_bundle")
        if bundle_dir:
            candidate = Path(bundle_dir) / "metrics" / "knowledge_coverage.json"
            if candidate.is_file():
                return str(candidate.resolve())
    except Exception:
        return None
    return None


def load_knowledge_coverage_for_source(source_sha256: str) -> Dict[str, Any] | None:
    path = discover_knowledge_coverage_path(source_sha256)
    if not path:
        return None
    return _read(Path(path))
