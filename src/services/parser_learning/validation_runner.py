"""Registry-driven mechanical validation for parser-learning promotion gates."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


def _load_hook(spec: Mapping[str, Any]):
    module = str(spec.get("module") or "")
    name = str(spec.get("callable") or "")
    if not module or not name:
        raise ValueError("parser learning validation hook requires module and callable")
    hook = getattr(importlib.import_module(module), name, None)
    if not callable(hook):
        raise ValueError(f"parser learning validation hook is not callable: {module}.{name}")
    return hook


def _decode_fixture_payload(fixture: Mapping[str, Any]) -> bytes:
    encoding = str(fixture.get("payload_encoding") or "")
    raw = fixture.get("payload")
    if encoding == "base64":
        return base64.b64decode(str(raw or ""))
    if encoding == "hex":
        return bytes.fromhex(str(raw or ""))
    raise ValueError(f"unsupported negative fixture payload encoding: {encoding}")


def _fixture_workspace(root: Path, fixture: Mapping[str, Any], *, format_plugin: str) -> Path:
    from src.services.representation_sweep import sweep_region, write_representation_brief_cache

    payload = _decode_fixture_payload(fixture)
    span_length = int(fixture.get("span_length") or len(payload))
    if span_length <= 0:
        raise ValueError("negative fixture span_length must be positive")
    data = payload[:span_length]
    source_label = str(fixture.get("source_label") or fixture.get("fixture_id") or "")
    if not source_label:
        raise ValueError("negative fixture requires source_label or fixture_id")
    source_bytes = source_label.encode("utf-8")
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    region_id = str(fixture.get("region_id") or f"negative-{source_digest}")
    workspace = root / f"negative-{str(fixture.get('fixture_id') or source_digest)}"
    (workspace / "unknown").mkdir(parents=True, exist_ok=True)
    (workspace / "manifest.json").write_text(
        json.dumps(
            {
                "source_before": {"sha256": source_digest},
                "details": {"snapshot_id": f"negative-{source_digest}", "format_plugin": format_plugin},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    region = {"region_id": region_id, "span": {"offset": 0, "length": len(data)}, "neighbor_anchor_ids": []}
    (workspace / "unknown" / "regions.json").write_text(json.dumps([region], sort_keys=True), encoding="utf-8")
    write_representation_brief_cache(workspace, region_id, sweep_region(data, offset=0))
    return workspace


def check_deterministic_replay(
    workspaces: Sequence[Path],
    observations: Sequence[Mapping[str, Any]],
    *,
    candidates: Sequence[Mapping[str, Any]] | None = None,
    bundle: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Dict[str, Any]:
    del candidates, context
    normalizer = _load_hook(bundle["registry"]["normalizers"][0]["impl"])
    replay_ids: List[str] = []
    for root in workspaces:
        replay = normalizer(root, bundle=bundle)
        replay_ids.extend(str(item["observation_id"]) for item in replay)
    original_ids = sorted(str(item["observation_id"]) for item in observations)
    passed = sorted(replay_ids) == original_ids
    return {
        "result_name": "deterministic_replay",
        "passed": passed,
        "details": {"observation_count": len(original_ids), "replay_observation_count": len(replay_ids), "replay_match": passed},
    }


def check_negative_fixture_result(
    workspaces: Sequence[Path],
    observations: Sequence[Mapping[str, Any]],
    *,
    candidates: Sequence[Mapping[str, Any]] | None = None,
    bundle: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Dict[str, Any]:
    del workspaces, observations, candidates
    validation_cfg = dict(bundle["policy"].get("validation") or {})
    fixtures = list(validation_cfg.get("negative_fixtures") or [])
    if not fixtures:
        return {"result_name": "negative_fixture_result", "passed": False, "details": {"reason": "no_negative_fixtures_configured"}}

    from .core import run_parser_learning

    scratch = Path(str(context.get("scratch_root") or "")).resolve() if context.get("scratch_root") else None
    if scratch is None:
        return {"result_name": "negative_fixture_result", "passed": False, "details": {"reason": "scratch_root_missing"}}

    format_plugin = str(context.get("format_plugin") or "")
    base_profile_id = str(context.get("base_profile_id") or "")
    if not format_plugin or not base_profile_id:
        return {"result_name": "negative_fixture_result", "passed": False, "details": {"reason": "format_context_missing"}}

    fixture_root = scratch / "negative_fixtures"
    fixture_root.mkdir(parents=True, exist_ok=True)
    outcomes = []
    for fixture in fixtures:
        workspace = _fixture_workspace(fixture_root, fixture, format_plugin=format_plugin)
        result = run_parser_learning(
            [workspace],
            output_workspace=fixture_root / str(fixture.get("fixture_id") or workspace.name),
            format_plugin=format_plugin,
            base_profile_id=base_profile_id,
            validation_results={"deterministic_replay": True, "negative_fixture_result": True, "no_coverage_regression": True, "no_graph_regression": True},
        )
        validations = json.loads((Path(result["artifact_root"]) / "validations" / "index.json").read_text(encoding="utf-8"))
        eligible = [item for item in validations if item.get("eligible")]
        forbid = bool(fixture.get("forbid_eligible_candidates", True))
        passed = (not eligible) if forbid else bool(eligible)
        outcomes.append(
            {
                "fixture_id": str(fixture.get("fixture_id") or ""),
                "candidate_count": int(result.get("candidate_count") or 0),
                "eligible_validation_count": len(eligible),
                "passed": passed,
            }
        )
    return {"result_name": "negative_fixture_result", "passed": all(item["passed"] for item in outcomes), "details": {"fixtures": outcomes}}


def check_no_coverage_regression(
    workspaces: Sequence[Path],
    observations: Sequence[Mapping[str, Any]],
    *,
    candidates: Sequence[Mapping[str, Any]] | None = None,
    bundle: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Dict[str, Any]:
    del candidates
    regression = dict((bundle["policy"].get("validation") or {}).get("regression") or {})
    baseline = context.get("coverage_baseline")
    if baseline is None:
        if regression.get("require_baseline_for_coverage"):
            return {"result_name": "no_coverage_regression", "passed": False, "details": {"reason": "coverage_baseline_missing"}}
        observed = _coverage_metrics(workspaces, observations)
        return {"result_name": "no_coverage_regression", "passed": True, "details": {"mode": "baseline_not_required", "observed": observed}}

    observed = _coverage_metrics(workspaces, observations)
    allowed_drop = float(regression.get("maximum_coverage_drop") or 0)
    baseline_regions = float(dict(baseline).get("region_count") or 0)
    observed_regions = float(observed["region_count"])
    drop = 0.0 if baseline_regions <= 0 else max(0.0, (baseline_regions - observed_regions) / baseline_regions)
    passed = drop <= allowed_drop
    return {
        "result_name": "no_coverage_regression",
        "passed": passed,
        "details": {"baseline": dict(baseline), "observed": observed, "coverage_drop": drop, "maximum_allowed_drop": allowed_drop},
    }


def check_no_graph_regression(
    workspaces: Sequence[Path],
    observations: Sequence[Mapping[str, Any]],
    *,
    candidates: Sequence[Mapping[str, Any]] | None = None,
    bundle: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Dict[str, Any]:
    del observations, candidates
    regression = dict((bundle["policy"].get("validation") or {}).get("regression") or {})
    baseline = context.get("graph_baseline")
    if baseline is None:
        if regression.get("require_baseline_for_graph"):
            return {"result_name": "no_graph_regression", "passed": False, "details": {"reason": "graph_baseline_missing"}}
        observed = _graph_metrics(workspaces)
        return {"result_name": "no_graph_regression", "passed": True, "details": {"mode": "baseline_not_required", "observed": observed}}

    observed = _graph_metrics(workspaces)
    allowed_drop = float(regression.get("maximum_graph_node_drop") or 0)
    baseline_nodes = float(dict(baseline).get("node_count") or 0)
    observed_nodes = float(observed["node_count"])
    drop = 0.0 if baseline_nodes <= 0 else max(0.0, (baseline_nodes - observed_nodes) / baseline_nodes)
    passed = drop <= allowed_drop
    return {
        "result_name": "no_graph_regression",
        "passed": passed,
        "details": {"baseline": dict(baseline), "observed": observed, "node_drop": drop, "maximum_allowed_drop": allowed_drop},
    }


def _coverage_metrics(workspaces: Sequence[Path], observations: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    region_ids = {(str(item["source_digest"]), str(item["region_id"])) for item in observations}
    workspace_regions = 0
    for root in workspaces:
        regions_path = root / "unknown" / "regions.json"
        if regions_path.is_file():
            workspace_regions += len(json.loads(regions_path.read_text(encoding="utf-8")))
    return {"region_count": len(region_ids), "workspace_region_entries": workspace_regions, "observation_count": len(observations)}


def _graph_metrics(workspaces: Sequence[Path]) -> Dict[str, Any]:
    node_count = 0
    edge_count = 0
    for root in workspaces:
        graph_path = root / "graph" / "snapshot.json"
        if not graph_path.is_file():
            continue
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        if isinstance(nodes, list):
            node_count += len(nodes)
        if isinstance(edges, list):
            edge_count += len(edges)
    return {"node_count": node_count, "edge_count": edge_count, "workspace_graph_files": sum(1 for root in workspaces if (root / "graph" / "snapshot.json").is_file())}


def run_validation_checks(
    workspaces: Sequence[str | Path],
    observations: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    roots = [Path(value).resolve() for value in workspaces]
    active_context = dict(context or {})
    checks = list((bundle.get("registry") or {}).get("validation_checks") or [])
    if not checks:
        raise ValueError("parser learning registry has no validation_checks")

    results = []
    facts: Dict[str, bool] = {}
    for spec in checks:
        result_name = str(spec.get("result_name") or "")
        if not result_name:
            raise ValueError("parser learning validation check requires result_name")
        outcome = _load_hook(spec["impl"])(roots, observations, candidates=candidates, bundle=bundle, context=active_context)
        if str(outcome.get("result_name") or "") != result_name:
            raise ValueError(f"validation hook returned mismatched result_name: {outcome.get('result_name')}")
        results.append(outcome)
        facts[result_name] = bool(outcome.get("passed"))

    artifact = {
        "schema_version": 1,
        "operation": "parser_learning_mechanical_validation",
        "checks": results,
        "facts": facts,
        "policy_digest": bundle["policy_digest"],
        "registry_digest": bundle["registry_digest"],
    }
    return {"facts": facts, "artifact": artifact}
