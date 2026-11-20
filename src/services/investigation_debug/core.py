"""Wave 0–7 investigation debug capture, classification, and deliverables."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from src.services.candidate_lineage import resolve_candidate_lineage, verify_candidate_lineage_chain
from src.services.full_decode import (
    build_full_decode_model_packet,
    inspect_full_decode_run,
    verify_full_decode_run,
)
from src.services.full_decode.core import load_full_decode_bundle
from src.services.live_investigation import load_live_investigation_policy, run_live_investigation_e2e
from src.services.unresolved_inference import inspect_unresolved_inference_run, run_unresolved_inference_e2e, verify_unresolved_inference_run


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _identity(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _preserved_debug_snapshot(preserved_path: Path) -> Dict[str, Any]:
    from src.services.preserved_binary_inference import inspect_preserved_binary_inference_run, verify_preserved_binary_inference_run

    path = preserved_path.resolve()
    run = _read(path)
    artifacts = dict(run.get("artifacts") or {})
    return {
        "run_id": run.get("run_id"),
        "status": run.get("status"),
        "verified": verify_preserved_binary_inference_run(path)["ok"],
        "run_path": str(path),
        "forensic_bundle_path": artifacts.get("forensic_bundle"),
        "forensic_bundle_manifest_path": artifacts.get("forensic_bundle_manifest"),
        "knowledge_coverage_path": artifacts.get("forensic_bundle_metrics"),
        "inspection": inspect_preserved_binary_inference_run(path),
    }


def _segment_overlap(start_a: int, length_a: int, start_b: int, length_b: int) -> int:
    end_a, end_b = start_a + length_a, start_b + length_b
    return max(0, min(end_a, end_b) - max(start_a, start_b))


def load_investigation_debug_policy(policy_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(policy_path).resolve() if policy_path else _root() / "config" / "investigation_debug_policy.json"
    policy = _read(path)
    required = {"schema_version", "policy_id", "revision", "artifact_root", "live_investigation_policy_path", "waves"}
    if set(policy) != required or int(policy["schema_version"]) != 1:
        raise ValueError("invalid investigation debug policy")
    live_path = (_root() / policy["live_investigation_policy_path"]).resolve()
    if not live_path.is_file():
        raise ValueError("investigation debug policy references missing live investigation policy")
    return {"policy": policy, "policy_path": str(path), "live_investigation_policy_path": str(live_path)}


def _provider_frontier_metrics(providers: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    output = {}
    for provider in providers:
        provider_id = str(provider["provider_id"])
        candidates = list(provider.get("candidates") or [])
        output[provider_id] = {
            "candidate_count": len(candidates),
            "frontier_empty": len(candidates) == 0,
            "proof_id_count": len(provider.get("proof_ids") or []),
            "verified": bool(provider.get("verified")),
        }
    return output


def _proof_span_union(run_root: Path) -> List[Dict[str, int]]:
    spans: List[Dict[str, int]] = []
    candidates_root = run_root / "candidates"
    if not candidates_root.is_dir():
        return spans
    for candidate_dir in candidates_root.iterdir():
        proof_path = candidate_dir / "proof_spans.json"
        if proof_path.is_file():
            for item in _read(proof_path):
                spans.append({"offset": int(item["offset"]), "length": int(item["length"])})
    return spans


def _coverage_metrics(coverage: Mapping[str, Any]) -> Dict[str, Any]:
    summary = dict(coverage.get("summary") or {})
    unresolved_segments = [item for item in coverage.get("segments") or [] if item.get("class") == "unresolved"]
    return {
        "coverage_complete": bool(coverage.get("coverage_complete")),
        "verified_plaintext_bytes": int(summary.get("verified_plaintext", 0)),
        "preserved_binary_bytes": int(summary.get("preserved_binary", 0)),
        "verified_decoded_binary_bytes": int(summary.get("verified_decoded_binary", 0)),
        "unresolved_bytes": int(summary.get("unresolved", 0)),
        "unresolved_segment_count": len(unresolved_segments),
        "unresolved_segments": [{"offset": int(item["offset"]), "length": int(item["length"]), "segment_id": str(item["segment_id"])} for item in unresolved_segments],
    }


def build_provider_gap_report(*, inspected: Mapping[str, Any], run_root: Path) -> Dict[str, Any]:
    coverage = inspected["coverage"]
    metrics = _coverage_metrics(coverage)
    proof_spans = _proof_span_union(run_root)
    unresolved_mass = int(metrics["unresolved_bytes"])
    overlapped = 0
    gaps = []
    for segment in metrics["unresolved_segments"]:
        offset, length = int(segment["offset"]), int(segment["length"])
        segment_overlap = sum(_segment_overlap(offset, length, int(span["offset"]), int(span["length"])) for span in proof_spans)
        uncovered = max(0, length - segment_overlap)
        overlapped += segment_overlap
        if uncovered:
            gaps.append({"segment_id": segment["segment_id"], "offset": offset, "length": length, "proof_overlap_bytes": segment_overlap, "uncovered_bytes": uncovered})
    overlap_coefficient = (overlapped / unresolved_mass) if unresolved_mass else 1.0
    return {
        "schema_version": 1,
        "operation": "provider_gap_report",
        "run_id": inspected["run_id"],
        "unresolved_bytes": unresolved_mass,
        "proof_span_count": len(proof_spans),
        "proof_owned_changed_bytes": int((inspected.get("candidate") or {}).get("proof_owned_changed_bytes") or 0),
        "overlap_coefficient": round(overlap_coefficient, 6),
        "uncovered_unresolved_bytes": unresolved_mass - overlapped,
        "gap_segments": gaps,
        "provider_frontier": _provider_frontier_metrics(inspected.get("providers") or []),
    }


def _multi_turn_policy_scan() -> List[Dict[str, Any]]:
    rows = []
    config_root = _root() / "config"
    for path in sorted(config_root.glob("*policy.json")):
        policy = _read(path)
        boundary = policy.get("model_boundary") or {}
        allowed = list(boundary.get("allowed_actions") or [])
        if "request_registered_measurement" not in allowed:
            continue
        contracts = dict(boundary.get("action_contracts") or {})
        rows.append({"policy_file": str(path.relative_to(_root())), "policy_id": str(policy.get("policy_id") or ""), "allowed_actions": allowed, "measurement_contract_present": "request_registered_measurement" in contracts})
    return rows


def build_multi_turn_closure_report(*, live_summary: Mapping[str, Any], full_decode_run_path: Path) -> Dict[str, Any]:
    bundle = load_full_decode_bundle()
    registry_measurements = [str(item["measurement_id"]) for item in bundle["registry"]["registered_measurements"]]
    executed_path = Path(_read(full_decode_run_path)["run_root"]).resolve() / "measurements" / "executed.json"
    executed = _read(executed_path) if executed_path.is_file() else {"measurements": []}
    advisory_turns = [turn for turn in live_summary.get("turns") or [] if turn.get("phase") == "advisory_closure"]
    dead_letters = []
    for row in _multi_turn_policy_scan():
        policy_file = str(row["policy_file"]).replace("\\", "/")
        if policy_file in {"config/full_decode_policy.json", "config/full_decode_closure_policy.json"}:
            executor = "src.services.full_decode.core.execute_registered_measurements"
            status = "wired" if executed.get("measurements") or advisory_turns else "available_not_used"
        elif policy_file == "config/alternate_scope_policy.json":
            executor = "not_wired_to_full_decode"
            status = "advisory_only"
        else:
            executor = "unknown"
            status = "policy_only"
        dead_letters.append({**row, "policy_file": policy_file, "executor": executor, "status": status})
    return {
        "schema_version": 1,
        "operation": "multi_turn_closure_report",
        "registered_measurement_ids": registry_measurements,
        "executed_measurement_count": len(executed.get("measurements") or []),
        "advisory_turn_count": len(advisory_turns),
        "executed_new_work_turns": sum(1 for turn in advisory_turns if turn.get("executed_new_work")),
        "policy_rows": dead_letters,
        "class_g_resolved_for_full_decode": bool(executed.get("measurements") or advisory_turns),
    }


def build_gemma_advisory_assessment(*, packet: Mapping[str, Any], gemma_health: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    candidates = list(packet.get("candidates") or [])
    measurements = list(packet.get("measurements") or [])
    pending = [item for item in measurements if str(item.get("status")) == "pending"]
    if not candidates and not measurements:
        verdict = "irrelevant_empty_frontier"
    elif gemma_health and not gemma_health.get("healthy"):
        verdict = "server_unavailable"
    elif pending:
        verdict = "sufficient"
    elif candidates:
        verdict = "sufficient"
    else:
        verdict = "packet_builder_gap"
    return {
        "schema_version": 1,
        "operation": "gemma_advisory_assessment",
        "verdict": verdict,
        "candidate_count": len(candidates),
        "measurement_count": len(measurements),
        "pending_measurement_count": len(pending),
        "allowed_actions": list(packet.get("allowed_actions") or []),
        "gemma_health": gemma_health,
    }


def classify_debug_bottleneck(baseline: Mapping[str, Any]) -> Dict[str, Any]:
    evidence_refs: List[str] = []
    secondary: List[str] = []
    full_decode = baseline.get("full_decode") or {}
    verified = bool(full_decode.get("verified"))
    evidence_refs.append("full_decode.verified")
    if not verified:
        return {"schema_version": 1, "operation": "debug_classification", "primary_class": "integrity_failed", "secondary_classes": [], "evidence_refs": evidence_refs, "hypothesis_map": {"H5": "blocked_by_integrity"}}

    metrics = baseline.get("metrics") or {}
    unresolved_bytes = int(metrics.get("unresolved_bytes") or 0)
    evidence_refs.append("metrics.unresolved_bytes")
    if unresolved_bytes == 0:
        return {"schema_version": 1, "operation": "debug_classification", "primary_class": "complete", "secondary_classes": [], "evidence_refs": evidence_refs, "hypothesis_map": {}}

    provider_frontier = baseline.get("provider_frontier") or {}
    local = provider_frontier.get("local-transform-proof") or {}
    if local.get("frontier_empty"):
        evidence_refs.append("provider_frontier.local-transform-proof.frontier_empty")
        primary = "A"
        hypothesis_map = {"H1": "confirmed", "H5": "not_primary"}
    else:
        primary = None
        hypothesis_map = {"H1": "rejected"}

    overlap = float((baseline.get("provider_gap") or {}).get("overlap_coefficient") or 0.0)
    if overlap < 1.0 and primary is None:
        if int(metrics.get("proof_owned_changed_bytes") or 0) > 0:
            primary = "C"
            hypothesis_map["H2"] = "possible_span_mapping_gap"
            evidence_refs.append("provider_gap.overlap_coefficient")
        else:
            primary = "B"
            hypothesis_map["H2"] = "confirmed_provider_composition_gap"
            evidence_refs.append("provider_gap.overlap_coefficient")

    key_hunt = baseline.get("key_hunt") or {}
    if key_hunt.get("keys_found") and overlap < 1.0:
        secondary.append("D")
        hypothesis_map["H3"] = "confirmed_keyspace_bridge_gap"
        evidence_refs.append("key_hunt.keys_found")

    unresolved = baseline.get("unresolved_inference") or {}
    if unresolved.get("status") == "evidence_exhausted" and verified:
        secondary.append("E")
        hypothesis_map["H7"] = "possible_true_metadata"
        evidence_refs.append("unresolved_inference.status")

    closure = baseline.get("multi_turn_closure") or {}
    if not closure.get("class_g_resolved_for_full_decode"):
        secondary.append("G")
        hypothesis_map["H5"] = "confirmed_before_closure"
        evidence_refs.append("multi_turn_closure.class_g_resolved_for_full_decode")
    else:
        hypothesis_map["H5"] = "resolved_by_closure_orchestrator"

    if primary is None:
        primary = secondary.pop(0) if secondary else "B"
    return {
        "schema_version": 1,
        "operation": "debug_classification",
        "primary_class": primary,
        "secondary_classes": secondary,
        "evidence_refs": evidence_refs,
        "hypothesis_map": hypothesis_map,
    }


def capture_debug_baseline(
    source_path: str | Path,
    parent_path: str | Path,
    *,
    output_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    investigation_root: str | Path | None = None,
    lab_root: str | Path | None = None,
) -> Dict[str, Any]:
    bundle = load_investigation_debug_policy(policy_path)
    policy = bundle["policy"]
    waves = policy["waves"]
    source_file, parent_file = Path(source_path).resolve(), Path(parent_path).resolve()
    source_identity, parent_identity = _identity(source_file), _identity(parent_file)
    bundle_id = "investigation-debug-" + _digest({"source": source_identity["sha256"], "parent": parent_identity["sha256"], "policy": _digest(policy)})
    root = (Path(output_root).resolve() if output_root else (_root() / policy["artifact_root"]).resolve()) / bundle_id
    root.mkdir(parents=True, exist_ok=True)

    live_summary = None
    if waves.get("run_live_investigation"):
        live_summary = run_live_investigation_e2e(source_file, parent_file, output_root=root / "live_investigation", policy_path=bundle["live_investigation_policy_path"])
        _write(root / "live_investigation_summary.json", live_summary)
        full_decode_run_path = Path(live_summary["source_run_path"])
    else:
        raise ValueError("live investigation wave is required for debug baseline")

    inspected = inspect_full_decode_run(full_decode_run_path)
    verification = verify_full_decode_run(full_decode_run_path)
    run_root = Path(inspected["run_root"]).resolve()
    coverage_metrics = _coverage_metrics(inspected["coverage"])
    provider_frontier = _provider_frontier_metrics(inspected.get("providers") or [])
    provider_gap = build_provider_gap_report(inspected=inspected, run_root=run_root)
    packet = build_full_decode_model_packet(full_decode_run_path, policy_path=load_live_investigation_policy(bundle["live_investigation_policy_path"])["full_decode_policy_path"], registry_path=load_live_investigation_policy(bundle["live_investigation_policy_path"])["full_decode_registry_path"])

    lineage = None
    if waves.get("run_candidate_lineage"):
        lineage = resolve_candidate_lineage(source_sha256=source_identity["sha256"], file_path=str(source_file))
        _write(root / "candidate_lineage.json", lineage)

    unresolved = None
    if waves.get("run_unresolved_inference"):
        unresolved_run = run_unresolved_inference_e2e(full_decode_run_path, output_root=root / "unresolved_inference")
        unresolved_path = Path(unresolved_run["run_root"]) / "run.json"
        unresolved = {
            "run_id": unresolved_run["run_id"],
            "status": unresolved_run["status"],
            "verified": verify_unresolved_inference_run(unresolved_path)["ok"],
            "inspection": inspect_unresolved_inference_run(unresolved_path),
        }
        _write(root / "unresolved_inference.json", unresolved)

    preserved = None
    live_preserved = None
    preserved_ready = int(coverage_metrics['unresolved_bytes']) == 0
    if not preserved_ready and (waves.get('run_live_preserved_investigation') or waves.get('run_preserved_binary_inference')):
        preserved = {'skipped': True, 'status': 'not_verified', 'reason': 'upstream_has_unresolved_bytes'}
        live_preserved = dict(preserved)
    if waves.get("run_live_preserved_investigation") and preserved_ready:
        from src.services.preserved_binary_inference.live import run_live_preserved_investigation_e2e

        advisor = None
        if lab_root:
            lab = Path(lab_root).resolve()
            try:
                routing = _read(lab / "config" / "model_capability_routing.json")
                llm = _read(lab / "config" / "llm_config.json")
                capability = next(iter(routing["capabilities"].values()))
                agent_id = capability["agent_priority"][0]
                port = int(llm["agents"][agent_id]["launch_params"]["port"])
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
                    if response.status == 200:
                        import sys

                        if str(lab) not in sys.path:
                            sys.path.insert(0, str(lab))
                        from hexeditor_tools.llm import LLMClient
                        from src.services.preserved_binary_inference.live import gemma_preserved_advisory_action, load_live_preserved_investigation_policy

                        policy_bundle = load_live_preserved_investigation_policy()
                        client = LLMClient(f"http://127.0.0.1:{port}")

                        def advisor(packet):
                            return gemma_preserved_advisory_action(packet, policy_bundle=policy_bundle, llm_client=client)

            except (urllib.error.URLError, TimeoutError, RuntimeError, ImportError):
                advisor = None
        live_preserved = run_live_preserved_investigation_e2e(
            full_decode_run_path,
            output_root=root / "live_preserved_investigation",
            advisor=advisor,
        )
        _write(root / "live_preserved_investigation_summary.json", live_preserved)
        from src.services.preserved_binary_inference import inspect_preserved_binary_inference_run, verify_preserved_binary_inference_run

        preserved_path = Path(live_preserved["preserved_run_path"])
        preserved = _preserved_debug_snapshot(preserved_path)
        preserved["live_turn_count"] = live_preserved["turn_count"]
        _write(root / "preserved_binary_inference.json", preserved)
    elif waves.get("run_preserved_binary_inference") and preserved_ready:
        from src.services.preserved_binary_inference import inspect_preserved_binary_inference_run, run_preserved_binary_inference_e2e, verify_preserved_binary_inference_run

        preserved_run = run_preserved_binary_inference_e2e(full_decode_run_path, output_root=root / "preserved_binary_inference")
        preserved_path = Path(preserved_run["run_root"]) / "run.json"
        preserved = _preserved_debug_snapshot(preserved_path)
        _write(root / "preserved_binary_inference.json", preserved)

    key_hunt = {"skipped": True, "reason": "key_hunt_removed_from_standalone"}

    gemma_health = None
    if waves.get("attempt_gemma_health_check") and lab_root:
        live_policy = load_live_investigation_policy(bundle["live_investigation_policy_path"])
        lab = Path(lab_root).resolve()
        routing = _read(lab / "config" / "model_capability_routing.json")
        llm = _read(lab / "config" / "llm_config.json")
        capability = next(iter(routing["capabilities"].values()))
        agent_id = capability["agent_priority"][0]
        port = int(llm["agents"][agent_id]["launch_params"]["port"])
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
            gemma_health = {"healthy": response.status == 200, "agent_id": agent_id, "port": port, "server": payload}
        except (urllib.error.URLError, TimeoutError) as exc:
            gemma_health = {"healthy": False, "agent_id": agent_id, "port": port, "error": str(exc)}

    multi_turn_closure = build_multi_turn_closure_report(live_summary=live_summary, full_decode_run_path=full_decode_run_path)
    gemma_assessment = build_gemma_advisory_assessment(packet=packet, gemma_health=gemma_health)

    baseline = {
        "schema_version": 1,
        "operation": "debug_baseline",
        "bundle_id": bundle_id,
        "artifact_root": str(root),
        "source": source_identity,
        "parent": parent_identity,
        "input_digests": {"source_sha256": source_identity["sha256"], "parent_sha256": parent_identity["sha256"], "policy_digest": _digest(policy)},
        "full_decode": {"run_id": inspected["run_id"], "status": inspected["status"], "verified": verification["ok"], "run_path": str(full_decode_run_path), "candidate_id": inspected["candidate"]["candidate_id"]},
        "metrics": {
            **coverage_metrics,
            "proof_owned_changed_bytes": int(inspected["candidate"]["proof_owned_changed_bytes"]),
            "changed_bytes": int(inspected["candidate"]["changed_bytes"]),
            "provider_candidate_count": {key: value["candidate_count"] for key, value in provider_frontier.items()},
            "independent_regime_count": sum(1 for value in provider_frontier.values() if value["candidate_count"] > 0),
            "key_hunt_keys_found": bool(key_hunt.get("keys_found")),
            "key_hunt_phase_exhausted": bool(key_hunt.get("phase_exhausted")),
            "unresolved_graph_node_count": int(((unresolved or {}).get("inspection") or {}).get("graph_summary", {}).get("node_count") or 0),
            "owned_preserved_bytes": int((((preserved or {}).get("inspection") or {}).get("decision") or {}).get("owned_preserved_bytes") or 0),
            "unowned_preserved_bytes": int((((preserved or {}).get("inspection") or {}).get("decision") or {}).get("unowned_preserved_bytes") or 0),
            "structural_metadata_preserved_bytes": int((((preserved or {}).get("inspection") or {}).get("candidate") or {}).get("structural_metadata_bytes") or 0),
        },
        "provider_frontier": provider_frontier,
        "provider_gap": provider_gap,
        "live_investigation": {"investigation_id": live_summary["investigation_id"], "turn_count": live_summary["turn_count"], "final_status": live_summary["final_status"]},
        "candidate_lineage": {"node_count": len((lineage or {}).get("nodes") or []), "chain_ok": (lineage or {}).get("chain_ok")},
        "unresolved_inference": unresolved or {"skipped": True},
        "preserved_binary_inference": preserved or {"skipped": True},
        "preserved_run_path": (preserved or {}).get("run_path"),
        "forensic_bundle_path": (preserved or {}).get("forensic_bundle_path"),
        "live_preserved_investigation": live_preserved or {"skipped": True},
        "key_hunt": key_hunt,
        "multi_turn_closure": multi_turn_closure,
        "gemma_advisory": gemma_assessment,
        "model_packet_digest": _digest({"candidate_count": len(packet.get("candidates") or []), "measurement_count": len(packet.get("measurements") or [])}),
    }
    if lineage is not None:
        baseline["candidate_lineage"]["verified"] = verify_candidate_lineage_chain(lineage).get("ok")
    _write(root / "debug_baseline.json", baseline)
    return baseline


def run_investigation_debug_e2e(
    source_path: str | Path,
    parent_path: str | Path,
    *,
    output_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    investigation_root: str | Path | None = None,
    lab_root: str | Path | None = None,
) -> Dict[str, Any]:
    baseline = capture_debug_baseline(source_path, parent_path, output_root=output_root, policy_path=policy_path, investigation_root=investigation_root, lab_root=lab_root)
    root = Path(baseline["artifact_root"])
    classification = classify_debug_bottleneck(baseline)
    recommendation = {
        "schema_version": 1,
        "operation": "debug_recommendation",
        "primary_class": classification["primary_class"],
        "next_plan_pointers": [],
    }
    pointers = {
        "A": "docs/plans/binary_transform_inference_engine/plan.md",
        "B": "docs/plans/full_file_decode_to_plaintext_ascii/plan.md",
        "C": "docs/plans/full_file_decode_to_plaintext_ascii/plan.md",
        "D": "docs/plans/evidence_driven_keyspace_inference/plan.md",
        "E": "docs/plans/unresolved_byte_ownership_and_dependency_inference/plan.md",
        "F": "docs/plans/unresolved_byte_ownership_and_dependency_inference/plan.md",
        "G": "docs/plans/live_file_investigation_debug/plan.md",
    }
    recommendation["next_plan_pointers"] = [pointers.get(classification["primary_class"], "docs/plans/live_file_investigation_debug/plan.md")]
    for secondary in classification.get("secondary_classes") or []:
        plan = pointers.get(secondary)
        if plan and plan not in recommendation["next_plan_pointers"]:
            recommendation["next_plan_pointers"].append(plan)

    _write(root / "debug_classification.json", classification)
    _write(root / "provider_gap_report.json", baseline["provider_gap"])
    _write(root / "multi_turn_closure_report.json", baseline["multi_turn_closure"])
    _write(root / "gemma_advisory_assessment.json", baseline["gemma_advisory"])
    _write(root / "recommendation.json", recommendation)
    recommendation_md = "\n".join(
        [
            "# Investigation Debug Recommendation",
            "",
            f"primary_class={classification['primary_class']}",
            f"secondary_classes={','.join(classification.get('secondary_classes') or []) or 'none'}",
            "",
            "## Next plan pointers",
            *[f"- {item}" for item in recommendation["next_plan_pointers"]],
            "",
        ]
    )
    (root / "recommendation.md").write_text(recommendation_md, encoding="utf-8")
    if baseline.get("key_hunt") and not baseline["key_hunt"].get("skipped"):
        _write(root / "keyhunt_decode_bridge_report.json", {"schema_version": 1, "operation": "keyhunt_decode_bridge_report", "keys_found": baseline["key_hunt"].get("keys_found"), "proof_span_overlap_coefficient": baseline["provider_gap"]["overlap_coefficient"], "bridge_present": False})

    summary = {
        "schema_version": 1,
        "operation": "investigation_debug_e2e",
        "bundle_id": baseline["bundle_id"],
        "artifact_root": baseline["artifact_root"],
        "primary_class": classification["primary_class"],
        "secondary_classes": classification["secondary_classes"],
        "final_status": baseline["full_decode"]["status"],
        "verified": baseline["full_decode"]["verified"],
        "unresolved_bytes": baseline["metrics"]["unresolved_bytes"],
        "recommendation": recommendation,
    }
    _write(root / "summary.json", summary)
    return summary
