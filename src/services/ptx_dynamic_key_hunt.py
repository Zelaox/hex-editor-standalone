"""Policy-driven PTX key hunt with optional advisory model hypotheses."""

from __future__ import annotations

import hashlib
import importlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping

from src.services.ptx_runtime_analysis import ByteSource, analyze_runtime_source
from src.services.plaintext_profiles import score_plaintext_profiles


HypothesisProvider = Callable[[Mapping[str, Any], str], Iterable[Mapping[str, Any]]]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _id(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _profile_evidence(result: Mapping[str, Any]) -> Dict[str, Any]:
    """Return model-safe profile evidence without source paths or token hashes."""
    best = dict(result.get("best") or {})
    if not best:
        return {"available": False, "profile_match": False, "best": None}
    return {
        "available": bool(result.get("available")),
        "profile_match": bool(result.get("profile_match")),
        "best": {
            "profile_id": str(best.get("profile_id") or ""),
            "similarity": float(best.get("similarity") or 0.0),
            "components": {str(key): float(value) for key, value in (best.get("components") or {}).items()},
        },
    }


def load_key_hunt_policy(path: str | Path) -> Dict[str, Any]:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    required = ("schema_version", "budgets", "transform_registry", "capability")
    missing = [key for key in required if key not in policy]
    if missing:
        raise ValueError(f"key hunt policy missing: {', '.join(missing)}")
    return policy


def compile_hypothesis(hypothesis: Mapping[str, Any], policy: Mapping[str, Any], source_size: int) -> Dict[str, Any]:
    family = str(hypothesis.get("transform_family_id") or "")
    registry = dict(policy.get("transform_registry") or {})
    if family not in registry:
        raise ValueError("unknown transform family")
    ranges = list(hypothesis.get("source_ranges") or [])
    if not ranges:
        raise ValueError("hypothesis requires bounded source_ranges")
    normalized = []
    for item in ranges:
        offset, length = int(item.get("offset", -1)), int(item.get("length", -1))
        if offset < 0 or length <= 0 or offset + length > source_size:
            raise ValueError("hypothesis source range exceeds source bounds")
        normalized.append({"offset": offset, "length": length})
    key_hex = str((hypothesis.get("constraints") or {}).get("key_hex") or "").replace(" ", "")
    if bool(registry[family].get("requires_key_hex")):
        if not key_hex or len(key_hex) % 2:
            raise ValueError("XOR hypothesis requires an even-length key_hex constraint")
        bytes.fromhex(key_hex)
    executor = dict(registry[family].get("executor") or {})
    if not executor.get("module") or not executor.get("function"):
        raise ValueError("transform family has no registered executor")
    descriptor = {"transform_family_id": family, "source_ranges": normalized, "constraints": {"key_hex": key_hex}, "executor": executor, "registry_revision": policy.get("registry_revision")}
    descriptor["descriptor_id"] = _id(descriptor)
    return descriptor


def _apply_descriptor(source: bytes, descriptor: Mapping[str, Any]) -> bytes:
    executor = dict(descriptor.get("executor") or {})
    module = importlib.import_module(str(executor["module"]))
    function = getattr(module, str(executor["function"]), None)
    if not callable(function):
        raise ValueError("registered transform executor is not callable")
    return bytes(function(source, descriptor))


def _evidence_packet(source: ByteSource, snapshot: Mapping[str, Any], attempts: List[Mapping[str, Any]], policy: Mapping[str, Any], remaining: int) -> Dict[str, Any]:
    preview_limit = int((policy.get("budgets") or {}).get("max_preview_bytes", 256))
    packet = {
        "schema_version": 1,
        "source": {"sha256": source.identity["sha256"], "size": source.size},
        "snapshot": {"snapshot_id": snapshot["snapshot_id"], "signals": snapshot["signals"], "diagnostics": snapshot["diagnostics"][:32], "plaintext_profile": snapshot.get("plaintext_profile"), "coverage_summary": snapshot.get("coverage_summary"), "unknown_regions": [{"region_id": item.get("region_id"), "span": item.get("span"), "features": item.get("features"), "neighbor_anchor_ids": item.get("neighbor_anchor_ids")} for item in (snapshot.get("unknown_regions") or [])[:32]]},
        "preview_hex": source.read(0, min(source.size, preview_limit)).hex(),
        "previous_attempts": attempts[-int((policy.get("budgets") or {}).get("max_attempts_in_packet", 32)):],
        "remaining_candidate_budget": remaining,
        "allowed_transform_families": sorted((policy.get("transform_registry") or {}).keys()),
    }
    packet["packet_id"] = _id(packet)
    return packet


def run_dynamic_key_hunt(
    source_path: str | Path,
    policy: Mapping[str, Any],
    *,
    hypothesis_provider: HypothesisProvider | None = None,
    checkpoint_path: str | Path | None = None,
) -> Dict[str, Any]:
    source = ByteSource.from_path(source_path, max_bytes=int((policy.get("budgets") or {}).get("max_source_bytes", 268435456)))
    baseline = analyze_runtime_source(source, policy=policy.get("parser_policy")).to_dict()
    baseline_profile = _profile_evidence(score_plaintext_profiles(source.bytes()))
    baseline["plaintext_profile"] = baseline_profile
    budgets = dict(policy.get("budgets") or {})
    max_candidates = max(0, int(budgets.get("max_candidates", 256)))
    max_seconds = max(0.01, float(budgets.get("max_seconds", 60)))
    started = time.monotonic()
    attempts: List[Dict[str, Any]] = []
    seen: set[str] = set()
    checkpoint = Path(checkpoint_path).expanduser().resolve() if checkpoint_path else None
    if checkpoint and checkpoint.is_file():
        existing = json.loads(checkpoint.read_text(encoding="utf-8"))
        if existing.get("source_sha256") != source.identity["sha256"] or existing.get("policy_digest") != _id(policy):
            raise ValueError("checkpoint source or policy mismatch")
        attempts = list(existing.get("attempts") or [])
        seen = {str(item.get("descriptor_id")) for item in attempts}

    seed_hypotheses = list(policy.get("seed_hypotheses") or [])
    status = "exhausted"
    verified: Dict[str, Any] | None = None
    iteration = 0
    while len(attempts) < max_candidates and time.monotonic() - started < max_seconds:
        remaining = max_candidates - len(attempts)
        packet = _evidence_packet(source, baseline, attempts, policy, remaining)
        if iteration == 0 and seed_hypotheses:
            proposals = seed_hypotheses
            origin = "policy_seed"
        elif hypothesis_provider is not None:
            proposals = list(hypothesis_provider(packet, str(policy["capability"])))
            origin = "model_proposal"
        else:
            status = "model_unavailable" if not attempts else "exhausted"
            break
        novel = 0
        for hypothesis in proposals:
            if len(attempts) >= max_candidates or time.monotonic() - started >= max_seconds:
                break
            if origin == "model_proposal" and str((hypothesis.get("constraints") or {}).get("key_hex") or "").strip():
                attempts.append({"status": "rejected_before_execution", "reason": "model_direct_key_material_forbidden", "hypothesis_digest": _id(hypothesis), "origin": origin, "packet_id": packet["packet_id"]})
                continue
            try:
                descriptor = compile_hypothesis(hypothesis, policy, source.size)
            except (ValueError, TypeError) as exc:
                attempts.append({"status": "rejected_before_execution", "reason": str(exc), "hypothesis_digest": _id(hypothesis), "origin": origin, "packet_id": packet["packet_id"]})
                continue
            descriptor_id = str(descriptor["descriptor_id"])
            if descriptor_id in seen:
                continue
            seen.add(descriptor_id)
            novel += 1
            candidate_bytes = _apply_descriptor(source.bytes(), descriptor)
            candidate = analyze_runtime_source(ByteSource.from_bytes(candidate_bytes, descriptor=descriptor), policy=policy.get("parser_policy")).to_dict()
            candidate_profile = _profile_evidence(score_plaintext_profiles(candidate_bytes))
            non_identity = candidate["source"]["sha256"] != source.identity["sha256"]
            base_signals, signals = baseline["signals"], candidate["signals"]
            semantic_gain = float(signals["coverage_ratio"]) - float(base_signals["coverage_ratio"])
            printable_gain = float(signals["printable_ratio"]) - float(base_signals["printable_ratio"])
            baseline_similarity = float(((baseline_profile.get("best") or {}).get("similarity") or 0.0))
            candidate_similarity = float(((candidate_profile.get("best") or {}).get("similarity") or 0.0))
            profile_similarity_gain = candidate_similarity - baseline_similarity
            gate = dict(policy.get("promotion_gate") or {})
            changed_windows = sum(1 for item in descriptor["source_ranges"] if source.bytes()[int(item["offset"]):int(item["offset"])+int(item["length"])] != candidate_bytes[int(item["offset"]):int(item["offset"])+int(item["length"])])
            cross_window_ok = changed_windows >= int(gate.get("minimum_cross_window_agreement", 2))
            promote = bool(non_identity and cross_window_ok and semantic_gain >= float(gate.get("minimum_coverage_gain", 0.01)) and printable_gain >= float(gate.get("minimum_printable_gain", 0.0)) and signals.get("graph_consistent") and signals.get("timeline_consistent"))
            attempt = {"descriptor_id": descriptor_id, "descriptor": descriptor, "origin": origin, "packet_id": packet["packet_id"], "candidate_sha256": candidate["source"]["sha256"], "mechanical_evidence": {"non_identity": non_identity, "coverage_gain": semantic_gain, "printable_gain": printable_gain, "plaintext_profile": candidate_profile, "plaintext_profile_similarity_gain": round(profile_similarity_gain, 6), "plaintext_profile_is_advisory": True, "changed_windows": changed_windows, "cross_window_ok": cross_window_ok, "graph_consistent": signals.get("graph_consistent"), "timeline_consistent": signals.get("timeline_consistent")}, "candidate_validated": promote, "key_verified": promote, "promote_allowed": promote, "status": "verified" if promote else "rejected"}
            attempts.append(attempt)
            if promote:
                rerun = _apply_descriptor(source.bytes(), descriptor)
                if hashlib.sha256(rerun).hexdigest() == candidate["source"]["sha256"]:
                    verified, status = attempt, "promoted"
                    break
                attempt.update({"candidate_validated": False, "key_verified": False, "promote_allowed": False, "status": "failed_integrity"})
                status = "failed_integrity"
        if checkpoint:
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            temporary = checkpoint.with_suffix(checkpoint.suffix + ".tmp")
            temporary.write_text(json.dumps({"schema_version": 1, "source_sha256": source.identity["sha256"], "policy_digest": _id(policy), "attempts": attempts}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temporary.replace(checkpoint)
        if verified or status == "failed_integrity":
            break
        if novel == 0:
            status = "no_novel_hypotheses"
            break
        iteration += 1
    else:
        status = "budget_exhausted"
    return {"ok": status not in ("failed_integrity",), "operation": "ptx_dynamic_key_hunt", "status": status, "source_sha256": source.identity["sha256"], "baseline_snapshot_id": baseline["snapshot_id"], "capability": policy["capability"], "model_role": "advisory_only", "mechanical_authority": True, "attempts": attempts, "verified_candidate": verified, "keys_found": bool(verified), "materialized": False, "checkpoint": str(checkpoint) if checkpoint else None}
