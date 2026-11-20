"""Live Gemma advisory loop over preserved-binary ownership runs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from .core import (
    _digest,
    _read,
    _root,
    _write,
    build_preserved_model_packet,
    load_preserved_bundle,
    run_preserved_binary_inference_e2e,
    validate_preserved_model_action,
    verify_preserved_binary_inference_run,
)


def load_live_preserved_investigation_policy(policy_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(policy_path).resolve() if policy_path else _root() / "config" / "live_preserved_investigation_policy.json"
    policy = _read(path)
    required = {
        "schema_version",
        "policy_id",
        "revision",
        "artifact_root",
        "preserved_inference_policy_path",
        "preserved_inference_registry_path",
        "closure",
        "gemma_live_output_root",
    }
    if set(policy) != required or int(policy["schema_version"]) != 1:
        raise ValueError("invalid live preserved investigation policy")
    inference_policy = (_root() / policy["preserved_inference_policy_path"]).resolve()
    inference_registry = (_root() / policy["preserved_inference_registry_path"]).resolve()
    bundle = load_preserved_bundle(inference_policy, inference_registry)
    return {
        "policy": policy,
        "preserved_inference_policy_path": str(inference_policy),
        "preserved_inference_registry_path": str(inference_registry),
        "preserved_bundle": bundle,
    }


def mechanical_preserved_advisory_action(packet: Mapping[str, Any]) -> Dict[str, Any]:
    clusters = list(packet.get("clusters") or [])
    if clusters:
        return {"action": "prioritize_existing_cluster", "target_id": str(clusters[0]["cluster_id"]), "reason": "mechanical closure prioritizes first preserved cluster"}
    hypotheses = list(packet.get("hypotheses") or [])
    if not hypotheses:
        raise RuntimeError("mechanical advisor has no clusters or hypotheses")
    return {"action": "rank_existing_hypothesis", "target_id": str(hypotheses[0]["target_id"]), "reason": "mechanical closure ranks first ownership hypothesis"}


def _generate_advisory(llm_client: Any, prompt: str, *, boundary: Mapping[str, Any], grammar: str) -> Mapping[str, Any]:
    kwargs = {"max_tokens": int(boundary["maximum_tokens"]), "temperature": float(boundary["temperature"])}
    try:
        return llm_client.generate(prompt, grammar=grammar, **kwargs)
    except RuntimeError as exc:
        message = str(exc).casefold()
        if "grammar" not in message or not any(token in message for token in ("parse", "sampler", "initialize")):
            raise
        return llm_client.generate(prompt, **kwargs)


def _advisory_text(response: Mapping[str, Any] | None) -> str:
    envelope = response or {}
    content = str(envelope.get("content") or "").strip()
    reasoning = str(envelope.get("reasoning_content") or "").strip()
    return "\n".join(part for part in (content, reasoning) if part)


def gemma_preserved_advisory_action(packet: Mapping[str, Any], *, policy_bundle: Mapping[str, Any], llm_client: Any) -> Dict[str, Any]:
    boundary = policy_bundle["preserved_bundle"]["policy"]["model_boundary"]
    decode_policy = policy_bundle["preserved_inference_policy_path"]
    decode_registry = policy_bundle["preserved_inference_registry_path"]
    maximum_attempts = int(boundary["maximum_attempts"])
    grammar = (_root() / boundary["grammar_path"]).read_text(encoding="utf-8")
    clusters = list(packet.get("clusters") or [])
    hypotheses = list(packet.get("hypotheses") or [])

    def validate_action(action: Mapping[str, Any]) -> Dict[str, Any]:
        return validate_preserved_model_action(action, packet, policy_path=decode_policy, registry_path=decode_registry)

    if clusters and int(packet.get("unowned_preserved_bytes") or 0) > 0:
        options = [{"number": index, **item} for index, item in enumerate(clusters, 1)]
        prompt = (
            "/no_think\nReturn JSON with action prioritize_existing_cluster and target_id matching a cluster_id from the packet. "
            "Do not invent offsets, bytes, keys, or promotion.\n"
            + json.dumps({"run_verified": packet["run_verified"], "unowned_preserved_bytes": packet["unowned_preserved_bytes"], "clusters": options}, sort_keys=True)
        )
    else:
        options = [{"number": index, **item} for index, item in enumerate(hypotheses[:32], 1)]
        prompt = (
            "/no_think\nReturn JSON with action rank_existing_hypothesis and target_id matching a proof target_id. "
            "Prefer structural_metadata gate passed when present. No offsets, bytes, keys, or promotion.\n"
            + json.dumps(
                {
                    "run_verified": packet["run_verified"],
                    "owned_preserved_bytes": packet["owned_preserved_bytes"],
                    "hypotheses": options,
                },
                sort_keys=True,
            )
        )
    active_prompt = prompt
    last_error = ""
    for _ in range(maximum_attempts):
        response = _generate_advisory(llm_client, active_prompt, boundary=boundary, grammar=grammar)
        content = _advisory_text(response)
        try:
            match = re.search(r"\{.*?\}", content, re.S)
            parsed = json.loads(match.group(0) if match else content)
            action = {
                "action": str(parsed.get("action") or ""),
                "target_id": str(parsed.get("target_id") or ""),
                "reason": str(parsed.get("reason") or "gemma preserved advisory"),
            }
            return validate_action(action)
        except (ValueError, json.JSONDecodeError, KeyError) as exc:
            last_error = str(exc)
            active_prompt = prompt + "\nValidator rejection: " + last_error + ". Correct the JSON only."
    fallback = mechanical_preserved_advisory_action(packet)
    fallback["reason"] = "gemma fallback after advisory rejection: " + last_error
    return validate_action(fallback)


def run_live_preserved_investigation_e2e(
    full_decode_run_path: str | Path,
    *,
    output_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    advisor: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    bundle = load_live_preserved_investigation_policy(policy_path)
    policy = bundle["policy"]
    inference_policy = bundle["preserved_inference_policy_path"]
    inference_registry = bundle["preserved_inference_registry_path"]
    base = Path(output_root).resolve() if output_root else (_root() / policy["artifact_root"]).resolve()
    base.mkdir(parents=True, exist_ok=True)
    upstream = Path(full_decode_run_path).resolve()
    investigation_id = "live-preserved-" + _digest({"upstream": str(upstream), "policy": _digest(policy)})
    root = base / investigation_id
    root.mkdir(parents=True, exist_ok=True)

    preserved = run_preserved_binary_inference_e2e(
        upstream,
        output_root=root / "preserved_inference",
        policy_path=inference_policy,
        registry_path=inference_registry,
    )
    preserved_path = Path(preserved["run_root"]) / "run.json"
    turns = [
        {
            "turn": 0,
            "phase": "preserved_ownership_inference",
            "status": preserved["status"],
            "run_path": str(preserved_path),
            "verified": verify_preserved_binary_inference_run(preserved_path)["ok"],
        }
    ]
    advisor_fn = advisor or mechanical_preserved_advisory_action
    maximum_turns = int(policy["closure"]["maximum_turns"])
    turn = 1
    while turn <= maximum_turns:
        packet = build_preserved_model_packet(preserved_path)
        action = dict(advisor_fn(packet))
        validate_preserved_model_action(action, packet, policy_path=inference_policy, registry_path=inference_registry)
        turns.append(
            {
                "turn": turn,
                "phase": "gemma_preserved_advisory",
                "accepted_action": action,
                "owned_preserved_bytes": packet["owned_preserved_bytes"],
                "unowned_preserved_bytes": packet["unowned_preserved_bytes"],
                "run_path": str(preserved_path),
                "verified": verify_preserved_binary_inference_run(preserved_path)["ok"],
            }
        )
        if int(packet["unowned_preserved_bytes"]) == 0 and turn >= 1:
            break
        turn += 1

    summary = {
        "schema_version": 1,
        "operation": "live_preserved_investigation_e2e",
        "investigation_id": investigation_id,
        "artifact_root": str(root),
        "full_decode_run_path": str(upstream),
        "preserved_run_path": str(preserved_path),
        "final_status": preserved["status"],
        "turn_count": len(turns),
        "turns": turns,
        "verified": verify_preserved_binary_inference_run(preserved_path)["ok"],
    }
    _write(root / "summary.json", summary)
    return summary
