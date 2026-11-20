"""Multi-turn live investigation closure with Gemma advisory and measurement execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Sequence

from src.services.full_decode.core import (
    apply_full_decode_advisory_action,
    build_full_decode_model_packet,
    load_full_decode_bundle,
    run_full_decode_e2e,
    validate_full_decode_model_action,
    verify_full_decode_run,
)


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def load_live_investigation_policy(policy_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(policy_path).resolve() if policy_path else _root() / "config" / "live_investigation_policy.json"
    policy = _read(path)
    required = {"schema_version", "policy_id", "revision", "artifact_root", "full_decode_policy_path", "full_decode_registry_path", "closure", "gemma_live_output_root"}
    if set(policy) != required or int(policy["schema_version"]) != 1:
        raise ValueError("invalid live investigation policy")
    full_decode_policy = (_root() / policy["full_decode_policy_path"]).resolve()
    full_decode_registry = (_root() / policy["full_decode_registry_path"]).resolve()
    if not full_decode_policy.is_file() or not full_decode_registry.is_file():
        raise ValueError("live investigation policy references missing full-decode bundle files")
    bundle = load_full_decode_bundle(full_decode_policy, full_decode_registry)
    return {"policy": policy, "full_decode_policy_path": str(full_decode_policy), "full_decode_registry_path": str(full_decode_registry), "full_decode_bundle": bundle}


def mechanical_advisory_action(packet: Mapping[str, Any]) -> Dict[str, Any]:
    pending = [item for item in packet.get("measurements", []) if str(item.get("status")) == "pending"]
    if pending:
        return {"action": "request_registered_measurement", "measurement_ids": [str(pending[0]["measurement_id"])], "reason": "mechanical closure executes the first pending registered measurement"}
    candidates = list(packet.get("candidates") or [])
    if not candidates:
        raise RuntimeError("mechanical advisor has no pending measurements or candidates")
    return {"action": "rank_existing_candidate", "candidate_id": str(candidates[0]["candidate_id"]), "reason": "mechanical closure ranks the verified frontier candidate"}


def _generate_advisory(llm_client: Any, prompt: str, *, boundary: Mapping[str, Any], grammar: str) -> Mapping[str, Any]:
    """Generate with GBNF when supported, retaining validator authority on fallback."""
    kwargs = {
        "max_tokens": int(boundary["maximum_tokens"]),
        "temperature": float(boundary["temperature"]),
    }
    try:
        return llm_client.generate(prompt, grammar=grammar, **kwargs)
    except RuntimeError as exc:
        message = str(exc).casefold()
        if "grammar" not in message or not any(token in message for token in ("parse", "sampler", "initialize")):
            raise
        return llm_client.generate(prompt, **kwargs)


def _advisory_text(response: Mapping[str, Any] | None) -> str:
    """Normalize chat runtimes that separate final and reasoning channels."""
    envelope = response or {}
    content = str(envelope.get("content") or "").strip()
    reasoning = str(envelope.get("reasoning_content") or "").strip()
    return "\n".join(part for part in (content, reasoning) if part)


def gemma_advisory_action(packet: Mapping[str, Any], *, lab_root: Path, policy_bundle: Mapping[str, Any], llm_client: Any) -> Dict[str, Any]:
    editor = _root()
    boundary = policy_bundle["full_decode_bundle"]["policy"]["model_boundary"]
    pending = [item for item in packet.get("measurements", []) if str(item.get("status")) == "pending"]
    candidates = list(packet.get("candidates") or [])
    decode_policy = policy_bundle["full_decode_policy_path"]
    decode_registry = policy_bundle["full_decode_registry_path"]
    maximum_attempts = int(boundary["maximum_attempts"])

    def validate_action(action: Mapping[str, Any]) -> Dict[str, Any]:
        return validate_full_decode_model_action(action, packet, policy_path=decode_policy, registry_path=decode_registry)

    if pending:
        options = [{"number": index, **item} for index, item in enumerate(pending, 1)]
        grammar_path = boundary["closure_grammar_path"]
        prompt = "/no_think\nReturn JSON with action request_registered_measurement and measurement_numbers as a one-element integer list. Pick exactly one pending measurement number. Do not invent offsets, scopes, transforms, bytes, keys, decryption, or promotion.\n" + json.dumps({"run_verified": packet["run_verified"], "pending_measurements": options}, sort_keys=True)
        numbers = " | ".join(f'"{index}"' for index in range(1, len(options) + 1))
        grammar = (_root() / grammar_path).read_text(encoding="utf-8").replace("__CANDIDATE_NUMBERS__", numbers)
        active_prompt = prompt
        last_error = ""
        for _ in range(maximum_attempts):
            response = _generate_advisory(llm_client, active_prompt, boundary=boundary, grammar=grammar)
            content = _advisory_text(response)
            try:
                match = re.search(r"\{.*?\}", content, re.S)
                parsed = json.loads(match.group(0) if match else content)
                selected = parsed.get("measurement_numbers")
                if (not isinstance(selected, list) or not selected) and isinstance(parsed.get("selected_candidate_number"), int):
                    selected = [parsed["selected_candidate_number"]]
                if not isinstance(selected, list) or not selected:
                    raise ValueError("measurement_numbers must be a non-empty list")
                measurement_ids = [str(options[int(number) - 1]["measurement_id"]) for number in selected if isinstance(number, int) and 1 <= int(number) <= len(options)]
                if not measurement_ids:
                    raise ValueError("selected measurement numbers did not resolve to pending measurements")
                action = {"action": "request_registered_measurement", "measurement_ids": measurement_ids, "reason": str(parsed.get("reason") or "gemma advisory measurement request")}
                return validate_action(action)
            except (ValueError, json.JSONDecodeError, KeyError, IndexError) as exc:
                last_error = str(exc)
                active_prompt = prompt + "\nValidator rejection: " + last_error + ". Correct the JSON only."
        if len(pending) == 1:
            return validate_action({"action": "request_registered_measurement", "measurement_ids": [str(pending[0]["measurement_id"])], "reason": "gemma fallback to sole pending measurement after advisory rejection: " + last_error})
        raise ValueError("Gemma exhausted configured advisory attempts for pending measurements: " + last_error)

    options = [{"number": index, **item} for index, item in enumerate(candidates, 1)]
    grammar_path = boundary["grammar_path"]
    prompt = "/no_think\nSelect exactly one existing candidate by number. Prefer passed gates and fewer unresolved bytes. Do not invent offsets, scopes, transforms, bytes, keys, decryption, or promotion. Return only required JSON.\n" + json.dumps({"run_verified": packet["run_verified"], "options": options}, sort_keys=True)
    numbers = " | ".join(f'"{index}"' for index in range(1, len(options) + 1))
    grammar = (_root() / grammar_path).read_text(encoding="utf-8").replace("__CANDIDATE_NUMBERS__", numbers)
    active_prompt = prompt
    last_error = ""
    for _ in range(maximum_attempts):
        response = _generate_advisory(llm_client, active_prompt, boundary=boundary, grammar=grammar)
        content = _advisory_text(response)
        try:
            match = re.search(r"\{.*?\}", content, re.S)
            parsed = json.loads(match.group(0) if match else content)
            selected = parsed.get("selected_candidate_number")
            if not isinstance(selected, int) or not 1 <= selected <= len(options):
                raise ValueError("candidate number is outside the mechanical packet")
            action = {"action": "rank_existing_candidate", "candidate_id": str(options[selected - 1]["candidate_id"]), "reason": str(parsed.get("reason") or "gemma advisory rank")}
            return validate_action(action)
        except (ValueError, json.JSONDecodeError, KeyError) as exc:
            last_error = str(exc)
            active_prompt = prompt + "\nValidator rejection: " + last_error + ". Correct the JSON only."
    raise ValueError("Gemma exhausted configured advisory attempts for candidate ranking: " + last_error)


def run_live_investigation_e2e(
    source_path: str | Path,
    parent_path: str | Path,
    *,
    output_root: str | Path | None = None,
    policy_path: str | Path | None = None,
    advisor: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    lab_root: str | Path | None = None,
) -> Dict[str, Any]:
    bundle = load_live_investigation_policy(policy_path)
    policy = bundle["policy"]
    decode_policy = bundle["full_decode_policy_path"]
    decode_registry = bundle["full_decode_registry_path"]
    base = Path(output_root).resolve() if output_root else (_root() / policy["artifact_root"]).resolve()
    base.mkdir(parents=True, exist_ok=True)
    investigation_id = "live-investigation-" + _digest({"source": str(Path(source_path).resolve()), "parent": str(Path(parent_path).resolve()), "policy": _digest(policy)})
    root = base / investigation_id
    root.mkdir(parents=True, exist_ok=True)

    run = run_full_decode_e2e(source_path, parent_path, output_root=root / "full_decode", policy_path=decode_policy, registry_path=decode_registry)
    run_path = Path(run["run_root"]) / "run.json"
    turns = [{"turn": 0, "phase": "initial_full_decode", "status": run["status"], "run_path": str(run_path), "verified": verify_full_decode_run(run_path)["ok"]}]
    advisor_fn = advisor or mechanical_advisory_action
    maximum_turns = int(policy["closure"]["maximum_turns"])

    turn = 1
    while run["status"] != "completed" and turn <= maximum_turns:
        packet = build_full_decode_model_packet(run_path, policy_path=decode_policy, registry_path=decode_registry)
        pending = [item for item in packet.get("measurements", []) if str(item.get("status")) == "pending"]
        if not pending and run["status"] in ("partial_unresolved", "evidence_exhausted"):
            break
        action = dict(advisor_fn(packet))
        result = apply_full_decode_advisory_action(run_path, action, policy_path=decode_policy, registry_path=decode_registry)
        run = _read(run_path)
        turns.append({"turn": turn, "phase": "advisory_closure", "accepted_action": action, "executed_new_work": bool(result.get("executed_new_work")), "status": run["status"], "run_path": str(run_path), "verified": verify_full_decode_run(run_path)["ok"]})
        if not result.get("executed_new_work"):
            break
        turn += 1

    summary = {"schema_version": 1, "operation": "live_investigation_e2e", "investigation_id": investigation_id, "artifact_root": str(root), "source_run_path": str(run_path), "final_status": run["status"], "turn_count": len(turns), "turns": turns, "verified": verify_full_decode_run(run_path)["ok"]}
    _write(root / "summary.json", summary)
    return summary
