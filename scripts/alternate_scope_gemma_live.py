"""Run live Gemma advisory inference over a verified alternate-scope artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    lab = Path(args.lab_root).resolve()
    editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from hexeditor_tools.llm import LLMClient
    from src.services.alternate_scope import build_alternate_scope_model_packet, load_alternate_scope_bundle, validate_model_actions, verify_alternate_scope_run

    run_path = Path(args.run).resolve()
    verified = verify_alternate_scope_run(run_path)
    if not verified["ok"]:
        raise RuntimeError("alternate-scope input failed integrity verification")
    packet = build_alternate_scope_model_packet(run_path)
    routing = json.loads((lab / "config" / "model_capability_routing.json").read_text(encoding="utf-8"))
    llm = json.loads((lab / "config" / "llm_config.json").read_text(encoding="utf-8"))
    capability = next(iter(routing["capabilities"].values()))
    agent_id = capability["agent_priority"][0]
    port = int(llm["agents"][agent_id]["launch_params"]["port"])
    model_options = [{"number": index, "strategy_id": item["strategy_id"], "independence_group_count": item["independence_group_count"], "gate_statuses": item["gate_statuses"]} for index, item in enumerate(packet["hypotheses"], 1)]
    model_input = {"terminal_state": packet["terminal_state"], "options": model_options}
    prompt = "Select exactly one existing option by number. Rank first by largest independence_group_count, then by largest count of passed gates, then by fewest failed gates. Do not claim promotion. Keep reason under 20 words. Return only the required JSON.\n" + json.dumps(model_input, sort_keys=True, default=str)
    started = time.monotonic()
    client = LLMClient(f"http://127.0.0.1:{port}")
    active_bundle = load_alternate_scope_bundle()
    maximum_attempts = int(active_bundle["policy"]["budgets"]["maximum_model_attempts"])
    grammar_path = (editor / active_bundle["policy"]["model_boundary"]["grammar_path"]).resolve()
    grammar = grammar_path.read_text(encoding="utf-8")
    attempts, validated, content, active_prompt = [], None, "", prompt
    for attempt_number in range(1, maximum_attempts + 1):
        response = client.generate(active_prompt, max_tokens=192, temperature=0.0, grammar=grammar)
        content = str((response or {}).get("content") or "").strip()
        try:
            match = re.search(r"\{.*\}", content, re.S)
            parsed = json.loads(match.group(0) if match else content)
            selected_number = parsed.get("selected_hypothesis_number")
            if not isinstance(selected_number, int) or not 1 <= selected_number <= len(packet["hypotheses"]):
                raise ValueError("Gemma selected an option outside the mechanical packet")
            reason = parsed.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("Gemma response reason is missing")
            selected = packet["hypotheses"][selected_number - 1]
            non_passed = sorted(gate_id for gate_id, status in selected["gate_statuses"].items() if status != "passed")
            actions = [{"action": "rank_existing_hypotheses", "hypothesis_ids": [selected["hypothesis_id"]], "observed_non_passed_gate_ids": non_passed, "reason": reason}]
            validated = validate_model_actions(actions, packet)
            attempts.append({"attempt": attempt_number, "accepted": True, "response": content})
            break
        except (ValueError, json.JSONDecodeError) as exc:
            attempts.append({"attempt": attempt_number, "accepted": False, "error": str(exc), "response": content})
            active_prompt = prompt + "\nMechanical validator rejection from the previous attempt: " + str(exc) + ". Return a corrected JSON object only; do not dispute or override the mechanical result."
    if validated is None:
        raise RuntimeError(f"Gemma exhausted the configured advisory validation attempts: {json.dumps(attempts, sort_keys=True)}")
    result_base = {"schema_version": 1, "operation": "alternate_scope_gemma_live", "agent_id": agent_id, "port": port, "source_run_id": packet["run_id"], "source_run_verified": True, "packet_digest": hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(), "prompt_bytes": len(prompt.encode("utf-8")), "elapsed_seconds": round(time.monotonic() - started, 3), "schema_valid": True, "authority_valid": True, "accepted_actions": validated, "attempts": attempts, "model_role": "advisory_only", "mechanical_authority": True, "raw_content": content}
    result_id = "gemma-live-" + hashlib.sha256(json.dumps(result_base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    root = Path(args.output).resolve() / result_id
    result = {**result_base, "result_id": result_id, "artifact_root": str(root)}
    _write(root / "packet.json", packet)
    _write(root / "result.json", result)
    print(json.dumps({"ok": True, "result_id": result_id, "artifact_root": str(root), "agent_id": agent_id, "elapsed_seconds": result["elapsed_seconds"], "attempt_count": len(attempts), "accepted_action_count": len(validated), "source_run_verified": True, "authority_valid": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
