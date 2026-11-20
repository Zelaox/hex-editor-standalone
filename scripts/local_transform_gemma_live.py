"""Run live Gemma as a schema-bounded adviser over a verified local-transform frontier."""

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


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    lab = Path(args.lab_root).resolve(); editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from hexeditor_tools.llm import LLMClient
    from src.services.local_transform import build_local_transform_model_packet, validate_local_transform_model_action

    packet = build_local_transform_model_packet(Path(args.run).resolve())
    policy = json.loads((editor / "config" / "local_transform_policy.json").read_text(encoding="utf-8"))
    routing = json.loads((lab / "config" / "model_capability_routing.json").read_text(encoding="utf-8"))
    llm = json.loads((lab / "config" / "llm_config.json").read_text(encoding="utf-8"))
    capability = next(iter(routing["capabilities"].values()))
    agent_id = capability["agent_priority"][0]
    port = int(llm["agents"][agent_id]["launch_params"]["port"])
    boundary = policy["model_boundary"]
    eligible = set(packet["advisory_eligible_candidate_ids"])
    options = [{"number": index, **item, "mechanically_eligible": item["candidate_id"] in eligible} for index, item in enumerate(packet["candidates"], 1)]
    if not options:
        raise RuntimeError("verified packet has no mechanically generated candidate")
    prompt = "Select exactly one mechanically generated option by number. Do not invent parameters, offsets, scopes, transforms, decryption claims, or promotion. Return only required JSON.\n" + json.dumps({"run_verified": packet["run_verified"], "options": options}, sort_keys=True)
    grammar_template = (editor / boundary["grammar_path"]).read_text(encoding="utf-8")
    allowed_numbers = " | ".join(f'\"{index}\"' for index in range(1, len(options) + 1))
    grammar = grammar_template.replace("__CANDIDATE_NUMBERS__", allowed_numbers)
    client = LLMClient(f"http://127.0.0.1:{port}")
    attempts, accepted, content, started = [], None, "", time.monotonic()
    active_prompt = prompt
    for number in range(1, int(boundary["maximum_attempts"]) + 1):
        response = client.generate(active_prompt, max_tokens=int(boundary["maximum_tokens"]), temperature=float(boundary["temperature"]), grammar=grammar)
        content = str((response or {}).get("content") or "").strip()
        try:
            match = re.search(r"\{.*\}", content, re.S)
            parsed = json.loads(match.group(0) if match else content)
            selected = parsed.get("selected_candidate_number")
            if not isinstance(selected, int) or not 1 <= selected <= len(options):
                raise ValueError("candidate number is outside the mechanical packet")
            action = {"action": "rank_existing_candidate", "candidate_id": options[selected - 1]["candidate_id"], "reason": parsed.get("reason")}
            accepted = validate_local_transform_model_action(action, packet)
            attempts.append({"attempt": number, "accepted": True, "response": content})
            break
        except (ValueError, json.JSONDecodeError) as exc:
            attempts.append({"attempt": number, "accepted": False, "error": str(exc), "response": content})
            active_prompt = prompt + "\nValidator rejection: " + str(exc) + ". Correct the JSON only."
    if accepted is None:
        raise RuntimeError("Gemma exhausted configured advisory attempts: " + json.dumps(attempts, sort_keys=True))
    base = {"schema_version": 1, "operation": "local_transform_gemma_live", "source_run_id": packet["run_id"], "source_run_verified": True, "agent_id": agent_id, "port": port, "model_role": "advisory_only", "mechanical_authority": True, "authority_valid": True, "accepted_action": accepted, "attempts": attempts, "elapsed_seconds": round(time.monotonic() - started, 3), "packet_digest": _digest(packet)}
    result_id = "local-transform-gemma-" + _digest(base)
    root = Path(args.output).resolve() / result_id
    result = {**base, "result_id": result_id, "artifact_root": str(root)}
    _write(root / "packet.json", packet); _write(root / "result.json", result)
    print(json.dumps({"ok": True, "result_id": result_id, "artifact_root": str(root), "accepted_action": accepted}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
