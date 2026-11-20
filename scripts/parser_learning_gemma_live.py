"""Run Gemma over a bounded parser-learning packet and validate advisory actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    lab = Path(args.lab_root).resolve()
    editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from hexeditor_tools.llm import LLMClient
    from src.services.parser_learning import (
        build_gemma_packet,
        build_gemma_prompt,
        load_parser_learning_bundle,
        parse_gemma_model_content,
        validate_gemma_actions,
    )

    bundle = load_parser_learning_bundle()
    config = bundle["policy"]["gemma_packet"]
    routing = json.loads((lab / "config" / "model_capability_routing.json").read_text(encoding="utf-8"))
    llm = json.loads((lab / "config" / "llm_config.json").read_text(encoding="utf-8"))
    route = routing["capabilities"][config["capability_id"]]
    agent_id = route["agent_priority"][0]
    port = int(llm["agents"][agent_id]["launch_params"]["port"])
    run_path = Path(args.run).resolve()
    run = json.loads(run_path.read_text(encoding="utf-8-sig"))
    candidates = json.loads((run_path.parent / "candidates" / "index.json").read_text(encoding="utf-8-sig"))
    validations = json.loads((run_path.parent / "validations" / "index.json").read_text(encoding="utf-8-sig"))
    packet = build_gemma_packet(candidates, validations, bundle=bundle)
    prompt = build_gemma_prompt(packet, bundle=bundle)
    grammar_path = (editor / config["grammar_path"]).resolve()
    grammar = grammar_path.read_text(encoding="utf-8")
    response = LLMClient(f"http://127.0.0.1:{port}").generate(
        prompt,
        max_tokens=int(config["max_model_tokens"]),
        temperature=float(config["temperature"]),
        grammar=grammar,
    )
    if not response:
        raise RuntimeError("Gemma parser-learning request failed without a response payload")
    content = str(response.get("content") or "").strip()
    if not content:
        raise RuntimeError(f"Gemma parser-learning response content is empty: {json.dumps(response, sort_keys=True, default=str)}")
    actions = parse_gemma_model_content(content)
    validated = validate_gemma_actions(actions, packet, bundle=bundle)
    output = {
        "agent_id": agent_id,
        "port": port,
        "prompt_bytes": len(prompt.encode("utf-8")),
        "raw_content": content,
        "raw_actions": actions,
        "validation": validated,
    }
    target = run_path.parent / "gemma_actions.json"
    target.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": validated["ok"],
                "output": str(target),
                "accepted_count": len(validated["accepted"]),
                "rejected_count": len(validated["rejected"]),
                "agent_id": agent_id,
            },
            sort_keys=True,
        )
    )
    return 0 if validated["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
