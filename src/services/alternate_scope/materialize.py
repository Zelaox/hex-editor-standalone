"""Materialize a Gemma-selected, mechanically bounded transform candidate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from .core import verify_alternate_scope_run


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def materialize_gemma_scope_candidate(source_path: str | Path, alternate_run_path: str | Path, gemma_result_path: str | Path, destination: str | Path) -> Dict[str, Any]:
    source_file, run_file, gemma_file, target = (Path(value).expanduser().resolve() for value in (source_path, alternate_run_path, gemma_result_path, destination))
    if source_file == target:
        raise ValueError("scope candidate must not overwrite its source")
    verified = verify_alternate_scope_run(run_file)
    if not verified["ok"]:
        raise ValueError("alternate-scope run failed integrity verification")
    run, gemma = _read(run_file), _read(gemma_file)
    if not gemma.get("source_run_verified") or not gemma.get("authority_valid") or str(gemma.get("source_run_id")) != str(run["run_id"]):
        raise ValueError("Gemma result is not authority-valid for this alternate-scope run")
    source = source_file.read_bytes()
    source_sha = hashlib.sha256(source).hexdigest()
    if source_sha != str(run["source"]["sha256"]):
        raise ValueError("source digest does not match alternate-scope run")
    actions = list(gemma.get("accepted_actions") or [])
    if len(actions) != 1 or len(actions[0].get("hypothesis_ids") or []) != 1:
        raise ValueError("Gemma result must select exactly one hypothesis")
    selected_id = str(actions[0]["hypothesis_ids"][0])
    hypotheses = _read(Path(run["artifacts"]["hypotheses"]))
    selected = next((item for item in hypotheses if str(item["scope_hypothesis_id"]) == selected_id), None)
    if selected is None:
        raise ValueError("selected hypothesis is absent from the verified run")
    observations = _read(Path(run["artifacts"]["observations"]))
    material_observation = next((item for item in observations if str(item["observation_id"]) == str(selected["candidate_material_ref"])), None)
    if material_observation is None:
        raise ValueError("selected hypothesis has no admitted transform material")
    material = bytes.fromhex(str(material_observation["value_hex"]))
    if not material:
        raise ValueError("admitted transform material is empty")
    artifact = bytearray(source)
    changed, transformed = 0, 0
    for scope in selected["scopes"]:
        start, length = int(scope["offset"]), int(scope["length"])
        if start < 0 or length <= 0 or start + length > len(source):
            raise ValueError("selected scope is outside source bounds")
        before = source[start:start + length]
        after = bytes(value ^ material[index % len(material)] for index, value in enumerate(before))
        artifact[start:start + length] = after
        changed += sum(left != right for left, right in zip(before, after))
        transformed += length
    for preserve in selected["preserve_spans"]:
        start, length = int(preserve["offset"]), int(preserve["length"])
        if bytes(artifact[start:start + length]) != source[start:start + length]:
            raise ValueError("selected scope mutated a protected span")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_bytes(bytes(artifact))
    os.replace(temporary, target)
    output_sha = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = {"schema_version": 1, "operation": "materialize_gemma_scope_candidate", "status": "experimental_scope_candidate", "source_path": str(source_file), "source_sha256": source_sha, "source_preserved": hashlib.sha256(source_file.read_bytes()).hexdigest() == source_sha, "alternate_scope_run_id": run["run_id"], "gemma_result_id": gemma["result_id"], "selected_hypothesis_id": selected_id, "mechanical_non_passed_gate_ids": list(actions[0]["observed_non_passed_gate_ids"]), "destination": str(target), "output_sha256": output_sha, "bytes_written": len(artifact), "transformed_bytes": transformed, "changed_bytes": changed, "verified_decryption": False}
    manifest_path = target.with_suffix(target.suffix + ".manifest.json")
    _write_json(manifest_path, manifest)
    return {**manifest, "manifest_path": str(manifest_path)}
