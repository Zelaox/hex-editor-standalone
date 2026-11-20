"""Proof ledger compiler, protected-span registry, and run-completion hooks."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _cid(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value)}"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_schema(name: str, value: Any) -> None:
    schema = _read(_root() / "schemas" / name)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"{name} validation failed: {errors[0].message}")


def _hook(spec: Mapping[str, Any]):
    function = getattr(importlib.import_module(str(spec["module"])), str(spec["callable"]), None)
    if not callable(function):
        raise ValueError(f"invalid proof-ledger hook: {spec}")
    return function


def _strict_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set, actual = set(expected), set(value)
    if actual != expected_set:
        raise ValueError(f"invalid {label}: missing={sorted(expected_set - actual)}, extra={sorted(actual - expected_set)}")


def load_proof_ledger_bundle(
    policy_path: str | Path | None = None,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    policy_file = Path(policy_path).resolve() if policy_path else _root() / "config" / "proof_ledger_policy.json"
    registry_file = Path(registry_path).resolve() if registry_path else _root() / "config" / "proof_ledger_registry.json"
    policy, registry = _read(policy_file), _read(registry_file)
    _strict_keys(
        policy,
        {
            "schema_version",
            "policy_id",
            "revision",
            "artifact_root",
            "lineage_key_fields",
            "protection",
            "delta_triggers",
            "acceptance_axes",
            "preservation_gates",
            "composition",
            "advisory_packet",
            "audit",
        },
        "proof-ledger policy",
    )
    _strict_keys(
        registry,
        {
            "schema_version",
            "registry_id",
            "revision",
            "rail_adapters",
            "composition_evaluator",
            "delta_compiler",
            "delta_packet_builder",
            "frontier_accumulator",
        },
        "proof-ledger registry",
    )
    if int(policy["schema_version"]) != 1 or int(registry["schema_version"]) != 1:
        raise ValueError("unsupported proof-ledger schema version")
    for spec in registry["rail_adapters"]:
        _hook(spec["normalizer"])
        _hook(spec["axis_extractors"])
    for key in ("composition_evaluator", "delta_compiler", "delta_packet_builder", "frontier_accumulator"):
        _hook(registry[key])
    implementation_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {
        "policy": policy,
        "registry": registry,
        "policy_digest": _digest(policy),
        "registry_digest": _digest(registry),
        "implementation_digest": implementation_digest,
    }


def lineage_key_from_run(run: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> str:
    fields = list(bundle["policy"]["lineage_key_fields"])
    payload = {}
    for name in fields:
        if name in run:
            payload[name] = run[name]
            continue
        if name.endswith("_sha256"):
            stem = name.removesuffix("_sha256")
            block = run.get(stem)
            if isinstance(block, Mapping) and block.get("sha256"):
                payload[name] = block["sha256"]
                continue
        raise ValueError(f"lineage key field missing from run: {name}")
    return _digest(payload)


def span_identity(span: Mapping[str, Any]) -> Tuple[int, int]:
    return int(span["offset"]), int(span["length"])


def proof_span_id(record: Mapping[str, Any]) -> str:
    return str(record["proof_span_id"])


def _ledger_root(bundle: Mapping[str, Any]) -> Path:
    return (_root() / str(bundle["policy"]["artifact_root"])).resolve()


def _lineage_dir(bundle: Mapping[str, Any], key: str) -> Path:
    return _ledger_root(bundle) / "lineages" / key


def _adapter_for_rail(bundle: Mapping[str, Any], rail_id: str) -> Mapping[str, Any]:
    for item in bundle["registry"]["rail_adapters"]:
        if str(item["rail_id"]) == rail_id:
            return item
    raise ValueError(f"unsupported proof-ledger rail: {rail_id}")


def _normalize_run(run_path: Path, rail_id: str, *, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    adapter = _adapter_for_rail(bundle, rail_id)
    return _hook(adapter["normalizer"])(run_path, bundle=bundle)


def _is_protected(record: Mapping[str, Any], *, bundle: Mapping[str, Any]) -> bool:
    protection = bundle["policy"]["protection"]
    if str(record.get("coverage_class")) not in set(protection["protected_coverage_classes"]):
        return False
    if str(record.get("truth_state")) not in set(protection["protected_truth_states"]):
        return False
    if bool(protection.get("require_proof_reference")) and not list(record.get("evidence_refs") or []):
        return False
    required_gates = set(protection.get("required_producer_gate_ids") or [])
    if required_gates and not required_gates.issubset(set(record.get("gate_refs") or [])):
        return False
    return True


def _merge_span_records(existing: Mapping[str, Any], incoming: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    superseded_by = list(incoming.get("supersedes") or [])
    if superseded_by and proof_span_id(incoming) != proof_span_id(existing):
        merged["truth_state"] = "superseded"
        merged["supersedes"] = sorted(set(list(existing.get("supersedes") or []) + superseded_by))
        return merged
    for key in ("gate_refs", "evidence_refs", "counterexample_refs", "supersedes"):
        merged[key] = sorted(set(list(existing.get(key) or []) + list(incoming.get(key) or [])))
    if str(incoming.get("truth_state")) in {"proof_owned", "verified_plaintext"}:
        merged["truth_state"] = incoming["truth_state"]
    if incoming.get("candidate_sha256"):
        merged["candidate_sha256"] = incoming["candidate_sha256"]
    return merged


def compile_proof_ledger_from_run(
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    path = Path(run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    if not run_file.is_file():
        raise ValueError(f"run.json missing: {run_file}")
    run = _read(run_file)
    normalized = _normalize_run(run_file, rail_id, bundle=bundle)
    key = lineage_key_from_run(run, bundle=bundle)
    incoming_records = [dict(item) for item in normalized["proof_span_records"]]
    for record in incoming_records:
        _validate_schema("proof_span_record.schema.json", record)
    lineage_dir = _lineage_dir(bundle, key)
    registry_path = lineage_dir / "protected_registry.json"
    ledger_path = lineage_dir / "ledger.json"
    registry: Dict[str, Any]
    if registry_path.is_file():
        registry = _read(registry_path)
    else:
        registry = {
            "schema_version": 1,
            "lineage_key": key,
            "protected_spans": {},
            "updated_at": _utc_now(),
        }
    protected = dict(registry.get("protected_spans") or {})
    for record in incoming_records:
        span_id = proof_span_id(record)
        if span_id in protected:
            protected[span_id] = _merge_span_records(protected[span_id], record)
        else:
            protected[span_id] = record
        if not _is_protected(protected[span_id], bundle=bundle) and str(protected[span_id].get("truth_state")) != "superseded":
            protected.pop(span_id, None)
    registry["protected_spans"] = protected
    registry["protected_span_count"] = len(protected)
    registry["updated_at"] = _utc_now()
    ledger_entry = {
        "schema_version": 1,
        "lineage_key": key,
        "run_id": str(run.get("run_id") or ""),
        "rail_id": rail_id,
        "compiled_at": _utc_now(),
        "proof_span_records": incoming_records,
        "protected_span_count": len(protected),
        "axis_values": normalized.get("axis_values") or {},
    }
    ledger: Dict[str, Any]
    if ledger_path.is_file():
        ledger = _read(ledger_path)
    else:
        ledger = {"schema_version": 1, "lineage_key": key, "entries": []}
    ledger["entries"] = list(ledger.get("entries") or []) + [ledger_entry]
    ledger["latest_run_id"] = ledger_entry["run_id"]
    ledger["protected_span_count"] = len(protected)
    _write(registry_path, registry)
    _write(ledger_path, ledger)
    _write(
        lineage_dir / "runs" / f"{ledger_entry['run_id']}.json",
        {"run_path": str(run_file), "rail_id": rail_id, "compiled_at": ledger_entry["compiled_at"]},
    )
    from .frontier import accumulate_lineage_frontier

    frontier = accumulate_lineage_frontier(key, normalized.get("candidate_manifests") or [], bundle=bundle)
    _write(lineage_dir / "frontier.json", frontier)
    return {
        "ok": True,
        "lineage_key": key,
        "protected_span_count": len(protected),
        "run_id": ledger_entry["run_id"],
        "registry_path": str(registry_path),
        "ledger_path": str(ledger_path),
        "frontier_path": str(lineage_dir / "frontier.json"),
    }


def load_protected_spans(lineage_key: str, *, bundle: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    registry_path = _lineage_dir(bundle, lineage_key) / "protected_registry.json"
    if not registry_path.is_file():
        return []
    registry = _read(registry_path)
    return [dict(item) for item in dict(registry.get("protected_spans") or {}).values()]


def query_lineage_ledger(lineage_key: str, *, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    lineage_dir = _lineage_dir(bundle, lineage_key)
    registry_path = lineage_dir / "protected_registry.json"
    ledger_path = lineage_dir / "frontier.json"
    result: Dict[str, Any] = {"lineage_key": lineage_key, "exists": registry_path.is_file()}
    if registry_path.is_file():
        registry = _read(registry_path)
        result["protected_span_count"] = int(registry.get("protected_span_count") or 0)
        result["protected_spans"] = list(dict(registry.get("protected_spans") or {}).values())
    if ledger_path.is_file():
        result["frontier"] = _read(ledger_path)
    return result


def preservation_metrics(
    parent: bytes,
    candidate: bytes,
    protected_spans: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    lost, preserved, superseded_loss = [], [], []
    for record in protected_spans:
        offset, length = span_identity(record["span"])
        end = offset + length
        if end > len(parent) or end > len(candidate):
            lost.append(proof_span_id(record))
            continue
        proven_digest = str(record.get("proven_bytes_digest") or "")
        if not proven_digest:
            preserved.append(proof_span_id(record))
            continue
        candidate_digest = hashlib.sha256(candidate[offset:end]).hexdigest()
        if candidate_digest == proven_digest:
            preserved.append(proof_span_id(record))
        elif list(record.get("supersedes") or []):
            superseded_loss.append(proof_span_id(record))
        else:
            lost.append(proof_span_id(record))
    return {
        "lost_proof_owned_span_ids": lost,
        "preserved_proof_owned_span_ids": preserved,
        "superseded_loss_span_ids": superseded_loss,
        "lost_proof_owned_span_count": len(lost),
        "preserved_proof_owned_span_count": len(preserved),
    }


def check_preservation_gates(
    parent: bytes,
    candidate: bytes,
    protected_spans: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any],
    parent_plaintext_bytes: int = 0,
    candidate_plaintext_bytes: int = 0,
) -> Dict[str, Any]:
    metrics = preservation_metrics(parent, candidate, protected_spans)
    gates = dict(bundle["policy"]["preservation_gates"])
    checks: Dict[str, bool] = {}
    if bool(gates.get("proof_owned_non_regression", {}).get("enabled", False)):
        checks["proof_owned_non_regression"] = int(metrics["lost_proof_owned_span_count"]) == 0
    if bool(gates.get("supported_plaintext_non_regression", {}).get("enabled", False)):
        checks["supported_plaintext_non_regression"] = candidate_plaintext_bytes >= parent_plaintext_bytes
    if bool(gates.get("ledger_supersession_valid", {}).get("enabled", False)):
        checks["ledger_supersession_valid"] = all(
            span_id in set(metrics["superseded_loss_span_ids"])
            for span_id in metrics["lost_proof_owned_span_ids"]
        ) or int(metrics["lost_proof_owned_span_count"]) == 0
    required = [
        gate_id
        for gate_id, spec in gates.items()
        if bool(spec.get("enabled")) and bool(spec.get("required_for_composition"))
    ]
    return {
        "checks": checks,
        "metrics": metrics,
        "passed": all(checks.get(gate_id, False) for gate_id in required),
        "required_gates": required,
    }


def try_compile_proof_ledger_on_run_complete(
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    try:
        result = compile_proof_ledger_from_run(run_path, rail_id, bundle=bundle)
        from src.services.learning_db import try_index_proof_ledger_on_run_complete

        try_index_proof_ledger_on_run_complete(run_path, rail_id, bundle=bundle, compile_result=result)
        return result
    except Exception as exc:
        return {"ok": False, "error": str(exc), "rail_id": rail_id, "run_path": str(run_path)}


def audit_parent_child_loss(
    parent_bytes: bytes,
    candidate_bytes: bytes,
    protected_spans: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    metrics = preservation_metrics(parent_bytes, candidate_bytes, protected_spans)
    hypothetical_losses = []
    for record in protected_spans:
        span_id = proof_span_id(record)
        if span_id in metrics["lost_proof_owned_span_ids"]:
            hypothetical_losses.append(
                {
                    "proof_span_id": span_id,
                    "span": dict(record["span"]),
                    "truth_state": record.get("truth_state"),
                    "coverage_class": record.get("coverage_class"),
                }
            )
    return {"metrics": metrics, "hypothetical_losses": hypothetical_losses}
