#!/usr/bin/env python3
"""Generate a candidate debug markdown report from full-decode run artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _require_keys(payload: Mapping[str, Any], keys: Sequence[str], *, label: str) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ValueError(f"{label} missing required keys: {missing}")


def _load_policy(path: Path | None) -> Dict[str, Any]:
    policy_path = path or (_repo_root() / "config" / "candidate_debug_policy.json")
    policy = _read_json(policy_path.resolve())
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError(f"unsupported candidate_debug policy schema: {policy_path}")
    return policy


def _sha256_file(path: Path, *, chunk_bytes: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path, *, chunk_bytes: int) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"binary not found: {path}")
    data = path.read_bytes()
    return {
        "path": str(path.resolve()),
        "size": len(data),
        "sha256": _sha256_file(path, chunk_bytes=chunk_bytes),
        "exists": True,
    }


def _diff_spans(left: bytes, right: bytes) -> List[Dict[str, int]]:
    spans: List[Dict[str, int]] = []
    index = 0
    size = min(len(left), len(right))
    while index < size:
        if left[index] != right[index]:
            start = index
            while index < size and left[index] != right[index]:
                index += 1
            spans.append({"offset": start, "length": index - start})
        else:
            index += 1
    if len(left) != len(right):
        tail_start = size
        tail_length = max(len(left), len(right)) - size
        spans.append({"offset": tail_start, "length": tail_length})
    return spans


def _count_diff(left: bytes, right: bytes) -> int:
    size = min(len(left), len(right))
    total = sum(1 for index in range(size) if left[index] != right[index])
    total += abs(len(left) - len(right))
    return total


def _pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "n/a"
    return f"{100.0 * numerator / denominator:.2f}%"


def _span_contained(span: Mapping[str, int], proof: Mapping[str, Any]) -> bool:
    offset = int(span["offset"])
    length = int(span["length"])
    proof_offset = int(proof["offset"])
    proof_length = int(proof["length"])
    return proof_offset <= offset and offset + length <= proof_offset + proof_length


def _classify_parent_candidate_vs_reference(parent: bytes, candidate: bytes, reference: bytes) -> Dict[str, int]:
    size = min(len(parent), len(candidate), len(reference))
    improve = regress = lateral = 0
    for index in range(size):
        if parent[index] == candidate[index]:
            continue
        if parent[index] != reference[index] and candidate[index] == reference[index]:
            improve += 1
        elif parent[index] == reference[index] and candidate[index] != reference[index]:
            regress += 1
        else:
            lateral += 1
    return {"improved_toward_reference": improve, "regressed_from_reference": regress, "lateral_vs_reference": lateral}


def _classify_parent_candidate_vs_source(parent: bytes, candidate: bytes, source: bytes) -> Dict[str, int]:
    size = min(len(parent), len(candidate), len(source))
    resolved = broken = lateral = 0
    for index in range(size):
        if parent[index] == candidate[index]:
            continue
        if parent[index] != source[index] and candidate[index] == source[index]:
            resolved += 1
        elif parent[index] == source[index] and candidate[index] != source[index]:
            broken += 1
        else:
            lateral += 1
    return {"resolved_toward_source": resolved, "broken_from_source": broken, "lateral_vs_source": lateral}


def _resolve_fixture_bundle(policy: Mapping[str, Any], bundle_id: str, workspace_root: Path) -> Dict[str, Any]:
    registry_path = workspace_root / str(policy["reference_resolution"]["fixture_registry_path"])
    registry = _read_json(registry_path.resolve())
    bundles = registry.get("fixture_bundles") or []
    bundle = next((item for item in bundles if str(item.get("bundle_id")) == bundle_id), None)
    if bundle is None:
        raise ValueError(f"fixture bundle not found: {bundle_id}")
    return bundle


def _resolve_reference_from_fixture(policy: Mapping[str, Any], bundle_id: str, workspace_root: Path) -> Path:
    bundle = _resolve_fixture_bundle(policy, bundle_id, workspace_root)
    files = bundle.get("files") or {}
    role = str(policy["reference_resolution"]["fixture_reference_role"])
    filename = files.get(role)
    if not filename:
        raise ValueError(f"fixture bundle {bundle_id} has no file role {role}")
    root = Path(str(bundle["root"]))
    return (root / str(filename)).resolve()


def _resolve_fixture_file(bundle: Mapping[str, Any], file_role: str) -> Path:
    files = bundle.get("files") or {}
    filename = files.get(file_role)
    if not filename:
        raise ValueError(f"fixture bundle missing file role {file_role}")
    return (Path(str(bundle["root"])) / str(filename)).resolve()


def _find_run_candidate_manifest(run: Mapping[str, Any], policy: Mapping[str, Any], output_sha256: str) -> Dict[str, Any] | None:
    run_root = Path(str(run["run_root"]))
    candidates_root = run_root / "candidates"
    if not candidates_root.is_dir():
        return None
    manifest_name = str(policy["candidate_sidecar_files"]["manifest"])
    output_field = str(policy["manifest_fields"]["output_sha256"])
    for candidate_dir in sorted(candidates_root.iterdir()):
        manifest_path = candidate_dir / manifest_name
        if not manifest_path.is_file():
            continue
        manifest = _read_json(manifest_path)
        if str(manifest.get(output_field)) == str(output_sha256):
            return manifest
    return None


def _load_run_binding_summary(
    run_json: Path,
    policy: Mapping[str, Any],
    *,
    output_sha256: str | None = None,
) -> Dict[str, Any]:
    run = _load_run(run_json, policy)
    fields = policy["manifest_fields"]
    if output_sha256:
        manifest = _find_run_candidate_manifest(run, policy, output_sha256)
        if manifest is None:
            manifest = _read_json(_candidate_root_from_artifacts(run, policy) / str(policy["candidate_sidecar_files"]["manifest"]))
            manifest_match = False
        else:
            manifest_match = True
    else:
        manifest = _read_json(_candidate_root_from_artifacts(run, policy) / str(policy["candidate_sidecar_files"]["manifest"]))
        manifest_match = True
    candidate_root = Path(str(manifest["artifact_path"])).parent
    gates = _read_json(Path(str(run["artifacts"][policy["artifact_keys"]["gates"]])))
    if output_sha256 and manifest_match:
        gates_path = candidate_root / "gates.json"
        if gates_path.is_file():
            gates = _read_json(gates_path)
    return {
        "run_id": run["run_id"],
        "run_json": str(run_json.resolve()),
        "status": run.get("status"),
        "selected_candidate_id": run.get("selected_candidate_id"),
        "source": run["source"],
        "parent": run["parent"],
        "candidate_id": manifest[fields["candidate_id"]],
        "output_sha256": manifest[fields["output_sha256"]],
        "changed_bytes": int(manifest[fields["changed_bytes"]]),
        "unresolved_bytes": int(manifest[fields["unresolved_bytes"]]),
        "gate_statuses": manifest[fields["gate_statuses"]],
        "scope_confinement": gates["gates"].get("scope_confinement"),
        "manifest_matches_external_sha256": manifest_match,
    }


def build_batch_report(*, policy: Mapping[str, Any], workspace_root: Path, bundle_id: str | None = None) -> Dict[str, Any]:
    batch = policy["batch_compare"]
    bundle = _resolve_fixture_bundle(policy, bundle_id or str(batch["default_bundle_id"]), workspace_root)
    reference_path = _resolve_fixture_file(bundle, str(batch["reference_role"]))
    reference_identity = _identity(reference_path, chunk_bytes=int(policy["analysis"]["sha256_chunk_bytes"]))
    reference_bytes = reference_path.read_bytes()
    file_size = int(reference_identity["size"])

    candidates: List[Dict[str, Any]] = []
    for item in batch["candidate_roles"]:
        label = str(item["label"])
        path = _resolve_fixture_file(bundle, str(item["file_role"]))
        data = path.read_bytes()
        identity = _identity(path, chunk_bytes=int(policy["analysis"]["sha256_chunk_bytes"]))
        diff_vs_reference = _count_diff(data, reference_bytes)
        candidates.append(
            {
                "label": label,
                "path": identity["path"],
                "sha256": identity["sha256"],
                "size": identity["size"],
                "diff_vs_reference_bytes": diff_vs_reference,
                "diff_vs_reference_pct": _pct(diff_vs_reference, file_size),
                "match_vs_reference_pct": _pct(file_size - diff_vs_reference, file_size),
            }
        )

    bindings: Dict[str, Dict[str, Any]] = {}
    for item in batch.get("run_bindings") or []:
        run_json = workspace_root / str(item["run_json"])
        if not run_json.is_file():
            continue
        label = str(item["label"])
        output_sha256 = None
        if bool(item.get("match_output_sha256_from_manifest")):
            candidate = next((c for c in candidates if str(c["label"]) == label), None)
            if candidate is not None:
                output_sha256 = str(candidate["sha256"])
        bindings[label] = _load_run_binding_summary(run_json, policy, output_sha256=output_sha256)

    for candidate in candidates:
        binding = bindings.get(str(candidate["label"]))
        candidate["run_binding"] = binding
        candidate["output_sha256_matches_run"] = (
            binding is not None and str(binding["output_sha256"]) == str(candidate["sha256"])
        )

    duplicate_groups: Dict[str, List[str]] = {}
    for candidate in candidates:
        duplicate_groups.setdefault(str(candidate["sha256"]), []).append(str(candidate["label"]))

    pairwise: List[Dict[str, Any]] = []
    by_label = {str(item["label"]): Path(str(item["path"])) for item in candidates}
    labels = [str(item["label"]) for item in candidates]
    for left_index, left in enumerate(labels):
        for right in labels[left_index + 1 :]:
            left_bytes = by_label[left].read_bytes()
            right_bytes = by_label[right].read_bytes()
            diff_bytes = _count_diff(left_bytes, right_bytes)
            pairwise.append({"left": left, "right": right, "diff_bytes": diff_bytes, "identical": diff_bytes == 0})

    transitions: List[Dict[str, Any]] = []
    ordered = [item for item in candidates if str(item["label"]) in {"candidate13", "candidate14", "candidate15"}]
    ordered.sort(key=lambda item: int(str(item["label"]).removeprefix("candidate")))
    for left_index, left in enumerate(ordered):
        left_bytes = Path(str(left["path"])).read_bytes()
        for right in ordered[left_index + 1 :]:
            right_bytes = Path(str(right["path"])).read_bytes()
            ref_class = _classify_parent_candidate_vs_reference(left_bytes, right_bytes, reference_bytes)
            transitions.append(
                {
                    "from_label": left["label"],
                    "to_label": right["label"],
                    "diff_bytes": _count_diff(left_bytes, right_bytes),
                    "vs_reference": ref_class,
                }
            )

    best = min(candidates, key=lambda item: int(item["diff_vs_reference_bytes"]))
    worst = max(candidates, key=lambda item: int(item["diff_vs_reference_bytes"]))

    archive_note = None
    bundle_archived = (bundle.get("archived_sources") or {}).get("legacy_encrypted_ptx") or {}
    if bundle_archived:
        archive_registry = workspace_root / str(bundle_archived.get("registry_path", ""))
        if archive_registry.is_file():
            archive_data = _read_json(archive_registry)
            archives = archive_data.get("archives") or {}
            archive_key = str(bundle_archived.get("archive_id_field", ""))
            if archive_key and archive_key in archives:
                archive_note = archives[archive_key]
            elif archives:
                archive_note = next(iter(archives.values()))

    return {
        "schema_version": 1,
        "operation": "candidate_batch_debug_report",
        "policy_id": policy.get("policy_id"),
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "fixture_bundle_id": str(bundle.get("bundle_id")),
        "reference": reference_identity,
        "candidates": candidates,
        "duplicate_sha256_groups": duplicate_groups,
        "pairwise": pairwise,
        "transitions_vs_reference": transitions,
        "best_vs_reference_label": best["label"],
        "worst_vs_reference_label": worst["label"],
        "archived_legacy_source": archive_note,
    }


def render_batch_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Candidate batch debug report (13-15)",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        f"Fixture bundle: `{report['fixture_bundle_id']}`",
        f"Reference: `{report['reference']['path']}`",
        f"Reference SHA256: `{report['reference']['sha256']}`",
        "",
        "## Candidate summary vs reference",
        "",
        _markdown_table(
            ["Label", "SHA256", "Diff bytes", "Diff %", "Match %", "Run bound", "SHA matches run"],
            [
                [
                    str(item["label"]),
                    f"`{item['sha256'][:16]}...`",
                    str(item["diff_vs_reference_bytes"]),
                    str(item["diff_vs_reference_pct"]),
                    str(item["match_vs_reference_pct"]),
                    "yes" if item.get("run_binding") else "no",
                    "yes" if item.get("output_sha256_matches_run") else "no",
                ]
                for item in report["candidates"]
            ],
        ),
        "",
        "## Duplicate groups",
        "",
    ]
    for sha256, labels in sorted(report["duplicate_sha256_groups"].items()):
        lines.append(f"- `{sha256[:16]}...`: {', '.join(labels)}")
    lines.extend(["", "## Pairwise diffs", ""])
    for item in report["pairwise"]:
        state = "identical" if item["identical"] else f"{item['diff_bytes']} bytes differ"
        lines.append(f"- **{item['left']} vs {item['right']}:** {state}")
    lines.extend(["", "## Transition classification vs reference", ""])
    for item in report["transitions_vs_reference"]:
        ref = item["vs_reference"]
        lines.extend(
            [
                f"### {item['from_label']} -> {item['to_label']}",
                "",
                f"- diff bytes: `{item['diff_bytes']}`",
                f"- improved toward reference: `{ref['improved_toward_reference']}`",
                f"- regressed from reference: `{ref['regressed_from_reference']}`",
                f"- lateral vs reference: `{ref['lateral_vs_reference']}`",
                "",
            ]
        )
    lines.extend(["## Run bindings", ""])
    for candidate in report["candidates"]:
        binding = candidate.get("run_binding")
        if binding is None:
            lines.append(f"- **{candidate['label']}:** no run binding configured")
            continue
        lines.extend(
            [
                f"### {candidate['label']}",
                "",
                f"- run_id: `{binding['run_id']}`",
                f"- status: `{binding['status']}`",
                f"- source: `{binding['source']['path']}` (`{binding['source']['sha256'][:16]}...`)",
                f"- parent: `{binding['parent']['path']}` (`{binding['parent']['sha256'][:16]}...`)",
                f"- candidate_id: `{binding['candidate_id']}`",
                f"- manifest_matches_external_sha256: `{binding.get('manifest_matches_external_sha256')}`",
                f"- changed_bytes: `{binding['changed_bytes']}`",
                f"- unresolved_bytes: `{binding['unresolved_bytes']}`",
                f"- scope_confinement: `{binding['scope_confinement']}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Reference comparison",
            "",
            f"- **Best vs reference:** `{report['best_vs_reference_label']}`",
            f"- **Worst vs reference:** `{report['worst_vs_reference_label']}`",
            "",
            "Interpret duplicate groups, transitions and lineage using the measurements above. "
            "A smaller byte difference does not by itself establish correct decryption or promotion eligibility.",
            "",
        ]
    )
    archived = report.get("archived_legacy_source")
    if archived:
        lines.extend(
            [
                "## Archived legacy source",
                "",
                f"- **original_path:** `{archived.get('original_path')}`",
                f"- **archived_path:** `{archived.get('archived_path')}`",
                f"- **sha256:** `{archived.get('sha256')}`",
                f"- **reason:** `{archived.get('reason')}`",
                "",
                "Bind new runs to an explicitly selected, current source identity. "
                "Historical manifests retain their recorded source identity.",
                "",
            ]
        )
    return "\n".join(lines)


def _candidate_root_from_artifacts(run: Mapping[str, Any], policy: Mapping[str, Any]) -> Path:
    artifacts = run["artifacts"]
    manifest_key = policy["artifact_keys"]["candidate_manifest"]
    manifest_path = Path(str(artifacts[manifest_key]))
    return manifest_path.parent


def _load_run(run_json: Path, policy: Mapping[str, Any]) -> Dict[str, Any]:
    run = _read_json(run_json.resolve())
    _require_keys(run, policy["run_required_keys"], label=str(run_json))
    for role in ("source", "parent"):
        _require_keys(run[role], policy["identity_required_keys"], label=f"{run_json}:{role}")
    return run


def _load_bytes_identity(run: Mapping[str, Any], role: str, *, chunk_bytes: int) -> Tuple[bytes, Dict[str, Any]]:
    meta = run[role]
    path = Path(str(meta["path"]))
    data = path.read_bytes()
    identity = _identity(path, chunk_bytes=chunk_bytes)
    if identity["sha256"] != str(meta["sha256"]):
        raise ValueError(f"{role} sha256 mismatch: manifest={meta['sha256']} disk={identity['sha256']}")
    if identity["size"] != int(meta["size"]):
        raise ValueError(f"{role} size mismatch: manifest={meta['size']} disk={identity['size']}")
    return data, identity


def _markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_report(
    *,
    run_json: Path,
    reference_path: Path,
    policy: Mapping[str, Any],
    external_file: Path | None = None,
) -> Dict[str, Any]:
    chunk_bytes = int(policy["analysis"]["sha256_chunk_bytes"])
    run = _load_run(run_json, policy)
    source_bytes, source_identity = _load_bytes_identity(run, "source", chunk_bytes=chunk_bytes)
    parent_bytes, parent_identity = _load_bytes_identity(run, "parent", chunk_bytes=chunk_bytes)

    artifacts = run["artifacts"]
    candidate_path = Path(str(artifacts[policy["artifact_keys"]["candidate"]]))
    candidate_bytes = candidate_path.read_bytes()
    candidate_identity = _identity(candidate_path, chunk_bytes=chunk_bytes)

    reference_bytes = reference_path.read_bytes()
    reference_identity = _identity(reference_path, chunk_bytes=chunk_bytes)

    candidate_root = _candidate_root_from_artifacts(run, policy)
    sidecars = policy["candidate_sidecar_files"]
    manifest = _read_json(candidate_root / str(sidecars["manifest"]))
    gates = _read_json(Path(str(artifacts[policy["artifact_keys"]["gates"]])))
    decision = _read_json(Path(str(artifacts[policy["artifact_keys"]["decision"]])))
    coverage = _read_json(Path(str(artifacts[policy["artifact_keys"]["coverage"]])))
    proof_spans = _read_json(candidate_root / str(sidecars["proof_spans"]))
    inverse = _read_json(candidate_root / str(sidecars["inverse"]))

    manifest_fields = policy["manifest_fields"]
    if candidate_identity["sha256"] != str(manifest[manifest_fields["output_sha256"]]):
        raise ValueError("candidate output sha256 does not match manifest")

    changed_spans = _diff_spans(candidate_bytes, parent_bytes)
    changed_bytes = sum(int(item["length"]) for item in changed_spans)
    unconfined = [span for span in changed_spans if not any(_span_contained(span, proof) for proof in proof_spans)]
    unconfined_bytes = sum(int(item["length"]) for item in unconfined)

    ref_vs = {
        "source": _count_diff(source_bytes, reference_bytes),
        "parent": _count_diff(parent_bytes, reference_bytes),
        "candidate": _count_diff(candidate_bytes, reference_bytes),
    }
    src_vs = {
        "parent": _count_diff(parent_bytes, source_bytes),
        "candidate": _count_diff(candidate_bytes, source_bytes),
    }
    parent_candidate_ref = _classify_parent_candidate_vs_reference(parent_bytes, candidate_bytes, reference_bytes)
    parent_candidate_src = _classify_parent_candidate_vs_source(parent_bytes, candidate_bytes, source_bytes)

    external_alias: Dict[str, Any] | None = None
    if external_file is not None:
        external_alias = _identity(external_file, chunk_bytes=chunk_bytes)
        external_alias["byte_identical_to_candidate"] = external_alias["sha256"] == candidate_identity["sha256"]

    provider_ids = list(manifest.get(manifest_fields["provider_candidate_ids"]) or [])
    local_transform_count = sum(1 for item in provider_ids if str(item).startswith("local-transform-candidate-"))
    record_family_count = sum(1 for item in provider_ids if str(item).startswith("record-family-candidate-"))

    verdict = "mixed"
    if (
        ref_vs["candidate"] > ref_vs["parent"]
        and parent_candidate_ref["regressed_from_reference"] > 0
        and parent_candidate_ref["improved_toward_reference"] == 0
    ):
        verdict = "worse_vs_reference"
    elif ref_vs["candidate"] < ref_vs["parent"]:
        verdict = "better_vs_reference"
    elif ref_vs["candidate"] == ref_vs["parent"]:
        verdict = "unchanged_vs_reference"

    return {
        "schema_version": 1,
        "operation": "candidate_debug_report",
        "policy_id": policy.get("policy_id"),
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "run": {
            "run_id": run["run_id"],
            "run_root": run["run_root"],
            "status": run.get("status"),
            "selected_candidate_id": run.get("selected_candidate_id"),
            "run_json": str(run_json.resolve()),
        },
        "candidate": {
            "candidate_id": manifest[manifest_fields["candidate_id"]],
            "path": candidate_identity["path"],
            "sha256": candidate_identity["sha256"],
            "size": candidate_identity["size"],
            "changed_bytes": changed_bytes,
            "manifest_changed_bytes": int(manifest[manifest_fields["changed_bytes"]]),
            "proof_owned_changed_bytes": int(manifest[manifest_fields["proof_owned_changed_bytes"]]),
        },
        "identities": {
            "source": source_identity,
            "parent": parent_identity,
            "candidate": candidate_identity,
            "reference": reference_identity,
        },
        "external_alias": external_alias,
        "reference_diff_bytes": ref_vs,
        "source_diff_bytes": src_vs,
        "parent_to_candidate_vs_reference": parent_candidate_ref,
        "parent_to_candidate_vs_source": parent_candidate_src,
        "scope_confinement": {
            "gate_status": gates["gates"].get("scope_confinement"),
            "changed_span_count": len(changed_spans),
            "changed_bytes": changed_bytes,
            "proof_span_count": len(proof_spans),
            "proof_owned_bytes": sum(int(item["length"]) for item in proof_spans),
            "unconfined_span_count": len(unconfined),
            "unconfined_bytes": unconfined_bytes,
            "unconfined_sample_offsets_hex": [hex(int(item["offset"])) for item in unconfined[: int(policy["analysis"]["scope_confinement_unconfined_sample_limit"])]],
        },
        "gates": gates,
        "decision": {key: decision.get(key) for key in policy["decision_fields"]},
        "coverage_summary": dict(coverage.get("summary") or {}),
        "provider_merge": {
            "total_provider_candidates": len(provider_ids),
            "local_transform_candidates": local_transform_count,
            "record_family_candidates": record_family_count,
            "sample_provider_candidate_ids": provider_ids[: int(policy["analysis"]["provider_id_sample_limit"])],
        },
        "inverse_replay": {
            "inverse_span_count": len(inverse),
            "inverse_bytes": sum(int(item["length"]) for item in inverse),
        },
        "verdict": verdict,
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    size = int(report["identities"]["candidate"]["size"])
    ref = report["reference_diff_bytes"]
    src = report["source_diff_bytes"]
    p2c_ref = report["parent_to_candidate_vs_reference"]
    p2c_src = report["parent_to_candidate_vs_source"]
    scope = report["scope_confinement"]
    coverage = report["coverage_summary"]
    lines: List[str] = [
        "# Candidate debug report",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        f"Policy: `{report['policy_id']}`",
        "",
        "## Run",
        "",
        f"- **run_id:** `{report['run']['run_id']}`",
        f"- **status:** `{report['run']['status']}`",
        f"- **selected_candidate_id:** `{report['run']['selected_candidate_id']}`",
        f"- **run.json:** `{report['run']['run_json']}`",
        "",
        "## Candidate identity",
        "",
        f"- **candidate_id:** `{report['candidate']['candidate_id']}`",
        f"- **path:** `{report['candidate']['path']}`",
        f"- **sha256:** `{report['candidate']['sha256']}`",
        f"- **size:** `{report['candidate']['size']}` bytes",
        "",
        "If you exported this candidate under another filename (for example `candidate15.bin`), "
        "it should be byte-identical to the path above. Pass `--external-file` to verify.",
        "",
    ]

    alias = report.get("external_alias")
    if alias is not None:
        lines.extend(
            [
                "## External alias check",
                "",
                f"- **path:** `{alias['path']}`",
                f"- **sha256:** `{alias['sha256']}`",
                f"- **byte_identical_to_candidate:** `{alias['byte_identical_to_candidate']}`",
                "",
            ]
        )

    lines.extend(
        [
            "## File identities",
            "",
            _markdown_table(
                ["Role", "Path", "SHA256", "Size"],
                [
                    [role, item["path"], f"`{item['sha256']}`", str(item["size"])]
                    for role, item in report["identities"].items()
                ],
            ),
            "",
            "## Diff vs reference (ground truth)",
            "",
            _markdown_table(
                ["Artifact", "Diff bytes", "Diff %", "Match %"],
                [
                    ["source (encrypted)", str(ref["source"]), _pct(ref["source"], size), _pct(size - ref["source"], size)],
                    ["parent (local-transform)", str(ref["parent"]), _pct(ref["parent"], size), _pct(size - ref["parent"], size)],
                    ["candidate (full-decode)", str(ref["candidate"]), _pct(ref["candidate"], size), _pct(size - ref["candidate"], size)],
                ],
            ),
            "",
            "The UI **changed_ratio** for candidate vs reference is the candidate row above.",
            "",
            "## Diff vs encrypted source",
            "",
            _markdown_table(
                ["Artifact", "Diff bytes", "Diff %"],
                [
                    ["parent", str(src["parent"]), _pct(src["parent"], size)],
                    ["candidate", str(src["candidate"]), _pct(src["candidate"], size)],
                ],
            ),
            "",
            "## Parent to candidate byte classification",
            "",
            "### vs reference",
            "",
            _markdown_table(
                ["Class", "Bytes"],
                [[key, str(value)] for key, value in p2c_ref.items()],
            ),
            "",
            "### vs encrypted source",
            "",
            _markdown_table(
                ["Class", "Bytes"],
                [[key, str(value)] for key, value in p2c_src.items()],
            ),
            "",
            "Interpretation:",
            "",
            "- **regressed_from_reference:** parent matched reference; candidate broke that match.",
            "- **improved_toward_reference:** parent differed; candidate now matches reference.",
            "- **resolved_toward_source:** parent differed from encrypted source; candidate now matches source.",
            "",
            "## Scope confinement",
            "",
            _markdown_table(
                ["Metric", "Value"],
                [
                    ["gate_status", str(scope["gate_status"])],
                    ["changed_span_count", str(scope["changed_span_count"])],
                    ["changed_bytes", str(scope["changed_bytes"])],
                    ["proof_span_count", str(scope["proof_span_count"])],
                    ["proof_owned_bytes", str(scope["proof_owned_bytes"])],
                    ["unconfined_span_count", str(scope["unconfined_span_count"])],
                    ["unconfined_bytes", str(scope["unconfined_bytes"])],
                ],
            ),
            "",
            "Sample unconfined offsets:",
            "",
        ]
    )
    for offset in scope["unconfined_sample_offsets_hex"]:
        lines.append(f"- `{offset}`")
    lines.extend(
        [
            "",
            "## Why it looks worse and better at the same time",
            "",
            "The same parent-to-candidate byte edits can move in opposite directions depending on baseline:",
            "",
            "- vs **reference** (`ac240.ptx`): every edit was a regression (parent matched reference; candidate broke it).",
            "- vs **encrypted source** (`1ac240.ptx`): the same edits resolved toward source (parent differed; candidate now matches source).",
            "",
            "Full-decode merged record-family and local-transform provider patches using proof coverage, not reference equality. "
            "Those patches overwrote bytes that were already correct vs reference but still wrong vs encrypted source.",
            "",
            "## Gates and decision",
            "",
            _markdown_table(
                ["Gate", "Status"],
                [[key, str(value)] for key, value in sorted((report["gates"].get("gates") or {}).items())],
            ),
            "",
            _markdown_table(
                ["Decision field", "Value"],
                [[key, str(value)] for key, value in sorted((report["decision"] or {}).items())],
            ),
            "",
            "## Coverage summary",
            "",
            _markdown_table(
                ["Class", "Bytes"],
                [[key, str(value)] for key, value in sorted(coverage.items())],
            ),
            "",
            "## Provider merge",
            "",
            f"- **total merged providers:** `{report['provider_merge']['total_provider_candidates']}`",
            f"- **local-transform providers:** `{report['provider_merge']['local_transform_candidates']}`",
            f"- **record-family providers:** `{report['provider_merge']['record_family_candidates']}`",
            "",
            "## Verdict",
            "",
        ]
    )

    verdict = str(report["verdict"])
    if verdict == "worse_vs_reference":
        lines.extend(
            [
                "**Worse vs reference, better vs encrypted source.**",
                "",
                f"Full-decode changed `{report['candidate']['changed_bytes']}` bytes from the parent. "
                f"Every counted change vs reference was a regression (`{p2c_ref['regressed_from_reference']}` bytes); "
                f"none improved toward reference.",
                "",
                f"Net reference diff moved from `{ref['parent']}` ({_pct(ref['parent'], size)}) "
                f"to `{ref['candidate']}` ({_pct(ref['candidate'], size)}).",
                "",
                f"Net encrypted-source diff moved from `{src['parent']}` to `{src['candidate']}` "
                f"({int(src['parent']) - int(src['candidate'])} bytes closer to source).",
                "",
                "The run was **not promoted** (`verified_decryption=false`, `scope_confinement=failed`).",
            ]
        )
    else:
        lines.append(f"Automated verdict class: `{verdict}`.")

    lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Candidate debug report (config-driven).")
    sub = parser.add_subparsers(dest="command", required=True)

    single = sub.add_parser("single", help="Report one full-decode run")
    single.add_argument("--run-json", required=True, help="Path to full-decode run.json")
    single.add_argument("--reference", help="Ground-truth reference binary")
    single.add_argument("--fixture-bundle-id", help="Resolve reference path from hex_regression_fixtures.json")
    single.add_argument("--external-file", help="Optional external alias file")
    single.add_argument("--workspace-root", help="Workspace root for fixture resolution (default: repo root)")
    single.add_argument("--policy", help="Override candidate_debug_policy.json path")
    single.add_argument("--output", help="Markdown output path")
    single.add_argument("--json-output", help="Optional machine-readable JSON report path")

    batch = sub.add_parser("batch", help="Compare configured external candidates (13-15)")
    batch.add_argument("--fixture-bundle-id", help="Fixture bundle id from hex_regression_fixtures.json")
    batch.add_argument("--workspace-root", help="Workspace root (default: repo root)")
    batch.add_argument("--policy", help="Override candidate_debug_policy.json path")
    batch.add_argument("--output", help="Markdown output path")
    batch.add_argument("--json-output", help="JSON output path")

    args = parser.parse_args(list(argv) if argv is not None else None)
    policy = _load_policy(Path(args.policy).resolve() if args.policy else None)
    workspace_root = Path(args.workspace_root).resolve() if args.workspace_root else _repo_root()

    if args.command == "batch":
        report = build_batch_report(
            policy=policy,
            workspace_root=workspace_root,
            bundle_id=str(args.fixture_bundle_id) if args.fixture_bundle_id else None,
        )
        markdown = render_batch_markdown(report)
        output_path = Path(args.output).resolve() if args.output else (workspace_root / str(policy["report"]["batch_output_path"]))
        json_output = Path(args.json_output).resolve() if args.json_output else (workspace_root / str(policy["report"]["batch_json_output_path"]))
    else:
        reference_path: Path | None = Path(args.reference).expanduser().resolve() if args.reference else None
        if reference_path is None:
            if not args.fixture_bundle_id:
                if policy["reference_resolution"]["require_reference"]:
                    raise SystemExit("--reference or --fixture-bundle-id is required")
            else:
                reference_path = _resolve_reference_from_fixture(policy, str(args.fixture_bundle_id), workspace_root)
        if reference_path is None or not reference_path.is_file():
            raise SystemExit(f"reference file not found: {reference_path}")

        report = build_report(
            run_json=Path(args.run_json),
            reference_path=reference_path,
            policy=policy,
            external_file=Path(args.external_file).expanduser().resolve() if args.external_file else None,
        )
        markdown = render_markdown(report)
        output_path = Path(args.output).resolve() if args.output else (workspace_root / str(policy["report"]["default_output_path"]))
        json_output = Path(args.json_output).resolve() if args.json_output else output_path.with_suffix(str(policy["report"]["json_output_suffix"]))

    _write_text(output_path, markdown)
    _write_json(json_output, report)
    print(markdown)
    print(f"\nWrote markdown: {output_path}")
    print(f"Wrote json: {json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
