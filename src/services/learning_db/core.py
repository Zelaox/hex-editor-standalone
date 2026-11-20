"""Config-driven SQLite learning index for hex editor and parser artifacts."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from jsonschema import Draft202012Validator


def _hex_editor_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _event_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value)}"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _require(mapping: Mapping[str, Any], names: Iterable[str], label: str) -> None:
    missing = set(names) - set(mapping)
    if missing:
        raise ValueError(f"{label} missing required keys: {sorted(missing)}")


def _validate_schema(name: str, value: Any) -> None:
    schema = _read_json(_hex_editor_root() / "schemas" / name)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"{name} validation failed: {errors[0].message}")


def _resolve_path(source: Mapping[str, Any], dotted: str) -> Any:
    current: Any = source
    for name in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        if name not in current:
            return None
        current = current[name]
    return current


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_hex_editor_config() -> Dict[str, Any]:
    path = _lab_root() / "config" / "hex_editor.json"
    if not path.is_file():
        raise ValueError(f"hex editor config missing: {path}")
    config = _read_json(path)
    if int(config.get("schema_version") or 0) != 1:
        raise ValueError("unsupported hex_editor.json schema_version")
    return config


def load_learning_db_bundle(
    *,
    policy_path: str | Path | None = None,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    policy = _read_json(Path(policy_path).resolve() if policy_path else _hex_editor_root() / "config" / "learning_db_policy.json")
    registry = _read_json(Path(registry_path).resolve() if registry_path else _hex_editor_root() / "config" / "learning_db_registry.json")
    _require(policy, ("schema_version", "policy_id", "revision", "storage", "tables", "sync", "queries"), "learning db policy")
    _require(registry, ("schema_version", "registry_id", "revision", "indexers"), "learning db registry")
    _validate_schema("learning_db_policy.schema.json", policy)
    _validate_schema("learning_db_registry.schema.json", registry)
    if int(policy["schema_version"]) != 1 or int(registry["schema_version"]) != 1:
        raise ValueError("unsupported learning db schema version")
    return {
        "policy": policy,
        "registry": registry,
        "policy_digest": _digest(policy),
        "registry_digest": _digest(registry),
    }


def learning_db_path(*, bundle: Mapping[str, Any] | None = None) -> Path:
    policy = dict((bundle or load_learning_db_bundle())["policy"])
    storage = dict(policy["storage"])
    path_source = dict(storage["path_source"])
    config_file = str(path_source["config_file"])
    path_key = str(path_source["path_key"])
    config_root = str(path_source["config_root"])
    config_path = Path(config_file)
    if not config_path.is_absolute():
        config_path = (_lab_root() if config_root == "lab" else _hex_editor_root()) / config_file
    if not config_path.is_file():
        raise ValueError(f"learning db path source config missing: {config_path}")
    config = _read_json(config_path)
    relative = str(config.get(path_key) or "")
    if not relative:
        raise ValueError(f"learning db path key missing from config: {path_key}")
    root = Path(relative)
    if not root.is_absolute():
        root = (_lab_root() if config_root == "lab" else _hex_editor_root()) / root
    filename = str(storage["filename"])
    if not filename:
        raise ValueError("learning db storage.filename is required")
    return root.resolve() / filename


def _connect(bundle: Mapping[str, Any]) -> sqlite3.Connection:
    path = learning_db_path(bundle=bundle)
    path.parent.mkdir(parents=True, exist_ok=True)
    storage = dict(bundle["policy"]["storage"])
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    journal_mode = str(storage.get("journal_mode") or "")
    synchronous = str(storage.get("synchronous") or "")
    if journal_mode:
        conn.execute(f"PRAGMA journal_mode={journal_mode}")
    if synchronous:
        conn.execute(f"PRAGMA synchronous={synchronous}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _sql_type(column: Mapping[str, Any]) -> str:
    return str(column["type"])


def _create_table_sql(table_name: str, table_spec: Mapping[str, Any]) -> str:
    columns = list(table_spec["columns"])
    primary_key = list(table_spec["primary_key"])
    parts = []
    for column in columns:
        name = str(column["name"])
        declaration = f"{name} {_sql_type(column)}"
        if column.get("not_null"):
            declaration += " NOT NULL"
        parts.append(declaration)
    parts.append(f"PRIMARY KEY ({', '.join(primary_key)})")
    return f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(parts)})"


def _create_index_sql(table_name: str, index_columns: Sequence[str], ordinal: int) -> str:
    index_name = f"idx_{table_name}_{ordinal}"
    joined = ", ".join(index_columns)
    return f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({joined})"


def _existing_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table_name})")}


def _migrate_table_columns(conn: sqlite3.Connection, table_name: str, table_spec: Mapping[str, Any]) -> None:
    existing = _existing_columns(conn, table_name)
    for column in table_spec["columns"]:
        name = str(column["name"])
        if name in existing:
            continue
        declaration = f"{name} {_sql_type(column)}"
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {declaration}")


def ensure_learning_db_schema(*, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    policy = bundle["policy"]
    tables = dict(policy["tables"])
    with _connect(bundle) as conn:
        for table_name, table_spec in tables.items():
            conn.execute(_create_table_sql(table_name, table_spec))
            _migrate_table_columns(conn, table_name, table_spec)
            for ordinal, index_columns in enumerate(table_spec.get("indexes") or []):
                conn.execute(_create_index_sql(table_name, list(index_columns), ordinal))
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("policy_digest", bundle["policy_digest"]),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("registry_digest", bundle["registry_digest"]),
        )
        conn.commit()
    return {"ok": True, "operation": "learning_db_ensure_schema", "db_path": str(learning_db_path(bundle=bundle))}


def _coerce_value(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return None
    return value


def _resolve_field(source: Mapping[str, Any], context: Mapping[str, Any], spec: str) -> Any:
    if spec.startswith("$context."):
        return context.get(spec[len("$context.") :])
    if spec.startswith("$literal."):
        literal = spec[len("$literal.") :]
        if literal == "null":
            return None
        if literal.isdigit() or (literal.startswith("-") and literal[1:].isdigit()):
            return int(literal)
        return literal
    return _resolve_path(source, spec)


def _build_record(
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    record_spec: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {}
    fields = dict(record_spec["fields"])
    timestamp_fields = dict(record_spec.get("timestamp_fields") or {})
    now = _utc_now()
    for column, spec in fields.items():
        row[column] = _coerce_value(_resolve_field(source, context, str(spec)))
    for column, mode in timestamp_fields.items():
        if mode == "insert_only" and existing and existing.get(column):
            row[column] = existing[column]
        else:
            row[column] = now
    return row


def _fetch_existing(conn: sqlite3.Connection, table: str, key_columns: Sequence[str], row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    where = " AND ".join(f"{column}=?" for column in key_columns)
    values = [row[column] for column in key_columns]
    cursor = conn.execute(f"SELECT * FROM {table} WHERE {where} LIMIT 1", values)
    item = cursor.fetchone()
    return dict(item) if item else None


def _upsert_row(conn: sqlite3.Connection, table: str, table_spec: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    columns = [str(column["name"]) for column in table_spec["columns"]]
    assignments = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    updates = ", ".join(f"{column}=excluded.{column}" for column in columns if column not in table_spec["primary_key"])
    sql = (
        f"INSERT INTO {table} ({assignments}) VALUES ({placeholders}) "
        f"ON CONFLICT({', '.join(table_spec['primary_key'])}) DO UPDATE SET {updates}"
    )
    conn.execute(sql, [row.get(column) for column in columns])


def _apply_record_specs(
    conn: sqlite3.Connection,
    bundle: Mapping[str, Any],
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    record_specs: Sequence[Mapping[str, Any]],
) -> int:
    tables = dict(bundle["policy"]["tables"])
    count = 0
    for record_spec in record_specs:
        table = str(record_spec["table"])
        table_spec = dict(tables[table])
        key_columns = list(record_spec["upsert_key"])
        existing = None
        preview = _build_record(source, context, record_spec)
        existing_row = _fetch_existing(conn, table, key_columns, preview)
        if existing_row:
            existing = existing_row
        row = _build_record(source, context, record_spec, existing=existing)
        _upsert_row(conn, table, table_spec, row)
        count += 1
    return count


def _indexer_by_id(bundle: Mapping[str, Any], indexer_id: str) -> Dict[str, Any]:
    for item in bundle["registry"]["indexers"]:
        if str(item.get("indexer_id") or "") == indexer_id:
            return dict(item)
    raise ValueError(f"unknown learning db indexer: {indexer_id}")


def _candidate_state_for_rail(rail_id: str, manifest: Mapping[str, Any]) -> str:
    if manifest.get("verified_decryption"):
        return "verified_decryption"
    if manifest.get("promotion_eligible"):
        return "promotion_eligible"
    gate_statuses = dict(manifest.get("gate_statuses") or {})
    if gate_statuses and all(status == "passed" for status in gate_statuses.values()):
        return "gates_passed"
    return str(manifest.get("status") or manifest.get("state") or "experimental")


def _rule_kind_for_manifest(manifest: Mapping[str, Any], rail_id: str) -> str:
    for key in ("rule_kind", "descriptor_id"):
        value = manifest.get(key)
        if value:
            return str(value)
    if "record-family" in str(manifest.get("candidate_id") or ""):
        return "record_family"
    if "local-transform" in str(manifest.get("candidate_id") or ""):
        return "local_transform"
    if "full-decode" in str(manifest.get("candidate_id") or ""):
        return "full_decode"
    return rail_id


def _decision_metrics(run: Mapping[str, Any]) -> Dict[str, Any]:
    decision_path = _resolve_path(run, "artifacts.decision")
    if not decision_path:
        return {}
    path = Path(str(decision_path))
    if not path.is_file():
        return {}
    decision = _read_json(path)
    metrics = {
        "decision_unresolved_bytes": int(decision.get("unresolved_bytes") or 0),
        "decision_coverage_complete": bool(decision.get("coverage_complete")),
        "decision_verified_decryption": bool(decision.get("verified_decryption")),
        "decision_promotion_eligible": bool(decision.get("promotion_eligible")),
    }
    for key in ("owned_preserved_bytes", "unowned_preserved_bytes", "structural_metadata_bytes"):
        if key in decision:
            metrics[f"decision_{key}"] = int(decision.get(key) or 0)
    return metrics


def _identity_lookup_spec(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    lookup = dict(bundle["policy"].get("identity_lookup") or {})
    run_columns = list(lookup.get("runs_sha_columns") or [])
    output_column = str(lookup.get("candidate_output_column") or "")
    if not run_columns or not output_column:
        raise ValueError("learning db policy missing identity_lookup configuration")
    return {"runs_sha_columns": run_columns, "candidate_output_column": output_column}


def query_runs_for_identity(
    identity_sha256: str,
    *,
    rail_id: str | None = None,
    limit: int | None = None,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    if not identity_sha256:
        return {"ok": True, "operation": "learning_db_query_runs_for_identity", "count": 0, "rows": []}
    bundle = dict(bundle or load_learning_db_bundle())
    lookup = _identity_lookup_spec(bundle)
    run_columns = list(lookup["runs_sha_columns"])
    output_column = str(lookup["candidate_output_column"])
    chosen_limit = _query_limits(bundle, limit)
    allowed_run_columns = {str(column["name"]) for column in bundle["policy"]["tables"]["runs"]["columns"]}
    for column in run_columns:
        if column not in allowed_run_columns:
            raise ValueError(f"identity_lookup runs_sha_columns contains unknown column: {column}")
    tables = dict(bundle["policy"]["tables"])
    candidate_columns = {str(column["name"]) for column in tables["candidates"]["columns"]}
    if output_column not in candidate_columns:
        raise ValueError(f"identity_lookup candidate_output_column unknown: {output_column}")
    ensure_learning_db_schema(bundle=bundle)
    rows_by_id: Dict[str, Dict[str, Any]] = {}
    with _connect(bundle) as conn:
        direct_clauses = " OR ".join(f"r.{column} = ?" for column in run_columns)
        direct_params: List[Any] = [identity_sha256 for _ in run_columns]
        rail_clause = ""
        if rail_id:
            rail_clause = " AND r.rail_id = ?"
            direct_params.append(rail_id)
        direct_sql = (
            f"SELECT r.* FROM runs r WHERE ({direct_clauses}){rail_clause} "
            f"ORDER BY r.indexed_at DESC LIMIT ?"
        )
        direct_params.append(chosen_limit)
        for item in conn.execute(direct_sql, direct_params).fetchall():
            row = dict(item)
            rows_by_id[str(row["run_id"])] = row
        candidate_sql = (
            f"SELECT r.* FROM runs r INNER JOIN candidates c ON c.run_id = r.run_id "
            f"WHERE c.{output_column} = ?"
        )
        candidate_params: List[Any] = [identity_sha256]
        if rail_id:
            candidate_sql += " AND r.rail_id = ?"
            candidate_params.append(rail_id)
        candidate_sql += " ORDER BY r.indexed_at DESC LIMIT ?"
        candidate_params.append(chosen_limit)
        for item in conn.execute(candidate_sql, candidate_params).fetchall():
            row = dict(item)
            rows_by_id[str(row["run_id"])] = row
    rows = sorted(rows_by_id.values(), key=lambda item: str(item.get("indexed_at") or ""), reverse=True)
    if len(rows) > chosen_limit:
        rows = rows[:chosen_limit]
    return {
        "ok": True,
        "operation": "learning_db_query_runs_for_identity",
        "count": len(rows),
        "rows": rows,
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def discover_rail_run_via_learning_db(
    rail_id: str,
    identity_sha256: str,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Resolve a verified rail run via learning DB index, then hydrate from artifacts."""
    if not identity_sha256:
        return {}
    from src.services.candidate_lineage.discover import _run_matches_identity
    from src.services.candidate_lineage.policy import import_rail_callable, load_candidate_lineage_policy

    bundle = dict(bundle or load_learning_db_bundle())
    lineage_policy = load_candidate_lineage_policy()
    rail = next((item for item in lineage_policy.get("rails") or [] if str(item.get("rail_id") or "") == rail_id), None)
    if rail is None:
        return {}
    query = query_runs_for_identity(identity_sha256, rail_id=rail_id, limit=1, bundle=bundle)
    rows = list(query.get("rows") or [])
    if not rows:
        return {}
    verify = import_rail_callable(rail, "verify_callable")
    inspect = import_rail_callable(rail, "inspect_callable")
    identity_roles = list(rail.get("identity_roles") or [])
    for row in rows:
        run_path_text = str(row.get("run_path") or "")
        if not run_path_text:
            continue
        path = Path(run_path_text)
        if not path.is_file():
            continue
        try:
            run = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        matched_role = _run_matches_identity(run, identity_sha256, identity_roles)
        candidate_match = False
        if matched_role is None:
            run_root = Path(str(run.get("run_root") or path.parent)).resolve()
            indexer = _indexer_by_id(bundle, "rail_run")
            manifest_glob = str(indexer.get("candidate_manifest_glob") or "candidates/*/manifest.json")
            for manifest_path in run_root.glob(manifest_glob):
                try:
                    manifest = _read_json(manifest_path)
                except (OSError, json.JSONDecodeError):
                    continue
                if str(manifest.get("output_sha256") or "") == identity_sha256:
                    candidate_match = True
                    matched_role = "candidate_output"
                    break
        if matched_role is None and not candidate_match:
            continue
        verified = verify(path)
        if not verified.get("ok"):
            continue
        inspected = inspect(path)
        if not inspected.get("verified"):
            continue
        return {
            "rail": rail_id,
            "run_id": run.get("run_id"),
            "run_path": str(path.resolve()),
            "matched_role": matched_role,
            "verified": True,
            "status": run.get("status"),
            "run": run,
            "inspected": inspected,
            "verification": verified,
            "state_source": "learning_db",
            "db_row": row,
        }
    return {}


def index_rail_run(
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
    format_plugin: str = "",
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"].get("enabled"):
        return {"ok": True, "operation": "learning_db_index_rail_run", "indexed": False, "reason": "sync_disabled"}
    indexer = _indexer_by_id(bundle, "rail_run")
    path = Path(run_path).resolve()
    if not path.is_file():
        raise ValueError(f"rail run missing: {path}")
    run = _read_json(path)
    run_root = Path(str(run.get("run_root") or path.parent)).resolve()
    context: Dict[str, Any] = {
        "rail_id": rail_id,
        "run_id": str(run.get("run_id") or ""),
        "run_path": str(path),
        "format_plugin": format_plugin,
        **_decision_metrics(run),
    }
    ensure_learning_db_schema(bundle=bundle)
    indexed_candidates = 0
    indexed_references = 0
    with _connect(bundle) as conn:
        _apply_record_specs(conn, bundle, run, context, indexer.get("records") or [])
        manifest_glob = str(indexer.get("candidate_manifest_glob") or "")
        if manifest_glob:
            for manifest_path in sorted(run_root.glob(manifest_glob)):
                manifest = _read_json(manifest_path)
                candidate_context = {
                    **context,
                    "candidate_state": _candidate_state_for_rail(rail_id, manifest),
                    "rule_kind": _rule_kind_for_manifest(manifest, rail_id),
                }
                indexed_candidates += _apply_record_specs(conn, bundle, manifest, candidate_context, indexer.get("candidate_records") or [])
        indexed_references = _index_reference_parser_coverages(conn, bundle, run_root, indexer)
        conn.commit()
    event = {
        "event_kind": "rail_run_indexed",
        "entity_id": context["run_id"],
        "rail_id": rail_id,
        "payload": {"run_path": str(path), "candidate_count": indexed_candidates},
    }
    record_learning_event(event, bundle=bundle)
    return {
        "ok": True,
        "operation": "learning_db_index_rail_run",
        "indexed": True,
        "run_id": context["run_id"],
        "rail_id": rail_id,
        "candidate_count": indexed_candidates,
        "reference_parser_coverage_count": indexed_references,
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def _discover_path_for_sha256(sha256: str, hint_root: Path | None = None) -> str | None:
    hex_root = _hex_editor_root()
    config = _load_hex_editor_config()
    artifact_base = Path(str(config.get("artifact_root") or ""))
    if not artifact_base.is_absolute():
        artifact_base = hex_root / artifact_base
    search_roots: list[Path] = []
    if hint_root is not None and hint_root.is_dir():
        search_roots.append(hint_root.resolve())
    if artifact_base.is_dir():
        search_roots.append(artifact_base.resolve())
    for base in search_roots:
        for run_file in base.rglob("run.json"):
            try:
                run = _read_json(run_file)
            except (OSError, json.JSONDecodeError):
                continue
            for role in ("source", "parent", "reference"):
                item = run.get(role)
                if not isinstance(item, Mapping):
                    continue
                if str(item.get("sha256") or "") != sha256:
                    continue
                path_text = str(item.get("path") or "")
                if path_text and Path(path_text).is_file():
                    return path_text
            local_root = run_file.parent
            for manifest_path in local_root.glob("candidates/*/manifest.json"):
                try:
                    manifest = _read_json(manifest_path)
                except (OSError, json.JSONDecodeError):
                    continue
                if str(manifest.get("reference_sha256") or "") != sha256:
                    continue
                reference = manifest.get("reference")
                ref_path = str(manifest.get("reference_path") or "")
                if not ref_path and isinstance(reference, Mapping):
                    ref_path = str(reference.get("path") or "")
                if ref_path and Path(ref_path).is_file():
                    return ref_path
    bundle = load_learning_db_bundle()
    ensure_learning_db_schema(bundle=bundle)
    with _connect(bundle) as conn:
        row = conn.execute(
            "SELECT source_path FROM sources WHERE source_sha256 = ? AND source_path IS NOT NULL LIMIT 1",
            (sha256,),
        ).fetchone()
        if row and row["source_path"] and Path(str(row["source_path"])).is_file():
            return str(row["source_path"])
    for summary_path in hex_root.rglob("*summary.json"):
        try:
            summary = _read_json(summary_path)
        except (OSError, json.JSONDecodeError):
            continue
        ref_path = str(summary.get("reference_path") or "")
        if not ref_path or not Path(ref_path).is_file():
            continue
        digest = hashlib.sha256(Path(ref_path).read_bytes()).hexdigest()
        if digest == sha256:
            return ref_path
    return None


def _parser_coverage_from_path(path: Path) -> Dict[str, Any]:
    from src.runtime.byte_source import ByteSource
    from src.plugins.ptx.runtime_analysis import build_ptx_snapshot, load_binary_dynamic_config
    from src.runtime.format_router import detect_format_plugin

    cfg = load_binary_dynamic_config()
    max_bytes = int(cfg.get("max_source_bytes", 268435456))
    source = ByteSource.from_path(path, max_bytes=max_bytes)
    snapshot = build_ptx_snapshot(source, policy=cfg)
    payload = snapshot.to_dict()
    summary = dict(payload.get("coverage_summary") or {})
    unknown = summary.get("unknown_bytes")
    if unknown is None:
        by_class = dict(summary.get("bytes_by_class") or {})
        unknown = by_class.get("unknown")
    complete = summary.get("coverage_complete")
    metrics = {
        "source_sha256": str(source.identity["sha256"]),
        "size_bytes": len(source.bytes()),
        "unknown_bytes": None if unknown is None else int(unknown),
        "coverage_complete": None if complete is None else bool(complete),
        "format_plugin": str(payload.get("format_plugin") or "ptx"),
        "timecode_count": None,
        "plaintext_run_count": None,
    }
    if detect_format_plugin(path, cfg=cfg) == "ptx":
        from src.services.plaintext_runs import discover_printable_runs
        from src.ptx_handler import PTXFile

        runs = discover_printable_runs(source.bytes())
        metrics["plaintext_run_count"] = len(runs)
        handler = PTXFile(str(path))
        if handler.parse():
            metrics["timecode_count"] = len(handler.timecodes or [])
        if handler.file_cache:
            handler.file_cache.close()
    return metrics


def index_parser_coverage_for_path(
    path: str | Path,
    *,
    bundle: Mapping[str, Any] | None = None,
    format_plugin: str = "",
) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"parser coverage source missing: {resolved}")
    metrics = _parser_coverage_from_path(resolved)
    bundle = dict(bundle or load_learning_db_bundle())
    ensure_learning_db_schema(bundle=bundle)
    tables = dict(bundle["policy"]["tables"])
    now = _utc_now()
    with _connect(bundle) as conn:
        existing = _fetch_existing(conn, "sources", ["source_sha256"], {"source_sha256": metrics["source_sha256"]})
        row = {
            "source_sha256": metrics["source_sha256"],
            "size_bytes": metrics["size_bytes"],
            "source_path": str(resolved),
            "format_plugin": format_plugin or metrics.get("format_plugin") or "ptx",
            "unknown_bytes": metrics["unknown_bytes"],
            "coverage_complete": _coerce_value(metrics["coverage_complete"]),
            "timecode_count": metrics.get("timecode_count"),
            "plaintext_run_count": metrics.get("plaintext_run_count"),
            "first_indexed_at": existing["first_indexed_at"] if existing else now,
            "last_indexed_at": now,
        }
        _upsert_row(conn, "sources", dict(tables["sources"]), row)
        conn.commit()
    record_learning_event(
        {
            "event_kind": "parser_coverage_indexed",
            "entity_id": metrics["source_sha256"],
            "rail_id": "parser_coverage",
            "payload": {
                "source_path": str(resolved),
                "unknown_bytes": metrics["unknown_bytes"],
                "coverage_complete": metrics["coverage_complete"],
            },
        },
        bundle=bundle,
    )
    return {
        "ok": True,
        "operation": "learning_db_index_parser_coverage",
        **metrics,
        "source_path": str(resolved),
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def lookup_parser_coverage(source_sha256: str, *, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any] | None:
    bundle = dict(bundle or load_learning_db_bundle())
    ensure_learning_db_schema(bundle=bundle)
    with _connect(bundle) as conn:
        row = conn.execute(
            "SELECT source_sha256, unknown_bytes, coverage_complete, source_path, timecode_count, plaintext_run_count FROM sources WHERE source_sha256 = ? LIMIT 1",
            (source_sha256,),
        ).fetchone()
    if row is None or row["unknown_bytes"] is None:
        return None
    complete = row["coverage_complete"]
    return {
        "unknown_bytes": int(row["unknown_bytes"]),
        "coverage_complete": None if complete is None else bool(int(complete)),
        "source_path": row["source_path"],
        "timecode_count": None if row["timecode_count"] is None else int(row["timecode_count"]),
        "plaintext_run_count": None if row["plaintext_run_count"] is None else int(row["plaintext_run_count"]),
        "metrics_source": "learning_db_sources",
    }


def _index_reference_parser_coverages(
    conn: sqlite3.Connection,
    bundle: Mapping[str, Any],
    run_root: Path,
    indexer: Mapping[str, Any],
) -> int:
    manifest_glob = str(indexer.get("candidate_manifest_glob") or "")
    if not manifest_glob:
        return 0
    indexed = 0
    seen: set[str] = set()
    for manifest_path in sorted(run_root.glob(manifest_glob)):
        try:
            manifest = _read_json(manifest_path)
        except (OSError, json.JSONDecodeError):
            continue
        reference_sha = str(manifest.get("reference_sha256") or "")
        if not reference_sha or reference_sha in seen:
            continue
        seen.add(reference_sha)
        existing = conn.execute(
            "SELECT unknown_bytes FROM sources WHERE source_sha256 = ? LIMIT 1",
            (reference_sha,),
        ).fetchone()
        if existing and existing["unknown_bytes"] is not None:
            continue
        path_text = _discover_path_for_sha256(reference_sha, run_root)
        if not path_text:
            continue
        try:
            index_parser_coverage_for_path(path_text, bundle=bundle)
            indexed += 1
        except (OSError, ValueError):
            continue
    return indexed


def index_parser_learning_run(
    artifact_root: str | Path,
    *,
    bundle: Mapping[str, Any] | None = None,
    format_plugin: str = "",
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"].get("enabled"):
        return {"ok": True, "operation": "learning_db_index_parser_learning_run", "indexed": False, "reason": "sync_disabled"}
    indexer = _indexer_by_id(bundle, "parser_learning_run")
    root = Path(artifact_root).resolve()
    run_file = root / "run.json"
    if not run_file.is_file():
        raise ValueError(f"parser learning run missing: {run_file}")
    run = _read_json(run_file)
    parser_policy_path = _hex_editor_root() / str(indexer.get("parser_learning_policy_path") or bundle["policy"]["sync"]["parser_learning_policy_path"])
    parser_policy = _read_json(parser_policy_path)
    layout = dict(parser_policy["artifact_layout"])
    observations_path = root / layout["observations"]
    candidates_path = root / layout["candidates"]
    observations = _read_json(observations_path) if observations_path.is_file() else []
    candidates = _read_json(candidates_path) if candidates_path.is_file() else []
    run_id = _event_id("parser-learning-run", {"artifact_root": str(root), "policy_digest": run.get("policy_digest")})
    context: Dict[str, Any] = {
        "format_plugin": format_plugin,
        "parser_learning_run_root": str(root),
        "parser_learning_run_id": run_id,
        "event_id": _event_id("parser-learning-event", {"artifact_root": str(root), "observation_count": len(observations)}),
        "payload_json": json.dumps({"observation_count": run.get("observation_count"), "candidate_count": run.get("candidate_count")}, sort_keys=True),
        "source_digest": str((observations[0] or {}).get("source_digest") or "") if observations else "",
    }
    ensure_learning_db_schema(bundle=bundle)
    indexed_observations = 0
    indexed_candidates = 0
    with _connect(bundle) as conn:
        _apply_record_specs(conn, bundle, run, context, indexer.get("records") or [])
        for observation in observations:
            indexed_observations += _apply_record_specs(conn, bundle, observation, context, indexer.get("observation_records") or [])
        for candidate in candidates:
            candidate_context = {**context, "source_digest": str(candidate.get("source_digest") or context.get("source_digest") or "")}
            indexed_candidates += _apply_record_specs(conn, bundle, candidate, candidate_context, indexer.get("candidate_records") or [])
        conn.commit()
    record_learning_event(
        {
            "event_kind": "parser_learning_indexed",
            "entity_id": run_id,
            "rail_id": "parser_learning",
            "payload": {"artifact_root": str(root), "observation_count": indexed_observations, "candidate_count": indexed_candidates},
        },
        bundle=bundle,
    )
    return {
        "ok": True,
        "operation": "learning_db_index_parser_learning_run",
        "indexed": True,
        "observation_count": indexed_observations,
        "candidate_count": indexed_candidates,
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def index_finding_ledger(
    ledger_root: str | Path | None = None,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"].get("enabled"):
        return {"ok": True, "operation": "learning_db_index_finding_ledger", "indexed": False, "reason": "sync_disabled"}
    indexer = _indexer_by_id(bundle, "finding_ledger")
    if ledger_root is None:
        policy_path = _hex_editor_root() / str(bundle["policy"]["sync"]["finding_ledger_policy_path"])
        record_policy = _read_json(policy_path)
        relative = str(dict(record_policy["finding_ledger"])["root"])
        root = Path(relative)
        if not root.is_absolute():
            root = _hex_editor_root() / root
    else:
        root = Path(ledger_root).resolve()
    record_glob = str(indexer.get("record_glob") or "records/*/*.json")
    ensure_learning_db_schema(bundle=bundle)
    indexed = 0
    with _connect(bundle) as conn:
        for path in sorted(root.glob(record_glob)):
            record = _read_json(path)
            context = {"artifact_path": str(path.resolve())}
            indexed += _apply_record_specs(conn, bundle, record, context, indexer.get("records") or [])
        conn.commit()
    return {"ok": True, "operation": "learning_db_index_finding_ledger", "indexed": True, "finding_count": indexed, "db_path": str(learning_db_path(bundle=bundle))}


def record_learning_event(event: Mapping[str, Any], *, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    _require(event, ("event_kind",), "learning event")
    ensure_learning_db_schema(bundle=bundle)
    event_id = _event_id("learning-event", event)
    row = {
        "event_id": event_id,
        "event_kind": str(event["event_kind"]),
        "entity_id": event.get("entity_id"),
        "rail_id": event.get("rail_id"),
        "payload_json": json.dumps(dict(event.get("payload") or {}), sort_keys=True),
        "indexed_at": _utc_now(),
    }
    tables = dict(bundle["policy"]["tables"])
    with _connect(bundle) as conn:
        _upsert_row(conn, "learning_events", dict(tables["learning_events"]), row)
        conn.commit()
    return {"ok": True, "operation": "learning_db_record_event", "event_id": event_id}


def _query_limits(bundle: Mapping[str, Any], limit: int | None) -> int:
    queries = dict(bundle["policy"]["queries"])
    default_limit = int(queries["default_limit"])
    max_limit = int(queries["max_limit"])
    chosen = default_limit if limit is None else int(limit)
    if chosen <= 0 or chosen > max_limit:
        raise ValueError("learning db query limit is outside configured bounds")
    return chosen


def query_learning_db(
    table: str,
    *,
    filters: Mapping[str, Any] | None = None,
    order_by: str | None = None,
    descending: bool = True,
    limit: int | None = None,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    tables = dict(bundle["policy"]["tables"])
    if table not in tables:
        raise ValueError(f"unknown learning db table: {table}")
    table_spec = dict(tables[table])
    allowed_columns = {str(column["name"]) for column in table_spec["columns"]}
    chosen_limit = _query_limits(bundle, limit)
    clauses: List[str] = []
    values: List[Any] = []
    for key, value in dict(filters or {}).items():
        if key not in allowed_columns:
            raise ValueError(f"unknown learning db filter column: {key}")
        clauses.append(f"{key} = ?")
        values.append(value)
    sql = f"SELECT * FROM {table}"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    if order_by:
        if order_by not in allowed_columns:
            raise ValueError(f"unknown learning db order column: {order_by}")
        sql += f" ORDER BY {order_by} {'DESC' if descending else 'ASC'}"
    sql += " LIMIT ?"
    values.append(chosen_limit)
    ensure_learning_db_schema(bundle=bundle)
    with _connect(bundle) as conn:
        rows = [dict(item) for item in conn.execute(sql, values).fetchall()]
    return {"ok": True, "operation": "learning_db_query", "table": table, "count": len(rows), "rows": rows, "db_path": str(learning_db_path(bundle=bundle))}


def inspect_learning_db(*, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    ensure_learning_db_schema(bundle=bundle)
    tables = dict(bundle["policy"]["tables"])
    summary: Dict[str, Any] = {}
    with _connect(bundle) as conn:
        for table_name in tables:
            if table_name == "meta":
                continue
            count = conn.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()["count"]
            summary[table_name] = int(count)
        meta = {str(row["key"]): str(row["value"]) for row in conn.execute("SELECT key, value FROM meta").fetchall()}
    return {
        "ok": True,
        "operation": "learning_db_inspect",
        "db_path": str(learning_db_path(bundle=bundle)),
        "policy_digest": bundle["policy_digest"],
        "registry_digest": bundle["registry_digest"],
        "meta": meta,
        "table_counts": summary,
    }


def query_learning_db_readonly(table: str, *, case_id: str | None = None,
                               limit: int | None = None, bundle=None) -> Dict[str, Any]:
    """Read a checkpointed DB without migrations, initialization, WAL or timestamps."""
    import re
    bundle = dict(bundle or load_learning_db_bundle())
    path = learning_db_path(bundle=bundle)
    if not path.is_file():
        return {"ok": False, "status": "not_found", "count": 0, "rows": []}
    wal = path.with_name(path.name + "-wal")
    if wal.is_file() and wal.stat().st_size:
        return {"ok": False, "status": "requires_checkpointed_snapshot", "count": 0, "rows": []}
    if table not in bundle["policy"]["tables"] or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", table):
        raise ValueError("unknown_learning_table")
    columns = {c["name"] for c in bundle["policy"]["tables"][table]["columns"]}
    if case_id is not None and "case_id" not in columns:
        raise ValueError("table_has_no_case_scope")
    sql = f'SELECT * FROM "{table}"'
    args = []
    if case_id is not None:
        sql += " WHERE case_id = ?"
        args.append(case_id)
    sql += " ORDER BY " + ",".join('"'+key+'"' for key in bundle["policy"]["tables"][table]["primary_key"])
    sql += " LIMIT ?"
    args.append(_query_limits(bundle, limit))
    try:
        with sqlite3.connect(path.resolve().as_uri()+"?mode=ro&immutable=1", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            rows = [dict(row) for row in conn.execute(sql, args)]
        return {"ok": True, "status": "completed", "count": len(rows), "rows": rows}
    except sqlite3.Error:
        return {"ok": False, "status": "schema_or_database_unavailable", "count": 0, "rows": []}


def inspect_learning_db_readonly(*, bundle=None) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    path = learning_db_path(bundle=bundle)
    if not path.is_file():
        return {"ok": False, "status": "not_found", "table_counts": {}}
    wal = path.with_name(path.name+"-wal")
    if wal.is_file() and wal.stat().st_size:
        return {"ok": False, "status": "requires_checkpointed_snapshot", "table_counts": {}}
    import re
    try:
        with sqlite3.connect(path.resolve().as_uri()+"?mode=ro&immutable=1", uri=True) as conn:
            conn.execute("PRAGMA query_only=ON")
            available = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            counts = {}
            for table in bundle["policy"]["tables"]:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", table):
                    raise ValueError("invalid_table_identifier")
                counts[table] = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] if table in available else None
        return {"ok": True, "status": "completed", "table_counts": counts, "db_path": str(path)}
    except sqlite3.Error:
        return {"ok": False, "status": "schema_or_database_unavailable", "table_counts": {}}


def index_browser_forensic_run(run_root, *, policy, bundle=None) -> Dict[str, Any]:
    """Index only verified, masked artifacts, using registry-declared field mappings."""
    from src.services.browser_forensics.engine import verify
    from src.services.browser_forensics.common import digest
    root = Path(run_root).resolve()
    if not verify(root)["ok"]:
        raise ValueError("unverified_forensic_run")
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"]["enabled"]:
        return {"indexed": False, "reason": "sync_disabled"}
    indexer = next(i for i in bundle["registry"]["indexers"] if i["indexer_id"] == policy["indexer_id"])
    manifest = _read_json(root / "manifest.json")
    result = _read_json(root / "result.json")
    ensure_learning_db_schema(bundle=bundle)
    context = {"artifact_path": str(root / "result.json"), "case_id": manifest["case_id"],
               "capture_id": manifest["capture_id"], "run_id": manifest["run_id"]}
    with _connect(bundle) as conn:
        _apply_record_specs(conn, bundle, manifest, context, indexer["records"])
        for source in manifest["files"]:
            ctx = {**context, "association_id": digest({"case": context["case_id"], "capture": context["capture_id"],
                                                      "source": source["sha256"], "path": source["path"]})}
            _apply_record_specs(conn, bundle, source, ctx, indexer["source_records"])
        for finding in result["findings"]:
            spans = finding["source_spans"]
            ctx = {**context, "scoped_finding_id": digest({"case": context["case_id"], "capture": context["capture_id"], "finding": finding["finding_id"]}),
                   "span_offset": spans[0]["offset"] if len(spans) == 1 else None,
                   "span_length": spans[0]["length"] if len(spans) == 1 else None}
            _apply_record_specs(conn, bundle, finding, ctx, indexer["finding_records"])
        conn.commit()
    return {"indexed": True, "run_id": manifest["run_id"]}


def index_private_message_recovery(run_root, *, bundle=None):
    """Index only the sealed recovery's masked summary; never its candidate text."""
    from src.services.browser_forensics.private_recovery import open_payload
    from src.services.browser_forensics.common import digest
    root = Path(run_root).resolve()
    summary = _read_json(root/"summary.json")
    # Authenticated current-user payload binds case and analysis identity.
    open_payload(root, summary["case_id"])
    identity = _read_json(root/"identity.json")
    policy = _read_json(root/"recovery_policy.json")
    if digest(policy) != identity["recovery_policy_digest"]:
        raise ValueError("recovery_policy_digest_mismatch")
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"]["enabled"]:
        return {"indexed": False, "reason": "sync_disabled"}
    indexer = next(i for i in bundle["registry"]["indexers"] if i["indexer_id"] == policy["indexer_id"])
    ensure_learning_db_schema(bundle=bundle)
    context = {"artifact_path": str(root/"summary.json")}
    with _connect(bundle) as conn:
        _apply_record_specs(conn, bundle, summary, context, indexer["records"])
        conn.commit()
    return {"indexed": True, "run_id": summary["run_id"]}


def sync_learning_db(
    *,
    rail_ids: Sequence[str] | None = None,
    include_findings: bool = True,
    scan_limit: int | None = None,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    sync = dict(bundle["policy"]["sync"])
    if not sync.get("enabled"):
        return {"ok": True, "operation": "learning_db_sync", "synced": False, "reason": "sync_disabled"}
    limit = int(scan_limit if scan_limit is not None else sync["backfill_scan_limit"])
    lineage_path = _hex_editor_root() / str(sync["lineage_policy_path"])
    lineage = _read_json(lineage_path)
    artifact_base = Path(str(lineage.get("artifact_root") or ""))
    if not artifact_base.is_absolute():
        artifact_base = (_hex_editor_root() / artifact_base).resolve()
    selected_rails = list(rail_ids) if rail_ids else [str(item["rail_id"]) for item in lineage.get("rails") or []]
    indexed_runs = 0
    for rail in lineage.get("rails") or []:
        rail_id = str(rail.get("rail_id") or "")
        if rail_id not in selected_rails:
            continue
        subdir = str(rail.get("artifact_subdir") or "")
        run_glob = str(rail.get("run_glob") or "*/run.json")
        base = artifact_base / subdir
        if not base.is_dir():
            continue
        verify_module = str(rail.get("verify_module") or "")
        verify_callable = str(rail.get("verify_callable") or "")
        module = importlib.import_module(verify_module)
        verify = getattr(module, verify_callable)
        candidate_paths = sorted(base.glob(run_glob), key=lambda item: item.stat().st_mtime_ns, reverse=True)
        if run_glob == "*/run.json":
            nested = sorted(base.glob("**/run.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)
            seen = {str(path.resolve()) for path in candidate_paths}
            for path in nested:
                key = str(path.resolve())
                if key in seen:
                    continue
                seen.add(key)
                candidate_paths.append(path)
            candidate_paths.sort(key=lambda item: item.stat().st_mtime_ns, reverse=True)
        for path in candidate_paths[:limit]:
            if not verify(path).get("ok"):
                continue
            index_rail_run(path, rail_id, bundle=bundle)
            indexed_runs += 1
    finding_count = 0
    if include_findings:
        finding_result = index_finding_ledger(bundle=bundle)
        finding_count = int(finding_result.get("finding_count") or 0)
    return {
        "ok": True,
        "operation": "learning_db_sync",
        "synced": True,
        "indexed_runs": indexed_runs,
        "finding_count": finding_count,
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def try_index_parser_learning_on_run_complete(
    artifact_root: str | Path,
    *,
    format_plugin: str = "",
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    sync = dict(bundle["policy"]["sync"])
    if not sync.get("enabled") or not sync.get("on_run_complete"):
        return {"ok": True, "indexed": False, "reason": "sync_hook_disabled"}
    try:
        return index_parser_learning_run(artifact_root, bundle=bundle, format_plugin=format_plugin)
    except Exception as exc:
        if sync.get("fail_on_index_error"):
            raise
        return {"ok": False, "indexed": False, "error": str(exc), "artifact_root": str(artifact_root)}


def try_index_learning_db_on_run_complete(
    run_path: str | Path,
    rail_id: str,
    *,
    format_plugin: str = "",
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    sync = dict(bundle["policy"]["sync"])
    if not sync.get("enabled") or not sync.get("on_run_complete"):
        return {"ok": True, "indexed": False, "reason": "sync_hook_disabled"}
    try:
        return index_rail_run(run_path, rail_id, bundle=bundle, format_plugin=format_plugin)
    except Exception as exc:
        if sync.get("fail_on_index_error"):
            raise
        return {"ok": False, "indexed": False, "error": str(exc), "rail_id": rail_id, "run_path": str(run_path)}


def index_proof_ledger_artifacts(
    compile_result: Mapping[str, Any],
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"].get("enabled"):
        return {"ok": True, "indexed": False, "reason": "sync_disabled"}
    path = Path(run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    run = _read_json(run_file)
    lineage_key = str(compile_result.get("lineage_key") or "")
    registry_path = Path(str(compile_result.get("registry_path") or ""))
    protected = []
    if registry_path.is_file():
        protected = list(dict(_read_json(registry_path).get("protected_spans") or {}).values())
    ensure_learning_db_schema(bundle=bundle)
    indexed_spans = 0
    now = _utc_now()
    with _connect(bundle) as conn:
        tables = dict(bundle["policy"]["tables"])
        for record in protected:
            row = {
                "proof_span_id": str(record["proof_span_id"]),
                "lineage_key": lineage_key,
                "source_sha256": str(record.get("source_sha256") or run["source"]["sha256"]),
                "parent_sha256": str(record.get("parent_sha256") or run["parent"]["sha256"]),
                "candidate_sha256": record.get("candidate_sha256"),
                "span_offset": int(record["span"]["offset"]),
                "span_length": int(record["span"]["length"]),
                "coverage_class": str(record.get("coverage_class") or ""),
                "truth_state": str(record.get("truth_state") or ""),
                "producer_run_id": str((record.get("producer") or {}).get("run_id") or run.get("run_id") or ""),
                "rail_id": rail_id,
                "artifact_path": str(registry_path),
                "indexed_at": now,
            }
            _upsert_row(conn, "proof_spans", dict(tables["proof_spans"]), row)
            indexed_spans += 1
        decision_path = Path(str(run.get("run_root") or run_file.parent)) / "final" / "decision.json"
        preservation_blocked = 0
        if decision_path.is_file():
            preservation_blocked = 1 if bool(_read_json(decision_path).get("preservation_blocked")) else 0
        event_row = {
            "event_id": _event_id("preservation-event", {"run_id": run.get("run_id"), "lineage_key": lineage_key}),
            "lineage_key": lineage_key,
            "run_id": str(run.get("run_id") or ""),
            "rail_id": rail_id,
            "protected_span_count": int(compile_result.get("protected_span_count") or 0),
            "preservation_blocked": preservation_blocked,
            "payload_json": json.dumps({"registry_path": str(registry_path)}, sort_keys=True),
            "indexed_at": now,
        }
        _upsert_row(conn, "preservation_events", dict(tables["preservation_events"]), event_row)
        lineage_dir = registry_path.parent
        deltas_dir = lineage_dir / "deltas"
        indexed_deltas = 0
        if deltas_dir.is_dir():
            for delta_path in sorted(deltas_dir.glob("*.json")):
                delta = _read_json(delta_path)
                row = {
                    "delta_id": str(delta["delta_id"]),
                    "delta_kind": str(delta["delta_kind"]),
                    "lineage_key": str(delta.get("lineage_key") or lineage_key),
                    "from_run_id": str((delta.get("from") or {}).get("run_id") or ""),
                    "to_run_id": str((delta.get("to") or {}).get("run_id") or ""),
                    "lost_proof_owned_span_count": int((delta.get("summary") or {}).get("lost_proof_owned_span_count") or 0),
                    "artifact_path": str(delta_path),
                    "indexed_at": now,
                }
                _upsert_row(conn, "cross_run_deltas", dict(tables["cross_run_deltas"]), row)
                indexed_deltas += 1
        conn.commit()
    record_learning_event(
        {
            "event_kind": "proof_ledger_indexed",
            "entity_id": str(run.get("run_id") or ""),
            "rail_id": rail_id,
            "payload": {"lineage_key": lineage_key, "protected_span_count": indexed_spans, "delta_count": indexed_deltas},
        },
        bundle=bundle,
    )
    return {
        "ok": True,
        "operation": "learning_db_index_proof_ledger",
        "indexed": True,
        "lineage_key": lineage_key,
        "proof_span_count": indexed_spans,
        "delta_count": indexed_deltas,
        "db_path": str(learning_db_path(bundle=bundle)),
    }


def try_index_proof_ledger_on_run_complete(
    run_path: str | Path,
    rail_id: str,
    *,
    bundle: Mapping[str, Any] | None = None,
    compile_result: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    sync = dict(bundle["policy"]["sync"])
    if not sync.get("enabled") or not sync.get("on_run_complete"):
        return {"ok": True, "indexed": False, "reason": "sync_hook_disabled"}
    if not compile_result or not compile_result.get("ok"):
        return {"ok": True, "indexed": False, "reason": "compile_result_missing"}
    try:
        return index_proof_ledger_artifacts(compile_result, run_path, rail_id, bundle=bundle)
    except Exception as exc:
        if sync.get("fail_on_index_error"):
            raise
        return {"ok": False, "indexed": False, "error": str(exc), "rail_id": rail_id, "run_path": str(run_path)}


def query_runs_for_source(source_sha256: str, *, limit: int | None = None, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    return query_learning_db("runs", filters={"source_sha256": source_sha256}, order_by="indexed_at", limit=limit, bundle=bundle)


def query_candidates_for_source(source_sha256: str, *, limit: int | None = None, bundle: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    return query_learning_db("candidates", filters={"source_sha256": source_sha256}, order_by="indexed_at", limit=limit, bundle=bundle)


def index_pseudocode_region_map(
    artifact_root: str | Path,
    *,
    summary: Mapping[str, Any],
    region_map: Mapping[str, Any],
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_learning_db_bundle())
    if not bundle["policy"]["sync"].get("enabled"):
        return {"ok": True, "indexed": False, "reason": "sync_disabled"}
    ensure_learning_db_schema(bundle=bundle)
    source = dict(region_map.get("source") or summary.get("source") or {})
    digest = str(region_map.get("digest") or summary.get("digest") or "")
    finding_id = _event_id("pseudocode-region-map", {"digest": digest, "source_sha256": source.get("sha256")})
    event_id = _event_id("pseudocode-region-map-event", {"digest": digest, "artifact_root": str(artifact_root)})
    now = _utc_now()
    size = int(source.get("size") or 0)
    row_finding = {
        "finding_id": finding_id,
        "kind": "pseudocode_region_map",
        "state": "verified",
        "source_sha256": str(source.get("sha256") or ""),
        "span_offset": 0,
        "span_length": size,
        "producer_run_id": digest,
        "summary": str(summary.get("operation") or "binary_pseudocode_render"),
        "artifact_path": str(summary.get("region_map_path") or artifact_root),
        "indexed_at": now,
    }
    payload = {
        "digest": digest,
        "region_count": region_map.get("region_count"),
        "raw_region_count": region_map.get("raw_region_count"),
        "routing_policy_id": region_map.get("routing_policy_id"),
        "merge_policy_id": region_map.get("merge_policy_id"),
    }
    row_event = {
        "event_id": event_id,
        "event_kind": "pseudocode_region_map",
        "entity_id": digest,
        "rail_id": "region_routed_pseudocode",
        "payload_json": json.dumps(payload, sort_keys=True, ensure_ascii=False),
        "indexed_at": now,
    }
    tables = dict(bundle["policy"]["tables"])
    with _connect(bundle) as conn:
        _upsert_row(conn, "findings", tables["findings"], row_finding)
        _upsert_row(conn, "learning_events", tables["learning_events"], row_event)
    return {"ok": True, "indexed": True, "finding_id": finding_id, "event_id": event_id}
