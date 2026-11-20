"""Shared canonical identities and schema-validated policy loading."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def editor_root():
    return Path(__file__).resolve().parents[3]


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def validate(value, schema_name):
    from jsonschema import Draft202012Validator
    Draft202012Validator(read_json(editor_root() / "schemas" / schema_name)).validate(value)


def load_policy(path=None):
    policy = read_json(path or editor_root() / "config" / "browser_forensics_policy.json")
    validate(policy, "browser_forensics_policy.schema.json")
    return policy


def confined(root, relative):
    root = Path(root).resolve()
    if Path(relative).is_absolute():
        raise ValueError("absolute_child_path")
    result = (root / relative).resolve()
    if not result.is_relative_to(root):
        raise ValueError("path_escape")
    return result
