"""JSON Schema validation for PTX pipeline artifacts."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from src.services.ptx_pipeline_policy import hex_editor_root


@lru_cache(maxsize=1)
def _schema_registry() -> Registry:
    root = hex_editor_root() / "schemas"
    registry: Registry = Registry()
    for path in sorted(root.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8-sig"))
        registry = registry.with_resource(path.name, Resource.from_contents(contents))
    return registry


def validate_against_schema(schema_name: str, value: Any) -> None:
    schema_path = hex_editor_root() / "schemas" / schema_name
    if not schema_path.is_file():
        raise FileNotFoundError(f"missing schema: {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8-sig"))
    validator = Draft202012Validator(schema, registry=_schema_registry())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"{schema_name} validation failed: {errors[0].message}")
