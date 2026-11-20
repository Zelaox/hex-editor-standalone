"""Standalone application paths, independent of any enclosing workspace."""
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]
