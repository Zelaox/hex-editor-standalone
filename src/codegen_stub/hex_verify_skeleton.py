# === HEX_VERIFY_BEGIN ===
"""Hex editor codegen verify skeleton — stub lane only; fails closed until authorized."""

from __future__ import annotations

from typing import Any, Mapping


class HexVerifyHookMissing(RuntimeError):
    pass


def _missing(hook: str) -> HexVerifyHookMissing:
    return HexVerifyHookMissing(f"HEX_VERIFY_HOOK_MISSING:{hook}")


# === HEX_VERIFY_HOOKS_BEGIN ===


def verify_workspace_integrity(_context: Mapping[str, Any]) -> None:
    raise _missing("verify_workspace_integrity")


def verify_region_inspect(_context: Mapping[str, Any]) -> None:
    raise _missing("verify_region_inspect")


def verify_experiment_diff(_context: Mapping[str, Any]) -> None:
    raise _missing("verify_experiment_diff")


# === HEX_VERIFY_HOOKS_END ===
# === HEX_VERIFY_END ===
