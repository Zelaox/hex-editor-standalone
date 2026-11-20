"""Shell entry for Hex Editor tools (portable JSON CLI for local and cloud agents)."""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_import_path() -> None:
    editor_root = Path(__file__).resolve().parents[1]
    editor_str = str(editor_root)
    if editor_str not in sys.path:
        sys.path.insert(0, editor_str)


def main() -> int:
    _bootstrap_import_path()
    from hexeditor_tools.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
