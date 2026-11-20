"""Display a current-user sealed recovery in memory, never plaintext stdout/files."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-path", required=True)
    parser.add_argument("--case-id", required=True)
    args = parser.parse_args()
    run_path = str(Path(args.run_path).resolve())
    from hexeditor_tools.cli import bootstrap_lab_runtime
    bootstrap_lab_runtime(ROOT)
    from hexeditor_tools.api import _forensic_root
    from src.private_recovery_viewer import create_private_viewer
    from PyQt5.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    try:
        viewer = create_private_viewer(_forensic_root(run_path), args.case_id)
    except (OSError, ValueError, RuntimeError, KeyError):
        parser.exit(2, "Private recovery could not be verified/opened.\n")
    viewer.showMaximized()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
