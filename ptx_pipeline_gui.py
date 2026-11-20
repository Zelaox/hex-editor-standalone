#!/usr/bin/env python3
"""Entry point for the PTX pipeline GUI."""

from __future__ import annotations

import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from src.logging_config import setup_logging
from src.ptx_pipeline_gui import main

if __name__ == "__main__":
    setup_logging()
    raise SystemExit(main())
