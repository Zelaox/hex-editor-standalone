"""Benchmark hex load/render paths and report memory usage."""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_sample(path: Path, size_bytes: int) -> None:
    block = bytes((index * 17 + 31) & 0xFF for index in range(65536))
    with path.open("wb") as handle:
        remaining = size_bytes
        while remaining > 0:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)


def _profile_full(data: bytes, bytes_per_line: int = 16) -> dict:
    from src.utils import bytes_to_hex_view

    started = time.perf_counter()
    text = bytes_to_hex_view(data, bytes_per_line=bytes_per_line, base_offset=0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {"mode": "full", "hex_chars": len(text), "elapsed_ms": round(elapsed_ms, 2)}


def _profile_viewport(data: bytes, *, file_size: int, top_line: int, line_count: int, bytes_per_line: int = 16) -> dict:
    from src.utils import bytes_to_hex_view

    offset = top_line * bytes_per_line
    length = min(line_count * bytes_per_line, max(0, file_size - offset))
    window = data[offset : offset + length]
    started = time.perf_counter()
    text = bytes_to_hex_view(window, bytes_per_line=bytes_per_line, base_offset=offset)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {"mode": "viewport", "hex_chars": len(text), "window_bytes": length, "elapsed_ms": round(elapsed_ms, 2)}


def _profile_viewport_scroll(data: bytes, *, file_size: int, steps: int, line_count: int, bytes_per_line: int = 16) -> dict:
    from src.utils import bytes_to_hex_view

    top_line = 0
    started = time.perf_counter()
    renders = 0
    for _ in range(steps):
        offset = top_line * bytes_per_line
        length = min(line_count * bytes_per_line, max(0, file_size - offset))
        window = data[offset : offset + length]
        bytes_to_hex_view(window, bytes_per_line=bytes_per_line, base_offset=offset)
        renders += 1
        top_line = min(top_line + 1, max(0, (file_size // bytes_per_line) - 1))
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {
        "mode": "viewport_scroll",
        "steps": steps,
        "line_window": line_count,
        "renders": renders,
        "elapsed_ms": round(elapsed_ms, 2),
        "ms_per_step": round(elapsed_ms / max(steps, 1), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile hex editor load memory and timing")
    parser.add_argument("--size-mb", type=float, default=12.0, help="Synthetic file size in megabytes")
    parser.add_argument("--keep-file", action="store_true", help="Keep generated sample file")
    args = parser.parse_args()

    root = _root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.services.ui_policy import load_ui_policy

    policy = load_ui_policy()
    budgets = dict(policy.get("load_budgets") or {})
    size_bytes = max(1, int(args.size_mb * 1024 * 1024))
    sample = root / "test_output" / f"profile_{size_bytes}.bin"
    sample.parent.mkdir(parents=True, exist_ok=True)
    _write_sample(sample, size_bytes)
    data = sample.read_bytes()

    tracemalloc.start()
    full = _profile_full(data)
    current_full, peak_full = tracemalloc.get_traced_memory()
    viewport = _profile_viewport(
        data,
        file_size=size_bytes,
        top_line=max(0, (size_bytes // 16 // 2) - 64),
        line_count=int(budgets["hex_viewport_document_lines"]),
    )
    overscan = int(budgets["hex_viewport_overscan_lines"])
    scroll_window = min(int(budgets["hex_viewport_document_lines"]), 40 + (overscan * 2))
    scroll = _profile_viewport_scroll(data, file_size=size_bytes, steps=500, line_count=scroll_window)
    current_viewport, peak_viewport = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    report = {
        "sample_path": str(sample.resolve()),
        "sample_bytes": size_bytes,
        "policy": {
            "hex_view_mode": budgets.get("hex_view_mode"),
            "hex_viewport_file_bytes": budgets.get("hex_viewport_file_bytes"),
            "hex_viewport_document_lines": budgets.get("hex_viewport_document_lines"),
        },
        "full_render": {**full, "tracemalloc_peak_bytes": peak_full},
        "viewport_render": {**viewport, "tracemalloc_peak_bytes": peak_viewport},
        "viewport_scroll_500_steps": scroll,
        "speedup_ms": round(full["elapsed_ms"] / max(viewport["elapsed_ms"], 0.001), 2),
        "hex_output_reduction": round(full["hex_chars"] / max(viewport["hex_chars"], 1), 2),
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if not args.keep_file:
        sample.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
