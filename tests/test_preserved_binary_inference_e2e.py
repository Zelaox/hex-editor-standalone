from __future__ import annotations

from pathlib import Path


def test_preserved_ownership_parent_baseline(tmp_path: Path):
    from src.services.full_decode import run_full_decode_e2e, verify_full_decode_run
    from src.services.preserved_binary_inference import run_preserved_binary_inference_e2e, verify_preserved_binary_inference_run

    size = 4096
    lane = 0x33
    parent = bytearray((index % 256 for index in range(size)))
    source = bytearray(parent)
    for index in range(400, 3600):
        source[index] = parent[index] ^ lane
    source_path = tmp_path / "source.bin"
    parent_path = tmp_path / "parent.bin"
    source_path.write_bytes(source)
    parent_path.write_bytes(parent)

    decode = run_full_decode_e2e(source_path, parent_path, output_root=tmp_path / "full_decode")
    decode_path = Path(decode["run_root"]) / "run.json"
    assert verify_full_decode_run(decode_path)["ok"]

    preserved = run_preserved_binary_inference_e2e(decode_path, output_root=tmp_path / "preserved")
    assert preserved["status"] == "completed"
    assert verify_preserved_binary_inference_run(Path(preserved["run_root"]) / "run.json")["ok"]
