from __future__ import annotations

from pathlib import Path


def test_lineage_lane_provider_accepts_single_span_dominant_xor_lane(tmp_path: Path):
    from src.services.full_decode.core import load_full_decode_bundle, run_lineage_lane_provider

    size = 12000
    lane = 0x94
    parent = bytearray((index % 256 for index in range(size)))
    source = bytearray(parent)
    for index in range(500, 11000):
        source[index] = parent[index] ^ lane
    source_path = tmp_path / "source.bin"
    parent_path = tmp_path / "parent.bin"
    source_path.write_bytes(source)
    parent_path.write_bytes(parent)

    bundle = load_full_decode_bundle()
    result = run_lineage_lane_provider(source_path, parent_path, tmp_path / "provider", bundle=bundle)
    assert result["candidates"], "dominant XOR lane should produce a verified candidate"
    candidate = result["candidates"][0]
    assert int(candidate["changed_bytes"]) >= 10000
    assert candidate["validation"]["passed"] is True


def test_lineage_lane_provider_includes_verified_secondary_xor_lanes(tmp_path: Path):
    from src.services.full_decode.core import load_full_decode_bundle, run_lineage_lane_provider

    size = 12000
    primary_lane = 0x94
    secondary_lane = 0x28
    parent = bytearray((index % 256 for index in range(size)))
    source = bytearray(parent)
    for index in range(500, 11000):
        source[index] = parent[index] ^ primary_lane
    for index in range(200, 400):
        source[index] = parent[index] ^ secondary_lane
    for index in range(11200, 11300):
        source[index] = parent[index] ^ secondary_lane
    source_path = tmp_path / "source.bin"
    parent_path = tmp_path / "parent.bin"
    source_path.write_bytes(source)
    parent_path.write_bytes(parent)

    bundle = load_full_decode_bundle()
    result = run_lineage_lane_provider(source_path, parent_path, tmp_path / "provider", bundle=bundle)
    assert result["candidates"]
    candidate = result["candidates"][0]
    assert int(candidate["changed_bytes"]) >= 10500
    artifact = Path(candidate["artifact_path"]).read_bytes()
    for index in range(200, 400):
        assert artifact[index] == source[index]
    for index in range(11200, 11300):
        assert artifact[index] == source[index]
