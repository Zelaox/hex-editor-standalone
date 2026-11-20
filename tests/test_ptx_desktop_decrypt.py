from __future__ import annotations

from pathlib import Path

from src.services import ptx_desktop_decrypt
from src.services.ptx_auto_decrypt import materialize_ptx_decrypt_to_path


def test_materialize_verified_xor_is_atomic_and_preserves_source(tmp_path: Path):
    clear = b"HEAD" + b"Track Clip Timeline"
    encrypted = clear[:4] + bytes(value ^ 0x5A for value in clear[4:])
    source = tmp_path / "encrypted.ptx"
    destination = tmp_path / "decrypted.ptx"
    source.write_bytes(encrypted)
    result = materialize_ptx_decrypt_to_path(source, destination, "5a", algorithm="xor_single_byte", transform_start=4)
    assert result["ok"] is True
    assert destination.read_bytes() == clear
    assert source.read_bytes() == encrypted
    assert result["source_preserved"] is True


def test_materialize_refuses_source_overwrite(tmp_path: Path):
    source = tmp_path / "source.ptx"
    source.write_bytes(b"data")
    result = materialize_ptx_decrypt_to_path(source, source, "01", algorithm="xor_single_byte", transform_start=0)
    assert result["ok"] is False
    assert "must not overwrite" in result["error"]


def test_desktop_decrypt_does_not_write_unverified_candidate(tmp_path: Path, monkeypatch):
    source, destination = tmp_path / "source.ptx", tmp_path / "output.ptx"
    source.write_bytes(b"cipher")
    monkeypatch.setattr(ptx_desktop_decrypt, "probe_ptx_decrypt_keys", lambda *_args, **_kwargs: {"ok": True, "keys_found": False, "promotion_evidence": {"promoted": False}})
    result = ptx_desktop_decrypt.decrypt_ptx_with_verified_probe(source, destination)
    assert result["status"] == "no_verified_candidate"
    assert not destination.exists()


def test_desktop_decrypt_materializes_only_promoted_candidate(tmp_path: Path, monkeypatch):
    source, destination = tmp_path / "source.ptx", tmp_path / "output.ptx"
    source.write_bytes(b"cipher")
    monkeypatch.setattr(ptx_desktop_decrypt, "probe_ptx_decrypt_keys", lambda *_args, **_kwargs: {"ok": True, "keys_found": True, "best_key_hex": "5a", "best_algorithm": "xor_single_byte", "xor_start_offset": 4, "promotion_evidence": {"promoted": True}})
    captured = {}
    def materialize(src, dst, key_hex, **kwargs):
        captured.update({"src": src, "dst": dst, "key_hex": key_hex, **kwargs})
        return {"ok": True, "decrypted_path": str(dst)}
    monkeypatch.setattr(ptx_desktop_decrypt, "materialize_ptx_decrypt_to_path", materialize)
    result = ptx_desktop_decrypt.decrypt_ptx_with_verified_probe(source, destination)
    assert result["status"] == "materialized"
    assert captured["key_hex"] == "5a"
    assert captured["transform_start"] == 4
