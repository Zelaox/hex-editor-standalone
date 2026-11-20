"""Auto-materialize decrypted PTX copies for Chat UI download links."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict
from urllib.parse import quote

from src.services.ptx_key_discovery import DEFAULT_SAMPLE_OFFSET, _parse_key_hex, _xor_apply


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_source_beside_artifact(source: Path, out_dir: Path) -> Path:
    """Copy read-only source snapshot into the artifact folder beside the decrypt output."""
    resolved_source = source.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    target = (out_dir / resolved_source.name).resolve()
    if resolved_source == target:
        return target
    source_digest = _file_sha256(resolved_source)
    if target.is_file() and _file_sha256(target) == source_digest:
        return target
    if target.is_file():
        target = (out_dir / f"{resolved_source.stem}_original{resolved_source.suffix}").resolve()
        if target.is_file() and _file_sha256(target) == source_digest:
            return target
    shutil.copy2(resolved_source, target)
    return target


def decrypted_output_dir() -> Path:
    lab = _lab_root()
    config = json.loads((lab / "config" / "hex_editor.json").read_text(encoding="utf-8"))
    out = (lab / config["runtime_root"] / "decrypted").resolve()
    out.mkdir(parents=True, exist_ok=True)
    return out


def build_chat_file_download_url(abs_path: Path) -> str:
    return f"/api/chat/hex-editor/file?path={quote(str(abs_path.resolve()), safe='')}"


def build_chat_ui_links(
    *,
    decrypted_path: Path,
    key_hex: str,
    source_path: Path,
    source_snapshot_path: Path | None = None,
) -> Dict[str, str]:
    url = build_chat_file_download_url(decrypted_path)
    name = decrypted_path.name
    markdown_link = f"[{name}]({url})"
    snapshot = source_snapshot_path or source_path
    source_url = build_chat_file_download_url(snapshot)
    source_markdown = f"[{snapshot.name}]({source_url})"
    must_include = f"Dekrypterad fil (auto): {markdown_link}"
    if snapshot.parent.resolve() == decrypted_path.parent.resolve():
        must_include = f"Original + dekrypterad i samma mapp: {source_markdown} | {markdown_link}"
    return {
        "decrypted_path": str(decrypted_path.resolve()),
        "source_path": str(source_path.resolve()),
        "source_snapshot_path": str(snapshot.resolve()),
        "artifact_folder": str(decrypted_path.parent.resolve()),
        "key_hex": str(key_hex),
        "url": url,
        "markdown_link": markdown_link,
        "source_url": source_url,
        "source_markdown_link": source_markdown,
        "must_include_in_reply": must_include,
    }


def materialize_ptx_decrypt_copy(
    source: str | Path,
    key_hex: str,
    *,
    algorithm: str = "xor_single_byte",
    xor_start_offset: int = DEFAULT_SAMPLE_OFFSET,
    artifact_output_dir: str | Path | None = None,
) -> Dict[str, Any]:
    """Write a decrypted PTX copy for Chat UI download (workspace artifacts or runtime fallback)."""
    resolved = Path(source).expanduser().resolve()
    if resolved.suffix.lower() != ".ptx":
        return {"ok": False, "error": "materialize requires a .ptx source file"}

    try:
        key = _parse_key_hex(str(key_hex))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    raw = resolved.read_bytes()
    start = max(0, min(int(xor_start_offset), len(raw)))
    algo = str(algorithm or "xor_single_byte")

    if algo == "aes128_ecb":
        from src.services.ptx_crypto_primitives import aes128_ecb_decrypt, pkcs7_unpad

        if len(key) != 16:
            return {"ok": False, "error": "AES-128 materialize requires 16-byte key_hex"}
        body = raw[start:]
        body = body[: len(body) - (len(body) % 16)]
        decrypted_body = aes128_ecb_decrypt(body, key)
        decrypted_body, _ = pkcs7_unpad(decrypted_body)
        decrypted = raw[:start] + decrypted_body
        key_label = key.hex()
        out_name = f"{resolved.stem}_aes{key_label[:8]}_decrypted.ptx"
    else:
        body = _xor_apply(raw[start:], key)
        decrypted = raw[:start] + body
        key_label = key.hex()
        out_name = f"{resolved.stem}_key{key_label}_decrypted.ptx"
    if artifact_output_dir is not None:
        out_dir = Path(artifact_output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = decrypted_output_dir()
    out_path = out_dir / out_name
    out_path.write_bytes(decrypted)
    source_snapshot = snapshot_source_beside_artifact(resolved, out_dir)

    digest = hashlib.sha256(decrypted).hexdigest()
    links = build_chat_ui_links(
        decrypted_path=out_path,
        key_hex=key_label,
        source_path=resolved,
        source_snapshot_path=source_snapshot,
    )
    return {
        "ok": True,
        "decrypted_path": str(out_path.resolve()),
        "source_snapshot_path": str(source_snapshot.resolve()),
        "artifact_folder": str(out_dir.resolve()),
        "bytes_written": len(decrypted),
        "sha256": digest,
        "source_sha256": _file_sha256(resolved),
        "algorithm": algo,
        "xor_start_offset": start,
        "chat_ui_links": links,
    }


def materialize_ptx_decrypt_to_path(
    source: str | Path,
    destination: str | Path,
    key_hex: str,
    *,
    algorithm: str,
    transform_start: int,
) -> Dict[str, Any]:
    """Atomically write one explicitly confirmed verified decrypt result."""
    resolved = Path(source).expanduser().resolve()
    target = Path(destination).expanduser().resolve()
    if resolved.suffix.lower() != ".ptx" or target.suffix.lower() != ".ptx":
        return {"ok": False, "error": "source and destination must be .ptx files"}
    if resolved == target:
        return {"ok": False, "error": "decrypted destination must not overwrite the source"}
    try:
        key = _parse_key_hex(str(key_hex))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    raw = resolved.read_bytes()
    start = max(0, min(int(transform_start), len(raw)))
    algo = str(algorithm or "")
    if algo == "aes128_ecb":
        from src.services.ptx_crypto_primitives import aes128_ecb_decrypt, pkcs7_unpad

        if len(key) != 16:
            return {"ok": False, "error": "AES-128 materialize requires 16-byte key_hex"}
        body = raw[start:]
        aligned_length = len(body) - (len(body) % 16)
        decrypted_body = aes128_ecb_decrypt(body[:aligned_length], key)
        decrypted_body, _ = pkcs7_unpad(decrypted_body)
        decrypted = raw[:start] + decrypted_body + body[aligned_length:]
    elif algo in ("xor_single_byte", "xor_repeating"):
        decrypted = raw[:start] + _xor_apply(raw[start:], key)
    else:
        return {"ok": False, "error": f"unsupported verified algorithm: {algo}"}
    source_sha = hashlib.sha256(raw).hexdigest()
    output_sha = hashlib.sha256(decrypted).hexdigest()
    if output_sha == source_sha:
        return {"ok": False, "error": "identity transform refused"}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(decrypted)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    if _file_sha256(resolved) != source_sha:
        target.unlink(missing_ok=True)
        return {"ok": False, "error": "source changed during decrypt; output removed"}
    return {"ok": True, "decrypted_path": str(target), "source_sha256": source_sha, "sha256": output_sha, "bytes_written": len(decrypted), "algorithm": algo, "transform_start": start, "source_preserved": True}
