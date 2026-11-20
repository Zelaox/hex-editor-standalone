"""Per-run investigation workspace under data/ — SSOT for one hex_investigation run_id."""

from __future__ import annotations
from src.project import project_root

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

_SAFE_STEM_RE = re.compile(r"[^\w.-]+")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def investigation_root() -> Path:
    lab = project_root()
    cfg_path = lab / "config" / "hex_editor.json"
    rel = "data/investigations"
    if cfg_path.is_file():
        try:
            rel = str(json.loads(cfg_path.read_text(encoding="utf-8")).get("investigation_root") or rel)
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    root = (lab / rel).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def investigation_id(*, source_path: Path, source_sha256: str) -> str:
    stem = _SAFE_STEM_RE.sub("_", source_path.stem).strip("._")[:32] or "target"
    digest = str(source_sha256 or "").strip().lower()
    if not digest:
        digest = hashlib.sha256(str(source_path.resolve()).encode("utf-8")).hexdigest()
    return f"{stem}_{digest[:16]}"


def investigation_run_id(*, source_path: Path, source_sha256: str, run_id: str) -> str:
    """One workspace folder per investigation run — never reuse hunt/milestone state across runs."""
    base = investigation_id(source_path=source_path, source_sha256=source_sha256)
    slug = _SAFE_STEM_RE.sub("_", str(run_id or "").strip().lower())[:16]
    if not slug:
        raise ValueError("run_id required for run-scoped investigation workspace")
    return f"{base}__{slug}"


def _fresh_workspace_state(*, run_id: str = "", goal_text: str = "", user_message: str = "") -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "completed_milestones": [],
        "pending_milestones": [],
        "session_carry": {},
        "decrypt_key_hunt": {},
        "chat_ui_links": {},
        "next_action": {},
        "operation_log": [],
    }
    if run_id:
        state["run_id"] = str(run_id)
    if goal_text:
        state["goal_text"] = str(goal_text)
    if user_message:
        state["user_message"] = str(user_message)
    return state


def _source_facts(path: str | Path) -> Dict[str, Any]:
    from hexeditor_tools.file_access import resolve_and_validate

    validation = resolve_and_validate(path)
    if not validation.get("ok"):
        raise ValueError(validation.get("error") or "invalid source path")
    resolved = validation["path"]
    sha256 = ""
    size = 0
    try:
        lab = project_root()
        editor_root = lab
        editor_path = str(editor_root)
        if editor_path not in sys.path and editor_root.is_dir():
            sys.path.insert(0, editor_path)
        from src.services.binary_inspection import binary_file_info

        info = binary_file_info(resolved)
        source = info.get("source") or {}
        sha256 = str(source.get("sha256") or "")
        size = int(source.get("size") or resolved.stat().st_size)
    except Exception:
        raw = resolved.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        size = len(raw)
    return {
        "source_path": str(resolved),
        "source_sha256": sha256,
        "source_size": size,
        "suffix": resolved.suffix.lower(),
    }


class HexInvestigationWorkspace:
    """All investigation data for one target file lives under this folder."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.manifest_path = self.root / "manifest.json"
        self.contract_path = self.root / "contract.json"
        self.state_path = self.root / "state.json"
        self.journal_path = self.root / "journal.jsonl"
        self.artifacts_dir = self.root / "artifacts"
        self.decrypted_dir = self.artifacts_dir / "decrypted"

    @property
    def investigation_id(self) -> str:
        return self.root.name

    @classmethod
    def open(cls, investigation_id: str) -> Optional["HexInvestigationWorkspace"]:
        root = investigation_root() / investigation_id
        if not (root / "manifest.json").is_file():
            return None
        ws = cls(root)
        ws.decrypted_dir.mkdir(parents=True, exist_ok=True)
        return ws

    @classmethod
    def ensure(
        cls,
        source_path: str | Path,
        *,
        goal_text: str = "",
        turn_id: str = "",
        user_message: str = "",
        run_id: str = "",
    ) -> "HexInvestigationWorkspace":
        facts = _source_facts(source_path)
        resolved = Path(facts["source_path"])
        if str(run_id or "").strip():
            inv_id = investigation_run_id(
                source_path=resolved,
                source_sha256=facts["source_sha256"],
                run_id=str(run_id),
            )
        else:
            inv_id = investigation_id(source_path=resolved, source_sha256=facts["source_sha256"])
        root = investigation_root() / inv_id
        is_new = not (root / "state.json").is_file()
        root.mkdir(parents=True, exist_ok=True)
        ws = cls(root)
        ws.decrypted_dir.mkdir(parents=True, exist_ok=True)
        now = _utc_now()
        manifest = ws.load_manifest() or {}
        manifest.update(
            {
                "schema_version": 1,
                "investigation_id": inv_id,
                "source_path": facts["source_path"],
                "source_sha256": facts["source_sha256"],
                "source_size": facts["source_size"],
                "suffix": facts["suffix"],
                "scope_id": "hex_investigation_readonly",
                "created_at": manifest.get("created_at") or now,
                "updated_at": now,
            }
        )
        if run_id:
            manifest["run_id"] = str(run_id)
        if goal_text:
            manifest["goal_text"] = str(goal_text)
        if turn_id:
            manifest["last_turn_id"] = str(turn_id)
        ws.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        if is_new and run_id:
            state = _fresh_workspace_state(
                run_id=str(run_id),
                goal_text=str(goal_text or ""),
                user_message=str(user_message or ""),
            )
        else:
            state = ws.load_state()
            if goal_text and not state.get("goal_text"):
                state["goal_text"] = str(goal_text)
            if user_message and not state.get("user_message"):
                state["user_message"] = str(user_message)
            if run_id:
                state["run_id"] = str(run_id)
        ws.save_state(state)
        return ws

    def load_manifest(self) -> Dict[str, Any]:
        if not self.manifest_path.is_file():
            return {}
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def load_state(self) -> Dict[str, Any]:
        if not self.state_path.is_file():
            return {
                "completed_milestones": [],
                "pending_milestones": [],
                "session_carry": {},
                "decrypt_key_hunt": {},
                "chat_ui_links": {},
                "next_action": {},
                "operation_log": [],
            }
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def load_contract(self) -> Dict[str, Any]:
        if not self.contract_path.is_file():
            return {}
        try:
            return json.loads(self.contract_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def save_state(self, state: Mapping[str, Any]) -> None:
        payload = dict(state)
        payload["updated_at"] = _utc_now()
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        manifest = self.load_manifest()
        if manifest:
            manifest["updated_at"] = payload["updated_at"]
            self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def append_journal(self, entry: Mapping[str, Any]) -> None:
        row = {"ts": _utc_now(), **dict(entry)}
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def sync_contract(self, analysis: Mapping[str, Any], *, user_message: str = "") -> Dict[str, Any]:
        from hexeditor_tools.investigation import compile_investigation_breakdown, apply_completed_milestones
        state = self.load_state()
        breakdown = compile_investigation_breakdown(analysis, str(self.load_manifest().get("source_path") or ""), user_message=user_message)
        breakdown = apply_completed_milestones(breakdown, state.get("completed_milestones") or [])
        self.contract_path.write_text(json.dumps(breakdown, indent=2), encoding="utf-8")
        state["pending_milestones"] = [str(item["id"]) for item in breakdown.get("milestones", []) if item.get("status") not in {"done", "ready"}]
        self.save_state(state)
        return breakdown

    def _breakdown_for_disk(self, breakdown: Mapping[str, Any], execution_id: str, revision: int) -> Dict[str, Any]:
        return dict(breakdown)

    def mark_milestones_done(self, milestone_ids: List[str], *, reason: str = "") -> None:
        from hexeditor_tools.investigation import apply_completed_milestones
        state = self.load_state()
        done = set(state.get("completed_milestones") or []) | {str(item) for item in milestone_ids if item}
        state["completed_milestones"] = sorted(done)
        contract = self.load_contract()
        if contract:
            contract = apply_completed_milestones(contract, state["completed_milestones"])
            self.contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
            state["pending_milestones"] = [str(item["id"]) for item in contract.get("milestones", []) if item.get("status") != "done"]
        self.save_state(state)
        if reason:
            self.append_journal({"event": "milestones_done", "milestones": milestone_ids, "reason": reason})

    def apply_probe_result(self, probe_result: Mapping[str, Any], *, turn_id: str = "") -> Dict[str, Any]:
        from hexeditor_tools.key_hunt import apply_probe_to_hunt

        state = self.load_state()
        hunt = dict(state.get("decrypt_key_hunt") or {})
        if not hunt:
            manifest = self.load_manifest()
            hunt = {
                "target_path": manifest.get("source_path", ""),
                "goal_text": state.get("goal_text") or manifest.get("goal_text") or "",
                "keys_found": False,
                "best_key_hex": "",
                "phase": "probe",
            }
        state["decrypt_key_hunt"] = apply_probe_to_hunt(hunt, probe_result)
        updated_hunt = dict(state["decrypt_key_hunt"])
        carry = dict(state.get("session_carry") or {})
        carry["decrypt_key_hunt"] = updated_hunt
        promotion = dict(probe_result.get("promotion_evidence") or {})
        if probe_result.get("keys_found") and promotion.get("promoted"):
            carry["last_key_hex"] = str(probe_result.get("best_key_hex") or "")
            carry["promotion_evidence"] = promotion
            links = probe_result.get("chat_ui_links") or {}
            if links:
                state["chat_ui_links"] = links
                carry["decrypted_path"] = links.get("decrypted_path", "")
                carry["decrypted_markdown_link"] = links.get("markdown_link", "")
                carry["source_snapshot_path"] = links.get("source_snapshot_path", "")
                carry["source_markdown_link"] = links.get("source_markdown_link", "")
                carry["artifact_folder"] = links.get("artifact_folder", "")
            completed = list(state.get("completed_milestones") or [])
            if "M7" in completed and "M8" in completed:
                self.mark_milestones_done(["M9"], reason="promotion_gate_passed")
        else:
            carry["last_key_cursor"] = int(updated_hunt.get("last_key_cursor") or 0)
        state["session_carry"] = carry
        state["last_probe"] = {
            "keys_found": bool(probe_result.get("keys_found")),
            "best_key_hex": str(probe_result.get("best_key_hex") or ""),
            "turn_id": turn_id,
        }
        self.save_state(state)
        self.append_journal(
            {
                "event": "ptx_probe_decrypt_keys",
                "turn_id": turn_id,
                "keys_found": bool(probe_result.get("keys_found")),
                "best_key_hex": probe_result.get("best_key_hex"),
            }
        )
        return state

    def artifacts_decrypted_dir(self) -> Path:
        self.decrypted_dir.mkdir(parents=True, exist_ok=True)
        return self.decrypted_dir

    def persist_checkpoint_artifacts(
        self,
        pointer: Mapping[str, Any],
        *,
        brief: Optional[Mapping[str, Any]] = None,
        inspect_cursor: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write artifact pointer + compiled brief cache under artifacts/."""
        import sys

        hex_root = project_root()
        if str(hex_root) not in sys.path:
            sys.path.insert(0, str(hex_root))
        from src.services.snapshot_brief_compiler import brief_digest, compile_snapshot_brief

        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        pointer_payload = dict(pointer)
        (self.artifacts_dir / "pointer.json").write_text(
            json.dumps(pointer_payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        compiled = dict(brief or compile_snapshot_brief(pointer_payload, inspect_cursor=inspect_cursor))
        digest = str(compiled.get("brief_digest") or brief_digest(compiled))
        (self.artifacts_dir / "snapshot_brief.json").write_text(
            json.dumps(compiled, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        (self.artifacts_dir / "brief_digest.sha256").write_text(digest + "\n", encoding="utf-8")
        state = self.load_state()
        state["artifact_pointer"] = pointer_payload
        state["brief_digest"] = digest
        state["inspect_cursor"] = dict(compiled.get("inspect_cursor") or inspect_cursor or {})
        carry = dict(state.get("session_carry") or {})
        carry["artifact_pointer"] = pointer_payload
        carry["brief_digest"] = digest
        carry["inspect_cursor"] = dict(state["inspect_cursor"])
        carry["snapshot_brief"] = compiled
        state["session_carry"] = carry
        self.save_state(state)
        self.append_journal(
            {
                "event": "artifact_bound",
                "operation_id": pointer_payload.get("operation_id"),
                "brief_digest": digest,
            }
        )
        self.append_journal({"event": "brief_compiled", "brief_digest": digest})
        return {
            "ok": True,
            "artifact_pointer": pointer_payload,
            "brief_digest": digest,
            "snapshot_brief": compiled,
        }

    def load_checkpoint_brief(self) -> Dict[str, Any]:
        brief_path = self.artifacts_dir / "snapshot_brief.json"
        if brief_path.is_file():
            return json.loads(brief_path.read_text(encoding="utf-8"))
        pointer_path = self.artifacts_dir / "pointer.json"
        if not pointer_path.is_file():
            return {}
        import sys

        hex_root = project_root()
        if str(hex_root) not in sys.path:
            sys.path.insert(0, str(hex_root))
        from src.services.snapshot_brief_compiler import compile_snapshot_brief

        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        state = self.load_state()
        return compile_snapshot_brief(pointer, inspect_cursor=state.get("inspect_cursor"))

    def format_chat_brief(self) -> str:
        manifest = self.load_manifest()
        state = self.load_state()
        contract = self.load_contract()
        done = list(state.get("completed_milestones") or [])
        pending = list(state.get("pending_milestones") or [])
        if not pending and contract:
            pending = [
                str(item.get("id"))
                for item in contract.get("milestones") or []
                if isinstance(item, dict) and str(item.get("status") or "") not in {"done"}
            ]
        lines = [
            "## Investigation workspace (per-file data/)",
            "",
            f"- Folder: `{self.root}`",
            f"- Target: `{manifest.get('source_path', '?')}`",
            f"- SHA256: `{manifest.get('source_sha256', '?')}`",
        ]
        if done:
            lines.append(f"- **Done:** {', '.join(done)}")
        if pending:
            lines.append(f"- **Pending:** {', '.join(pending[:8])}")
        hunt = state.get("decrypt_key_hunt") or {}
        if hunt.get("keys_found"):
            lines.append(f"- Decrypt key (hypothesis): `{hunt.get('best_key_hex')}`")
        links = state.get("chat_ui_links") or {}
        if links.get("markdown_link"):
            lines.append(f"- Auto-decrypted: {links.get('markdown_link')}")
        if links.get("source_markdown_link"):
            lines.append(f"- Original (snapshot): {links.get('source_markdown_link')}")
        if links.get("artifact_folder"):
            lines.append(f"- Artifact folder: `{links.get('artifact_folder')}`")
        next_action = state.get("next_action") or {}
        if next_action.get("operation"):
            lines.append(
                f"- Next: `{next_action.get('operation')}` — {next_action.get('reason', '')}"
            )
        lines.append("- Full state: manifest.json, contract.json, state.json, journal.jsonl")
        return "\n".join(lines).strip()


def ensure_workspace_for_path(
    source_path: str | Path,
    *,
    goal_text: str = "",
    turn_id: str = "",
    user_message: str = "",
    run_id: str = "",
) -> HexInvestigationWorkspace:
    return HexInvestigationWorkspace.ensure(
        source_path,
        goal_text=goal_text,
        turn_id=turn_id,
        user_message=user_message,
        run_id=run_id,
    )


def try_workspace_for_path(source_path: str | Path) -> Optional[HexInvestigationWorkspace]:
    try:
        facts = _source_facts(source_path)
    except ValueError:
        return None
    inv_id = investigation_id(
        source_path=Path(facts["source_path"]),
        source_sha256=facts["source_sha256"],
    )
    return HexInvestigationWorkspace.open(inv_id)


def persist_probe_to_workspace(
    source_path: str | Path,
    probe_result: Mapping[str, Any],
    *,
    turn_id: str = "",
    goal_text: str = "",
    user_message: str = "",
) -> Optional[HexInvestigationWorkspace]:
    import os

    import os

    active_run_id = str(os.environ.get("HEX_INVESTIGATION_RUN_ID") or "")
    ws = ensure_workspace_for_path(
        source_path,
        goal_text=goal_text,
        turn_id=turn_id,
        user_message=user_message,
        run_id=active_run_id,
    )
    if os.environ.get("HEX_INVESTIGATION_RUNNER_ACTIVE") == "1":
        state = ws.load_state()
        state["last_probe"] = {
            "keys_found": bool(probe_result.get("keys_found")),
            "best_key_hex": str(probe_result.get("best_key_hex") or ""),
            "probe_phase_id": str(probe_result.get("probe_phase_id") or ""),
            "phase_exhausted": bool(probe_result.get("phase_exhausted")),
            "turn_id": turn_id,
        }
        ws.save_state(state)
        return ws
    ws.apply_probe_result(probe_result, turn_id=turn_id)
    return ws


def find_workspace_by_source_sha256(source_sha256: str) -> Optional[HexInvestigationWorkspace]:
    digest = str(source_sha256 or "").strip().lower()
    if not digest:
        return None
    suffix = digest[:16]
    root = investigation_root()
    for path in sorted(root.glob(f"*_{suffix}"), key=lambda p: p.stat().st_mtime, reverse=True):
        ws = HexInvestigationWorkspace(path)
        manifest = ws.load_manifest()
        if str(manifest.get("source_sha256") or "").lower().startswith(suffix):
            return ws
    return None
