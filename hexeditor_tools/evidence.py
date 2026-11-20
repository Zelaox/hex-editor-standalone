"""SSOT: verified_facts vs model_hypotheses — hard epistemic separation for hex investigation."""

from __future__ import annotations

from src.project import project_root

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

SCHEMA_VERSION = 1

# Parser-derived labels must never appear as verified facts without byte backing.
_FORBIDDEN_VERIFIED_INTERPRETATIONS = frozenset(
    {
        "encrypted",
        "encryption_type",
        "encryption algorithm",
        "corrupt",
        "corruption",
        "timecode",
        "section header",
        "session info",
    }
)

EPISTEMIC_RULES = (
    "verified_facts: only direct tool observations (bytes, hashes, sizes, match offsets). "
    "model_hypotheses: parser labels, regex hits, format guesses — always with confidence. "
    "Never promote encrypted=true or encryption_type=N to verified_facts because a parser said so."
)


def verified_fact(
    *,
    bytes_at: str,
    value: str,
    source: str,
    observation: str = "raw_bytes",
) -> Dict[str, Any]:
    return {
        "kind": "verified_fact",
        "bytes_at": str(bytes_at),
        "value": str(value),
        "source": str(source),
        "observation": str(observation),
    }


def model_hypothesis(
    *,
    interpreted_as: str,
    confidence: str = "low",
    parser_provenance: str = "",
    bytes_at: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "kind": "model_hypothesis",
        "interpreted_as": str(interpreted_as),
        "confidence": str(confidence),
        "parser_provenance": str(parser_provenance or ""),
        "bytes_at": str(bytes_at) if bytes_at else None,
        "details": dict(details or {}),
    }


def compile_epistemic_state_from_binary_info(result: Mapping[str, Any]) -> Dict[str, Any]:
    source = result.get("source") or {}
    verified: List[Dict[str, Any]] = []
    if source.get("size") is not None:
        verified.append(
            verified_fact(
                bytes_at="file",
                value=f"size={source.get('size')} bytes",
                source="binary_file_info",
                observation="filesystem_stat",
            )
        )
    if source.get("sha256"):
        verified.append(
            verified_fact(
                bytes_at="file",
                value=str(source.get("sha256")),
                source="binary_file_info",
                observation="sha256_digest",
            )
        )
    prefix = str(result.get("prefix_hex") or "").strip()
    if prefix:
        verified.append(
            verified_fact(
                bytes_at="0x00-0x1F",
                value=prefix,
                source="binary_file_info",
                observation="raw_bytes",
            )
        )
    return _wrap(verified, [])


def compile_epistemic_state_from_read_range(result: Mapping[str, Any]) -> Dict[str, Any]:
    offset = int(result.get("offset") or 0)
    length = int(result.get("returned_length") or 0)
    end = max(offset, offset + length - 1) if length else offset
    verified = [
        verified_fact(
            bytes_at=f"0x{offset:X}-0x{end:X}",
            value=str(result.get("hex") or ""),
            source="binary_read_range",
            observation="raw_bytes",
        ),
    ]
    if result.get("ascii"):
        verified.append(
            verified_fact(
                bytes_at=f"0x{offset:X}-0x{end:X}",
                value=str(result.get("ascii")),
                source="binary_read_range",
                observation="printable_ascii",
            )
        )
    return _wrap(verified, [])


def compile_epistemic_state_from_search(result: Mapping[str, Any]) -> Dict[str, Any]:
    matches = list(result.get("matches") or [])
    verified = [
        verified_fact(
            bytes_at=f"0x{int(offset):X}",
            value=f"pattern match at offset 0x{int(offset):X}",
            source="binary_search",
            observation="match_offset",
        )
        for offset in matches[:20]
    ]
    hypotheses: List[Dict[str, Any]] = []
    if result.get("limit_reached"):
        hypotheses.append(
            model_hypothesis(
                interpreted_as="search result set may be incomplete",
                confidence="high",
                parser_provenance="binary_search.limit_reached",
            )
        )
    return _wrap(verified, hypotheses)


def compile_epistemic_state_from_pe_analysis(
    result: Mapping[str, Any],
    *,
    byte_evidence: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """PE plugin: MZ/PE byte windows → verified_facts; pefile labels → model_hypotheses."""
    verified: List[Dict[str, Any]] = []
    hypotheses: List[Dict[str, Any]] = []

    source = result.get("source") or {}
    if source.get("size") is not None:
        verified.append(
            verified_fact(
                bytes_at="file",
                value=f"size={source.get('size')} bytes",
                source="pe_analyze",
                observation="filesystem_stat",
            )
        )
    if source.get("sha256"):
        verified.append(
            verified_fact(
                bytes_at="file",
                value=str(source.get("sha256")),
                source="pe_analyze",
                observation="sha256_digest",
            )
        )

    for window in byte_evidence or []:
        offset = int(window.get("offset") or 0)
        length = int(window.get("length") or 0)
        end = max(offset, offset + length - 1) if length else offset
        hexdump = window.get("hexdump") or []
        if hexdump:
            verified.append(
                verified_fact(
                    bytes_at=f"0x{offset:X}-0x{end:X}",
                    value="\n".join(str(line) for line in hexdump[:6]),
                    source="pe_evidence.build_byte_evidence",
                    observation="raw_bytes",
                )
            )
        label = str(window.get("label") or "")
        if label == "dos_header_mz":
            hypotheses.append(
                model_hypothesis(
                    interpreted_as="DOS header MZ signature (PE container hypothesis)",
                    confidence="medium",
                    parser_provenance="pefile.PE",
                    bytes_at="0x0-0x1",
                )
            )

    for finding in result.get("findings") or []:
        label = str(finding.get("label") or finding.get("kind") or "")
        value = finding.get("value")
        provenance = str(finding.get("provenance") or "pefile")
        if label == "pe_header" and isinstance(value, dict):
            for field in ("machine", "number_of_sections", "entry_section_name"):
                if value.get(field) is not None:
                    hypotheses.append(
                        model_hypothesis(
                            interpreted_as=f"PE header field {field}",
                            confidence="heuristic",
                            parser_provenance=provenance,
                            bytes_at="pe_header",
                            details={field: value.get(field)},
                        )
                    )
            optional = value.get("optional_header") or {}
            if optional.get("AddressOfEntryPoint") is not None:
                hypotheses.append(
                    model_hypothesis(
                        interpreted_as="PE optional header AddressOfEntryPoint",
                        confidence="heuristic",
                        parser_provenance=provenance,
                        bytes_at=f"0x{int(optional['AddressOfEntryPoint']):X}",
                    )
                )
        elif label == "sections" and isinstance(value, list):
            for section in value[:6]:
                if isinstance(section, dict):
                    hypotheses.append(
                        model_hypothesis(
                            interpreted_as=f"PE section {section.get('name')}",
                            confidence="low",
                            parser_provenance=provenance,
                            bytes_at=f"0x{int(section.get('virtual_address') or 0):X}",
                            details=section,
                        )
                    )
        elif label in {"imports", "exports"} and isinstance(value, list):
            for item in value[:6]:
                hypotheses.append(
                    model_hypothesis(
                        interpreted_as=f"PE {label} entry (symbol table hypothesis)",
                        confidence="low",
                        parser_provenance=provenance,
                        details={"name": item},
                    )
                )

    return _wrap(verified, hypotheses)


def compile_epistemic_state_from_disasm(result: Mapping[str, Any]) -> Dict[str, Any]:
    verified: List[Dict[str, Any]] = []
    hypotheses: List[Dict[str, Any]] = []
    for finding in result.get("findings") or []:
        if str(finding.get("label") or "") != "disasm_entry":
            continue
        payload = finding.get("value") or {}
        for instr in list(payload.get("instructions") or [])[:16]:
            if not isinstance(instr, dict):
                continue
            verified.append(
                verified_fact(
                    bytes_at=str(instr.get("address") or "?"),
                    value=f"{instr.get('mnemonic')} {instr.get('operands')}".strip(),
                    source="disasm_readonly",
                    observation="disasm_instruction",
                )
            )
        hypotheses.append(
            model_hypothesis(
                interpreted_as="entry-point disassembly slice (control flow not proven)",
                confidence="low",
                parser_provenance="capstone.disasm_lite",
                bytes_at=str(payload.get("entry_rva") or "?"),
            )
        )
    return _wrap(verified, hypotheses)


def compile_epistemic_state_from_ptx_analysis(
    result: Mapping[str, Any],
    *,
    byte_evidence: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """PTX plugin: bytes → verified_facts; parser JSON → model_hypotheses only."""
    verified: List[Dict[str, Any]] = []
    hypotheses: List[Dict[str, Any]] = []

    source = result.get("source") or {}
    if source.get("size") is not None:
        verified.append(
            verified_fact(
                bytes_at="file",
                value=f"size={source.get('size')} bytes",
                source="ptx_analyze",
                observation="filesystem_stat",
            )
        )
    if source.get("sha256"):
        verified.append(
            verified_fact(
                bytes_at="file",
                value=str(source.get("sha256")),
                source="ptx_analyze",
                observation="sha256_digest",
            )
        )

    for window in byte_evidence or []:
        offset = int(window.get("offset") or 0)
        length = int(window.get("length") or 0)
        end = max(offset, offset + length - 1) if length else offset
        hexdump = window.get("hexdump") or []
        if hexdump:
            verified.append(
                verified_fact(
                    bytes_at=f"0x{offset:X}-0x{end:X}",
                    value="\n".join(str(line) for line in hexdump[:8]),
                    source="ptx_evidence.build_byte_evidence",
                    observation="raw_bytes",
                )
            )
        label = str(window.get("label") or "")
        if label == "encryption_field_window_0x10":
            hypotheses.append(
                model_hypothesis(
                    interpreted_as="encryption_type field (uint32 LE hypothesis)",
                    confidence="low",
                    parser_provenance="PTXHeader.encryption_type",
                    bytes_at="0x10-0x13",
                )
            )

    for finding in result.get("findings") or []:
        label = str(finding.get("label") or finding.get("kind") or "")
        value = finding.get("value")
        confidence = str(finding.get("confidence") or "heuristic")
        provenance = str(finding.get("provenance") or finding.get("source") or "ptx_parser")

        if label == "header" and isinstance(value, dict):
            enc_info = value.get("encryption_info") or {}
            layout = str(value.get("layout") or "")
            if enc_info.get("encrypted"):
                if layout == "session_text_header":
                    hypotheses.append(
                        model_hypothesis(
                            interpreted_as="parser flag body_encrypted=true (no cleartext SMPTE anchors in file)",
                            confidence="low",
                            parser_provenance=provenance,
                            bytes_at="file",
                            details={"body_encrypted": value.get("body_encrypted")},
                        )
                    )
                else:
                    hypotheses.append(
                        model_hypothesis(
                            interpreted_as="parser flag encrypted=true (non-zero encryption_type field)",
                            confidence="low",
                            parser_provenance=provenance,
                            bytes_at="0x10-0x13",
                            details={"encryption_type": value.get("encryption_type")},
                        )
                    )
            for field in ("magic", "version", "flags", "size"):
                if field in value:
                    hypotheses.append(
                        model_hypothesis(
                            interpreted_as=f"PTX header field {field}",
                            confidence=confidence,
                            parser_provenance=provenance,
                            bytes_at="0x00-0x1F",
                            details={field: value.get(field)},
                        )
                    )
            misaligned = value.get("misaligned_binary_fields")
            if isinstance(misaligned, dict):
                for field in ("version", "flags", "size", "encryption_type"):
                    if field in misaligned:
                        hypotheses.append(
                            model_hypothesis(
                                interpreted_as=f"misaligned legacy header field {field}",
                                confidence="low",
                                parser_provenance=provenance,
                                bytes_at="0x00-0x1F",
                                details={field: misaligned.get(field), "layout": layout},
                            )
                        )
            for session_string in value.get("session_strings") or []:
                hypotheses.append(
                    model_hypothesis(
                        interpreted_as="cleartext session metadata string",
                        confidence="verified",
                        parser_provenance=provenance,
                        bytes_at="0x20+",
                        details={"value": session_string},
                    )
                )
        elif label == "sections" and isinstance(value, list):
            for section in value[:8]:
                if not isinstance(section, dict):
                    continue
                hypotheses.append(
                    model_hypothesis(
                        interpreted_as="PTX section header (heuristic)",
                        confidence="low",
                        parser_provenance=provenance,
                        bytes_at=str(section.get("offset") or ""),
                        details=section,
                    )
                )
        elif label == "timecodes" and isinstance(value, list):
            for item in value[:8]:
                if not isinstance(item, dict):
                    continue
                hypotheses.append(
                    model_hypothesis(
                        interpreted_as="timecode regex hit (unverified)",
                        confidence="low",
                        parser_provenance=provenance,
                        bytes_at=f"0x{int(item.get('offset', 0)):X}",
                        details=item,
                    )
                )

    return _wrap(verified, hypotheses)


def validate_epistemic_separation(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return violations when verified_facts contain parser interpretations."""
    violations: List[Dict[str, Any]] = []
    for index, fact in enumerate(state.get("verified_facts") or []):
        if not isinstance(fact, dict):
            continue
        blob = f"{fact.get('value', '')} {fact.get('observation', '')}".lower()
        if fact.get("observation") in {"raw_bytes", "sha256_digest", "filesystem_stat", "match_offset", "printable_ascii"}:
            continue
        for forbidden in _FORBIDDEN_VERIFIED_INTERPRETATIONS:
            if forbidden in blob:
                violations.append(
                    {
                        "issue_code": "parser_claim_in_verified_facts",
                        "index": index,
                        "blocking": True,
                        "explanation": (
                            f"verified_facts[{index}] appears to contain parser interpretation "
                            f"({forbidden!r}). Move to model_hypotheses with confidence."
                        ),
                    }
                )
                break
    return violations


def format_epistemic_state_compact(
    state: Mapping[str, Any],
    *,
    max_facts: int = 6,
    max_hypotheses: int = 8,
) -> str:
    """Short evidence bundle for LLM synthesis — not the full chat contract dump."""
    lines = ["verified_facts:"]
    facts = list(state.get("verified_facts") or [])[:max_facts]
    if not facts:
        lines.append("- (none)")
    for fact in facts:
        if isinstance(fact, dict):
            lines.append(
                f"- {fact.get('bytes_at')}: {str(fact.get('value') or '')[:120]} "
                f"({fact.get('source')})"
            )
    extra_facts = len(state.get("verified_facts") or []) - len(facts)
    if extra_facts > 0:
        lines.append(f"- … +{extra_facts} more byte windows omitted")

    lines.append("")
    lines.append("model_hypotheses:")
    hyps = list(state.get("model_hypotheses") or [])[:max_hypotheses]
    if not hyps:
        lines.append("- (none)")
    for item in hyps:
        if isinstance(item, dict):
            lines.append(
                f"- {item.get('interpreted_as')} "
                f"(confidence={item.get('confidence')}, at={item.get('bytes_at') or '?'})"
            )
    extra_h = len(state.get("model_hypotheses") or []) - len(hyps)
    if extra_h > 0:
        lines.append(f"- … +{extra_h} more hypotheses omitted")
    return "\n".join(lines)


def format_epistemic_state_for_chat(state: Mapping[str, Any]) -> str:
    lines = [
        "## Epistemic state (mandatory separation)",
        "",
        f"Rules: {state.get('epistemic_rules') or EPISTEMIC_RULES}",
        "",
        "### verified_facts",
        "(Direct tool observations only — bytes, hashes, sizes, match offsets.)",
        "",
    ]
    facts = state.get("verified_facts") or []
    if not facts:
        lines.append("- (none yet)")
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        lines.append(
            f"- **{fact.get('bytes_at')}** [{fact.get('observation')} via {fact.get('source')}]"
        )
        lines.append(f"  - `{fact.get('value')}`")

    lines.extend(["", "### model_hypotheses", "(Parser labels — never treat as proven facts.)", ""])
    hypotheses = state.get("model_hypotheses") or []
    if not hypotheses:
        lines.append("- (none)")
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        at = item.get("bytes_at") or "?"
        lines.append(
            f"- **{item.get('interpreted_as')}** "
            f"(confidence: {item.get('confidence')}, bytes_at: {at})"
        )
        prov = item.get("parser_provenance")
        if prov:
            lines.append(f"  - provenance: `{prov}`")

    violations = validate_epistemic_separation(state)
    if violations:
        lines.extend(["", "### epistemic violations (blocking)"])
        for violation in violations:
            lines.append(f"- {violation.get('explanation')}")
    return "\n".join(lines).strip()


def merge_epistemic_states(*states: Mapping[str, Any]) -> Dict[str, Any]:
    verified: List[Dict[str, Any]] = []
    hypotheses: List[Dict[str, Any]] = []
    for state in states:
        verified.extend(list(state.get("verified_facts") or []))
        hypotheses.extend(list(state.get("model_hypotheses") or []))
    return _wrap(verified, hypotheses)


def session_handoff_epistemic_template() -> Dict[str, Any]:
    """Shape for SessionContinuityContract — models must not blur fact/hypothesis."""
    return {
        "verified_facts": [],
        "model_hypotheses": [],
        "promotion_rules": {
            "to_verified_fact": [
                "binary_file_info sha256/size/prefix",
                "binary_read_range hex at offset",
                "binary_search match offset",
            ],
            "never_promote_without_bytes": [
                "encrypted",
                "encryption_type",
                "encryption algorithm",
                "corruption",
                "timecode validity",
                "section type name",
            ],
        },
    }


def _wrap(
    verified_facts: Sequence[Dict[str, Any]],
    model_hypotheses: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "epistemic_rules": EPISTEMIC_RULES,
        "verified_facts": list(verified_facts),
        "model_hypotheses": list(model_hypotheses),
    }
    state["epistemic_valid"] = not validate_epistemic_separation(state)
    return state
