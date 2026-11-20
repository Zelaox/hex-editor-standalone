"""Policy-driven composition evaluator with preservation gates."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .core import check_preservation_gates, load_protected_spans, lineage_key_from_run, preservation_metrics  # noqa: F401


def _resolve_axis_value(axis: Mapping[str, Any], *, composition: Mapping[str, Any], parent: bytes, source: bytes, bundle: Mapping[str, Any], protected_count: int) -> int:
    del parent, source
    source_path = str(axis.get("source") or "")
    if source_path == "ledger.protected_span_count":
        return protected_count
    if source_path == "manifest.unresolved_bytes":
        return int(composition.get("unresolved_bytes") or 0)
    if source_path == "manifest.changed_bytes":
        return int(composition.get("changed_bytes") or 0)
    if source_path == "manifest.reference_metrics.reference_diff_bytes":
        return int((composition.get("reference_metrics") or {}).get("reference_diff_bytes") or 0)
    if source_path == "coverage.summary.verified_plaintext":
        return int(composition.get("verified_plaintext_bytes") or 0)
    ref = bundle.get("reference") or {}
    ref_bytes = ref.get("bytes")
    if ref_bytes is not None and source_path.startswith("reference"):
        from src.services.full_decode.core import _reference_transition_metrics

        metrics = _reference_transition_metrics(parent, composition["bytes"], ref_bytes)
        field = source_path.rsplit(".", 1)[-1]
        return int(metrics.get(field) or 0)
    return int(composition.get(source_path.rsplit(".", 1)[-1]) or 0)


def _pareto_rank_key(
    composition: Mapping[str, Any],
    *,
    parent: bytes,
    source: bytes,
    bundle: Mapping[str, Any],
    ledger_bundle: Mapping[str, Any],
    protected_count: int,
) -> Tuple[Any, ...]:
    axes = list(ledger_bundle["policy"]["acceptance_axes"])
    terms: List[Any] = []
    for axis in axes:
        value = _resolve_axis_value(axis, composition=composition, parent=parent, source=source, bundle=bundle, protected_count=protected_count)
        if str(axis.get("direction")) == "maximize":
            terms.append(-value)
        else:
            terms.append(value)
    terms.append(tuple(composition.get("provider_candidate_ids") or []))
    return tuple(terms)


def _attach_reference_metrics(composition: Mapping[str, Any], *, parent: bytes, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    item = dict(composition)
    reference = bundle.get("reference") or {}
    ref_bytes = reference.get("bytes")
    if ref_bytes is not None:
        from src.services.full_decode.core import _reference_transition_metrics

        item["reference_metrics"] = _reference_transition_metrics(parent, item["bytes"], ref_bytes)
    return item


def evaluate_compositions(
    compositions: Sequence[Mapping[str, Any]],
    parent: bytes,
    source: bytes,
    protected_spans: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any],
    ledger_bundle: Mapping[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    from .core import load_proof_ledger_bundle

    ledger_bundle = dict(ledger_bundle or load_proof_ledger_bundle())
    composition_policy = dict(ledger_bundle["policy"]["composition"])
    ref_eval = bundle["policy"]["reference_evaluation"]
    reference = bundle.get("reference") or {}
    reference_bytes = reference.get("bytes")
    enriched: List[Dict[str, Any]] = []
    for raw in compositions:
        item = _attach_reference_metrics(raw, parent=parent, bundle=bundle)
        preservation = check_preservation_gates(
            parent,
            item["bytes"],
            protected_spans,
            bundle=ledger_bundle,
            parent_plaintext_bytes=int(item.get("parent_verified_plaintext_bytes") or 0),
            candidate_plaintext_bytes=int(item.get("verified_plaintext_bytes") or 0),
        )
        item = {
            **item,
            "preservation": preservation,
            "preservation_passed": bool(preservation["passed"]),
            "lost_proof_owned_span_count": int(preservation["metrics"]["lost_proof_owned_span_count"]),
        }
        if bool(composition_policy.get("reject_lost_protected_spans")) and not preservation["passed"]:
            continue
        enriched.append(item)
    if reference_bytes and bool(ref_eval["enabled"]) and bool(ref_eval["require_reference_non_regression"]):
        non_regressing = [
            item
            for item in enriched
            if int((item.get("reference_metrics") or {}).get("reference_regression_bytes") or 0) == 0
        ]
        if non_regressing:
            enriched = non_regressing
    ranked = enriched
    protected_count = len(protected_spans)
    ranked.sort(key=lambda item: _pareto_rank_key(item, parent=parent, source=source, bundle=bundle, ledger_bundle=ledger_bundle, protected_count=protected_count))
    return ranked


def select_composition_with_preservation(
    compositions: Sequence[Mapping[str, Any]],
    *,
    parent: bytes,
    source: bytes,
    run: Mapping[str, Any],
    bundle: Mapping[str, Any],
    ledger_bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    from .core import load_proof_ledger_bundle

    ledger_bundle = dict(ledger_bundle or load_proof_ledger_bundle())
    key = lineage_key_from_run(run, bundle=ledger_bundle)
    protected = load_protected_spans(key, bundle=ledger_bundle)
    ranked = evaluate_compositions(compositions, parent, source, protected, bundle=bundle, ledger_bundle=ledger_bundle)
    composition_policy = dict(ledger_bundle["policy"]["composition"])
    fallback_reason = str(composition_policy.get("parent_fallback_reason") or "preservation_blocked_merge")
    if not ranked:
        return {
            "selected": {"bytes": parent, "proof_spans": [], "provider_candidate_ids": [], "resolved_source_bytes": 0, "changed_bytes": 0},
            "decision_reason": fallback_reason,
            "preservation_blocked": True,
            "protected_span_count": len(protected),
        }
    selected = ranked[0]
    ref_eval = bundle["policy"]["reference_evaluation"]
    reference = bundle.get("reference") or {}
    reference_bytes = reference.get("bytes")
    if reference_bytes and bool(ref_eval["enabled"]):
        from src.services.full_decode.core import _reference_transition_metrics

        selected_metrics = _reference_transition_metrics(parent, selected["bytes"], reference_bytes)
        parent_metrics = _reference_transition_metrics(parent, parent, reference_bytes)
        prefer_preservation = bool(composition_policy.get("prefer_preservation_over_reference", True))
        if int(selected_metrics["reference_diff_bytes"]) > int(parent_metrics["reference_diff_bytes"]):
            metrics = preservation_metrics(parent, selected["bytes"], protected)
            if int(metrics["lost_proof_owned_span_count"]) > 0 or not selected.get("preservation_passed", True):
                return {
                    "selected": {"bytes": parent, "proof_spans": [], "provider_candidate_ids": [], "resolved_source_bytes": 0, "changed_bytes": 0},
                    "decision_reason": fallback_reason,
                    "preservation_blocked": True,
                    "protected_span_count": len(protected),
                }
            if prefer_preservation and int(selected.get("changed_bytes") or 0) > 0:
                if bool(composition_policy.get("attempt_compatible_union")) and len(ranked) > 1:
                    from .frontier import attempt_compatible_union

                    union = attempt_compatible_union(selected["bytes"], ranked[1]["bytes"], parent, protected)
                    if union.get("ok"):
                        selected = {**selected, "bytes": union["bytes"], "changed_bytes": int(union.get("changed_bytes") or 0)}
                return {
                    "selected": selected,
                    "decision_reason": "preservation_over_reference",
                    "preservation_blocked": False,
                    "protected_span_count": len(protected),
                }
            if bool(composition_policy.get("attempt_compatible_union")) and len(ranked) > 1:
                from .frontier import attempt_compatible_union

                union = attempt_compatible_union(selected["bytes"], ranked[1]["bytes"], parent, protected)
                if union.get("ok"):
                    selected = {**selected, "bytes": union["bytes"], "changed_bytes": int(union.get("changed_bytes") or 0)}
                else:
                    return {
                        "selected": {"bytes": parent, "proof_spans": [], "provider_candidate_ids": [], "resolved_source_bytes": 0, "changed_bytes": 0},
                        "decision_reason": fallback_reason,
                        "preservation_blocked": True,
                        "protected_span_count": len(protected),
                    }
    return {
        "selected": selected,
        "decision_reason": "composition_selected",
        "preservation_blocked": False,
        "protected_span_count": len(protected),
    }
