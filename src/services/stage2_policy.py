"""Stage2 survivor selection — config-driven cap policy (fixes max(cheap, stage2) bug)."""

from __future__ import annotations

from typing import Any, List, Mapping, Sequence


def _resolve_stage2_policy(defaults: Mapping[str, Any], pipeline: Mapping[str, Any]) -> Mapping[str, Any]:
    policy = dict(defaults.get("stage2_policy") or {})
    cap_policy = str(pipeline.get("stage2_cap_policy") or policy.get("mode") or "min")
    max_survivors = int(pipeline.get("cheap_top_k") or 8)
    min_survivors = int(pipeline.get("stage2_top_k") or 4)
    score_gap = float(defaults.get("stage2_score_gap") or 3)
    return {
        "mode": cap_policy,
        "max_survivors": max(1, max_survivors),
        "min_survivors": max(1, min_survivors),
        "score_gap": score_gap,
    }


def select_stage2_survivors(
    cheap_candidates: Sequence[Mapping[str, Any]],
    *,
    pipeline: Mapping[str, Any],
    defaults: Mapping[str, Any] | None = None,
    force_full: bool = False,
) -> List[int]:
    if force_full:
        return list(range(len(cheap_candidates)))
    policy = _resolve_stage2_policy(dict(defaults or {}), pipeline)
    top_k = policy["max_survivors"]
    min_score = int(pipeline.get("cheap_min_score") or 1)
    ranked = sorted(
        range(len(cheap_candidates)),
        key=lambda index: (
            -int(cheap_candidates[index].get("score") or 0),
            str(cheap_candidates[index].get("key_hex") or cheap_candidates[index].get("name") or ""),
        ),
    )
    survivors: List[int] = []
    for index in ranked:
        item = cheap_candidates[index]
        if item.get("cheap_identity"):
            survivors.append(index)
            continue
        if int(item.get("score") or 0) >= min_score:
            survivors.append(index)
    for index in ranked[:top_k]:
        if index not in survivors:
            survivors.append(index)

    mode = str(policy["mode"])
    min_cap = policy["min_survivors"]
    max_cap = policy["max_survivors"]

    if mode == "max":
        stage2_cap = max_cap
    elif mode == "adaptive":
        scores = [int(cheap_candidates[i].get("score") or 0) for i in survivors]
        if len(scores) >= 2:
            scores_sorted = sorted(scores, reverse=True)
            gap = scores_sorted[0] - scores_sorted[min(len(scores_sorted) - 1, min_cap - 1)]
            stage2_cap = min_cap if gap >= policy["score_gap"] else max_cap
        else:
            stage2_cap = min_cap
    else:
        stage2_cap = min_cap

    ordered = [index for index in survivors if index in set(survivors)]
    seen: set[int] = set()
    unique: List[int] = []
    for index in ordered:
        if index not in seen:
            seen.add(index)
            unique.append(index)
    return unique[:stage2_cap]


def stage2_cap_applied(
    cheap_candidates: Sequence[Mapping[str, Any]],
    *,
    pipeline: Mapping[str, Any],
    defaults: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    survivors = select_stage2_survivors(cheap_candidates, pipeline=pipeline, defaults=defaults)
    policy = _resolve_stage2_policy(dict(defaults or {}), pipeline)
    return {
        "stage2_cap_applied": len(survivors),
        "stage2_cap_policy": policy["mode"],
        "max_survivors": policy["max_survivors"],
        "min_survivors": policy["min_survivors"],
    }
