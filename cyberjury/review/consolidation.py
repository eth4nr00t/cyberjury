"""Consolidate verified findings only on explicit complete coverage."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cyberjury.json_parse import extract_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SYSTEM = (
    "You consolidate already verified security findings. Preserve every independently "
    "exploitable or independently remediable path. Mark a finding covered only when the "
    "referenced kept findings together contain every attacker prerequisite, affected "
    "resource or operation, missing control, impact, and remediation in it. Similar wording, "
    "category, file, location, or root cause is not enough. Keep a broad finding when any "
    "residual exploit path remains. Use only the candidate ids supplied by the engine. "
    "Respond with one JSON object and nothing else."
)


@dataclass(frozen=True, kw_only=True)
class CoveredFinding[T]:
    """One verified finding whose full attack surface is represented elsewhere."""

    finding: T
    covered_by: tuple[T, ...]
    reason: str


@dataclass(frozen=True, kw_only=True)
class ConsolidationResult[T]:
    """Retained findings and fail loud coverage adjudication state."""

    findings: list[T]
    covered: list[CoveredFinding[T]] = field(default_factory=list)
    errors: int = 0
    error_details: list[str] = field(default_factory=list)


class ConsolidationError(ValueError):
    """A coverage reply did not decide every verified candidate safely."""


def consolidation_failure_reason(details: list[str]) -> str:
    """Render one concise failure reason for completion accounting."""
    if not details:
        return ""
    return f"finding consolidation failed: {'. '.join(dict.fromkeys(details))}"


def consolidate_verified_findings[T](
    findings: list[T],
    *,
    provider: Provider | None,
    model: str,
    record: Callable[[T], dict[str, Any]],
) -> ConsolidationResult[T]:
    """Remove an umbrella finding only when kept findings fully cover its paths."""
    if len(findings) < 2 or provider is None or not model:
        return ConsolidationResult(findings=findings)
    indexed_by_category: dict[str, list[tuple[int, T]]] = {}
    for index, finding in enumerate(findings):
        category = str(record(finding).get("category", "")).strip().lower()
        if not category:
            indexed_by_category[f"__uncategorized-{index}"] = [(index, finding)]
            continue
        indexed_by_category.setdefault(category, []).append((index, finding))
    repeated = [group for group in indexed_by_category.values() if len(group) >= 2]
    if not repeated:
        return ConsolidationResult(findings=findings)

    retained_indexes = {index for group in indexed_by_category.values() if len(group) == 1 for index, _finding in group}
    covered_by_index: list[tuple[int, tuple[int, ...], str]] = []
    for group in repeated:
        result = _consolidate_category(
            group,
            provider=provider,
            model=model,
            record=record,
        )
        if result.errors:
            return ConsolidationResult(
                findings=findings,
                errors=result.errors,
                error_details=result.error_details,
            )
        retained_indexes.update(index for index, _finding in result.findings)
        covered_by_index.extend(
            (
                covered.finding[0],
                tuple(target[0] for target in covered.covered_by),
                covered.reason,
            )
            for covered in result.covered
        )

    retained = [finding for index, finding in enumerate(findings) if index in retained_indexes]
    covered = [
        CoveredFinding(
            finding=findings[index],
            covered_by=tuple(findings[target] for target in targets),
            reason=reason,
        )
        for index, targets, reason in sorted(covered_by_index)
    ]
    return ConsolidationResult(findings=retained, covered=covered)


def _consolidate_category[T](
    indexed: list[tuple[int, T]],
    *,
    provider: Provider,
    model: str,
    record: Callable[[T], dict[str, Any]],
) -> ConsolidationResult[tuple[int, T]]:
    """Keep one model decision inside one canonical vulnerability class."""
    candidates = {f"candidate-{position}": item for position, item in enumerate(indexed, start=1)}
    payload = [dict(candidate_id=candidate_id, **record(item[1])) for candidate_id, item in candidates.items()]
    prompt = (
        "Decide every verified candidate exactly once. Use verdict keep when the candidate "
        "contains any independently exploitable or remediable path. Use verdict covered only "
        "when the union of the listed kept candidates fully represents it. A covered candidate "
        "may cite multiple kept candidates. Covered candidates cannot cover another candidate.\n\n"
        f"Verified candidates:\n{json.dumps(payload, ensure_ascii=False, indent=2)}\n\n"
        "Return exactly this shape:\n"
        '{"decisions":[{"candidate_id":"candidate-1","verdict":"keep|covered",'
        '"covered_by":["candidate-2"],"reason":"complete coverage explanation"}]}'
    )
    try:
        response = provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=model,
            max_tokens=DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
        )
        return _result_from_reply(indexed, candidates, lambda item: record(item[1]), response.text)
    except Exception as exc:
        return ConsolidationResult(
            findings=indexed,
            errors=1,
            error_details=[f"{type(exc).__name__}: {exc}"],
        )


def _result_from_reply[T](
    findings: list[T],
    candidates: dict[str, T],
    record: Callable[[T], dict[str, Any]],
    text: str,
) -> ConsolidationResult[T]:
    obj = extract_json_object(text)
    if obj is None or set(obj) != {"decisions"} or not isinstance(obj["decisions"], list):
        raise ConsolidationError("reply must contain only a decisions list")
    decisions: dict[str, tuple[str, tuple[str, ...], str]] = {}
    for raw in obj["decisions"]:
        if not isinstance(raw, dict) or set(raw) != {"candidate_id", "verdict", "covered_by", "reason"}:
            raise ConsolidationError("each decision must contain candidate_id, verdict, covered_by, and reason")
        candidate_id = raw["candidate_id"]
        verdict = raw["verdict"]
        covered_by = raw["covered_by"]
        reason = raw["reason"]
        if not isinstance(candidate_id, str) or candidate_id not in candidates:
            raise ConsolidationError("decision references an unknown candidate id")
        if candidate_id in decisions:
            raise ConsolidationError(f"candidate {candidate_id} was decided more than once")
        if verdict not in ("keep", "covered"):
            raise ConsolidationError(f"candidate {candidate_id} has an invalid verdict")
        if not isinstance(covered_by, list) or not all(isinstance(value, str) for value in covered_by):
            raise ConsolidationError(f"candidate {candidate_id} covered_by must be a string list")
        if len(covered_by) != len(set(covered_by)):
            raise ConsolidationError(f"candidate {candidate_id} repeats a coverage target")
        if not isinstance(reason, str):
            raise ConsolidationError(f"candidate {candidate_id} reason must be a string")
        decisions[candidate_id] = (verdict, tuple(covered_by), reason.strip())
    if set(decisions) != set(candidates):
        raise ConsolidationError("reply must decide every verified candidate exactly once")
    covered: list[CoveredFinding[T]] = []
    retained: list[T] = []
    for candidate_id, finding in candidates.items():
        verdict, target_ids, reason = decisions[candidate_id]
        if verdict == "keep":
            if target_ids:
                raise ConsolidationError(f"kept candidate {candidate_id} cannot name coverage targets")
            retained.append(finding)
            continue
        if not target_ids or not reason:
            raise ConsolidationError(f"covered candidate {candidate_id} needs targets and a reason")
        source_category = str(record(finding).get("category", "")).strip().lower()
        targets: list[T] = []
        for target_id in target_ids:
            if target_id == candidate_id or target_id not in candidates:
                raise ConsolidationError(f"candidate {candidate_id} has an invalid coverage target")
            target_verdict = decisions[target_id][0]
            if target_verdict != "keep":
                raise ConsolidationError(f"candidate {candidate_id} is covered by a non-kept candidate")
            target = candidates[target_id]
            target_category = str(record(target).get("category", "")).strip().lower()
            if source_category != target_category:
                raise ConsolidationError(f"candidate {candidate_id} crosses vulnerability classes")
            targets.append(target)
        covered.append(CoveredFinding(finding=finding, covered_by=tuple(targets), reason=reason))
    return ConsolidationResult(findings=retained, covered=covered)
