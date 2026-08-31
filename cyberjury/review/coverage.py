"""Analyze coverage relationships without changing the verified finding set."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cyberjury.json_parse import extract_complete_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SYSTEM = (
    "You annotate coverage among already verified security findings. Every candidate remains in the final report. "
    "Preserve every independently "
    "exploitable or independently remediable path. Suggest representation only when the "
    "referenced independent findings together contain every attacker prerequisite, affected "
    "resource or operation, missing control, impact, and remediation in it. Similar wording, "
    "category, file, location, or root cause is not enough. Keep a broad finding when any "
    "residual exploit path remains. Use only the candidate ids supplied by the engine. "
    "A represented verdict is a suggestion only, never a deletion. Respond with one JSON object and nothing else."
)


@dataclass(frozen=True, kw_only=True)
class CoverageSuggestion[T]:
    """A model suggestion that other findings represent one attack surface."""

    finding: T
    represented_by: tuple[T, ...]
    reason: str


@dataclass(frozen=True, kw_only=True)
class CoverageAnalysisResult[T]:
    """Unchanged findings and optional coverage suggestions."""

    findings: list[T]
    suggestions: list[CoverageSuggestion[T]] = field(default_factory=list)
    errors: int = 0
    error_details: list[str] = field(default_factory=list)


class CoverageAnalysisError(ValueError):
    """A coverage reply did not annotate every verified candidate safely."""


def coverage_analysis_failure_reason(details: list[str]) -> str:
    """Render one concise failure reason for completion accounting."""
    if not details:
        return ""
    return f"finding coverage analysis failed: {'. '.join(dict.fromkeys(details))}"


def suggest_finding_coverage[T](
    findings: list[T],
    *,
    provider: Provider | None,
    model: str,
    record: Callable[[T], dict[str, Any]],
) -> CoverageAnalysisResult[T]:
    """Annotate complete representation while preserving every verified finding."""
    if len(findings) < 2 or provider is None or not model:
        return CoverageAnalysisResult(findings=findings)
    indexed_by_category: dict[str, list[tuple[int, T]]] = {}
    for index, finding in enumerate(findings):
        category = str(record(finding).get("category", "")).strip().lower()
        if not category:
            indexed_by_category[f"__uncategorized-{index}"] = [(index, finding)]
            continue
        indexed_by_category.setdefault(category, []).append((index, finding))
    repeated = [group for group in indexed_by_category.values() if len(group) >= 2]
    if not repeated:
        return CoverageAnalysisResult(findings=findings)

    suggestions_by_index: list[tuple[int, tuple[int, ...], str]] = []
    for group in repeated:
        result = _analyze_category(
            group,
            provider=provider,
            model=model,
            record=record,
        )
        if result.errors:
            return CoverageAnalysisResult(
                findings=findings,
                errors=result.errors,
                error_details=result.error_details,
            )
        suggestions_by_index.extend(
            (
                suggestion.finding[0],
                tuple(target[0] for target in suggestion.represented_by),
                suggestion.reason,
            )
            for suggestion in result.suggestions
        )

    suggestions = [
        CoverageSuggestion(
            finding=findings[index],
            represented_by=tuple(findings[target] for target in targets),
            reason=reason,
        )
        for index, targets, reason in sorted(suggestions_by_index)
    ]
    return CoverageAnalysisResult(findings=findings, suggestions=suggestions)


def _analyze_category[T](
    indexed: list[tuple[int, T]],
    *,
    provider: Provider,
    model: str,
    record: Callable[[T], dict[str, Any]],
) -> CoverageAnalysisResult[tuple[int, T]]:
    """Analyze one canonical vulnerability class in isolation."""
    candidates = {f"candidate-{position}": item for position, item in enumerate(indexed, start=1)}
    payload = [dict(candidate_id=candidate_id, **record(item[1])) for candidate_id, item in candidates.items()]
    prompt = (
        "Annotate every verified candidate exactly once. Use verdict independent when the candidate "
        "contains any independently exploitable or remediable path. Use verdict represented only "
        "when the union of the listed independent candidates fully represents it. A represented candidate "
        "may cite multiple independent candidates. Represented candidates cannot represent another candidate.\n\n"
        f"Verified candidates:\n{json.dumps(payload, ensure_ascii=False, indent=2)}\n\n"
        "Return exactly this shape:\n"
        '{"decisions":[{"candidate_id":"candidate-1","verdict":"independent|represented",'
        '"represented_by":["candidate-2"],"reason":"complete representation explanation"}]}'
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
        return CoverageAnalysisResult(
            findings=indexed,
            errors=1,
            error_details=[f"{type(exc).__name__}: {exc}"],
        )


def _result_from_reply[T](
    findings: list[T],
    candidates: dict[str, T],
    record: Callable[[T], dict[str, Any]],
    text: str,
) -> CoverageAnalysisResult[T]:
    obj = extract_complete_json_object(text)
    if obj is None or set(obj) != {"decisions"} or not isinstance(obj["decisions"], list):
        raise CoverageAnalysisError("reply must contain only a decisions list")
    decisions: dict[str, tuple[str, tuple[str, ...], str]] = {}
    for raw in obj["decisions"]:
        if not isinstance(raw, dict) or set(raw) != {"candidate_id", "verdict", "represented_by", "reason"}:
            raise CoverageAnalysisError("each decision must contain candidate_id, verdict, represented_by, and reason")
        candidate_id = raw["candidate_id"]
        verdict = raw["verdict"]
        represented_by = raw["represented_by"]
        reason = raw["reason"]
        if not isinstance(candidate_id, str) or candidate_id not in candidates:
            raise CoverageAnalysisError("decision references an unknown candidate id")
        if candidate_id in decisions:
            raise CoverageAnalysisError(f"candidate {candidate_id} was decided more than once")
        if verdict not in ("independent", "represented"):
            raise CoverageAnalysisError(f"candidate {candidate_id} has an invalid verdict")
        if not isinstance(represented_by, list) or not all(isinstance(value, str) for value in represented_by):
            raise CoverageAnalysisError(f"candidate {candidate_id} represented_by must be a string list")
        if len(represented_by) != len(set(represented_by)):
            raise CoverageAnalysisError(f"candidate {candidate_id} repeats a representation target")
        if not isinstance(reason, str):
            raise CoverageAnalysisError(f"candidate {candidate_id} reason must be a string")
        decisions[candidate_id] = (verdict, tuple(represented_by), reason.strip())
    if set(decisions) != set(candidates):
        raise CoverageAnalysisError("reply must decide every verified candidate exactly once")
    suggestions: list[CoverageSuggestion[T]] = []
    for candidate_id, finding in candidates.items():
        verdict, target_ids, reason = decisions[candidate_id]
        if verdict == "independent":
            if target_ids:
                raise CoverageAnalysisError(f"independent candidate {candidate_id} cannot name representation targets")
            continue
        if not target_ids or not reason:
            raise CoverageAnalysisError(f"represented candidate {candidate_id} needs targets and a reason")
        source_category = str(record(finding).get("category", "")).strip().lower()
        targets: list[T] = []
        for target_id in target_ids:
            if target_id == candidate_id or target_id not in candidates:
                raise CoverageAnalysisError(f"candidate {candidate_id} has an invalid representation target")
            target_verdict = decisions[target_id][0]
            if target_verdict != "independent":
                raise CoverageAnalysisError(f"candidate {candidate_id} is represented by a non-independent candidate")
            target = candidates[target_id]
            target_category = str(record(target).get("category", "")).strip().lower()
            if source_category != target_category:
                raise CoverageAnalysisError(f"candidate {candidate_id} crosses vulnerability classes")
            targets.append(target)
        suggestions.append(CoverageSuggestion(finding=finding, represented_by=tuple(targets), reason=reason))
    return CoverageAnalysisResult(findings=list(candidates.values()), suggestions=suggestions)
