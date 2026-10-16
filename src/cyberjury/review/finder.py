"""Run the Finder over one review unit of any target.

A target supplies only its model contract, its reply checks beyond the shared finding
fields, and its primary location rule. Every target shares the finding fields, the prompt
envelope, the grounding guard, the bounded evidence judgment, the finding union, location
validation, and source operation and cited span binding.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Literal, Protocol

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.providers.base import Message, Provider, ResponseSchema
from cyberjury.review.context import (
    EvidencePromptContext,
    GroundingContext,
    SourceEvidence,
    SourceSpan,
    cited_source_spans,
)
from cyberjury.review.engine import (
    CorrectableRoleResponseError,
    EvidenceJudgment,
    ReviewCycle,
    ReviewUnit,
    RoleReply,
    parse_role_response,
    run_evidence_judgment,
    run_grounded_judgment,
)
from cyberjury.review.identity import canonical_category
from cyberjury.review.knowledge import load_review_brief, load_severity_rubric
from cyberjury.review.navigation import SourceNavigationSession, bind_source_operation, navigation_instructions
from cyberjury.review.paths import is_unsafe_rel
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.union import MERGE_RULE, finding_accumulator

_EXECUTION = DEFAULT_REVIEW_SETTINGS.execution


_REQUIRED_TEXT = ("title", "category", "entrypoint", "file", "evidence", "attack_path")


def finding_violations(item: Mapping[str, object], index: int) -> list[str]:
    """Name each schema-valid shared field value that cannot form a finding."""
    violations = []
    missing = [name for name in _REQUIRED_TEXT if not str(item[name]).strip()]
    if missing:
        violations.append(f"findings[{index}] must have nonempty fields: {', '.join(missing)}.")
    file = str(item["file"]).strip()
    if file and is_unsafe_rel(file):
        violations.append(f"findings[{index}].file must be a relative repository path.")
    if item["line"] < 1:
        violations.append(f"findings[{index}].line must be a positive integer.")
    refs = item["evidence_refs"]
    if not refs or not all(refs):
        violations.append(f"findings[{index}].evidence_refs must be a nonempty string list.")
    anchor = item.get("change_anchor")
    if anchor is not None and (not str(anchor["file"]).strip() or anchor["line"] < 1):
        violations.append(f"findings[{index}].change_anchor must name a nonempty file and a positive line.")
    return violations


def finding_from_item(item: Mapping[str, object]) -> Finding:
    """Map one validated reply finding onto the shared finding fields."""
    anchor = item.get("change_anchor")
    return Finding(
        title=item["title"].strip(),
        category=canonical_category(item["category"]),
        severity=item["severity"],
        entrypoint=item["entrypoint"].strip(),
        file=item["file"].strip(),
        line=item["line"],
        evidence=item["evidence"].strip(),
        attack_path=item["attack_path"].strip(),
        change_anchor=(
            ChangeAnchor(file=anchor["file"].strip(), line=anchor["line"], side=anchor["side"])
            if anchor is not None
            else None
        ),
        evidence_refs=tuple(item["evidence_refs"]),
    )


def findings_from_reply(reply: RoleReply) -> list[Finding]:
    """Map schema-valid findings and request a correction for values the schema cannot reject."""
    findings: list[Finding] = []
    corrections: list[str] = []
    for index, item in enumerate(reply["findings"]):
        violations = finding_violations(item, index)
        if violations:
            corrections.extend(violations)
        else:
            findings.append(finding_from_item(item))
    if corrections:
        raise CorrectableRoleResponseError(" ".join(corrections), tuple(findings), tuple(findings))
    return findings


def finding_prompt_record(finding: Finding) -> dict[str, object]:
    """Render one provisional finding in the exact response shape the model can return again."""
    record: dict[str, object] = {
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "entrypoint": finding.entrypoint,
        "file": finding.file,
        "line": finding.line,
    }
    if finding.change_anchor is not None:
        record["change_anchor"] = finding.change_anchor.to_dict()
    return {
        **record,
        "evidence": finding.evidence,
        "attack_path": finding.attack_path,
        "evidence_refs": list(finding.evidence_refs),
    }


class GroundedUnit(ReviewUnit, Protocol):
    """A planned unit bound to its initial grounding."""

    @property
    def grounding(self) -> GroundingContext:
        """The unit's initial evidence envelope."""


@dataclass(frozen=True, kw_only=True)
class ReviewTarget[U: GroundedUnit]:
    """What genuinely differs between review targets around the shared Finder judgment.

    A target that covers all files answers for every facts limitation and needs at least one
    unit; a diff answers only for the limitations its units scope.
    """

    kind: Literal["diff", "repository"]
    role: str
    response_schema: ResponseSchema
    system: Callable[..., str]
    findings_from_reply: Callable[[U, RoleReply], list[Finding]]
    locate: Callable[[U, Finding, tuple[SourceEvidence, ...], tuple[SourceSpan, ...]], Finding | None]
    location_failure: str
    covers_all_files: bool


class UnitFinder[U: GroundedUnit]:
    """One provider backed Finder seat bound to one target contract."""

    def __init__(
        self,
        target: ReviewTarget[U],
        *,
        provider: Provider,
        model: str,
        label: str,
        max_tokens: int = _EXECUTION.reviewer_max_output_tokens,
    ) -> None:
        """Bind the seat and render the target system contract once for every unit."""
        self._target = target
        self._provider = provider
        self._model = model
        self._label = label
        self._max_tokens = max_tokens
        review_brief = load_review_brief().render()
        rubric = load_severity_rubric()
        self._systems = {
            navigation: target.system(
                review_brief=review_brief,
                severity_rubric=rubric,
                navigation=navigation_instructions() if navigation else "",
            )
            for navigation in (False, True)
        }

    def review_unit(self, unit: U) -> ReviewCycle[Finding]:
        """Judge one grounded unit, keep only located findings, and bind their source operations and cited spans."""
        grounding = unit.grounding
        if not grounding.coverage.reviewable:
            return ReviewCycle(
                findings=[],
                errors=1,
                failure_reason=grounding.coverage.failure_reason,
                grounding=grounding.coverage,
            )
        cycle = run_grounded_judgment(
            grounding,
            run_judgment=lambda navigation: self._judge(unit, navigation),
            finder_label=self._label,
        )
        cycle = self._validate_locations(unit, cycle)
        session = grounding.navigator.session() if grounding.navigator is not None else None
        evidence = _unit_evidence(unit, cycle)
        return replace(
            cycle,
            findings=[
                replace(
                    bind_source_operation(finding, session),
                    cited_spans=cited_source_spans(
                        finding.evidence_refs, seed_spans=grounding.source_spans, source_evidence=evidence
                    ),
                )
                for finding in cycle.findings
            ],
        )

    def _judge(self, unit: U, navigation: SourceNavigationSession | None) -> EvidenceJudgment[Finding]:
        target = self._target

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            prompt = prompt_context.plan
            result = self._provider.complete(
                system=self._systems[prompt_context.navigation_available],
                messages=[Message(role="user", content=prompt.text)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prompt.stable_prefix,
                response_schema=target.response_schema,
            )
            return parse_role_response(result.text, role=target.role, response_schema=target.response_schema)

        return run_evidence_judgment(
            unit.grounding,
            ask=ask,
            findings_from_reply=lambda reply: target.findings_from_reply(unit, reply),
            accumulator=finding_accumulator(),
            target_chars=_EXECUTION.target_evidence_request_chars,
            max_followups=_EXECUTION.max_source_navigation_followups,
            evidence_refs=lambda finding: finding.evidence_refs,
            navigation=navigation,
            finding_prompt_record=finding_prompt_record,
            merge_rule=MERGE_RULE,
        )

    def _validate_locations(self, unit: U, cycle: ReviewCycle[Finding]) -> ReviewCycle[Finding]:
        """Keep findings whose primary location the target accepts; the rest stay explicitly incomplete."""
        evidence = _unit_evidence(unit, cycle)
        located = [
            (finding, self._target.locate(unit, finding, evidence, unit.grounding.source_spans))
            for finding in cycle.findings
        ]
        valid = [finding for _finding, finding in located if finding is not None]
        if len(valid) == len(cycle.findings):
            return cycle if valid == cycle.findings else replace(cycle, findings=valid)
        return replace(
            cycle,
            findings=valid,
            incomplete=[*cycle.incomplete, *(finding for finding, kept in located if kept is None)],
            failure_reason=". ".join(part for part in (cycle.failure_reason, self._target.location_failure) if part),
        )


def _unit_evidence(unit: GroundedUnit, cycle: ReviewCycle[Finding]) -> tuple[SourceEvidence, ...]:
    """Return every source receipt the unit's judgment held: initial grounding first, then delivered source."""
    return tuple(dict.fromkeys((*unit.grounding.source_evidence, *cycle.source_evidence)))
