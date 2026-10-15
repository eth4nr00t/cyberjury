"""Provider backed reviewer for one diff review unit.

Each unit runs one Finder judgment under the profile review contract. Navigation may add
Finder calls within the unit's evidence budget.
"""

from __future__ import annotations

from collections.abc import Callable

from cyberjury.detection import load_detection
from cyberjury.finding import Finding, finding_from_dict
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider, ResponseSchema
from cyberjury.review.context import EvidencePromptContext, GroundingContext
from cyberjury.review.diff.model import DiffLineRanges, canonical_diff_path, diff_line_ranges
from cyberjury.review.diff.prompts import (
    DIFF_FINDING_SCHEMA,
    FINDER_RESPONSE_SCHEMA,
    diff_finder_system,
    diff_prompt_plan,
)
from cyberjury.review.diff.union import finding_accumulator
from cyberjury.review.engine import (
    CorrectableRoleResponseError,
    EvidenceJudgment,
    JudgmentProgress,
    ReviewCycle,
    RoleResponseError,
    parse_role_response,
    run_evidence_judgment,
    run_grounded_judgment,
)
from cyberjury.review.knowledge import ReviewBrief
from cyberjury.review.navigation import SourceNavigationSession, navigation_instructions
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, emit_trace, finding_id


class AuditError(RuntimeError):
    """A Finder reply cannot support a complete diff review."""


def finding_prompt_record(finding: Finding) -> dict[str, object]:
    """Render one provisional finding in the exact response shape the model can return again."""
    data = finding.to_dict()
    record = {field: data.get(field) for field in DIFF_FINDING_SCHEMA["properties"]}
    record["evidence_refs"] = list(finding.evidence_refs)
    return record


def _findings_from_reply(
    items: list[dict[str, object]],
    *,
    canonicalize: Callable[[str], str],
    change_ranges: DiffLineRanges,
) -> list[Finding]:
    """Apply semantic checks the closed response schema cannot express."""
    findings = []
    valid_findings = []
    corrections = []
    for index, item in enumerate(items):
        violations = _semantic_violations(item, index)
        if violations:
            corrections.extend(violations)
            continue
        finding = finding_from_dict({**item, "category": canonicalize(str(item["category"]))})
        findings.append(finding)
        correction = _change_anchor_correction(item["change_anchor"], index, change_ranges)
        if correction:
            corrections.append(correction)
        else:
            valid_findings.append(finding)
    if corrections:
        raise CorrectableRoleResponseError(
            " ".join(corrections),
            tuple(valid_findings),
            tuple(findings),
        )
    return findings


def _semantic_violations(item: dict[str, object], index: int) -> list[str]:
    """Name each schema-valid field value that cannot form a finding."""
    violations = []
    required_strings = ("file", "category", "entrypoint", "description", "exploit_scenario")
    missing = [field for field in required_strings if not item[field].strip()]
    if missing:
        violations.append(f"findings[{index}] must have nonempty fields: {', '.join(missing)}.")
    if item["line"] < 1:
        violations.append(f"findings[{index}].line must be a positive integer.")
    if not 0.0 <= float(item["confidence"]) <= 1.0:
        violations.append(f"findings[{index}].confidence must be between 0 and 1.")
    refs = item["evidence_refs"]
    if not refs or not all(refs):
        violations.append(f"findings[{index}].evidence_refs must be a nonempty string list.")
    anchor = item["change_anchor"]
    if not anchor["file"].strip() or anchor["line"] < 1:
        violations.append(f"findings[{index}].change_anchor must name a nonempty file and a positive line.")
    return violations


def _change_anchor_correction(anchor: dict[str, object], index: int, ranges: DiffLineRanges) -> str:
    """Explain one invalid anchor using only exact changed line ranges."""
    line = anchor["line"]
    side = anchor["side"]
    available_paths = {*ranges.old, *ranges.new}
    normalized = canonical_diff_path(str(anchor["file"]), available_paths)
    selected = ranges.old if side == "old" else ranges.new
    if any(start <= line <= end for start, end in selected.get(normalized, ())):
        return ""
    if normalized in available_paths:
        candidates = []
        for candidate_side, by_path in (("old", ranges.old), ("new", ranges.new)):
            spans = by_path.get(normalized, ())
            if spans:
                rendered = ", ".join(str(start) if start == end else f"{start}-{end}" for start, end in spans)
                candidates.append(f"{candidate_side} lines {rendered}")
        choices = "; ".join(candidates)
        detail = f"Exact changed ranges for `{normalized}` are: {choices}."
    else:
        files = ", ".join(f"`{path}`" for path in sorted(available_paths))
        detail = f"The files with exact changed lines in this unit are: {files}."
    return (
        f"Finding {index} has an invalid `change_anchor`. {detail} Select one exact changed line that is "
        "causally responsible for this vulnerability. If none is responsible, remove the finding."
    )


def _audit_response(text: str, response_schema: ResponseSchema = FINDER_RESPONSE_SCHEMA) -> dict:
    """Translate the shared Finder contract failure into the diff public error."""
    try:
        return parse_role_response(
            text,
            role="diff finder",
            response_schema=response_schema,
        )
    except RoleResponseError as exc:
        raise AuditError(f"failed audit: {exc}") from exc


class AuditRunner:
    """One provider backed Finder for a diff review unit."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        content: ContentPaths,
        review_brief: ReviewBrief,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
    ) -> None:
        """Bind one provider to the selected profile's diff prompt configuration."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._content = content
        self._review_brief = review_brief

    def _run_judgment(
        self,
        diff: str,
        context: GroundingContext,
        navigation_session: SourceNavigationSession | None,
        *,
        trace: Trace | None = None,
    ) -> EvidenceJudgment[Finding]:
        change_ranges = diff_line_ranges(diff, load_detection(self._content.detection_file))

        rubric = self._content.severity_rubric_file.read_text(encoding="utf-8")
        systems = {
            navigation: diff_finder_system(
                review_brief=self._review_brief.render(),
                severity_rubric=rubric,
                navigation=navigation_instructions() if navigation else "",
            )
            for navigation in (False, True)
        }

        def ask(prompt_context: EvidencePromptContext) -> dict[str, object]:
            prompt = diff_prompt_plan(
                diff,
                context=prompt_context.source,
                catalog=prompt_context.catalog,
                followup=prompt_context.followup,
            )
            response_schema = FINDER_RESPONSE_SCHEMA
            result = self._provider.complete(
                system=systems[prompt_context.navigation_available],
                messages=[Message(role="user", content=prompt.text)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prompt.stable_prefix,
                response_schema=response_schema,
            )
            return _audit_response(result.text, response_schema)

        judgment = run_evidence_judgment(
            context,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(
                reply.get("findings"),
                canonicalize=self._review_brief.canonicalize_category,
                change_ranges=change_ranges,
            ),
            accumulator=finding_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda finding: finding.evidence_refs,
            trace=trace,
            navigation_session=navigation_session,
            model_role="finder",
            review_brief_sha256=self._review_brief.content_sha256,
            finding_prompt_record=finding_prompt_record,
        )
        emit_trace(
            trace,
            "finding",
            stage="generated",
            count=len(judgment.findings),
            findings=[
                {
                    "file": finding.file,
                    "finding_id": finding_id(finding),
                    "line": finding.line,
                    "category": finding.category,
                    "description": finding.description[:500],
                }
                for finding in judgment.findings
            ],
        )
        return judgment

    def review_unit(
        self,
        diff: str,
        *,
        context: GroundingContext,
        finder_label: str,
        on_judgment: JudgmentProgress | None = None,
        trace: Trace | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt the Finder judgment to the shared target cycle contract."""
        return run_grounded_judgment(
            context,
            run_judgment=lambda navigation: self._run_judgment(diff, context, navigation, trace=trace),
            label=self._review_brief.label,
            finder_label=finder_label,
            on_judgment=on_judgment,
            trace=trace,
        )
