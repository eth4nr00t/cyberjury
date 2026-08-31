"""Provider backed reviewers for one diff review unit.

Standard mode runs one Finder pass with one judgment per bounded knowledge pack. Each
adversarial round runs three roles: the Finder scans, the Challenger rebuts and
independently rescans, the Judge cross-validates, and the coded loop unions survivors.
Rounds repeat, feeding the union back to the Finder, until the configured clean-round
threshold is met or ``max_rounds`` is hit. Navigation and knowledge packs may add Finder calls.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from cyberjury.finding import Finding, finding_from_dict, finding_role_dict
from cyberjury.guides import load_guides, select_guides
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.review.context import (
    EvidencePromptContext,
    GroundingContext,
    merge_grounding_coverage,
    with_source_evidence,
)
from cyberjury.review.diff.model import diff_paths
from cyberjury.review.diff.prompts import (
    CHALLENGER_SYSTEM,
    DO_NOT_REPORT,
    FINDER_SYSTEM,
    FOCUS,
    JUDGE_SYSTEM,
    SYSTEM,
    challenger_prompt,
    diff_cache_prefix,
    finder_prompt,
    judge_prompt,
    severity_rubric_text,
    standard_audit_prompt_plan,
)
from cyberjury.review.diff.union import finding_accumulator, role_accumulator
from cyberjury.review.engine import (
    EvidenceJudgment,
    GroundedJudgmentTask,
    JudgmentProgress,
    PendingWorkRecord,
    ReviewCycle,
    ReviewOutcome,
    ReviewSchedule,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    parse_role_response,
    review_schedule,
    run_evidence_judgment,
    run_grounded_standard_judgments,
    run_review_cycles,
    run_role_round,
    validate_pending_records,
    validate_rebuttal_records,
)
from cyberjury.review.navigation import SourceNavigationSession
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, emit_trace, finding_id
from cyberjury.review.vulnerabilities import VulnerabilityCatalog


def guides_for_diff(diff: str, content: ContentPaths | None = None) -> str:
    """Render the language and framework guides selected by one diff."""
    paths = diff_paths(diff)
    guides = (
        load_guides(content.languages_dir, content.frameworks_dir, content.protocols_dir)
        if content is not None
        else None
    )
    return "\n\n---\n\n".join(guide.body for guide in select_guides(paths, source_text=diff, guides=guides))


class AuditError(RuntimeError):
    """A Finder reply cannot support a complete diff review."""


def _findings_from_reply(items: object) -> list[Finding]:
    """Reject malformed finding items instead of reporting failed work as clean."""
    if not isinstance(items, list):
        raise AuditError("failed audit: findings must be a list")
    findings = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise AuditError(f"failed audit: findings[{index}] must be an object")
        finding = finding_from_dict(item)
        if finding is None:
            raise AuditError(f"failed audit: findings[{index}] must name a source file")
        if "change_anchor" in item and finding.change_anchor is None:
            raise AuditError(f"failed audit: findings[{index}].change_anchor is malformed")
        required_strings = ("file", "category", "description")
        missing = [
            field for field in required_strings if not isinstance(item.get(field), str) or not str(item[field]).strip()
        ]
        if missing:
            raise AuditError(f"failed audit: findings[{index}] must have nonempty fields: {', '.join(missing)}")
        line = item.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise AuditError(f"failed audit: findings[{index}].line must be a positive integer")
        severity = item.get("severity")
        if not isinstance(severity, str) or severity.strip().upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise AuditError(f"failed audit: findings[{index}].severity is invalid")
        confidence = item.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise AuditError(f"failed audit: findings[{index}].confidence must be between 0 and 1")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref for ref in refs):
            raise AuditError(f"failed audit: findings[{index}].evidence_refs must be a nonempty string list")
        findings.append(finding)
    return findings


def _audit_response(text: str) -> dict:
    """Translate the shared Finder contract failure into the diff public error."""
    try:
        return parse_role_response(
            text,
            role="diff finder",
            required_keys=("findings",),
            optional_list_keys=("evidence_requests", "source_queries"),
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
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
        content: ContentPaths | None = None,
        focus: str = FOCUS,
        do_not_report: str = DO_NOT_REPORT,
    ) -> None:
        """Bind one provider to the standard diff prompt configuration."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._content = content
        self._focus = focus
        self._do_not_report = do_not_report
        vuln_dir = content.vulnerabilities_dir if content else None
        self._vulnerability_catalog = (
            VulnerabilityCatalog.load(vuln_dir) if vuln_dir is not None else VulnerabilityCatalog.load()
        )

    def _run_judgment(
        self,
        diff: str,
        *,
        categories: tuple[str, ...],
        selected_categories: tuple[str, ...] = (),
        vulnerabilities: str,
        context: GroundingContext | str,
        cache: bool,
        trace: Trace | None = None,
        judgment_id: int | None = None,
        navigation_session: SourceNavigationSession | None = None,
        max_followups: int = DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
    ) -> EvidenceJudgment[Finding]:
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")

        def ask(prompt_context: EvidencePromptContext) -> dict[str, object]:
            prompt = standard_audit_prompt_plan(
                diff,
                vulnerabilities=vulnerabilities,
                vulnerability_categories=categories,
                selected_vulnerability_categories=selected_categories,
                context=prompt_context.source,
                context_controls=prompt_context.controls,
                stack=guides_for_diff(diff, self._content),
                vulnerabilities_dir=vuln_dir,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=severity_rubric_text(self._content),
            )
            result = self._provider.complete(
                system=SYSTEM,
                messages=[Message(role="user", content=prompt.text)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=cache,
                cache_prefix=prompt.stable_prefix if cache else "",
            )
            return _audit_response(result.text)

        judgment = run_evidence_judgment(
            grounded,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(reply.get("findings")),
            accumulator=finding_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=max_followups,
            evidence_refs=lambda finding: finding.evidence_refs,
            trace=trace,
            judgment_id=judgment_id,
            navigation_session=navigation_session,
        )
        emit_trace(
            trace,
            "finding",
            stage="generated",
            judgment=judgment_id,
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

    def run(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: GroundingContext | str = "",
    ) -> list[Finding]:
        """Return complete standard findings for callers outside the coded scheduler."""
        if vulnerabilities:
            judgment = self._run_judgment(
                diff,
                categories=(),
                vulnerabilities=vulnerabilities,
                context=context,
                cache=False,
            )
            if judgment.failure_reason:
                raise AuditError(judgment.failure_reason)
            if not judgment.grounding.complete:
                raise AuditError(judgment.grounding.failure_reason or "grounding incomplete")
            return judgment.findings
        cycle = self.review_round(diff, context=context, finder_label=self._model)
        if not cycle.clean:
            raise AuditError(cycle.failure_reason)
        return cycle.findings

    def review_round(
        self,
        diff: str,
        *,
        context: GroundingContext | str = "",
        finder_label: str,
        on_judgment: JudgmentProgress | None = None,
        trace: Trace | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt the standard Finder call to the shared target cycle contract."""
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")

        navigation = grounded.navigator.session() if grounded.navigator is not None else None

        def plan(current: GroundingContext):
            return self._vulnerability_catalog.plan(diff, current.selection_text).packs

        def execute(task: GroundedJudgmentTask):
            selected = tuple(item.id for pack in task.plan for item in pack.items)
            return self._run_judgment(
                diff,
                categories=task.judgment.categories,
                selected_categories=selected,
                vulnerabilities=task.judgment.body,
                context=task.context,
                cache=task.cache,
                trace=trace,
                judgment_id=task.index,
                navigation_session=task.navigation,
                max_followups=task.remaining_followups,
            )

        return run_grounded_standard_judgments(
            grounded,
            plan_judgments=plan,
            execute_judgment=execute,
            describe_judgment=lambda pack: pack.label,
            finder_label=finder_label,
            accumulator=finding_accumulator(),
            key=lambda finding: (finding.file, finding.line, finding.category),
            title=lambda finding: finding.description,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            navigation_session=navigation,
            remaining_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            on_judgment=on_judgment,
            trace=trace,
        )


@dataclass
class _AdversarialRoundState:
    diff: str
    vulnerability_override: str
    grounded: GroundingContext
    stack: str
    known: tuple[Finding, ...]
    pending: tuple[PendingWorkRecord, ...]
    trace: Trace | None
    round_id: int | None
    rubric: str
    vulnerability_dir: Path | None
    active_grounding: GroundingContext
    navigation: SourceNavigationSession | None
    finder_followups: int


class AdversarialAuditRunner:
    """Finder, challenger, and judge runner for higher-recall diff review."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
        finder_model: str | None = None,
        challenger_model: str | None = None,
        judge_model: str | None = None,
        finder_provider: Provider | None = None,
        challenger_provider: Provider | None = None,
        judge_provider: Provider | None = None,
        finder_label: str | None = None,
        challenger_label: str | None = None,
        judge_label: str | None = None,
        content: ContentPaths | None = None,
        focus: str = FOCUS,
        do_not_report: str = DO_NOT_REPORT,
    ) -> None:
        """Bind finder, challenger, and judge seats for the adversarial pass loop."""
        self._max_tokens = max_tokens
        self._finder = (finder_provider or provider, finder_model or model)
        self._challenger = (challenger_provider or provider, challenger_model or model)
        self._judge = (judge_provider or provider, judge_model or model)
        self._finder_label = finder_label or self._finder[1]
        self._challenger_label = challenger_label or self._challenger[1]
        self._judge_label = judge_label or self._judge[1]
        self._content = content
        self._focus = focus
        self._do_not_report = do_not_report
        vuln_dir = content.vulnerabilities_dir if content else None
        self._vulnerability_catalog = (
            VulnerabilityCatalog.load(vuln_dir) if vuln_dir is not None else VulnerabilityCatalog.load()
        )

    def _selected_vulnerabilities(
        self,
        diff: str,
        grounded: GroundingContext,
        vulnerabilities: str,
    ) -> str:
        """Keep adversarial knowledge selection aligned with every review path."""
        if vulnerabilities:
            return vulnerabilities
        plan = self._vulnerability_catalog.plan(diff, grounded.selection_text)
        return self._vulnerability_catalog.render(list(plan.selected))

    def _ask(
        self,
        role: str,
        system: str,
        prompt: str,
        backend: tuple,
        *,
        required_keys: tuple[str, ...],
        optional_list_keys: tuple[str, ...] = (),
        object_list_keys: tuple[str, ...] = (),
    ) -> dict:
        """Require one usable role reply for the shared round executor."""
        provider, model = backend
        try:
            result = provider.complete(
                system=system,
                messages=[Message(role="user", content=prompt)],
                model=model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=diff_cache_prefix(prompt),
            )
        except Exception as exc:
            raise RoleResponseError(f"adversarial {role} call failed: {type(exc).__name__}: {exc}") from exc
        return parse_role_response(
            result.text,
            role=f"adversarial {role}",
            required_keys=required_keys,
            optional_list_keys=optional_list_keys,
            object_list_keys=object_list_keys,
        )

    def review_round(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: GroundingContext | str = "",
        stack: str = "",
        known: list[Finding] | None = None,
        pending: tuple[PendingWorkRecord, ...] = (),
        trace: Trace | None = None,
        round_id: int | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt one role sequence to the shared target cycle contract."""
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        navigation = grounded.navigator.session() if grounded.navigator is not None else None
        state = _AdversarialRoundState(
            diff=diff,
            vulnerability_override=vulnerabilities,
            grounded=grounded,
            stack=stack,
            known=tuple(known or ()),
            pending=pending,
            trace=trace,
            round_id=round_id,
            rubric=severity_rubric_text(self._content),
            vulnerability_dir=vuln_dir,
            active_grounding=grounded,
            navigation=navigation,
            finder_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
        )

        role_union = role_accumulator()
        role_round = run_role_round(
            find=lambda: self._run_finder_step(state),
            finder_label=self._finder_label,
            challenge=lambda findings: self._run_challenger_step(state, findings),
            challenger_label=self._challenger_label,
            judge=lambda findings, challenged: self._run_judge_step(state, findings, challenged),
            judge_label=self._judge_label,
            key=lambda finding: (finding.file, finding.line, finding.category),
            fold=role_union.fold,
            title=lambda finding: finding.description,
        )
        for finding in role_round.findings:
            self._emit_finding(state, finding, role="judge", stage="kept")
        return ReviewCycle(
            findings=role_round.findings,
            pending=role_round.pending,
            resolved_pending=role_round.resolved_pending,
            errors=0 if role_round.clean else 1,
            failure_reason=role_round.failure_reason,
            grounding=role_round.grounding,
            source_evidence=role_round.source_evidence,
        )

    def _run_finder_step(self, state: _AdversarialRoundState) -> EvidenceJudgment[Finding]:
        def ask(prompt_context: EvidencePromptContext) -> dict[str, object]:
            prompt = finder_prompt(
                state.diff,
                vulnerabilities=self._knowledge_for_state(state),
                context=prompt_context.source,
                context_controls=prompt_context.controls,
                prior=[finding.to_dict() for finding in state.known],
                vulnerabilities_dir=state.vulnerability_dir,
                stack=state.stack,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=state.rubric,
            )
            return self._ask(
                "finder",
                FINDER_SYSTEM,
                prompt,
                self._finder,
                required_keys=("findings",),
                optional_list_keys=("evidence_requests", "source_queries"),
            )

        judgment = run_evidence_judgment(
            state.grounded,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(reply.get("findings")),
            accumulator=role_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            evidence_refs=lambda finding: finding.evidence_refs,
            trace=state.trace,
            judgment_id=state.round_id,
            navigation_session=state.navigation,
            max_followups=state.finder_followups,
        )
        self._advance_state(state, judgment)
        self._emit_findings(state, judgment.findings, role="finder")
        return judgment

    def _run_challenger_step(
        self,
        state: _AdversarialRoundState,
        finder_findings: list[Finding],
    ) -> RoleChallenge[Finding]:
        last_reply: dict[str, object] = {}

        def ask(prompt_context: EvidencePromptContext) -> dict[str, object]:
            nonlocal last_reply
            prompt = challenger_prompt(
                state.diff,
                vulnerabilities=self._knowledge_for_state(state),
                context=prompt_context.source,
                context_controls=prompt_context.controls,
                finder_findings=[finding_role_dict(finding) for finding in finder_findings],
                vulnerabilities_dir=state.vulnerability_dir,
                stack=state.stack,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=state.rubric,
            )
            last_reply = self._ask(
                "challenger",
                CHALLENGER_SYSTEM,
                prompt,
                self._challenger,
                required_keys=("rebuttals", "new_findings"),
                optional_list_keys=("evidence_requests", "source_queries"),
                object_list_keys=("rebuttals",),
            )
            return last_reply

        judgment = run_evidence_judgment(
            state.active_grounding,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(reply.get("new_findings")),
            accumulator=role_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda finding: finding.evidence_refs,
            trace=state.trace,
            judgment_id=state.round_id,
            navigation_session=state.navigation,
        )
        if judgment.failure_reason:
            raise RoleResponseError(judgment.failure_reason)
        self._advance_state(state, judgment)
        new_findings = judgment.findings
        self._emit_findings(state, new_findings, role="challenger")
        return RoleChallenge(
            rebuttals=validate_rebuttal_records(last_reply["rebuttals"], role="adversarial challenger"),
            new_findings=new_findings,
            grounding=judgment.grounding,
            source_evidence=judgment.source_evidence,
            evidence_exchanges=judgment.evidence_exchanges,
        )

    def _run_judge_step(
        self,
        state: _AdversarialRoundState,
        finder_findings: list[Finding],
        challenged: RoleChallenge[Finding],
    ) -> RoleJudgment[Finding]:
        last_verdict: dict[str, object] = {}

        def ask(prompt_context: EvidencePromptContext) -> dict[str, object]:
            nonlocal last_verdict
            prompt = judge_prompt(
                state.diff,
                [finding_role_dict(finding) for finding in finder_findings],
                challenged.rebuttals,
                [finding_role_dict(finding) for finding in challenged.new_findings],
                context=prompt_context.source,
                context_controls=prompt_context.controls,
                vulnerabilities=self._knowledge_for_state(state),
                do_not_report=self._do_not_report,
                severity_rubric=state.rubric,
                pending=list(state.pending),
            )
            last_verdict = self._ask(
                "judge",
                JUDGE_SYSTEM,
                prompt,
                self._judge,
                required_keys=("findings",),
                optional_list_keys=(
                    "downgraded",
                    "dismissed",
                    "unresolved",
                    "investigate",
                    "resolved_pending",
                    "evidence_requests",
                    "source_queries",
                ),
                object_list_keys=(
                    "downgraded",
                    "dismissed",
                    "unresolved",
                    "investigate",
                ),
            )
            return last_verdict

        judgment = run_evidence_judgment(
            state.active_grounding,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(reply.get("findings")),
            accumulator=role_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda finding: finding.evidence_refs,
            trace=state.trace,
            judgment_id=state.round_id,
            navigation_session=state.navigation,
        )
        if judgment.failure_reason:
            raise RoleResponseError(judgment.failure_reason)
        self._advance_state(state, judgment)
        judged_findings = judgment.findings
        self._emit_findings(state, judged_findings, role="judge")
        unresolved = [
            {"kind": "unresolved", **item}
            for item in validate_pending_records(
                last_verdict.get("unresolved", []),
                role="adversarial judge unresolved",
            )
        ]
        investigate = [
            {"kind": "investigate", **item}
            for item in validate_pending_records(
                last_verdict.get("investigate", []),
                role="adversarial judge investigate",
            )
        ]
        resolved = last_verdict.get("resolved_pending", [])
        if not all(isinstance(item, str) for item in resolved):
            raise RoleResponseError("resolved_pending must contain string ids")
        known_pending = {item.get("id") for item in state.pending}
        unknown = [item for item in resolved if item not in known_pending]
        if unknown:
            raise RoleResponseError(f"resolved_pending contains unknown ids: {', '.join(unknown)}")
        return RoleJudgment(
            findings=judged_findings,
            pending=cast("list[PendingWorkRecord]", [*unresolved, *investigate]),
            resolved_pending=tuple(resolved),
            grounding=judgment.grounding,
            source_evidence=judgment.source_evidence,
            evidence_exchanges=judgment.evidence_exchanges,
        )

    def _knowledge_for_state(self, state: _AdversarialRoundState) -> str:
        return self._selected_vulnerabilities(
            state.diff,
            state.active_grounding,
            state.vulnerability_override,
        )

    @staticmethod
    def _advance_state(state: _AdversarialRoundState, judgment: EvidenceJudgment[Finding]) -> None:
        grounded = with_source_evidence(state.active_grounding, judgment.source_evidence)
        state.active_grounding = replace(
            grounded,
            coverage=merge_grounding_coverage((grounded.coverage, judgment.grounding)),
        )

    def _emit_findings(
        self,
        state: _AdversarialRoundState,
        findings: list[Finding],
        *,
        role: str,
    ) -> None:
        for finding in findings:
            self._emit_finding(state, finding, role=role, stage="generated")

    @staticmethod
    def _emit_finding(
        state: _AdversarialRoundState,
        finding: Finding,
        *,
        role: str,
        stage: str,
    ) -> None:
        details: dict[str, object] = {
            "stage": stage,
            "role": role,
            "round": state.round_id,
            "finding_id": finding_id(finding),
            "file": finding.file,
            "line": finding.line,
            "category": finding.category,
        }
        if stage == "generated":
            details["description"] = finding.description[:500]
        emit_trace(
            state.trace,
            "finding",
            **details,
        )

    def run(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: GroundingContext | str = "",
        stack: str = "",
        max_rounds: int = DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds,
        plan: ReviewSchedule | None = None,
        known: list[Finding] | None = None,
    ) -> ReviewOutcome[Finding]:
        """Run shared convergence over one diff unit's role rounds."""
        plan = plan or review_schedule(
            "adversarial",
            max_rounds=max_rounds,
            converge_after=DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge,
        )
        if plan.mode != "adversarial":
            raise ValueError("the adversarial runner requires an adversarial review plan")
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")
        vulnerabilities = self._selected_vulnerabilities(diff, grounded, vulnerabilities)
        outcome = run_review_cycles(
            plan=plan,
            execute=lambda _round, accumulated: self.review_round(
                diff,
                vulnerabilities=vulnerabilities,
                context=grounded,
                stack=stack,
                known=accumulated or known,
            ),
            execute_pending=lambda _round, accumulated, pending: self.review_round(
                diff,
                vulnerabilities=vulnerabilities,
                context=grounded,
                stack=stack,
                known=accumulated or known,
                pending=pending,
            ),
            accumulator=role_accumulator(),
        )
        if not outcome.failure_reason or outcome.errors:
            return outcome
        return replace(
            outcome,
            failure_reason=f"adversarial review did not converge within {plan.max_rounds} rounds",
        )
