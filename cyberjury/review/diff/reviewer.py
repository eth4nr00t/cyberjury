"""Provider backed reviewers for one diff review unit.

Standard mode runs one Finder pass with one judgment per bounded knowledge pack. Each
adversarial round runs three roles: the Finder scans, the Challenger rebuts and
independently rescans, the Judge cross-validates, and the coded loop unions survivors.
Rounds repeat, feeding the union back to the Finder, until two clean rounds add nothing
or ``max_rounds`` is hit. The loop costs roughly three role calls per round.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from cyberjury.finding import Finding, finding_from_dict
from cyberjury.guides import load_guides, select_guides
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.review.context import GroundingContext
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
    JudgmentProgress,
    ReviewCycle,
    ReviewOutcome,
    ReviewPlan,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    parse_role_response,
    review_plan,
    run_evidence_judgment,
    run_review_cycles,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, emit_trace, finding_id
from cyberjury.review.vulnerabilities import VulnerabilityCatalog, vulnerabilities_for_diff


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
        findings.append(finding)
    return findings


def _audit_response(text: str) -> dict:
    """Translate the shared Finder contract failure into the diff public error."""
    try:
        return parse_role_response(
            text,
            role="diff finder",
            required_keys=("findings",),
            optional_list_keys=("evidence_requests",),
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
    ) -> EvidenceJudgment[Finding]:
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")

        def ask(context_text: str) -> dict[str, object]:
            prompt = standard_audit_prompt_plan(
                diff,
                vulnerabilities=vulnerabilities,
                vulnerability_categories=categories,
                selected_vulnerability_categories=selected_categories,
                context=context_text,
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
            trace=trace,
            judgment_id=judgment_id,
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
        context_text = context.selection_text if isinstance(context, GroundingContext) else context
        knowledge = self._vulnerability_catalog.plan(diff, context_text)
        return run_standard_judgments(
            knowledge.packs,
            execute_judgment=lambda pack, cache: self._run_judgment(
                diff,
                categories=pack.categories,
                selected_categories=tuple(item.id for item in knowledge.selected),
                vulnerabilities=pack.body,
                context=context,
                cache=cache,
                trace=trace,
                judgment_id=knowledge.packs.index(pack) + 1,
            ),
            describe_judgment=lambda pack: pack.label,
            finder_label=finder_label,
            accumulator=finding_accumulator(),
            key=lambda finding: (finding.file, finding.line, finding.category),
            title=lambda finding: finding.description,
            on_judgment=on_judgment,
            trace=trace,
        )


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


@dataclass
class _AdversarialRoundState:
    diff: str
    vulnerabilities: str
    grounded: GroundingContext
    stack: str
    known: tuple[Finding, ...]
    trace: Trace | None
    round_id: int | None
    rubric: str
    vulnerability_dir: Path | None
    active_context: str


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

    def _selected_vulnerabilities(
        self,
        diff: str,
        grounded: GroundingContext,
        vulnerabilities: str,
    ) -> str:
        """Keep adversarial knowledge selection aligned with every review path."""
        if vulnerabilities:
            return vulnerabilities
        directory = self._content.vulnerabilities_dir if self._content else None
        if directory is not None:
            return vulnerabilities_for_diff(diff, context=grounded.selection_text, directory=directory)
        return vulnerabilities_for_diff(diff, context=grounded.selection_text)

    def _ask(
        self,
        role: str,
        system: str,
        prompt: str,
        backend: tuple,
        *,
        required_keys: tuple[str, ...],
        optional_list_keys: tuple[str, ...] = (),
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
        )

    def review_round(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: GroundingContext | str = "",
        stack: str = "",
        known: list[Finding] | None = None,
        trace: Trace | None = None,
        round_id: int | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt one role sequence to the shared target cycle contract."""
        grounded = context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="diff")
        vulnerabilities = self._selected_vulnerabilities(diff, grounded, vulnerabilities)
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        state = _AdversarialRoundState(
            diff=diff,
            vulnerabilities=vulnerabilities,
            grounded=grounded,
            stack=stack,
            known=tuple(known or ()),
            trace=trace,
            round_id=round_id,
            rubric=severity_rubric_text(self._content),
            vulnerability_dir=vuln_dir,
            active_context=grounded.prompt_text,
        )

        role_round = run_role_round(
            find=lambda: self._run_finder_step(state),
            finder_label=self._finder_label,
            challenge=lambda findings: self._run_challenger_step(state, findings),
            challenger_label=self._challenger_label,
            judge=lambda findings, challenged: self._run_judge_step(state, findings, challenged),
            judge_label=self._judge_label,
            key=lambda finding: (finding.file, finding.line, finding.category),
            title=lambda finding: finding.description,
        )
        for finding in role_round.findings:
            self._emit_finding(state, finding, role="judge", stage="kept")
        return ReviewCycle(
            findings=role_round.findings,
            pending=role_round.pending,
            errors=0 if role_round.clean else 1,
            failure_reason=role_round.failure_reason,
            grounding=role_round.grounding,
        )

    def _run_finder_step(self, state: _AdversarialRoundState) -> EvidenceJudgment[Finding]:
        def ask(context_text: str) -> dict[str, object]:
            prompt = finder_prompt(
                state.diff,
                vulnerabilities=state.vulnerabilities,
                context=context_text,
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
                optional_list_keys=("evidence_requests",),
            )

        judgment = run_evidence_judgment(
            state.grounded,
            ask=ask,
            findings_from_reply=lambda reply: _findings_from_reply(reply.get("findings")),
            accumulator=role_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            trace=state.trace,
            judgment_id=state.round_id,
        )
        state.active_context = judgment.prompt_context
        self._emit_findings(state, judgment.findings, role="finder")
        return judgment

    def _run_challenger_step(
        self,
        state: _AdversarialRoundState,
        finder_findings: list[Finding],
    ) -> RoleChallenge[Finding]:
        prompt = challenger_prompt(
            state.diff,
            vulnerabilities=state.vulnerabilities,
            context=state.active_context,
            finder_findings=[finding.to_dict() for finding in finder_findings],
            vulnerabilities_dir=state.vulnerability_dir,
            stack=state.stack,
            focus=self._focus,
            do_not_report=self._do_not_report,
            severity_rubric=state.rubric,
        )
        reply = self._ask(
            "challenger",
            CHALLENGER_SYSTEM,
            prompt,
            self._challenger,
            required_keys=("rebuttals", "new_findings"),
        )
        new_findings = _findings_from_reply(reply.get("new_findings"))
        self._emit_findings(state, new_findings, role="challenger")
        return RoleChallenge(rebuttals=_dicts(reply.get("rebuttals")), new_findings=new_findings)

    def _run_judge_step(
        self,
        state: _AdversarialRoundState,
        finder_findings: list[Finding],
        challenged: RoleChallenge[Finding],
    ) -> RoleJudgment[Finding]:
        prompt = judge_prompt(
            state.diff,
            [finding.to_dict() for finding in finder_findings],
            challenged.rebuttals,
            [finding.to_dict() for finding in challenged.new_findings],
            context=state.active_context,
            do_not_report=self._do_not_report,
            severity_rubric=state.rubric,
        )
        verdict = self._ask(
            "judge",
            JUDGE_SYSTEM,
            prompt,
            self._judge,
            required_keys=("findings",),
            optional_list_keys=("downgraded", "dismissed", "unresolved", "investigate"),
        )
        judged_findings = _findings_from_reply(verdict.get("findings"))
        self._emit_findings(state, judged_findings, role="judge")
        unresolved = [{"kind": "unresolved", **item} for item in _dicts(verdict.get("unresolved"))]
        investigate = [{"kind": "investigate", **item} for item in _dicts(verdict.get("investigate"))]
        return RoleJudgment(findings=judged_findings, pending=[*unresolved, *investigate])

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
        plan: ReviewPlan | None = None,
        known: list[Finding] | None = None,
    ) -> ReviewOutcome[Finding]:
        """Run shared convergence over one diff unit's role rounds."""
        plan = plan or review_plan(
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
            accumulator=role_accumulator(),
        )
        if not outcome.failure_reason or outcome.errors:
            return outcome
        return replace(
            outcome,
            failure_reason=f"adversarial review did not converge within {plan.max_rounds} rounds",
        )
