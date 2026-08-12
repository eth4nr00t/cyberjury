"""Provider backed reviewers for one diff review unit.

Standard mode runs one Finder pass with one judgment per bounded knowledge pack. Each
adversarial round runs three roles: the Finder scans, the Challenger rebuts and
independently rescans, the Judge cross-validates, and the coded loop unions survivors.
Rounds repeat, feeding the union back to the Finder, until two clean rounds add nothing
or ``max_rounds`` is hit. The loop costs roughly three role calls per round.
"""

from __future__ import annotations

import re
from dataclasses import replace

from cyberjury.domains.base import ContentPaths
from cyberjury.finding import Finding, findings_from_list
from cyberjury.guides import load_guides, select_guides
from cyberjury.providers.base import Message, Provider
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
    JudgmentProgress,
    ReviewCycle,
    ReviewOutcome,
    ReviewPlan,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    parse_role_response,
    review_plan,
    run_review_cycles,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.vulnerabilities import VulnerabilityCatalog, vulnerabilities_for_diff

_DIFF_PATH = re.compile(r"^(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", re.MULTILINE)


def guides_for_diff(diff: str, content: ContentPaths | None = None) -> str:
    """Render the language and framework guides selected by one diff."""
    paths = _DIFF_PATH.findall(diff)
    guides = (
        load_guides(content.languages_dir, content.frameworks_dir, content.protocols_dir)
        if content is not None
        else None
    )
    return "\n\n---\n\n".join(guide.body for guide in select_guides(paths, source_text=diff, guides=guides))


class AuditError(RuntimeError):
    """A Finder reply cannot support a complete diff review."""


def _audit_response(text: str) -> dict:
    """Translate the shared Finder contract failure into the diff public error."""
    try:
        return parse_role_response(text, role="diff finder", required_keys=("findings",))
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
        context: str,
        cache: bool,
    ) -> list[Finding]:
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        prompt = standard_audit_prompt_plan(
            diff,
            vulnerabilities=vulnerabilities,
            vulnerability_categories=categories,
            selected_vulnerability_categories=selected_categories,
            context=context,
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
        return findings_from_list(_audit_response(result.text).get("findings"))

    def run(self, diff: str, *, vulnerabilities: str = "", context: str = "") -> list[Finding]:
        """Return complete standard findings for callers outside the coded scheduler."""
        if vulnerabilities:
            return self._run_judgment(
                diff,
                categories=(),
                vulnerabilities=vulnerabilities,
                context=context,
                cache=False,
            )
        cycle = self.review_round(diff, context=context, finder_label=self._model)
        if not cycle.clean:
            raise AuditError(cycle.failure_reason)
        return cycle.findings

    def review_round(
        self,
        diff: str,
        *,
        context: str = "",
        finder_label: str,
        on_judgment: JudgmentProgress | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt the standard Finder call to the shared target cycle contract."""
        knowledge = self._vulnerability_catalog.plan(diff, context)
        return run_standard_judgments(
            knowledge.packs,
            execute_judgment=lambda pack, cache: self._run_judgment(
                diff,
                categories=pack.categories,
                selected_categories=tuple(item.id for item in knowledge.selected),
                vulnerabilities=pack.body,
                context=context,
                cache=cache,
            ),
            describe_judgment=lambda pack: pack.label,
            finder_label=finder_label,
            accumulator=finding_accumulator(),
            key=lambda finding: (finding.file, finding.line, finding.category),
            title=lambda finding: finding.description,
            on_judgment=on_judgment,
        )


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


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
        context: str = "",
        stack: str = "",
        known: list[Finding] | None = None,
    ) -> ReviewCycle[Finding]:
        """Adapt one role sequence to the shared target cycle contract."""
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        if not vulnerabilities:
            vulnerabilities = (
                vulnerabilities_for_diff(diff, context=context, directory=vuln_dir)
                if vuln_dir is not None
                else vulnerabilities_for_diff(diff, context=context)
            )
        rubric = severity_rubric_text(self._content)
        finder = finder_prompt(
            diff,
            vulnerabilities=vulnerabilities,
            context=context,
            prior=[finding.to_dict() for finding in known or []],
            vulnerabilities_dir=vuln_dir,
            stack=stack,
            focus=self._focus,
            do_not_report=self._do_not_report,
            severity_rubric=rubric,
        )
        role_responses: dict[str, dict] = {}

        def find() -> list[Finding]:
            role_responses["finder"] = self._ask(
                "finder",
                FINDER_SYSTEM,
                finder,
                self._finder,
                required_keys=("findings",),
            )
            return findings_from_list(role_responses["finder"].get("findings"))

        def challenge(_finder_findings: list[Finding]) -> RoleChallenge[Finding]:
            finder_findings = _dicts(role_responses["finder"].get("findings"))
            prompt = challenger_prompt(
                diff,
                vulnerabilities=vulnerabilities,
                context=context,
                finder_findings=finder_findings,
                vulnerabilities_dir=vuln_dir,
                stack=stack,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            role_responses["challenger"] = self._ask(
                "challenger",
                CHALLENGER_SYSTEM,
                prompt,
                self._challenger,
                required_keys=("rebuttals", "new_findings"),
            )
            return RoleChallenge(
                rebuttals=_dicts(role_responses["challenger"].get("rebuttals")),
                new_findings=findings_from_list(role_responses["challenger"].get("new_findings")),
            )

        def judge(
            _finder_findings: list[Finding],
            challenged: RoleChallenge[Finding],
        ) -> RoleJudgment[Finding]:
            finder_findings = _dicts(role_responses["finder"].get("findings"))
            new_findings = _dicts(role_responses["challenger"].get("new_findings"))
            prompt = judge_prompt(
                diff,
                finder_findings,
                challenged.rebuttals,
                new_findings,
                context=context,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            verdict = self._ask(
                "judge",
                JUDGE_SYSTEM,
                prompt,
                self._judge,
                required_keys=("findings",),
                optional_list_keys=("downgraded", "dismissed", "unresolved", "investigate"),
            )
            unresolved = [{"kind": "unresolved", **item} for item in _dicts(verdict.get("unresolved"))]
            investigate = [{"kind": "investigate", **item} for item in _dicts(verdict.get("investigate"))]
            return RoleJudgment(
                findings=findings_from_list(verdict.get("findings")),
                pending=[*unresolved, *investigate],
            )

        role_round = run_role_round(
            find=find,
            finder_label=self._finder_label,
            challenge=challenge,
            challenger_label=self._challenger_label,
            judge=judge,
            judge_label=self._judge_label,
            key=lambda finding: (finding.file, finding.line, finding.category),
            title=lambda finding: finding.description,
        )
        return ReviewCycle(
            findings=role_round.findings,
            pending=role_round.pending,
            errors=0 if role_round.clean else 1,
            failure_reason=role_round.failure_reason,
        )

    def run(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: str = "",
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
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        if not vulnerabilities:
            vulnerabilities = (
                vulnerabilities_for_diff(diff, context=context, directory=vuln_dir)
                if vuln_dir is not None
                else vulnerabilities_for_diff(diff, context=context)
            )
        outcome = run_review_cycles(
            plan=plan,
            execute=lambda _round, accumulated: self.review_round(
                diff,
                vulnerabilities=vulnerabilities,
                context=context,
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
