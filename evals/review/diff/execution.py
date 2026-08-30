"""Orchestrate benchmark cases through the product Diff Review boundary."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from cyberjury.finding import Finding
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Provider
from cyberjury.providers.configuration import build_diff_providers, provider_configuration_from_env
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffReviewOptions,
    DiffRoleOptions,
    DiffVerificationOptions,
    run_diff_review,
)
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace
from cyberjury.review.verification import Confirmer, ModelRefutationChecker, ModelVerifier, Verifier
from evals.benchmarks.cases import DiffCase, diff_text
from evals.review.failures import failure_summary
from evals.score.result import RepeatedResult, Result

from .progress import CaseProgress, Progress, with_run
from .results import (
    apply_score,
    apply_unkeyed,
    case_result,
    empty_result,
    merge,
    record_failure,
    score,
)
from .targets import materialize


@dataclass(frozen=True, kw_only=True)
class DiffRunOptions:
    """Provider wiring and role policy for one evaluation run."""

    provider: Provider
    model: str
    roles: DiffRoleOptions = field(default_factory=DiffRoleOptions)
    mode_override: str | None = None


@dataclass(frozen=True, kw_only=True)
class _CaseExecution:
    outcome: ReviewOutcome[Finding]
    findings: list[Finding]
    scored: Result | None


def run(
    cases: list[DiffCase],
    *,
    mode: str | None = None,
    rounds: int | None = None,
    model_override: str | None = None,
    runs: int = 1,
    target: str = "diff",
    progress: Progress | None = None,
    trace: Trace | None = None,
) -> Result | RepeatedResult:
    """Run diff benchmark cases with product provider wiring."""
    from cyberjury.envfile import load_env_file

    if runs < 1:
        raise ValueError("diff benchmark runs must be at least 1")
    provider_mode = mode or _default_provider_mode(cases)
    if provider_mode == "standard" and rounds is not None:
        raise ValueError("diff benchmark rounds apply only in adversarial mode")
    effective_rounds = (
        1 if provider_mode == "standard" else rounds or DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
    )
    load_env_file()
    providers = build_diff_providers(
        provider_configuration_from_env(model_override=model_override),
        provider_mode,
    )
    try:
        options = DiffRunOptions(
            provider=providers.base_provider,
            model=providers.base_model,
            mode_override=mode,
            roles=DiffRoleOptions(
                mode=provider_mode,
                max_rounds=effective_rounds,
                finder_provider=providers.finder_provider,
                finder_model=providers.finder_model,
                challenger_provider=providers.challenger_provider,
                challenger_model=providers.challenger_model,
                judge_provider=providers.judge_provider,
                judge_model=providers.judge_model,
                finder_label=providers.finder_model,
                challenger_label=providers.challenger_model,
                judge_label=providers.judge_model,
            ),
        )
        results = []
        for run_index in range(1, runs + 1):
            result = run_diff_cases(
                cases,
                options=options,
                progress=with_run(progress, run_index, runs),
                trace=with_run(trace, run_index, runs),
            )
            result.target = target
            results.append(result)
        return RepeatedResult.from_runs(target, results) if runs > 1 else results[0]
    finally:
        providers.close()


def _default_provider_mode(cases: list[DiffCase]) -> str:
    return "adversarial" if any(case.review_mode == "adversarial" for case in cases) else "standard"


def run_diff_cases(
    cases: list[DiffCase],
    *,
    options: DiffRunOptions,
    progress: Progress | None = None,
    trace: Trace | None = None,
) -> Result:
    """Run each diff case and fold its result into one batch score."""
    result = empty_result()
    total = len(cases)
    for index, case in enumerate(cases, 1):
        merge(result, _run_diff_case(case, index, total, options, progress, trace))
    return result


def _run_diff_case(
    case: DiffCase,
    index: int,
    total: int,
    options: DiffRunOptions,
    progress: Progress | None,
    trace: Trace | None,
) -> Result:
    result = case_result(case)
    roles = _case_roles(case, options)
    status = CaseProgress.start(progress, trace, case, index, total, roles.mode, options.model)
    try:
        execution = _execute_case(case, options, roles, status)
    except Exception as exc:
        status.failed(record_failure(result, case, exc))
        return result
    if execution.outcome.degraded:
        status.failed(record_failure(result, case, failure_summary(execution.outcome)))
        return result
    if execution.scored is not None:
        apply_score(result, execution.scored, scope=case.name)
        status.scored(execution.scored)
        return result
    apply_unkeyed(result, case, execution.findings)
    status.unkeyed(len(execution.findings), positive=case.is_positive)
    return result


def _case_roles(case: DiffCase, options: DiffRunOptions) -> DiffRoleOptions:
    mode = options.mode_override or case.review_mode
    if mode == "adversarial":
        return replace(
            options.roles,
            mode=mode,
            finder_label=options.roles.finder_label or options.roles.finder_model or options.model,
            challenger_label=options.roles.challenger_label or options.roles.challenger_model or options.model,
            judge_label=options.roles.judge_label or options.roles.judge_model or options.model,
        )
    return DiffRoleOptions(
        mode=mode,
        max_rounds=1,
        finder_label=options.model,
        challenger_label=options.model,
        judge_label=options.model,
    )


def _execute_case(
    case: DiffCase,
    options: DiffRunOptions,
    roles: DiffRoleOptions,
    status: CaseProgress,
) -> _CaseExecution:
    diff = diff_text(case)
    from cyberjury.profiles.registry import get_profile

    profile = get_profile(case.profile)
    with materialize(case, profile, diff) as target:
        verifier, confirmers, found_by = _verification(target.root, profile.paths, options.provider, roles)
        review = run_diff_review(
            diff,
            provider=options.provider,
            model=options.model,
            options=DiffReviewOptions(
                roles=roles,
                grounding=target.grounding,
                verification=DiffVerificationOptions(
                    root=str(target.root),
                    verifier=verifier,
                    confirmers=confirmers,
                    found_by=found_by,
                ),
                execution=DiffExecutionOptions(
                    profile=profile,
                    on_batch=status.batch_finished,
                    on_judgment=status.judgment_finished,
                    trace=status.trace(),
                ),
            ),
        )
        findings = review.outcome.findings
        scored = score(case, findings, target.root, status.trace()) if not review.outcome.degraded else None
        return _CaseExecution(outcome=review.outcome, findings=findings, scored=scored)


def _verification(
    root: Path,
    content: ContentPaths,
    provider: Provider,
    roles: DiffRoleOptions,
) -> tuple[Verifier, list[Confirmer], tuple[str, ...]]:
    challenger_provider = roles.challenger_provider or provider
    if roles.challenger_label is None:
        raise ValueError("diff role options require a challenger label")
    challenger_label = roles.challenger_label
    verifier: Verifier = ModelVerifier(provider=challenger_provider, model=challenger_label, content=content)
    seen = [(challenger_provider, challenger_label)]
    confirmers: list[Confirmer] = []
    judge_provider = roles.judge_provider or provider
    judge_label = roles.judge_label or challenger_label
    if not _seen_role(seen, judge_provider, judge_label):
        confirmers.append((judge_label, ModelRefutationChecker(provider=judge_provider, model=judge_label)))
        seen.append((judge_provider, judge_label))
    finder_provider = roles.finder_provider or provider
    finder_label = roles.finder_label or challenger_label
    if not _seen_role(seen, finder_provider, finder_label):
        confirmers.append((finder_label, ModelRefutationChecker(provider=finder_provider, model=finder_label)))
    found_by = (finder_label,) if roles.mode == "standard" else ()
    return verifier, confirmers, found_by


def _seen_role(seen: list[tuple[Provider, str]], provider: Provider, label: str) -> bool:
    return any(candidate is provider and candidate_label == label for candidate, candidate_label in seen)
