"""Orchestrate benchmark cases through the product Diff Review boundary."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass

from cyberjury.finding import Finding
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderCredentialsError,
    provider_configuration_from_env,
)
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.diff.checkout import DiffCheckoutHooks, review_diff_checkout
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace
from evals.benchmarks.cases import DiffCase, diff_text
from evals.review.failures import failure_summary
from evals.review.source import review_scope, source_root
from evals.score.result import RepeatedResult, Result

from .progress import CaseProgress, Progress, with_run
from .results import apply_score, case_result, empty_result, merge, record_failure, score

Attempt = Callable[[dict[str, object]], None]


@dataclass(frozen=True, kw_only=True)
class DiffRunOptions:
    """Provider seats, usage meter, and concurrency for one evaluation run."""

    configuration: ProviderConfiguration
    meter: UsageMeter
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency

    @property
    def model(self) -> str:
        """Return the finder model reported with each case."""
        return self.configuration.finder.model


@dataclass(frozen=True, kw_only=True)
class _CaseExecution:
    outcome: ReviewOutcome[Finding]
    findings: list[Finding]
    scored: Result | None


def run(
    cases: list[DiffCase],
    *,
    model_override: str | None = None,
    runs: int = 1,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    progress: Progress | None = None,
    trace: Trace | None = None,
    meter: UsageMeter | None = None,
    on_run_calls: Callable[[int, dict[str, object]], None] | None = None,
    on_attempt: Callable[[int, dict[str, object]], None] | None = None,
) -> Result | RepeatedResult:
    """Run diff benchmark cases through the product checkout Diff Review.

    `on_attempt` receives the run number and one adjudicable attempt record per case.
    """
    from cyberjury.envfile import load_env_file

    if runs < 1:
        raise ValueError("diff benchmark runs must be at least 1")
    load_env_file()
    meter = meter if meter is not None else UsageMeter()
    options = DiffRunOptions(
        configuration=provider_configuration_from_env(model_override=model_override),
        meter=meter,
        concurrency=concurrency,
    )
    results = []
    for run_index in range(1, runs + 1):
        completed_calls = len(meter.call_snapshot()) if on_run_calls is not None else 0
        result = run_diff_cases(
            cases,
            options=options,
            progress=with_run(progress, run_index, runs),
            trace=with_run(trace, run_index, runs),
            on_attempt=_numbered(on_attempt, run_index),
        )
        result.target = "diff"
        results.append(result)
        if on_run_calls is not None:
            on_run_calls(run_index, meter.document_from(completed_calls))
    if runs == 1:
        return results[0]
    return RepeatedResult.from_runs("diff", results)


def _numbered(on_attempt: Callable[[int, dict[str, object]], None] | None, run: int) -> Attempt | None:
    if on_attempt is None:
        return None

    def write(record: dict[str, object]) -> None:
        on_attempt(run, {"case": record["case"], "attempt": run, **record})

    return write


def run_diff_cases(
    cases: list[DiffCase],
    *,
    options: DiffRunOptions,
    progress: Progress | None = None,
    trace: Trace | None = None,
    on_attempt: Attempt | None = None,
) -> Result:
    """Run each diff case and fold its result into one batch score."""
    result = empty_result()
    total = len(cases)
    for index, case in enumerate(cases, 1):
        merge(result, _run_diff_case(case, index, total, options, progress, trace, on_attempt))
    return result


def _run_diff_case(
    case: DiffCase,
    index: int,
    total: int,
    options: DiffRunOptions,
    progress: Progress | None,
    trace: Trace | None,
    on_attempt: Attempt | None = None,
) -> Result:
    result = case_result(case)
    status = CaseProgress.start(progress, trace, case, index, total, options.model)
    try:
        execution = _execute_case(case, options, status)
    except ProviderCredentialsError:
        raise
    except Exception as exc:
        error = record_failure(result, case, exc)
        status.failed(error)
        _record_attempt(on_attempt, case, options.model, [], None, error)
        return result
    if execution.scored is None:
        error = record_failure(result, case, failure_summary(execution.outcome))
        status.failed(error)
        _record_attempt(on_attempt, case, options.model, execution.findings, None, error)
        return result
    apply_score(result, execution.scored, scope=case.name)
    status.scored(execution.scored)
    _record_attempt(on_attempt, case, options.model, execution.findings, execution.scored, "")
    return result


def _record_attempt(
    on_attempt: Attempt | None,
    case: DiffCase,
    model: str,
    findings: list[Finding],
    scored: Result | None,
    error: str,
) -> None:
    """Publish the attempt record that `adjudicate-diff` binds a source assessment ledger to."""
    if on_attempt is None:
        return
    record: dict[str, object] = {
        "case": case.name,
        "complete": scored is not None,
        "error": error,
        "expectation": case.expectation,
        "model": model,
        "expected_checks": json.loads(json.dumps([asdict(check) for check in case.answer_key.checks])),
        "findings": [
            {
                **finding.to_dict(),
                "candidate_id": finding.candidate_id,
                "evidence_refs": list(finding.evidence_refs),
                "found_by": list(finding.found_by),
            }
            for finding in findings
        ],
    }
    if scored is not None:
        result = case_result(case)
        apply_score(result, scored, scope=case.name)
        result.target = case.name
        record["result"] = result.to_dict()
    on_attempt(record)


def _execute_case(case: DiffCase, options: DiffRunOptions, status: CaseProgress) -> _CaseExecution:
    from cyberjury.profiles.registry import get_profile

    with source_root(case.target) as root:
        review = review_diff_checkout(
            diff_text(case),
            root=root,
            scope=review_scope(root, case.target),
            profile=get_profile(case.profile),
            configuration=options.configuration,
            meter=options.meter,
            concurrency=options.concurrency,
            hooks=DiffCheckoutHooks(
                on_batch=status.batch_finished,
                on_judgment=status.judgment_finished,
                trace=status.trace(),
            ),
        )
        outcome = review.result.outcome
        findings = list(outcome.findings)
        scored = score(case, findings, root, status.trace()) if not outcome.degraded else None
        return _CaseExecution(outcome=outcome, findings=findings, scored=scored)
