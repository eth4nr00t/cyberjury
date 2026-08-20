"""Orchestrate benchmark cases through the product Repository Review boundary."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from cyberjury.review.repository.engine import RepositoryRunOptions, run_repository_review
from evals.benchmarks.contract import RepositoryCase
from evals.review.failures import failure_summary
from evals.score.result import Result

from .progress import CaseProgress, Progress
from .results import failure_result, score_findings
from .targets import materialize


def run(
    case: RepositoryCase,
    *,
    workspace: str | Path,
    options: RepositoryRunOptions,
    progress: Progress | None = None,
) -> Result:
    """Run and score one repository benchmark through the coded product workflow."""
    roles = options.roles
    status = CaseProgress.start(progress, case, roles.mode, roles.model)
    try:
        from cyberjury.profiles.registry import get_profile

        profile = get_profile(case.profile)
        output = replace(options.output, profile=profile)
        run_options = status.bind(replace(options, output=output))
        with materialize(case, profile) as target:
            review = run_repository_review(target.scope, workspace, options=run_options)
            if review.outcome is None:
                return _failed(case, status, "repository review returned no completion outcome")
            if review.outcome.degraded:
                return _failed(case, status, failure_summary(review.outcome))
            findings = review.scaffold.workspace / "findings.json"
            result = score_findings(case, findings, source_root=target.scope)
    except Exception as exc:
        return _failed(case, status, exc)
    status.scored(result)
    return result


def _failed(case: RepositoryCase, status: CaseProgress, failure: Exception | str) -> Result:
    result = failure_result(case, failure)
    status.failed(result.error_details[0])
    return result
