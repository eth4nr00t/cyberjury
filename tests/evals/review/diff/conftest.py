"""Diff evaluation fixtures provide product result and target builders."""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def diff_result():
    def make(findings=None, *, degraded=False, failures=None, errors=0, incomplete=None, failure_reason=""):
        outcome = SimpleNamespace(
            findings=list(findings or []),
            failures=list(failures or []),
            degraded=degraded,
            errors=errors,
            incomplete=list(incomplete or []),
            pending=[],
            failure_reason=failure_reason,
            requires_convergence=False,
            converged=False,
        )
        return SimpleNamespace(outcome=outcome)

    return make


@pytest.fixture
def diff_options():
    def make(
        *,
        provider=None,
        model="m",
        mode=None,
        rounds=3,
        finder_provider=None,
        finder_model=None,
        challenger_provider=None,
        challenger_model=None,
        judge_provider=None,
        judge_model=None,
    ):
        from cyberjury.review.diff.engine import DiffRoleOptions
        from evals.review.diff import DiffRunOptions

        return DiffRunOptions(
            provider=provider,
            model=model,
            mode_override=mode,
            roles=DiffRoleOptions(
                max_rounds=rounds,
                finder_provider=finder_provider,
                finder_model=finder_model,
                challenger_provider=challenger_provider,
                challenger_model=challenger_model,
                judge_provider=judge_provider,
                judge_model=judge_model,
                finder_label=finder_model,
                challenger_label=challenger_model,
                judge_label=judge_model,
            ),
        )

    return make


@pytest.fixture
def git_runner():
    def run(cwd: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    return run
