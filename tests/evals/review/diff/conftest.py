"""Diff evaluation fixtures provide product result and target builders."""

import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.review.diff import targets


@pytest.fixture(autouse=True)
def repository_target_for_direct_cases(monkeypatch, tmp_path):
    """Give isolated direct cases the repository boundary required by production."""
    original = targets.source_root

    @contextmanager
    def source_root(target):
        if target:
            with original(target) as root:
                yield root
            return
        yield tmp_path

    monkeypatch.setattr(targets, "source_root", source_root)


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
        rounds=None,
        finder_provider=None,
        finder_model=None,
        challenger_provider=None,
        challenger_model=None,
        judge_provider=None,
        judge_model=None,
    ):
        from cyberjury.review.diff.engine import DiffRoleOptions
        from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
        from evals.review.diff import DiffRunOptions

        template_mode = mode or "adversarial"
        effective_rounds = (
            1 if template_mode == "standard" else rounds or DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
        )
        return DiffRunOptions(
            provider=provider,
            model=model,
            mode_override=mode,
            roles=DiffRoleOptions(
                mode=template_mode,
                max_rounds=effective_rounds,
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
