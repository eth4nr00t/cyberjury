"""Shared builders for repository engine tests."""

import json

from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryFinalizeOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    finalize_repository_review,
    run_repository_review,
)
from cyberjury.review.repository.reviewer import UnitChallenge, UnitReviewer
from cyberjury.review.repository.scaffold import WORKSPACE_MARKER
from cyberjury.review.repository.union import Candidate
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.verification import Verdict, Verifier


def run_review(target, workspace, **values):
    concurrency = values.pop("concurrency", DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency)
    roles = RepositoryRoleOptions(
        **{
            key: values.pop(key)
            for key in (
                "mode",
                "provider",
                "model",
                "challenger_provider",
                "challenger_model",
                "judge_provider",
                "judge_model",
                "reviewer",
                "challenger_reviewer",
                "judge_reviewer",
                "extra_finder_backends",
            )
            if key in values
        }
    )
    verification = RepositoryVerificationOptions(
        concurrency=concurrency,
        **{
            ("enabled" if key == "verify" else key): values.pop(key)
            for key in ("verify", "verifier", "confirmers", "votes", "on_verify")
            if key in values
        },
    )
    execution = RepositoryExecutionOptions(
        concurrency=concurrency,
        **{
            key: values.pop(key)
            for key in ("max_passes", "converge_after", "min_rounds", "on_pass", "on_judgment")
            if key in values
        },
    )
    output = RepositoryOutputOptions(
        **{key: values.pop(key) for key in ("profile", "poc_backend", "meter") if key in values}
    )
    lifecycle = RepositoryLifecycleOptions(fresh=values.pop("fresh", False))
    assert not values
    return run_repository_review(
        target,
        workspace,
        options=RepositoryRunOptions(
            roles=roles,
            verification=verification,
            execution=execution,
            lifecycle=lifecycle,
            output=output,
        ),
    )


def finalize_review(target, workspace, **values):
    verification = RepositoryVerificationOptions(
        **{
            ("enabled" if key == "verify" else key): values.pop(key)
            for key in (
                "verify",
                "verifier",
                "confirmers",
                "provider",
                "model",
                "votes",
                "concurrency",
                "on_verify",
            )
            if key in values
        }
    )
    output = RepositoryOutputOptions(
        **{key: values.pop(key) for key in ("profile", "poc_backend", "meter") if key in values}
    )
    assert not values
    return finalize_repository_review(
        target,
        workspace,
        options=RepositoryFinalizeOptions(verification=verification, output=output),
    )


def mark_workspace(project):
    marker = project / WORKSPACE_MARKER
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps({"project": project.name, "profile": "web"}) + "\n",
        encoding="utf-8",
    )


def finalize_workspace(tmp_path):
    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    for name in ("v.py", "s.py", "d.py"):
        (target / "app" / name).write_text("x = 1\n")
    workspace = tmp_path / "work"
    candidates = workspace / "proj" / "candidates"
    candidates.mkdir(parents=True)
    mark_workspace(workspace / "proj")
    return target, workspace, candidates


class _CountingReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        return [
            Candidate(
                title="wallet idor",
                category="idor",
                endpoint="GET /wallets/<id>",
                file="app/services/wallet.py",
                severity="HIGH",
            )
        ]


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True)


class _EmptyChallenger(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        return UnitChallenge(rebuttals=[], new_findings=[])


class _PassingJudge(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        return finder_findings + new_findings
