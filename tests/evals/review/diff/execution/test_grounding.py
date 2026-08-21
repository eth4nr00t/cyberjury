"""Diff benchmark grounding stays scoped to each materialized target."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from cyberjury.providers.base import Provider
from cyberjury.review.diff.engine import DiffReviewOptions
from evals.benchmarks.cases import DiffCase
from evals.review.diff import execution, run_diff_cases, targets
from tests.evals.review.diff.factories import diff_options as _diff_options
from tests.evals.review.diff.factories import diff_result as _diff_result
from tests.evals.review.diff.factories import git as _git


def test_run_diff_cases_routes_each_case_to_its_profile(monkeypatch):
    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen[diff] = (options.execution.profile.name, options.grounding.context)
        return _diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="web", diff="web-diff", context="web-context"),
        DiffCase(name="evm", diff="sol-diff", profile="evm"),
    ]
    run_diff_cases(cases, options=_diff_options())

    assert seen == {"web-diff": ("web", "web-context"), "sol-diff": ("evm", "")}


def test_run_diff_cases_collects_target_context(monkeypatch):
    contexts = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def prepare(self, diff):
                return [SimpleNamespace(grounding=SimpleNamespace(text=f"context from {path} for {profile.name}"))]

        return Collector()

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        assert options.grounding.prepare_diff is not None
        contexts[diff] = options.grounding.prepare_diff(diff)[0].grounding.text
        return _diff_result()

    monkeypatch.setattr(targets, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="targeted",
        diff="diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n",
        target={"type": "git", "path": "/repo"},
    )
    run_diff_cases([case], options=_diff_options())

    assert contexts[case.diff] == "context from /repo for web"


def test_diff_context_does_not_touch_repository_grounding(tmp_path, monkeypatch):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    def unexpected(*args, **kwargs):
        raise AssertionError("diff context touched repository grounding")

    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["options"] = options
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(targets, "prepare_git_scope", unexpected)
    monkeypatch.setattr(targets, "build_diff_context_collector", unexpected)
    monkeypatch.setattr(execution, "ModelVerifier", unexpected)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="diff-only",
        diff="diff --git a/Token.sol b/Token.sol\n+++ b/Token.sol\n+contract Token {}\n",
        context="repository evidence",
        profile="evm",
        review_context="diff",
    )
    run_diff_cases([case], options=_diff_options())

    options = seen["options"]
    assert options.grounding.context == ""
    assert options.grounding.prepare_diff is None
    assert options.verification.verifier is None


def test_run_diff_cases_collects_context_from_git_url_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.email", "test@example.com")
    _git(repository, "config", "user.name", "Test User")
    (repository / "server.py").write_text("value = 'base'\n", encoding="utf-8")
    _git(repository, "add", "server.py")
    _git(repository, "commit", "-m", "base")
    (repository / "server.py").write_text("value = 'ref'\n", encoding="utf-8")
    _git(repository, "add", "server.py")
    _git(repository, "commit", "-m", "ref")
    ref = _git(repository, "rev-parse", "HEAD")
    contexts = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def prepare(self, diff):
                text = Path(path, "server.py").read_text(encoding="utf-8").strip()
                return [SimpleNamespace(grounding=SimpleNamespace(text=text))]

        return Collector()

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        assert options.grounding.prepare_diff is not None
        contexts[diff] = options.grounding.prepare_diff(diff)[0].grounding.text
        return _diff_result()

    monkeypatch.setattr(targets, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="targeted-url",
        diff="diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n",
        target={"type": "git", "url": repository.as_uri(), "ref": ref},
    )
    run_diff_cases([case], options=_diff_options())

    assert contexts[case.diff] == "value = 'ref'"


def test_run_diff_cases_prepares_evm_scope_and_collects_scoped_facts(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)
    seen = {}

    @contextmanager
    def fake_source_root(case):
        yield root

    def fake_prepare(name, target, repository, review_scope, *, verify=True):
        seen["repository"] = repository
        seen["scope"] = review_scope
        return SimpleNamespace(ok=True, detail="prepared")

    def fake_collector(path, profile, *, facts_root=None, review_diff=""):
        seen["facts_root"] = facts_root

        class Collector:
            def prepare(self, diff):
                seen["prepared_diff"] = diff
                return [SimpleNamespace(grounding=SimpleNamespace(text="scoped context"))]

        return Collector()

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        assert options.grounding.prepare_diff is not None
        units = options.grounding.prepare_diff(diff)
        seen["review_grounding"] = units[0].grounding.text
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(targets, "prepare_git_scope", fake_prepare)
    monkeypatch.setattr(targets, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="evm-targeted",
        diff="diff --git a/contracts/Token.sol b/contracts/Token.sol\n+++ b/contracts/Token.sol\n+contract Token {}\n",
        target={"type": "git", "url": "https://example.com/repo.git", "path": "contracts"},
        profile="evm",
    )
    run_diff_cases([case], options=_diff_options())

    assert seen == {
        "repository": root,
        "scope": scope,
        "facts_root": scope,
        "prepared_diff": case.diff,
        "review_grounding": "scoped context",
    }
