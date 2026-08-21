"""Diff benchmark role and verification wiring mirrors the product path."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.providers.base import CompletionResult, Provider
from cyberjury.review.diff.engine import DiffReviewOptions, DiffRoleOptions
from evals.benchmarks.cases import DiffCase
from evals.review.diff import execution, run_diff_cases, targets
from tests.evals.review.diff.factories import diff_options as _diff_options
from tests.evals.review.diff.factories import diff_result as _diff_result


@dataclass
class _MutableProvider(Provider):
    name: str

    def complete(self, **kwargs) -> CompletionResult:
        return CompletionResult(text='{"findings": []}')


def test_run_diff_cases_uses_each_case_review_mode(monkeypatch):
    modes = []

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        modes.append(options.roles.mode)
        return _diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="standard", diff="standard", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial"),
    ]
    run_diff_cases(cases, options=_diff_options())

    assert modes == ["standard", "adversarial"]


def test_run_diff_cases_allows_explicit_mode_override(monkeypatch):
    modes = []

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        modes.append(options.roles.mode)
        return _diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial")
    run_diff_cases([case], options=_diff_options(mode="standard"))

    assert modes == ["standard"]


def test_standard_case_does_not_inherit_adversarial_seats(tmp_path, monkeypatch):
    base = object()
    finder = object()
    challenger = object()
    judge = object()
    verifier_providers = []
    review_roles = []

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    class FakeVerifier:
        def __init__(self, *, provider, model, content):
            verifier_providers.append(provider)

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        roles = options.roles
        review_roles.append((roles.finder_provider, roles.challenger_provider, roles.judge_provider))
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", FakeVerifier)
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: object())
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="standard", diff="standard", context="context", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", context="context", review_mode="adversarial"),
    ]
    options = _diff_options(
        provider=base,
        model="base",
        finder_provider=finder,
        finder_model="finder",
        challenger_provider=challenger,
        challenger_model="challenger",
        judge_provider=judge,
        judge_model="judge",
    )

    run_diff_cases(cases, options=options)

    assert verifier_providers == [base, challenger]
    assert review_roles == [(None, None, None), (finder, challenger, judge)]


def test_repository_context_verifies_by_default(tmp_path, monkeypatch):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["verification"] = options.verification
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        options=_diff_options(),
    )

    assert result.false_positives == []
    assert seen["verification"].verifier == "verifier"
    assert seen["verification"].root == str(tmp_path)
    assert seen["verification"].confirmers == []
    assert seen["verification"].found_by == ("m",)


def test_diff_context_does_not_verify(monkeypatch):
    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["verification"] = options.verification
        return _diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_context="diff")],
        options=_diff_options(),
    )

    assert seen["verification"].verifier is None
    assert seen["verification"].root is None
    assert seen["verification"].confirmers is None
    assert seen["verification"].found_by == ()


def test_distinct_role_models_confirm_refutations(tmp_path, monkeypatch):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["verification"] = options.verification
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    options = _diff_options(
        provider="finder-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_provider="judge-provider",
        judge_model="judge",
    )
    run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        options=options,
    )

    assert seen["verification"].confirmers == [("judge", "checker"), ("finder", "checker")]
    assert seen["verification"].found_by == ()


def test_role_model_inherits_base_provider_for_confirmation(tmp_path, monkeypatch):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_checker(**kwargs):
        seen.setdefault("checkers", []).append(kwargs)
        return "checker"

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["confirmers"] = options.verification.confirmers
        return _diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", fake_checker)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    options = _diff_options(
        provider="base-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_model="judge",
    )
    run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        options=options,
    )

    assert seen["confirmers"] == [("judge", "checker"), ("finder", "checker")]
    assert seen["checkers"][0] == {"provider": "base-provider", "model": "judge"}


def test_verification_deduplicates_mutable_providers_by_identity(tmp_path, monkeypatch):
    provider = _MutableProvider("shared")
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")

    _, confirmers, _ = execution._verification(
        DiffCase(name="case", diff="diff", review_context="repository"),
        tmp_path,
        WEB_PROFILE.paths,
        provider,
        DiffRoleOptions(
            mode="adversarial",
            challenger_provider=provider,
            challenger_label="shared",
            judge_provider=provider,
            judge_label="shared",
            finder_provider=provider,
            finder_label="shared",
        ),
    )

    assert confirmers == []


def test_verification_keeps_distinct_mutable_providers_with_the_same_model_label(tmp_path, monkeypatch):
    challenger = _MutableProvider("challenger")
    judge = _MutableProvider("judge")
    checker_providers = []

    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")

    def checker(**kwargs):
        checker_providers.append(kwargs["provider"])
        return "checker"

    monkeypatch.setattr(execution, "ModelRefutationChecker", checker)

    _, confirmers, _ = execution._verification(
        DiffCase(name="case", diff="diff", review_context="repository"),
        tmp_path,
        WEB_PROFILE.paths,
        challenger,
        DiffRoleOptions(
            mode="adversarial",
            challenger_provider=challenger,
            challenger_label="shared-model",
            judge_provider=judge,
            judge_label="shared-model",
            finder_provider=challenger,
            finder_label="shared-model",
        ),
    )

    assert confirmers == [("shared-model", "checker")]
    assert len(checker_providers) == 1
    assert checker_providers[0] is judge
