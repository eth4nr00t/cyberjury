"""Diff benchmark execution preserves score and failure semantics."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cyberjury.finding import Finding
from cyberjury.providers.base import Provider
from cyberjury.review.diff.engine import DiffReviewOptions
from evals.benchmarks.cases import DiffCase
from evals.benchmarks.contract import AnswerKey, KeyCheck
from evals.review.diff import execution, run_diff_cases

from .support import _diff_options, _diff_result


def test_evaluate_consumes_named_product_provider_seats(monkeypatch):
    from cyberjury.providers.configuration import DiffProviders, ProviderConfiguration, ProviderSeat
    from evals.review.diff import execution as diff_execution
    from evals.score.result import Result

    providers = DiffProviders(
        base_provider="base-provider",
        base_model="base-model",
        finder_provider="finder-provider",
        finder_model="finder-model",
        challenger_provider="challenger-provider",
        challenger_model="challenger-model",
        judge_provider="judge-provider",
        judge_model="judge-model",
    )
    seen = {}

    configuration = ProviderConfiguration(
        base=ProviderSeat(provider="openai", model="base-model"),
        finder=ProviderSeat(provider="openai", model="finder-model"),
        challenger=ProviderSeat(provider="openai", model="challenger-model"),
        judge=ProviderSeat(provider="openai", model="judge-model"),
        retries=0,
        timeout=10,
    )
    monkeypatch.setattr(diff_execution, "provider_configuration_from_env", lambda **kwargs: configuration)
    monkeypatch.setattr(diff_execution, "build_diff_providers", lambda config, mode: providers)

    def fake_run(cases, *, options, progress, trace):
        seen["options"] = options
        return Result(target="diff")

    monkeypatch.setattr(diff_execution, "run_diff_cases", fake_run)
    diff_execution.run(
        [DiffCase(name="case", diff="diff", review_mode="adversarial")],
        mode="adversarial",
    )

    options = seen["options"]
    assert options.provider == "base-provider"
    assert options.model == "base-model"
    assert options.roles.finder_provider == "finder-provider"
    assert options.roles.challenger_provider == "challenger-provider"
    assert options.roles.judge_provider == "judge-provider"


@pytest.mark.parametrize("runs", [0, -1])
def test_evaluate_rejects_nonpositive_runs_before_provider_setup(monkeypatch, runs):
    def unexpected_provider_setup(**kwargs):
        raise AssertionError("provider setup must not run for invalid repetition counts")

    monkeypatch.setattr(execution, "provider_configuration_from_env", unexpected_provider_setup)

    with pytest.raises(ValueError, match="runs must be at least 1"):
        execution.run([DiffCase(name="case", diff="diff")], runs=runs)


def _review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
    if "POSITIVE" in diff:
        return _diff_result([Finding(file="app.py", category="sql-injection", description="finding")])
    if "DEGRADED" in diff:
        return _diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="adversarial judge returned unparsable JSON")],
        )
    return _diff_result()


def test_run_diff_cases_handles_complete_results_and_degraded_work(monkeypatch):
    monkeypatch.setattr(execution, "run_diff_review", _review)
    cases = [
        DiffCase(name="p-hit", category="sql-injection", diff="diff --git POSITIVE"),
        DiffCase(name="p-miss", category="sql-injection", diff="diff --git CLEAN"),
        DiffCase(name="s-fp", category="", diff="diff --git POSITIVE"),
        DiffCase(name="s-ok", category="", diff="diff --git CLEAN"),
        DiffCase(name="p-degraded", category="sql-injection", diff="diff --git DEGRADED"),
    ]

    result = run_diff_cases(cases, options=_diff_options())

    assert result.found == ["p-hit"]
    assert result.missed == ["p-miss"]
    assert result.false_positives == ["s-fp"]
    assert result.errors == 1
    assert result.error_details == ["p-degraded: adversarial judge returned unparsable JSON"]


def test_run_diff_cases_describes_degraded_verification(monkeypatch):
    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        return _diff_result(degraded=True, errors=1, incomplete=["candidate"])

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="verification-failed", category="sql-injection", diff="diff --git change")],
        options=_diff_options(),
    )

    assert result.error_details == ["verification-failed: 1 review or verification errors, 1 incomplete findings"]


def test_run_diff_cases_combines_review_and_verification_failures(monkeypatch):
    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        return _diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="finder failed")],
            errors=1,
            incomplete=["candidate"],
            failure_reason="verification failed: upstream unavailable",
        )

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="multiple-failures", category="sql-injection", diff="diff --git change")],
        options=_diff_options(),
    )

    assert result.error_details == [
        "multiple-failures: finder failed, verification failed: upstream unavailable, "
        "1 review or verification errors, 1 incomplete findings"
    ]


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch):
    key = AnswerKey(
        benchmark_id="real-patch",
        checks=(
            KeyCheck(
                id="paid-auto-publish",
                expectation="findings",
                files=("app.py",),
                symbols=("publish_paid",),
                knowledge=("vuln:business-logic",),
                applies_to=("real-patch",),
            ),
        ),
    )

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        finding = Finding(
            file="other.py",
            line=10,
            category="business-logic",
            description="publish_paid is safe here",
        )
        return _diff_result([finding])

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="real-patch", category="business-logic", diff="diff --git WRONG", answer_key=key)],
        options=_diff_options(),
    )

    assert result.found == []
    assert result.missed == ["real-patch:paid-auto-publish"]
    assert result.extra == ["other.py:10:0"]


def test_diff_batch_scopes_reused_check_ids_to_each_case(monkeypatch):
    def answer_key(case_name: str) -> AnswerKey:
        return AnswerKey(
            benchmark_id=case_name,
            checks=(
                KeyCheck(
                    id="shared-check",
                    expectation="findings",
                    files=("app.py",),
                    knowledge=("vuln:business-logic",),
                    applies_to=(case_name,),
                ),
            ),
        )

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        findings = [Finding(file="app.py", category="business-logic")] if "HIT" in diff else []
        return _diff_result(findings)

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="case-a", category="business-logic", diff="HIT", answer_key=answer_key("case-a")),
        DiffCase(name="case-b", category="business-logic", diff="MISS", answer_key=answer_key("case-b")),
    ]

    result = run_diff_cases(cases, options=_diff_options())

    assert result.found == ["case-a:shared-check"]
    assert result.missed == ["case-b:shared-check"]
    assert len({*result.found, *result.missed}) == result.n_findings == 2


def test_diff_benchmark_error_keeps_file_recall_denominator(monkeypatch):
    key = AnswerKey(
        benchmark_id="real-patch",
        checks=(
            KeyCheck(
                id="file-keyed",
                expectation="findings",
                files=("app.py",),
                knowledge=("vuln:business-logic",),
                applies_to=("real-patch",),
            ),
        ),
    )

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        raise TimeoutError("provider timed out")

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="real-patch", category="business-logic", diff="diff --git TIMEOUT", answer_key=key)],
        options=_diff_options(),
    )

    assert result.errors == 1
    assert result.n_findings == 1
    assert result.n_file_findings == 1
    assert result.file_recall == 0.0
