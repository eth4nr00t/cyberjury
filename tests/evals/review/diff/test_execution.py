"""Diff evaluation execution tests cover runs, roles, grounding, and adapter symmetry."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.providers.base import CompletionResult, Provider
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import DiffReviewOptions, DiffRoleOptions
from evals.benchmarks.cases import DiffCase
from evals.benchmarks.contract import AnswerKey, KeyCheck
from evals.review.diff import execution, run_diff_cases, targets
from evals.review.diff.results import reports_from_findings
from evals.score.report import ReportChangeAnchor


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


def test_evaluate_closes_provider_bundle_when_a_run_fails(monkeypatch):
    from cyberjury.providers.configuration import DiffProviders

    closed = []

    class CloseProvider(MockProvider):
        def close(self):
            closed.append(self)

    provider = CloseProvider(default="{}")
    providers = DiffProviders(base_provider=provider, base_model="model", finder_provider=provider)
    monkeypatch.setattr(execution, "provider_configuration_from_env", lambda **kwargs: object())
    monkeypatch.setattr(execution, "build_diff_providers", lambda config, mode: providers)

    def fail_run(*args, **kwargs):
        raise RuntimeError("failed")

    monkeypatch.setattr(execution, "run_diff_cases", fail_run)

    with pytest.raises(RuntimeError, match="failed"):
        execution.run([DiffCase(name="case", diff="diff")])

    assert closed == [provider]


@pytest.mark.parametrize("runs", [0, -1])
def test_evaluate_rejects_nonpositive_runs_before_provider_setup(monkeypatch, runs):
    def unexpected_provider_setup(**kwargs):
        raise AssertionError("provider setup must not run for invalid repetition counts")

    monkeypatch.setattr(execution, "provider_configuration_from_env", unexpected_provider_setup)

    with pytest.raises(ValueError, match="runs must be at least 1"):
        execution.run([DiffCase(name="case", diff="diff")], runs=runs)


def test_run_diff_cases_handles_complete_results_and_degraded_work(monkeypatch, diff_options, diff_result):
    def review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        if "POSITIVE" in diff:
            return diff_result([Finding(file="app.py", category="sql-injection", description="finding")])
        if "DEGRADED" in diff:
            return diff_result(
                degraded=True,
                failures=[SimpleNamespace(reason="adversarial judge returned unparsable JSON")],
            )
        return diff_result()

    monkeypatch.setattr(execution, "run_diff_review", review)
    cases = [
        DiffCase(name="p-hit", category="sql-injection", diff="diff --git POSITIVE"),
        DiffCase(name="p-miss", category="sql-injection", diff="diff --git CLEAN"),
        DiffCase(name="s-fp", category="", diff="diff --git POSITIVE"),
        DiffCase(name="s-ok", category="", diff="diff --git CLEAN"),
        DiffCase(name="p-degraded", category="sql-injection", diff="diff --git DEGRADED"),
    ]

    result = run_diff_cases(cases, options=diff_options())

    assert result.found == ["p-hit"]
    assert result.missed == ["p-miss"]
    assert result.false_positives == ["s-fp"]
    assert result.errors == 1
    assert result.error_details == ["p-degraded: adversarial judge returned unparsable JSON"]


def test_run_diff_cases_describes_degraded_verification(monkeypatch, diff_options, diff_result):
    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        return diff_result(degraded=True, errors=1, incomplete=["candidate"])

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="verification-failed", category="sql-injection", diff="diff --git change")],
        options=diff_options(),
    )

    assert result.error_details == ["verification-failed: 1 review or verification errors, 1 incomplete findings"]


def test_run_diff_cases_combines_review_and_verification_failures(monkeypatch, diff_options, diff_result):
    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        return diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="finder failed")],
            errors=1,
            incomplete=["candidate"],
            failure_reason="verification failed: upstream unavailable",
        )

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="multiple-failures", category="sql-injection", diff="diff --git change")],
        options=diff_options(),
    )

    assert result.error_details == [
        "multiple-failures: finder failed, verification failed: upstream unavailable, "
        "1 review or verification errors, 1 incomplete findings"
    ]


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch, diff_options, diff_result):
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
        return diff_result([finding])

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="real-patch", category="business-logic", diff="diff --git WRONG", answer_key=key)],
        options=diff_options(),
    )

    assert result.found == []
    assert result.missed == ["real-patch:paid-auto-publish"]
    assert result.extra == ["other.py:10:0"]


def test_diff_report_adapter_preserves_the_product_change_anchor():
    finding = Finding(
        file="sink.py",
        line=21,
        category="command-injection",
        change_anchor=ChangeAnchor(file="route.py", line=8, side="old"),
    )

    report = reports_from_findings([finding])[0]

    assert report.change_anchor == ReportChangeAnchor(file="route.py", line=8, side="old")


def test_diff_batch_scopes_reused_check_ids_to_each_case(monkeypatch, diff_options, diff_result):
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
        return diff_result(findings)

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="case-a", category="business-logic", diff="HIT", answer_key=answer_key("case-a")),
        DiffCase(name="case-b", category="business-logic", diff="MISS", answer_key=answer_key("case-b")),
    ]

    result = run_diff_cases(cases, options=diff_options())

    assert result.found == ["case-a:shared-check"]
    assert result.missed == ["case-b:shared-check"]
    assert len({*result.found, *result.missed}) == result.n_findings == 2


def test_diff_benchmark_error_keeps_file_recall_denominator(monkeypatch, diff_options):
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
        options=diff_options(),
    )

    assert result.errors == 1
    assert result.n_findings == 1
    assert result.n_file_findings == 1
    assert result.file_recall == 0.0


@dataclass
class _MutableProvider(Provider):
    name: str

    def complete(self, **kwargs) -> CompletionResult:
        return CompletionResult(text='{"findings": []}')


def test_run_diff_cases_uses_each_case_review_mode(monkeypatch, diff_options, diff_result):
    modes = []

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        modes.append(options.roles.mode)
        return diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="standard", diff="standard", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial"),
    ]
    run_diff_cases(cases, options=diff_options())

    assert modes == ["standard", "adversarial"]


def test_run_diff_cases_allows_explicit_mode_override(monkeypatch, diff_options, diff_result):
    modes = []

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        modes.append(options.roles.mode)
        return diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial")
    run_diff_cases([case], options=diff_options(mode="standard"))

    assert modes == ["standard"]


def test_standard_case_does_not_inherit_adversarial_seats(tmp_path, monkeypatch, diff_options, diff_result):
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
        return diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", FakeVerifier)
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: object())
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    cases = [
        DiffCase(name="standard", diff="standard", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial"),
    ]
    options = diff_options(
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


def test_repository_context_verifies_by_default(tmp_path, monkeypatch, diff_options, diff_result):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["verification"] = options.verification
        return diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        options=diff_options(),
    )

    assert result.false_positives == []
    assert seen["verification"].verifier == "verifier"
    assert seen["verification"].root == str(tmp_path)
    assert seen["verification"].confirmers == ()
    assert seen["verification"].found_by == ("m",)


def test_distinct_role_models_confirm_refutations(tmp_path, monkeypatch, diff_options, diff_result):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["verification"] = options.verification
        return diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    options = diff_options(
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

    assert seen["verification"].confirmers == (("judge", "checker"), ("finder", "checker"))
    assert seen["verification"].found_by == ()


def test_role_model_inherits_base_provider_for_confirmation(tmp_path, monkeypatch, diff_options, diff_result):
    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_checker(**kwargs):
        seen.setdefault("checkers", []).append(kwargs)
        return "checker"

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen["confirmers"] = options.verification.confirmers
        return diff_result()

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", fake_checker)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    options = diff_options(
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

    assert seen["confirmers"] == (("judge", "checker"), ("finder", "checker"))
    assert seen["checkers"][0] == {"provider": "base-provider", "model": "judge"}


def test_verification_deduplicates_mutable_providers_by_identity(tmp_path, monkeypatch):
    provider = _MutableProvider("shared")
    monkeypatch.setattr(execution, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(execution, "ModelRefutationChecker", lambda **kwargs: "checker")

    _, confirmers, _ = execution._verification(
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


def test_run_diff_cases_routes_each_case_to_its_profile(monkeypatch, diff_options, diff_result):
    seen = {}

    class Collector:
        @staticmethod
        def prepare(diff):
            return []

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        seen[diff] = options.execution.profile.name
        return diff_result()

    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    monkeypatch.setattr(targets, "build_diff_context_collector", lambda *args, **kwargs: Collector())
    monkeypatch.setattr(
        targets,
        "prepare_git_scope",
        lambda *args, **kwargs: SimpleNamespace(ok=True, detail="prepared"),
    )
    cases = [
        DiffCase(name="web", diff="web-diff"),
        DiffCase(name="evm", diff="sol-diff", profile="evm"),
    ]
    run_diff_cases(cases, options=diff_options())

    assert seen == {"web-diff": "web", "sol-diff": "evm"}


def test_run_diff_cases_collects_target_context(monkeypatch, diff_options, diff_result):
    contexts = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def prepare(self, diff):
                return [SimpleNamespace(grounding=SimpleNamespace(text=f"context from {path} for {profile.name}"))]

        return Collector()

    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        assert options.grounding.prepare_diff is not None
        contexts[diff] = options.grounding.prepare_diff(diff)[0].grounding.text
        return diff_result()

    monkeypatch.setattr(targets, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="targeted",
        diff="diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n",
        target={"type": "git", "path": "/repo"},
    )
    run_diff_cases([case], options=diff_options())

    assert contexts[case.diff] == "context from /repo for web"


def test_diff_case_without_repository_target_fails_loud(monkeypatch, diff_options):
    @contextmanager
    def fake_source_root(case):
        yield None

    monkeypatch.setattr(targets, "source_root", fake_source_root)
    case = DiffCase(
        name="missing-repository",
        diff="diff --git a/Token.sol b/Token.sol\n+++ b/Token.sol\n+contract Token {}\n",
        profile="evm",
    )
    result = run_diff_cases([case], options=diff_options())

    assert result.errors == 1
    assert result.error_details == [
        "missing-repository: ValueError: diff case 'missing-repository' requires a repository target"
    ]


def test_run_diff_cases_collects_context_from_git_url_target(
    tmp_path, monkeypatch, diff_options, diff_result, git_runner
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repository = tmp_path / "repo"
    repository.mkdir()
    git_runner(repository, "init")
    git_runner(repository, "config", "user.email", "test@example.com")
    git_runner(repository, "config", "user.name", "Test User")
    (repository / "server.py").write_text("value = 'base'\n", encoding="utf-8")
    git_runner(repository, "add", "server.py")
    git_runner(repository, "commit", "-m", "base")
    (repository / "server.py").write_text("value = 'ref'\n", encoding="utf-8")
    git_runner(repository, "add", "server.py")
    git_runner(repository, "commit", "-m", "ref")
    ref = git_runner(repository, "rev-parse", "HEAD")
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
        return diff_result()

    monkeypatch.setattr(targets, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    case = DiffCase(
        name="targeted-url",
        diff="diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n",
        target={"type": "git", "url": repository.as_uri(), "ref": ref},
    )
    run_diff_cases([case], options=diff_options())

    assert contexts[case.diff] == "value = 'ref'"


def test_run_diff_cases_prepares_evm_scope_and_collects_scoped_facts(tmp_path, monkeypatch, diff_options, diff_result):
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
        return diff_result()

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
    run_diff_cases([case], options=diff_options())

    assert seen == {
        "repository": root,
        "scope": scope,
        "facts_root": scope,
        "prepared_diff": case.diff,
        "review_grounding": "scoped context",
    }


def test_review_mode_packages_have_matching_stage_modules():
    root = Path("evals/review")
    expected = {"execution.py", "progress.py", "results.py", "targets.py"}

    assert {path.name for path in (root / "diff").glob("*.py") if path.name != "__init__.py"} == expected
    assert {path.name for path in (root / "repository").glob("*.py") if path.name != "__init__.py"} == expected
