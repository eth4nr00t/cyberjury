"""Diff evaluation execution tests cover runs, seats, the shared checkout entry, and attempts."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.providers.configuration import ProviderCredentialsError
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from evals.benchmarks.contract import AnswerKey, ExpectedLocation, KeyCheck
from evals.review.diff import execution, run_diff_cases
from evals.review.diff.results import reports_from_findings
from evals.score.report import ReportChangeAnchor


def test_evaluate_consumes_the_product_provider_configuration(monkeypatch, diff_case, provider_configuration):
    from evals.score.result import Result

    configuration = provider_configuration(finder_model="finder-model")
    requested = {}
    seen = {}

    def configuration_from_env(**kwargs):
        requested.update(kwargs)
        return configuration

    def fake_run(cases, *, options, progress, trace, on_attempt):
        seen["options"] = options
        return Result(target="diff")

    monkeypatch.setattr(execution, "provider_configuration_from_env", configuration_from_env)
    monkeypatch.setattr(execution, "run_diff_cases", fake_run)
    meter = UsageMeter()
    execution.run([diff_case("case", "diff")], model_override="override", concurrency=3, meter=meter)

    options = seen["options"]
    assert requested == {"model_override": "override"}
    assert options.configuration is configuration
    assert options.model == "finder-model"
    assert options.meter is meter
    assert options.concurrency == 3


def test_evaluate_reports_one_valid_call_artifact_per_run(monkeypatch, diff_case, provider_configuration):
    from cyberjury.providers.base import Message
    from cyberjury.providers.metering import MeteringProvider, model_call_context, record_model_parse
    from evals.score.result import Result

    provider = MockProvider(default="{}")
    monkeypatch.setattr(execution, "provider_configuration_from_env", lambda **kwargs: provider_configuration())
    seen = []
    attempts = 0
    meter = UsageMeter()

    def fake_run(cases, *, options, progress, trace, on_attempt):
        nonlocal attempts
        attempts += 1
        with model_call_context(role="finder", trigger="initial_judgment", unit_id=f"unit-{attempts}") as context:
            MeteringProvider(provider, options.meter).complete(
                system="system", messages=[Message(role="user", content="source")], model="mock", max_tokens=100
            )
            record_model_parse("direct")
            context.navigation("not_requested")
        return Result(target="diff")

    monkeypatch.setattr(execution, "run_diff_cases", fake_run)

    execution.run(
        [diff_case("case", "diff")],
        runs=2,
        meter=meter,
        on_run_calls=lambda number, document: seen.append((number, document)),
    )

    assert [number for number, _document in seen] == [1, 2]
    assert [document["usage"]["model_requests"] for _number, document in seen] == [1, 1]
    assert [document["calls"][0]["unit_id"] for _number, document in seen] == ["unit-1", "unit-2"]
    assert meter.document()["usage"]["model_requests"] == 2


@pytest.mark.parametrize("runs", [0, -1])
def test_evaluate_rejects_nonpositive_runs_before_provider_setup(monkeypatch, runs, diff_case):
    def unexpected_provider_setup(**kwargs):
        raise AssertionError("provider setup must not run for invalid repetition counts")

    monkeypatch.setattr(execution, "provider_configuration_from_env", unexpected_provider_setup)

    with pytest.raises(ValueError, match="runs must be at least 1"):
        execution.run([diff_case("case", "diff")], runs=runs)


def test_run_diff_cases_handles_complete_results_and_degraded_work(monkeypatch, diff_options, diff_result, diff_case):
    def review(diff: str, **kwargs):
        if "POSITIVE" in diff:
            return diff_result([Finding(file="app.py", line=1, category="sql-injection", description="finding")])
        if "DEGRADED" in diff:
            return diff_result(
                degraded=True,
                failures=[SimpleNamespace(reason="finder returned unparsable JSON")],
            )
        return diff_result()

    monkeypatch.setattr(execution, "review_diff_checkout", review)
    cases = [
        diff_case("p-hit", "diff --git POSITIVE"),
        diff_case("p-miss", "diff --git CLEAN"),
        diff_case("s-fp", "diff --git POSITIVE", expectation="clean"),
        diff_case("s-ok", "diff --git CLEAN", expectation="clean"),
        diff_case("p-degraded", "diff --git DEGRADED"),
    ]

    result = run_diff_cases(cases, options=diff_options())

    assert result.found == ["p-hit:p-hit-check"]
    assert result.missed == ["p-miss:p-miss-check"]
    assert result.false_positives == ["s-fp:s-fp-check"]
    assert result.errors == 1
    assert result.error_details == ["p-degraded: finder returned unparsable JSON"]


def test_run_diff_cases_describes_degraded_verification(monkeypatch, diff_options, diff_result, diff_case):
    def fake_review(diff: str, **kwargs):
        return diff_result(degraded=True, errors=1, incomplete=["candidate"])

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    result = run_diff_cases(
        [diff_case("verification-failed", "diff --git change")],
        options=diff_options(),
    )

    assert result.error_details == ["verification-failed: 1 review or verification errors, 1 incomplete findings"]


def test_run_diff_cases_combines_review_and_verification_failures(monkeypatch, diff_options, diff_result, diff_case):
    def fake_review(diff: str, **kwargs):
        return diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="finder failed")],
            errors=1,
            incomplete=["candidate"],
            failure_reason="verification failed: upstream unavailable",
        )

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    result = run_diff_cases(
        [diff_case("multiple-failures", "diff --git change")],
        options=diff_options(),
    )

    assert result.error_details == [
        "multiple-failures: finder failed, verification failed: upstream unavailable, "
        "1 review or verification errors, 1 incomplete findings"
    ]


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch, diff_options, diff_result, diff_case):
    key = AnswerKey(
        benchmark_id="real-patch",
        checks=(
            KeyCheck(
                id="paid-auto-publish",
                expectation="findings",
                locations=(ExpectedLocation(file="app.py", symbol="publish_paid"),),
                applies_to=("real-patch",),
            ),
        ),
    )

    def fake_review(diff: str, **kwargs):
        finding = Finding(
            file="other.py",
            line=10,
            category="business-logic",
            description="publish_paid is safe here",
        )
        return diff_result([finding])

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    result = run_diff_cases(
        [diff_case("real-patch", "diff --git WRONG", checks=key.checks)],
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


def test_diff_batch_scopes_reused_check_ids_to_each_case(monkeypatch, diff_options, diff_result, diff_case):
    def answer_key(case_name: str) -> AnswerKey:
        return AnswerKey(
            benchmark_id=case_name,
            checks=(
                KeyCheck(
                    id="shared-check",
                    expectation="findings",
                    locations=(ExpectedLocation(file="app.py", line=1),),
                    applies_to=(case_name,),
                ),
            ),
        )

    def fake_review(diff: str, **kwargs):
        findings = [Finding(file="app.py", line=1, category="business-logic")] if "HIT" in diff else []
        return diff_result(findings)

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    cases = [
        diff_case("case-a", "HIT", checks=answer_key("case-a").checks),
        diff_case("case-b", "MISS", checks=answer_key("case-b").checks),
    ]

    result = run_diff_cases(cases, options=diff_options())

    assert result.found == ["case-a:shared-check"]
    assert result.missed == ["case-b:shared-check"]
    assert len({*result.found, *result.missed}) == result.n_findings == 2


def test_diff_benchmark_error_keeps_the_findings_denominator(monkeypatch, diff_options, diff_case):
    def fake_review(diff: str, **kwargs):
        raise TimeoutError("provider timed out")

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    result = run_diff_cases(
        [diff_case("real-patch", "diff --git TIMEOUT")],
        options=diff_options(),
    )

    assert result.errors == 1
    assert result.n_findings == 1
    assert result.recall == 0.0


def test_run_diff_cases_delegates_to_the_shared_checkout_review(
    tmp_path, monkeypatch, diff_options, diff_result, diff_case
):
    seen = {}

    @contextmanager
    def fake_source_root(target):
        yield tmp_path

    def fake_review(diff: str, **kwargs):
        seen["diff"] = diff
        seen.update(kwargs)
        kwargs["hooks"].on_batch(1, 1, 0.1)
        return diff_result()

    monkeypatch.setattr(execution, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    options = diff_options(concurrency=5)
    events = []
    run_diff_cases([diff_case("safe", "diff --git CLEAN")], options=options, progress=events.append)

    assert seen["diff"] == "diff --git CLEAN"
    assert seen["root"] == tmp_path
    assert seen["scope"] == tmp_path
    assert seen["profile"].name == WEB_PROFILE.name
    assert seen["configuration"] is options.configuration
    assert seen["meter"] is options.meter
    assert seen["concurrency"] == 5
    assert "source_snapshot" not in seen
    assert "dry_run_provider" not in seen
    assert [event["event"] for event in events] == ["case_started", "case_batch_finished", "case_finished"]


def test_run_diff_cases_aborts_on_missing_provider_credentials(monkeypatch, diff_options, diff_case):
    def fake_review(diff: str, **kwargs):
        raise ProviderCredentialsError("the openai seat has no reachable API key")

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    records = []

    with pytest.raises(ProviderCredentialsError, match="no reachable API key"):
        run_diff_cases([diff_case("case", "diff --git change")], options=diff_options(), on_attempt=records.append)
    assert records == []


def test_diff_case_without_a_git_target_fails_loud(diff_options, diff_case):
    patch = "diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n"
    case = diff_case("missing-repository", patch, target={"type": "directory", "path": "."})
    result = run_diff_cases([case], options=diff_options())

    assert result.errors == 1
    assert result.error_details == ["missing-repository: ValueError: benchmark target must be a pinned git source"]


def test_run_diff_cases_reviews_the_git_url_target_checkout(
    tmp_path, monkeypatch, diff_options, diff_result, git_runner, diff_case
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

    def fake_review(diff: str, **kwargs):
        contexts[diff] = Path(kwargs["root"], "server.py").read_text(encoding="utf-8").strip()
        return diff_result()

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    patch = "diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n"
    case = diff_case(
        "targeted-url",
        patch,
        target={"type": "git", "url": repository.as_uri(), "ref": ref},
    )
    run_diff_cases([case], options=diff_options())

    assert contexts[patch] == "value = 'ref'"


def test_run_diff_cases_scopes_facts_to_the_target_path(tmp_path, monkeypatch, diff_options, diff_result, diff_case):
    root = tmp_path / "repo"
    scope = root / "backend"
    scope.mkdir(parents=True)
    seen = {}

    @contextmanager
    def fake_source_root(case):
        yield root

    def fake_review(diff: str, **kwargs):
        seen.update(root=kwargs["root"], scope=kwargs["scope"], diff=diff)
        return diff_result()

    monkeypatch.setattr(execution, "source_root", fake_source_root)
    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    patch = "diff --git a/backend/app.py b/backend/app.py\n+++ b/backend/app.py\n+print(1)\n"
    case = diff_case(
        "web-targeted",
        patch,
        target={"type": "git", "url": "https://example.com/repo.git", "path": "backend"},
    )
    run_diff_cases([case], options=diff_options())

    assert seen == {"root": root, "scope": scope, "diff": patch}


def test_run_diff_cases_publishes_one_attempt_record_per_case(monkeypatch, diff_options, diff_result, diff_case):
    def fake_review(diff: str, **kwargs):
        if "BROKEN" in diff:
            raise RuntimeError("backend stalled")
        return diff_result([Finding(file="app.py", line=1, category="sql-injection", description="query")])

    monkeypatch.setattr(execution, "review_diff_checkout", fake_review)
    records = []
    cases = [diff_case("hit", "diff --git HIT"), diff_case("bad", "diff --git BROKEN")]

    run_diff_cases(cases, options=diff_options(), on_attempt=records.append)

    complete, failed = records
    assert complete["case"] == "hit"
    assert complete["complete"] is True
    assert complete["expected_checks"][0]["id"] == "hit-check"
    assert complete["findings"][0]["candidate_id"].startswith("candidate-")
    assert complete["result"]["target"] == "hit"
    assert complete["result"]["found"] == ["hit:hit-check"]
    assert failed["complete"] is False
    assert failed["error"] == "RuntimeError: backend stalled"
    assert "result" not in failed


def test_diff_source_root_fetches_exact_commit_targets(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.benchmarks.contract import AnswerKey
    from evals.review import source

    root = tmp_path / "repo"
    root.mkdir()
    calls = []

    @contextmanager
    def fake_target_tree(root, ref):
        yield tmp_path / "checkout"

    def fake_ensure(target, root=None):
        calls.append((target, root))

    monkeypatch.setattr(source, "git_target_root", lambda target: root)
    monkeypatch.setattr(source, "ensure_git_target_refs", fake_ensure)
    monkeypatch.setattr(source, "target_tree", fake_target_tree)

    case = DiffCase(
        name="needs-fetch",
        answer_key=AnswerKey(benchmark_id="t", checks=()),
        target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
    )
    with source.source_root(case.target) as checkout:
        assert checkout == tmp_path / "checkout"

    assert calls == [(case.target, root)]


def test_diff_review_root_uses_the_git_url_target_path(tmp_path):
    from evals.review.source import review_scope

    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)

    target = {"type": "git", "url": "https://example.com/repo.git", "path": "contracts"}
    assert review_scope(root, target) == scope


def test_diff_review_root_rejects_escaping_target_paths(tmp_path):
    from evals.review.source import review_scope

    root = tmp_path / "repo"
    root.mkdir()

    with pytest.raises(ValueError, match="inside the repository"):
        review_scope(root, {"type": "git", "url": "https://example.com/repo.git", "path": "../outside"})
