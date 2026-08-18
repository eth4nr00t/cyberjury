"""Diff benchmark execution tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from .support import (
    _diff_result,
    _git,
)


def test_run_diff_cases_handles_complete_results_and_degraded_work(monkeypatch):
    """Diff cases consume the complete result and retain degraded failure evidence."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        if "POSITIVE" in d:
            return _diff_result(["a-finding"])
        if "DEGRADED" in d:
            return _diff_result(
                degraded=True,
                failures=[
                    SimpleNamespace(
                        index=1,
                        total=1,
                        paths=("app.py",),
                        reason="adversarial judge returned unparsable JSON",
                    )
                ],
            )
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="p-hit", category="sql-injection", diff="diff --git POSITIVE"),
        DiffCase(name="p-miss", category="sql-injection", diff="diff --git CLEAN"),
        DiffCase(name="s-fp", category="", diff="diff --git POSITIVE"),
        DiffCase(name="s-ok", category="", diff="diff --git CLEAN"),
        DiffCase(name="p-degraded", category="sql-injection", diff="diff --git DEGRADED"),
    ]
    res = diffmod.run_diff_cases(cases, provider=None, model="m")
    assert res.found == ["p-hit"]
    assert res.missed == ["p-miss"]
    assert res.false_positives == ["s-fp"]
    assert res.errors == 1
    assert res.error_details == ["p-degraded: adversarial judge returned unparsable JSON"]


def test_run_diff_cases_describes_degraded_verification_without_batch_failures(monkeypatch):
    """A failed verification must not collapse into an unactionable degraded label."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    monkeypatch.setattr(
        diffmod,
        "run_diff_review",
        lambda *args, **kwargs: _diff_result(
            degraded=True,
            errors=1,
            incomplete=["candidate"],
        ),
    )

    result = diffmod.run_diff_cases(
        [DiffCase(name="verification-failed", category="sql-injection", diff="diff --git change")],
        provider=None,
        model="m",
    )

    assert result.error_details == ["verification-failed: 1 review or verification errors, 1 incomplete findings"]


def test_run_diff_cases_combines_batch_and_verification_failures(monkeypatch):
    """A batch failure must not hide a later verification failure."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    monkeypatch.setattr(
        diffmod,
        "run_diff_review",
        lambda *args, **kwargs: _diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="finder failed")],
            errors=1,
            incomplete=["candidate"],
            failure_reason="verification failed: upstream unavailable",
        ),
    )

    result = diffmod.run_diff_cases(
        [DiffCase(name="multiple-failures", category="sql-injection", diff="diff --git change")],
        provider=None,
        model="m",
    )

    assert result.error_details == [
        "multiple-failures: finder failed, verification failed: upstream unavailable, "
        "1 review or verification errors, 1 incomplete findings"
    ]


def test_run_diff_cases_reports_case_progress(monkeypatch):
    """Diff benchmarks report each case status while the run is active."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        if "BROKEN" in d:
            raise RuntimeError("backend stalled")
        kwargs["on_judgment"](1, 1, "general review", 0.1)
        return _diff_result()

    events = []
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    res = diffmod.run_diff_cases(
        [
            DiffCase(name="ok", category="", diff="diff --git CLEAN"),
            DiffCase(name="bad", category="", diff="diff --git BROKEN"),
        ],
        provider=None,
        model="m",
        progress=events.append,
    )

    assert res.errors == 1
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
        "case_started",
        "case_failed",
    ]
    assert events[0]["case"] == "ok"
    assert events[0]["index"] == 1
    assert events[0]["total"] == 2
    assert events[0]["profile"] == "web"
    assert events[1]["judgment_label"] == "general review"
    assert events[2]["reports"] == 0
    assert events[4]["error"] == "RuntimeError: backend stalled"


def test_run_diff_cases_uses_each_case_review_mode_without_an_override(monkeypatch):
    """A benchmark run honors the minimum mode declared by each case."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    modes = []

    def fake_audit(diff, *, mode, **kwargs):
        modes.append(mode)
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="standard", diff="standard", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial"),
    ]

    diffmod.run_diff_cases(cases, provider=None, model="m")

    assert modes == ["standard", "adversarial"]


def test_run_diff_cases_keeps_standard_role_wiring_stable_in_mixed_cases(tmp_path, monkeypatch):
    """A neighboring adversarial case cannot change a standard case's seats."""
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    base = object()
    finder = object()
    challenger = object()
    judge = object()
    verifier_providers = []
    audit_roles = []

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    class FakeVerifier:
        def __init__(self, *, provider, model, content):
            verifier_providers.append(provider)

    def fake_audit(diff, **kwargs):
        audit_roles.append(
            (
                kwargs["finder_provider"],
                kwargs["challenger_provider"],
                kwargs["judge_provider"],
            )
        )
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", FakeVerifier)
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: object())
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="standard", diff="standard", context="context", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", context="context", review_mode="adversarial"),
    ]

    diffmod.run_diff_cases(
        cases,
        provider=base,
        model="base",
        finder_provider=finder,
        finder_model="finder",
        challenger_provider=challenger,
        challenger_model="challenger",
        judge_provider=judge,
        judge_model="judge",
    )

    assert verifier_providers == [base, challenger]
    assert audit_roles == [(None, None, None), (finder, challenger, judge)]


def test_run_diff_cases_allows_an_explicit_mode_override(monkeypatch):
    """An experiment may force one mode across all selected cases."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    modes = []

    def fake_audit(diff, *, mode, **kwargs):
        modes.append(mode)
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial")

    diffmod.run_diff_cases([case], provider=None, model="m", mode="standard")

    assert modes == ["standard"]


def test_diff_progress_writer_emits_stderr_and_appends_sidecar_events(tmp_path, capsys):
    """Diff progress is visible before the final score JSON exists."""
    from evals.cli import _diff_progress_writer

    out = tmp_path / "result.json"
    sidecar = tmp_path / "result.cases.jsonl"
    sidecar.write_text("stale\n", encoding="utf-8")
    write = _diff_progress_writer(str(out))
    write(
        {
            "event": "case_started",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "run": 1,
            "runs": 1,
        }
    )
    write(
        {
            "event": "case_judgment_finished",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "elapsed_seconds": 0.75,
            "judgment": 1,
            "judgments": 2,
            "judgment_label": "sql-injection",
            "judgment_seconds": 0.7,
            "run": 1,
            "runs": 1,
        }
    )
    write(
        {
            "event": "case_finished",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "elapsed_seconds": 1.25,
            "reports": 1,
            "found": 1,
            "missed": 0,
            "false_positives": 0,
            "extra": 0,
            "run": 1,
            "runs": 1,
        }
    )

    output = capsys.readouterr().err
    assert "knowledge judgment 1/2 [sql-injection] finished" in output
    assert "project:task finished" in output
    events = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
    ]
    assert events[2]["case"] == "project:task"
    assert events[2]["found"] == 1


def test_diff_progress_formatter_fails_loud_on_unknown_events():
    """Unknown progress events are not reported as completed work."""
    from evals.cli import _format_diff_progress

    with pytest.raises(ValueError, match="unknown diff progress event"):
        _format_diff_progress(
            {
                "event": "unexpected",
                "case": "project:task",
                "index": 1,
                "total": 1,
            }
        )


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch):
    from cyberjury.finding import Finding
    from evals.benchmarks.cases import DiffCase
    from evals.benchmarks.contract import AnswerKey, KeyCheck
    from evals.review import diff as diffmod

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

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        finding = Finding(
            file="other.py",
            line=10,
            category="business-logic",
            description="publish_paid is safe here",
        )
        return _diff_result([finding])

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [
            DiffCase(
                name="real-patch",
                category="business-logic",
                diff="diff --git WRONG",
                answer_key=key,
            )
        ],
        provider=None,
        model="m",
    )

    assert res.found == []
    assert res.missed == ["paid-auto-publish"]
    assert res.extra == ["other.py:10:0"]


def test_diff_benchmark_error_keeps_file_recall_denominator(monkeypatch):
    """A failed case still counts file-keyed findings checks in the denominator."""
    from evals.benchmarks.cases import DiffCase
    from evals.benchmarks.contract import AnswerKey, KeyCheck
    from evals.review import diff as diffmod

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

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        raise TimeoutError("provider timed out")

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [
            DiffCase(
                name="real-patch",
                category="business-logic",
                diff="diff --git TIMEOUT",
                answer_key=key,
            )
        ],
        provider=None,
        model="m",
    )

    assert res.errors == 1
    assert res.n_findings == 1
    assert res.n_file_findings == 1
    assert res.file_recall == 0.0


def test_diff_benchmark_with_source_root_verifies_by_default(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verifier"] = verifier
        seen["verification_root"] = verification_root
        seen["verification_confirmers"] = verification_confirmers
        seen["verification_found_by"] = kwargs["verification_found_by"]
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        provider=None,
        model="m",
    )

    assert res.false_positives == []
    assert seen == {
        "verifier": "verifier",
        "verification_root": str(tmp_path),
        "verification_confirmers": [],
        "verification_found_by": ("m",),
    }


def test_diff_benchmark_without_source_root_does_not_verify(monkeypatch):
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    seen = {}

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verifier"] = verifier
        seen["verification_root"] = verification_root
        seen["verification_confirmers"] = verification_confirmers
        seen["verification_found_by"] = kwargs.get("verification_found_by")
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        provider=None,
        model="m",
    )

    assert res.false_positives == []
    assert seen == {
        "verifier": None,
        "verification_root": None,
        "verification_confirmers": None,
        "verification_found_by": (),
    }


def test_diff_benchmark_distinct_judge_model_confirms_refutations(monkeypatch, tmp_path):
    """The benchmark path should mirror CLI independent confirmer wiring."""
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verification_confirmers"] = verification_confirmers
        seen["verification_found_by"] = kwargs["verification_found_by"]
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        provider="finder-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_provider="judge-provider",
        judge_model="judge",
    )

    assert seen["verification_confirmers"] == [("judge", "checker"), ("finder", "checker")]
    assert seen["verification_found_by"] == ()


def test_diff_benchmark_judge_model_inherits_base_provider_for_confirmation(monkeypatch, tmp_path):
    """Role model overrides inherit the base provider in benchmark wiring."""
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_checker(**kwargs):
        seen.setdefault("checkers", []).append(kwargs)
        return "checker"

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verification_confirmers"] = verification_confirmers
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", fake_checker)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        provider="base-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_model="judge",
    )

    assert seen["verification_confirmers"] == [("judge", "checker"), ("finder", "checker")]
    assert seen["checkers"][0] == {"provider": "base-provider", "model": "judge"}


def test_run_diff_cases_routes_each_case_to_its_profile(monkeypatch):
    """A mixed batch must not reuse the first case's knowledge catalog."""
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    seen: dict[str, str] = {}
    contexts: dict[str, str] = {}

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        seen[d] = profile.name
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="w", category="", diff="web-diff", context="web-context"),
        DiffCase(name="s", category="", diff="sol-diff", profile="evm"),
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert seen == {"web-diff": "web", "sol-diff": "evm"}
    assert contexts["web-diff"] == "web-context"


def test_run_diff_cases_collects_target_context(monkeypatch):
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    contexts: dict[str, str] = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = f"context from {path} for {profile.name}"

                return Result()

            def text_for_diff(self, diff):
                return f"context from {path} for {profile.name}"

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(
            name="targeted",
            category="",
            diff="diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n",
            target={"type": "git", "path": "/repo"},
        )
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert contexts[cases[0].diff] == "context from /repo for web"


def test_run_diff_cases_keeps_diff_context_isolated_from_the_repository(tmp_path, monkeypatch):
    """A diff context case cannot consume repository evidence through another path."""
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    def unexpected(*args, **kwargs):
        raise AssertionError("diff context touched repository grounding")

    seen = {}

    def fake_audit(diff, **kwargs):
        seen.update(kwargs)
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "prepare_git_scope", unexpected)
    monkeypatch.setattr(diffmod, "build_diff_context_collector", unexpected)
    monkeypatch.setattr(diffmod, "ModelVerifier", unexpected)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(
        name="diff-only",
        diff="diff --git a/Token.sol b/Token.sol\n+++ b/Token.sol\n+contract Token {}\n",
        context="repository evidence",
        profile="evm",
        review_context="diff",
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert seen["context"] == ""
    assert seen["context_for_diff"] is None
    assert seen["verifier"] is None
    assert seen["verification_root"] is None


def test_run_diff_cases_collects_context_from_git_url_target(tmp_path, monkeypatch):
    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "server.py").write_text("value = 'base'\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "base")
    (repo / "server.py").write_text("value = 'ref'\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "ref")
    ref = _git(repo, "rev-parse", "HEAD")
    contexts: dict[str, str] = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = Path(path, "server.py").read_text(encoding="utf-8").strip()

                return Result()

            def text_for_diff(self, diff):
                return Path(path, "server.py").read_text(encoding="utf-8").strip()

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(
        name="targeted-url",
        category="",
        diff="diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n",
        target={"type": "git", "url": repo.as_uri(), "ref": ref},
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert contexts[case.diff] == "value = 'ref'"


def test_run_diff_cases_prepares_evm_scope_and_collects_scoped_facts(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)
    seen: dict[str, Path] = {}

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
            def collect(self, diff):
                return SimpleNamespace(text="scoped context")

            def text_for_diff(self, diff):
                return "batch context"

        return Collector()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "prepare_git_scope", fake_prepare)
    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", lambda *args, **kwargs: _diff_result())
    case = DiffCase(
        name="evm-targeted",
        diff="diff --git a/contracts/Token.sol b/contracts/Token.sol\n+++ b/contracts/Token.sol\n+contract Token {}\n",
        target={"type": "git", "url": "https://example.com/repo.git", "path": "contracts"},
        profile="evm",
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert seen == {"repository": root, "scope": scope, "facts_root": scope}
