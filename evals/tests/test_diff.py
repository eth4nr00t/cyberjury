"""Diff evaluation runs each pinned case through the product review command and records its artifacts."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.record import Record
from cyberjury.review import command as commandmod
from evals import diff
from evals.benchmarks.contract import ChangeAnchor
from tests.support import MockProvider


def _finder_reply(findings: list[dict]) -> str:
    return json.dumps({"findings": findings, "evidence_requests": [], "source_queries": []})


def _run(cases, state_dir, **values):
    options = {"runs": 1, "concurrency": 8, "progress": lambda _line: None, "on_attempt": lambda _record: None}
    return diff.run(cases, state_dir=state_dir, **(options | values))


@pytest.fixture
def scripted_model(monkeypatch):
    """Serve every product seat from one scripted provider, with no environment file or real key."""
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(commandmod, "load_env_file", lambda: [])
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def install(findings=(), *, error: BaseException | None = None) -> MockProvider:
        def respond(system, _prompt):
            if error is not None:
                raise error
            return _finder_reply([dict(item) for item in findings])

        provider = MockProvider(responder=respond)
        monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: provider)
        return provider

    return install


@pytest.fixture
def owner_finding():
    """Return one complete Finder finding on the benchmark diff's changed line."""
    return SimpleNamespace(
        reply={
            "title": "Create saves without an owner",
            "category": "missing-authorization",
            "severity": "HIGH",
            "entrypoint": "POST /create",
            "file": "views.py",
            "line": 2,
            "change_anchor": {"file": "views.py", "line": 2, "side": "new"},
            "evidence": "views.py:2 saves with owner=None",
            "attack_path": "anyone creates an unowned record",
            "evidence_refs": ["seed"],
        }
    )


def test_run_reviews_the_pinned_range_through_the_product_command(
    monkeypatch, tmp_path, case, scripted_model, owner_finding
):
    """A scripted finding is recorded with its anchor, the CYBERJURY_MODEL override, and attempt artifacts."""
    provider = scripted_model([owner_finding.reply])
    monkeypatch.setenv("CYBERJURY_MODEL", "override")

    (record,) = _run([case], tmp_path / "reviews")

    assert (record["case"], record["attempt"], record["complete"], record["error"]) == (case.name, 1, True, "")
    [finding] = record["findings"]
    assert {key: finding[key] for key in ("title", "entrypoint", "file", "line", "evidence", "attack_path")} == {
        "title": "Create saves without an owner",
        "entrypoint": "POST /create",
        "file": "views.py",
        "line": 2,
        "evidence": "views.py:2 saves with owner=None",
        "attack_path": "anyone creates an unowned record",
    }
    assert finding["change_anchor"] == {"file": "views.py", "line": 2, "side": "new"}
    assert {call["model"] for call in provider.calls} == {"override"}
    assert "+    return save(owner=None)" in provider.calls[0]["prompt"]
    [attempt] = (tmp_path / "reviews").glob("demo/*/run-01/reviews/*/attempts/*")
    assert json.loads((attempt / "model-calls.json").read_text())["usage"]["model_requests"] == len(provider.calls)


def test_run_forwards_its_concurrency_to_the_review(tmp_path, case, scripted_model):
    """Running with concurrency=3 records a review request with review concurrency 3."""
    scripted_model()

    _run([case], tmp_path / "reviews", concurrency=3)

    [attempt] = (tmp_path / "reviews").glob("demo/*/run-01/reviews/*/attempts/*")
    assert json.loads((attempt / "request.json").read_text())["concurrency"]["review"] == 3


def test_run_reports_each_case_start_and_finish(tmp_path, case, scripted_model, owner_finding):
    """One case with one scripted finding emits a started event and a finished event with reports 1."""
    scripted_model([owner_finding.reply])
    events = []

    _run([case], tmp_path / "reviews", progress=events.append)

    assert events[0] == f"[1/1] {case.name} started"
    assert events[-1].startswith(f"[1/1] {case.name} finished in ")
    assert events[-1].endswith("s, reports 1")


def test_run_records_a_failed_review_with_its_reason(tmp_path, case, scripted_model):
    """With runs=2 and a provider raising backend stalled, attempt 1 records the error and no findings."""
    scripted_model(error=RuntimeError("backend stalled"))
    events = []

    failed, again = _run([case], tmp_path / "reviews", runs=2, progress=events.append)

    assert (failed["attempt"], failed["complete"], again["attempt"]) == (1, False, 2)
    assert "backend stalled" in failed["error"]
    assert failed["findings"] == []
    assert events[1].startswith(f"run 1/2 [1/1] {case.name} failed after ")


def test_run_validates_change_anchors_before_any_model_call(tmp_path, case, scripted_model):
    """A check anchoring views.py:9, outside the patch, raises ValueError before any model call."""
    provider = scripted_model()
    check = replace(case.checks[0], change_anchors=(ChangeAnchor(file="views.py", line=9, side="new"),))

    with pytest.raises(ValueError, match="change anchor"):
        _run([replace(case, checks=(check,))], tmp_path / "reviews")
    assert provider.calls == []


def test_run_aborts_on_missing_provider_credentials(tmp_path, case, scripted_model, monkeypatch):
    """Removing ANTHROPIC_API_KEY makes the run exit via SystemExit without recording an attempt."""
    scripted_model()
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    records = []

    with pytest.raises(SystemExit):
        _run([case], tmp_path / "reviews", on_attempt=records.append)
    assert records == []


def test_an_interrupted_review_stops_the_run(tmp_path, case, scripted_model, monkeypatch):
    """An interrupted review raises KeyboardInterrupt instead of recording the case and moving on."""
    scripted_model()
    interrupted = Record(
        id="attempt-20260101-000000-11111111",
        status="interrupted",
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=1.0,
        attributes={"reason": "operator interrupted the command"},
    )
    monkeypatch.setattr(diff, "run_review_command", lambda _command, **_streams: interrupted)
    records = []

    with pytest.raises(KeyboardInterrupt):
        _run([case], tmp_path / "reviews", on_attempt=records.append)
    assert records == []
