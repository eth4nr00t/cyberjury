"""Diff evaluation runs each pinned case through the product review command and records its artifacts."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cyberjury import cli as climod
from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.mock import MockProvider
from evals import diff
from evals.benchmarks.cases import find_case
from evals.benchmarks.contract import ChangeAnchor


def _finder_reply(findings: list[dict]) -> str:
    return json.dumps({"findings": findings, "evidence_requests": [], "source_queries": []})


@pytest.fixture
def scripted_model(monkeypatch):
    """Serve every product seat from one scripted provider, with no environment file or real key."""
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(climod, "load_env_file", lambda: [])
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def install(findings=(), *, error: BaseException | None = None) -> MockProvider:
        def respond(system, _messages):
            if error is not None:
                raise error
            if "skeptical security reviewer" in system:
                return json.dumps(
                    {"real": True, "reason": "no shown fact refutes it", "control_file": "", "control_line": 0}
                )
            return _finder_reply([dict(item) for item in findings])

        provider = MockProvider(responder=respond)
        monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: provider)
        return provider

    return install


@pytest.fixture
def owner_finding():
    """One complete Finder finding on the benchmark diff's changed line."""
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


@pytest.fixture
def case(benchmark_project):
    return find_case(benchmark_project.diff_case, [benchmark_project.benchmark])


def test_run_reviews_the_pinned_range_through_the_product_command(tmp_path, case, scripted_model, owner_finding):
    provider = scripted_model([owner_finding.reply])
    events = []

    (record,) = diff.run(
        [case],
        workspace=tmp_path / "reviews",
        model_override="override",
        concurrency=3,
        progress=events.append,
    )

    assert (record["case"], record["attempt"], record["complete"], record["error"]) == (case.name, 1, True, "")
    [finding] = record["findings"]
    assert finding["candidate_id"] == finding["id"]
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
    finder_prompt = provider.calls[0]["messages"][0].content
    assert finder_prompt.startswith("Code under review, cited as `seed` (numbered unified diff):")
    assert "+    return save(owner=None)" in finder_prompt
    [attempt] = (tmp_path / "reviews").glob("demo/*/run-01/reviews/*/attempts/*")
    assert json.loads((attempt / "request.json").read_text())["concurrency"]["review"] == 3
    assert json.loads((attempt / "model-calls.json").read_text())["usage"]["model_requests"] == len(provider.calls)
    assert events[0] == f"[1/1] {case.name} started"
    assert events[-1].startswith(f"[1/1] {case.name} finished in ")
    assert events[-1].endswith("s, reports=1")


def test_run_records_a_failed_review_with_its_reason(tmp_path, case, scripted_model):
    scripted_model(error=RuntimeError("backend stalled"))
    events = []

    failed, again = diff.run([case], workspace=tmp_path / "reviews", runs=2, progress=events.append)

    assert (failed["attempt"], failed["complete"], again["attempt"]) == (1, False, 2)
    assert "backend stalled" in failed["error"]
    assert failed["findings"] == []
    assert events[1].startswith(f"run 1/2 [1/1] {case.name} failed after ")


def test_run_rejects_a_change_anchor_absent_from_the_reviewed_patch(tmp_path, case, scripted_model):
    provider = scripted_model()
    check = replace(case.checks[0], change_anchors=(ChangeAnchor(file="views.py", line=9, side="new"),))

    with pytest.raises(ValueError, match=r"change anchor .* is absent from the reviewed patch"):
        diff.run([replace(case, checks=(check,))], workspace=tmp_path / "reviews")
    assert provider.calls == []


def test_run_never_reuses_a_review_workspace(tmp_path, case, scripted_model):
    scripted_model()
    diff.case_workspace(tmp_path / "reviews", case, 1).mkdir(parents=True)

    with pytest.raises(ValueError, match="workspace already exists"):
        diff.run([case], workspace=tmp_path / "reviews")


def test_run_aborts_on_missing_provider_credentials(tmp_path, case, scripted_model, monkeypatch):
    scripted_model()
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    records = []

    with pytest.raises(SystemExit):
        diff.run([case], workspace=tmp_path / "reviews", on_attempt=records.append)
    assert records == []


def test_run_rejects_nonpositive_runs(tmp_path, case):
    with pytest.raises(ValueError, match="runs must be at least 1"):
        diff.run([case], workspace=tmp_path / "reviews", runs=0)
