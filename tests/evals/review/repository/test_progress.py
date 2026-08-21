"""Repository benchmark progress preserves caller callbacks and case identity."""

from dataclasses import replace

from cyberjury.review.repository.engine import RepositoryRunOptions
from evals.benchmarks.contract import RepositoryCase
from evals.review.repository.progress import CaseProgress


def test_progress_wraps_product_callbacks(tmp_path):
    events = []
    callbacks = []
    case = RepositoryCase(
        id="demo",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        profile="web",
    )
    options = RepositoryRunOptions()
    options = replace(
        options,
        verification=replace(options.verification, on_verify=lambda *args: callbacks.append(("verify", args))),
        execution=replace(
            options.execution,
            on_pass=lambda *args: callbacks.append(("pass", args)),
            on_judgment=lambda *args: callbacks.append(("judgment", args)),
        ),
    )
    progress = CaseProgress.start(events.append, case, "standard", "model")

    bound = progress.bind(options)
    bound.execution.on_pass(1, "finder", 2, 3)
    bound.execution.on_judgment("app.py", 1, 1, "finder", 0.5)
    bound.verification.on_verify(1, 1, 0.25)

    assert [name for name, _args in callbacks] == ["pass", "judgment", "verify"]
    assert [event["event"] for event in events] == [
        "case_started",
        "case_pass_finished",
        "case_judgment_finished",
        "case_verification_finished",
    ]
    assert all(event["case"] == "demo" for event in events)
