"""Repository resume skips completed work only when target identity is unchanged."""

import json

import pytest

from tests.cyberjury.review.repository.engine.factories import (
    _CountingReviewer,
    _CountingVerifier,
    _EmptyChallenger,
    _PassingJudge,
)
from tests.cyberjury.review.repository.engine.factories import run_review as _run_review


def test_resume_skips_reviewed_units_and_verified_findings(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    r1v = _CountingVerifier()
    _run_review(custody_repository, ws, reviewer=_CountingReviewer(), verifier=r1v, converge_after=1, max_passes=4)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1
    assert r1v.calls >= 1

    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    _run_review(custody_repository, ws, reviewer=r2, verifier=r2v, converge_after=1, max_passes=4, fresh=False)
    assert r2.calls == 0
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entry"] for f in findings_after_2} == {f["entry"] for f in findings_after_1}


def test_completed_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    _run_review(
        custody_repository,
        workspace,
        reviewer=_CountingReviewer(),
        verify=False,
        max_passes=1,
    )
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _CountingReviewer()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        _run_review(
            custody_repository,
            workspace,
            reviewer=resumed,
            verify=False,
            max_passes=1,
        )

    assert resumed.calls == 0


def test_nonconverged_adversarial_resume_replays_open_units_and_can_complete(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 1,
        "min_rounds": 1,
        "max_passes": 1,
        "concurrency": 1,
    }
    first_reviewer = _CountingReviewer()

    first = _run_review(custody_repository, ws, reviewer=first_reviewer, **shared)
    project = first.scaffold.workspace

    assert first.outcome.complete is False
    assert first.accumulator.converged is False
    first_finding_keys = {candidate.key() for candidate in first.accumulator.findings}
    assert first_finding_keys
    assert first_reviewer.calls > 0
    assert all("Status: open" in unit.read_text() for unit in (project / "units").glob("*.md"))
    first_status = json.loads((project / "_run.json").read_text())
    assert first_status["state"] == "incomplete"
    assert first_status["units_reviewed"] == 0

    second_reviewer = _CountingReviewer()
    second = _run_review(custody_repository, ws, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls > 0
    assert second.outcome.complete is True
    assert second.accumulator.converged is True
    assert {candidate.key() for candidate in second.accumulator.findings} == first_finding_keys
    assert all("Status: reviewed" in unit.read_text() for unit in (project / "units").glob("*.md"))
    second_status = json.loads((project / "_run.json").read_text())
    assert second_status["state"] == "converged"
    assert second_status["units_reviewed"] == second_status["units_total"]


def test_partial_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 2,
        "min_rounds": 1,
        "max_passes": 1,
        "concurrency": 1,
    }
    first = _run_review(custody_repository, workspace, reviewer=_CountingReviewer(), **shared)
    assert first.outcome.complete is False
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _CountingReviewer()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        _run_review(custody_repository, workspace, reviewer=resumed, **shared)

    assert resumed.calls == 0


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    _run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match=r"no _union\.json"):
        _run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )
