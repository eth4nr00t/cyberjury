"""Repository recovery keeps failed or corrupt work open across resume."""

import json

import pytest

from cyberjury.review.repository.gate import check_gate
from cyberjury.review.repository.reviewer import UnitReviewer
from cyberjury.review.repository.scaffold import unit_slug
from cyberjury.review.repository.union import Candidate
from cyberjury.review.verification import Verdict, Verifier
from tests.cyberjury.review.repository.engine.factories import (
    _CountingReviewer,
    _CountingVerifier,
    _EmptyChallenger,
    _PassingJudge,
)
from tests.cyberjury.review.repository.engine.factories import finalize_review as _finalize_review
from tests.cyberjury.review.repository.engine.factories import finalize_workspace as _finalize_ws
from tests.cyberjury.review.repository.engine.factories import run_review as _run_review


class _RaisingReviewer(UnitReviewer):
    """Raises for marked units and reviews the rest cleanly."""

    def __init__(self, fail_substr):
        self.fail_substr = fail_substr

    def review(self, unit, *, shared_context=""):
        if self.fail_substr in unit.name:
            raise RuntimeError("provider rate limited")
        return [
            Candidate(
                title="ok", category="idor", endpoint=f"GET /{unit.name}", file=unit.name, line=1, severity="HIGH"
            )
        ]


class _RecoveringUnitReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0
        self.failed = False

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        if unit.name == "beta/routes.py" and not self.failed:
            self.failed = True
            raise RuntimeError("temporary rate limit")
        return [
            Candidate(
                title=unit.name,
                category="idor",
                endpoint=f"GET /{unit.name}",
                file=unit.name,
                line=1,
                severity="HIGH",
            )
        ]


def _two_entrypoint_repository(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n'
        )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_failed_unit_stays_open_and_fails_the_gate(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"
    res = _run_review(
        repository, ws, reviewer=_RaisingReviewer("beta/routes.py"), verify=False, converge_after=1, max_passes=4
    )
    proj = ws / "twop"

    assert "beta/routes.py" in res.accumulator.failed_units
    assert res.accumulator.errors > 0

    units = {u.stem: u.read_text() for u in (proj / "units").glob("*.md")}
    assert "Status: open" in units[unit_slug("beta/routes.py")]
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]

    surface = (proj / "inventory" / "_surface.md").read_text()
    beta_row = next(line for line in surface.splitlines() if "beta/routes.py" in line)
    assert "open" in beta_row
    assert "reviewed" not in beta_row

    status = json.loads((proj / "_run.json").read_text())
    assert status["complete"] is False
    assert status["state"] == "incomplete"
    assert status["unit_failures"][0]["paths"] == ["beta/routes.py"]
    assert status["unit_failures"][0]["reason"] == "RuntimeError: provider rate limited"

    assert check_gate(proj).passed is False


def test_nonconverged_adversarial_run_keeps_successful_siblings_open(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    result = _run_review(
        repository,
        tmp_path / "ws",
        mode="adversarial",
        reviewer=_RaisingReviewer("beta/routes.py"),
        challenger_reviewer=_EmptyChallenger(),
        judge_reviewer=_PassingJudge(),
        verify=False,
        converge_after=1,
        min_rounds=1,
        max_passes=1,
        concurrency=1,
    )

    assert result.outcome.complete is False
    assert result.accumulator.converged is False
    assert result.accumulator.failed_units == {"beta/routes.py"}
    units = list((result.scaffold.workspace / "units").glob("*.md"))
    assert units
    assert all("Status: open" in unit.read_text() for unit in units)
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["units_reviewed"] == 0


def test_recovered_failure_stays_open_until_a_clean_resume(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    workspace = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 1,
        "min_rounds": 1,
        "max_passes": 3,
        "concurrency": 1,
    }

    first_reviewer = _RecoveringUnitReviewer()
    first = _run_review(repository, workspace, reviewer=first_reviewer, **shared)
    project = first.scaffold.workspace

    assert first.accumulator.converged is True
    assert first.outcome.complete is False
    assert first.accumulator.failed_units == {"beta/routes.py"}
    units = {unit.stem: unit.read_text() for unit in (project / "units").glob("*.md")}
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]
    assert "Status: open" in units[unit_slug("beta/routes.py")]

    second_reviewer = _CountingReviewer()
    second = _run_review(repository, workspace, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls > 0
    assert second.outcome.complete is True
    assert all("Status: reviewed" in unit.read_text() for unit in (project / "units").glob("*.md"))


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    _run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        _run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_finalize_raises_loud(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (ws / "proj" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    class _V(Verifier):
        def verify(self, c, root):
            return Verdict(real=True)

    with pytest.raises(ValueError, match="corrupt"):
        _finalize_review(target, ws, verifier=_V(), concurrency=1)


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {"candidate": {"real": 0, "reason": "corrupt"}},
        {"candidate": {"real": False, "reason": 1}},
        {"candidate": {"real": False}},
    ],
)
def test_structurally_corrupt_verified_checkpoint_raises_loud(tmp_path, checkpoint):
    from cyberjury.review.repository.verify import apply_verification

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    (ws / "_verified.json").write_text(json.dumps(checkpoint))
    findings = [Candidate(title="x", endpoint="GET /x", file="a.py", line=1)]

    with pytest.raises(ValueError, match="corrupt"):
        apply_verification(
            ws,
            findings,
            root=str(tmp_path),
            verifier=_CountingVerifier(),
            provider=None,
            model="m",
            votes=1,
            concurrency=1,
            fresh=False,
        )


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {},
        {"findings": {}},
        {"findings": ["bad"]},
        {"findings": [{}]},
        {"findings": [{"title": 1}]},
        {"findings": [{"title": "x", "severity": "URGENT"}]},
        {"findings": [{"title": "x", "status": "maybe"}]},
        {"findings": [{"line": True}]},
        {"findings": [{"found_by": [1]}]},
    ],
)
def test_structurally_corrupt_union_checkpoint_raises_loud(tmp_path, checkpoint):
    from cyberjury.review.repository.engine import _load_union

    (tmp_path / "_union.json").write_text(json.dumps(checkpoint))

    with pytest.raises(ValueError, match="corrupt"):
        _load_union(tmp_path)


def test_failed_verification_is_kept_for_the_run_but_not_frozen_for_resume(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

    class _Boom(Verifier):
        def verify(self, c, root):
            raise RuntimeError("rate limited")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = [Candidate(title="boom", endpoint="GET /a", file="a.py", line=1)]
    confirmed, vr = apply_verification(
        ws, findings, root=str(tmp_path), verifier=_Boom(), provider=None, model="m", votes=1, concurrency=1, fresh=True
    )
    assert [c.title for c in confirmed] == ["boom"]
    assert vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {}
    assert [c.title for c in vr.incomplete] == ["boom"]
    assert vr.error_details == ["RuntimeError: rate limited"]


def test_repository_outcome_and_status_preserve_verification_failure_reason(custody_repository, tmp_path):

    class _Boom(Verifier):
        def verify(self, candidate, root):
            raise RuntimeError("rate limited")

    result = _run_review(
        custody_repository,
        tmp_path / "ws",
        reviewer=_CountingReviewer(),
        verifier=_Boom(),
        converge_after=1,
        max_passes=1,
        concurrency=1,
    )

    assert result.outcome is not None
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["failure_reason"] == "verification failed: RuntimeError: rate limited"
