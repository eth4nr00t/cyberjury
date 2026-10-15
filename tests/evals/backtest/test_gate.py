"""The backtest gate rejects quality regressions and incomplete runs."""

from __future__ import annotations


def _assessment(**overrides):
    value = {
        "target": "t",
        "counts": {"supported": 1},
        "pending": [],
        "known_found": ["a"],
        "new_supported": [],
        "mismatched_assignments": [],
        "missing_introductions": [],
        "introduction_not_ancestor": [],
        "report_precision": 1.0,
        "machine_status_mismatch": False,
    }
    return value | overrides


def test_gate_ignores_raw_matches_and_fails_on_reviewed_regression():
    from evals.backtest.gate import gate

    base = {"target": "t", "found": ["a"], "n_reports": 1, "errors": 0}
    raw_regression = {"target": "t", "found": [], "false_positives": ["safe-x"], "n_reports": 1, "errors": 0}
    assert gate(raw_regression, base, adjudication=_assessment(), baseline_adjudication=_assessment()) == []
    fails = gate(
        base,
        base,
        precision_floor=0.8,
        adjudication=_assessment(known_found=[], report_precision=0.5),
        baseline_adjudication=_assessment(),
    )
    assert any("newly missed" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    from evals.backtest.gate import gate

    assert gate({"target": "t", "errors": 2, "n_reports": 1}, adjudication=_assessment())
    after = {"target": "t", "found": ["a"], "errors": 0, "extra": ["x", "y"], "n_reports": 1}
    assert gate(after, adjudication=_assessment()) == []


def test_gate_rejects_a_baseline_from_another_target():
    from evals.backtest.gate import gate

    fails = gate(
        {"target": "after", "n_findings": 2, "found": ["same"], "n_reports": 1},
        {"target": "before", "n_findings": 1, "found": ["same"], "n_reports": 1},
        adjudication=_assessment(),
        baseline_adjudication=_assessment(),
    )

    assert any("different targets" in message for message in fails)
    assert any("different findings denominators" in message for message in fails)


def test_adjudication_gate_requires_closed_reports_and_uses_source_assignment():
    from evals.backtest.gate import gate

    after = {"target": "t", "found": ["known"], "n_reports": 2, "errors": 0}
    adjudication = {
        "target": "t",
        "counts": {"supported": 1, "not_actionable": 1},
        "pending": [],
        "known_found": ["known"],
        "new_supported": [],
        "mismatched_assignments": [],
        "missing_introductions": [],
        "introduction_not_ancestor": [],
        "report_precision": 0.5,
        "machine_status_mismatch": False,
    }

    assert gate(after, adjudication=adjudication, require_introductions=True) == []
    assert any(
        "unique report precision" in message for message in gate(after, adjudication=adjudication, precision_floor=0.8)
    )
    disputed = dict(adjudication, pending=["candidate-" + "a" * 20])
    disputed_fails = gate(after, adjudication=disputed)
    assert any("still needing source assessment" in message for message in disputed_fails)
    pending_precision = dict(disputed, report_precision=None)
    assert any(
        "precision is unknown" in message
        for message in gate(after, adjudication=pending_precision, precision_floor=0.8)
    )
    wrong_match = dict(adjudication, mismatched_assignments=[{"check_id": "known"}])
    assert gate(after, adjudication=wrong_match) == []
    raw_disagrees = dict(after, found=[])
    assert gate(raw_disagrees, adjudication=adjudication) == []
    missing_intro = dict(adjudication, missing_introductions=["known"])
    assert any(
        "lack introduction diffs" in message
        for message in gate(after, adjudication=missing_intro, require_introductions=True)
    )
    unpaired = dict(adjudication, new_supported=["candidate-" + "b" * 20])
    assert any(
        "new supported issues without paired introduction" in message
        for message in gate(after, adjudication=unpaired, require_introductions=True)
    )
    inconsistent = dict(adjudication, machine_status_mismatch=True)
    assert any("machine confirmed labels disagree" in message for message in gate(after, adjudication=inconsistent))


def test_adjudication_gate_rejects_a_score_from_another_result():
    from evals.backtest.gate import gate

    after = {"target": "t", "found": ["known"], "n_reports": 2}
    adjudication = {
        "counts": {"supported": 1},
        "pending": [],
        "known_found": [],
        "new_supported": [],
        "mismatched_assignments": [],
        "missing_introductions": [],
        "introduction_not_ancestor": [],
        "report_precision": 0.5,
        "machine_status_mismatch": False,
    }

    assert any("count does not match" in message for message in gate(after, adjudication=adjudication))


def test_two_arm_gate_requires_source_assessments_for_both_arms():
    from evals.backtest.gate import gate

    before = {"target": "t", "found": [], "n_reports": 1}
    after = {"target": "t", "found": ["known"], "n_reports": 1}
    assessment = {
        "target": "t",
        "counts": {"supported": 1},
        "pending": [],
        "known_found": ["known"],
        "new_supported": [],
        "missing_introductions": [],
        "introduction_not_ancestor": [],
        "report_precision": 1.0,
        "machine_status_mismatch": False,
    }

    mixed = gate(after, before, adjudication=assessment)
    assert any("both comparison arms require source assessments" in message for message in mixed)

    changed = dict(assessment, known_found=[])
    fails = gate(after, before, adjudication=changed, baseline_adjudication=assessment)
    assert any("newly missed" in message for message in fails)


_FIRST = frozenset({"first"})


def _attempt(number, *, reviewed=("first",), raw=(), checks=("first",), pending=(), case="project:diff-1"):
    from evals.adjudication import DiffAdjudicationResult

    supported = len(reviewed)
    return DiffAdjudicationResult(
        case=case,
        attempt=number,
        source_commit="a" * 40,
        attempt_sha256=f"{case}-{number}",
        ledger_sha256="b" * 64,
        raw_found=tuple(raw),
        raw_missed=tuple(check for check in checks if check not in raw),
        reviewed_found=tuple(reviewed),
        reviewed_missed=tuple(check for check in checks if check not in reviewed),
        pending=tuple(pending),
        report_counts={"duplicate": 0, "needs_review": len(pending), "not_actionable": 1, "supported": supported},
    )


def test_reviewed_gate_uses_reviewed_majority_and_ignores_raw_misses():
    from evals.backtest.gate import reviewed_gate

    baseline = {"project:diff-1": (_attempt(1), _attempt(2), _attempt(3, reviewed=()))}
    same = {"project:diff-1": (_attempt(1), _attempt(2, reviewed=()), _attempt(3))}
    assert reviewed_gate(same, baseline) == []

    dropped = {"project:diff-1": (_attempt(1), _attempt(2, reviewed=()), _attempt(3, reviewed=()))}
    assert any("newly missed" in message for message in reviewed_gate(dropped, baseline))

    lost = {"project:diff-1": tuple(_attempt(number, reviewed=()) for number in (1, 2, 3))}
    minority = {"project:diff-1": (_attempt(1), _attempt(2, reviewed=()), _attempt(3, reviewed=()))}
    fails = reviewed_gate(lost, minority)
    assert any("lost every reviewed detection: first" in message for message in fails)
    assert not any("newly missed" in message for message in fails)


def test_reviewed_gate_requires_comparable_arms_and_closed_reports():
    from evals.backtest.gate import reviewed_gate

    baseline = {"project:diff-1": (_attempt(1), _attempt(2))}
    longer = {"project:diff-1": (_attempt(1), _attempt(2), _attempt(3))}
    assert any("different run counts" in message for message in reviewed_gate(longer, baseline))
    other = {"project:diff-2": (_attempt(1, case="project:diff-2"), _attempt(2, case="project:diff-2"))}
    assert any("different cases" in message for message in reviewed_gate(other, baseline))
    pending = {"project:diff-1": (_attempt(1, pending=("candidate-1",)), _attempt(2))}
    assert any("still needing source assessment" in message for message in reviewed_gate(pending))
    assert any("precision is unknown" in message for message in reviewed_gate(pending, precision_floor=0.5))
    assert any("below the floor" in message for message in reviewed_gate(baseline, precision_floor=0.8))


def test_certify_counts_reviewed_whole_case_passes_beside_raw_passes():
    from evals.backtest.gate import certify

    reviewed = {"project:diff-1": (_attempt(1), _attempt(2, raw=("first",)), _attempt(3, reviewed=()))}
    receipt = certify(reviewed, {"project:diff-1": _FIRST})

    assert receipt["passed"] is True
    assert receipt["cases"][0]["passes"] == [1, 2]
    assert receipt["cases"][0]["raw_passes"] == [2]
    assert receipt["raw_passed_cases"] == 0


def test_certify_fails_missing_short_pending_and_unexpected_cases():
    from evals.backtest.gate import certify

    short = {"project:diff-1": (_attempt(1), _attempt(2))}
    assert certify(short, {"project:diff-1": _FIRST})["failed_cases"] == ["project:diff-1"]
    pending = {"project:diff-1": (_attempt(1), _attempt(2), _attempt(3, pending=("candidate-1",)))}
    assert certify(pending, {"project:diff-1": _FIRST})["passed"] is False
    complete = {"project:diff-1": (_attempt(1), _attempt(2), _attempt(3))}
    receipt = certify(complete, {"project:diff-1": _FIRST, "project:diff-2": _FIRST})
    assert receipt["failed_cases"] == ["project:diff-2"]
    extra = certify(complete | {"project:diff-3": (_attempt(1, case="project:diff-3"),)}, {"project:diff-1": _FIRST})
    assert extra["passed"] is False
    assert extra["unexpected_cases"] == ["project:diff-3"]


def test_certify_rejects_attempts_scored_against_another_answer_key():
    import pytest

    from evals.backtest.gate import certify

    complete = {"project:diff-1": (_attempt(1), _attempt(2), _attempt(3))}
    with pytest.raises(ValueError, match="another answer key"):
        certify(complete, {"project:diff-1": frozenset({"first", "second"})})
