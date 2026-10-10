"""The backtest gate rejects quality regressions and incomplete runs."""

from __future__ import annotations


def test_gate_passes_clean_and_fails_on_regression():
    from evals.backtest.gate import gate

    base = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    good = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    assert gate(good, base, structural=False) == []
    bad = {"target": "t", "found": ["a"], "false_positives": ["safe-x"], "precision_known": 0.5, "errors": 0}
    fails = gate(bad, base, precision_floor=0.8, structural=False)
    assert any("newly missed" in f for f in fails)
    assert any("false positive" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    from evals.backtest.gate import gate

    assert gate({"target": "t", "errors": 2}, structural=False)
    assert (
        gate({"target": "t", "found": ["a"], "false_positives": [], "errors": 0, "extra": ["x", "y"]}, structural=False)
        == []
    )


def test_gate_rejects_a_baseline_from_another_target():
    from evals.backtest.gate import gate

    fails = gate(
        {"target": "after", "n_findings": 2, "found": ["same"]},
        {"target": "before", "n_findings": 1, "found": ["same"]},
        structural=False,
    )

    assert any("different targets" in message for message in fails)
    assert any("different findings denominators" in message for message in fails)


def test_gate_preserves_benchmark_contract_error(monkeypatch):
    from evals.backtest.gate import gate
    from evals.benchmarks import coverage

    def fail_validation() -> None:
        raise ValueError("knowledge.vulnerabilities has unknown id")

    monkeypatch.setattr(coverage, "coverage_problems", fail_validation)
    assert gate({"target": "t"}, structural=True) == [
        "benchmark contract validation failed: knowledge.vulnerabilities has unknown id"
    ]


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

    assert gate(after, structural=False, adjudication=adjudication, require_introductions=True) == []
    assert any(
        "unique report precision" in message
        for message in gate(after, structural=False, adjudication=adjudication, precision_floor=0.8)
    )
    disputed = dict(adjudication, pending=["candidate-" + "a" * 20])
    disputed_fails = gate(after, structural=False, adjudication=disputed)
    assert any("still needing source assessment" in message for message in disputed_fails)
    pending_precision = dict(disputed, report_precision=None)
    assert any(
        "precision is unknown" in message
        for message in gate(after, structural=False, adjudication=pending_precision, precision_floor=0.8)
    )
    wrong_match = dict(adjudication, mismatched_assignments=[{"check_id": "known"}])
    assert gate(after, structural=False, adjudication=wrong_match) == []
    raw_disagrees = dict(after, found=[])
    assert gate(raw_disagrees, structural=False, adjudication=adjudication) == []
    missing_intro = dict(adjudication, missing_introductions=["known"])
    assert any(
        "lack introduction diffs" in message
        for message in gate(after, structural=False, adjudication=missing_intro, require_introductions=True)
    )
    unpaired = dict(adjudication, new_supported=["candidate-" + "b" * 20])
    assert any(
        "new supported issues without paired introduction" in message
        for message in gate(after, structural=False, adjudication=unpaired, require_introductions=True)
    )
    inconsistent = dict(adjudication, machine_status_mismatch=True)
    assert any(
        "machine confirmed labels disagree" in message
        for message in gate(after, structural=False, adjudication=inconsistent)
    )


def test_adjudication_gate_rejects_a_score_from_another_result():
    from evals.backtest.gate import gate

    after = {"target": "t", "found": ["known"], "n_reports": 2}
    adjudication = {
        "target": "other",
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

    fails = gate(after, structural=False, adjudication=adjudication)

    assert any("target does not match" in message for message in fails)
    assert any("count does not match" in message for message in fails)


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

    mixed = gate(after, before, structural=False, adjudication=assessment)
    assert any("both comparison arms require source assessments" in message for message in mixed)

    changed = dict(assessment, known_found=[])
    fails = gate(after, before, structural=False, adjudication=changed, baseline_adjudication=assessment)
    assert any("newly missed" in message for message in fails)
