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


def test_gate_preserves_benchmark_contract_error(monkeypatch):
    from evals.backtest.gate import gate
    from evals.benchmarks import coverage

    def fail_validation() -> None:
        raise ValueError("knowledge.vulnerabilities has unknown id")

    monkeypatch.setattr(coverage, "coverage_problems", fail_validation)
    assert gate({"target": "t"}, structural=True) == [
        "benchmark contract validation failed: knowledge.vulnerabilities has unknown id"
    ]
