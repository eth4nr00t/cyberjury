"""Evaluation CLI exit status respects whole-case certification."""

from evals.cli import _emit
from evals.score.result import CaseGateResult, CaseRunResult, RepeatedResult, Result


def test_emit_fails_when_whole_case_gate_fails_despite_aggregate_recall(capsys):
    runs = [
        Result(target="diff", found=["a"], missed=["b"], n_findings=2),
        Result(target="diff", found=["b"], missed=["a"], n_findings=2),
        Result(target="diff", found=["a", "b"], n_findings=2),
    ]
    result = RepeatedResult.from_runs("diff", runs)
    result.case_gate = CaseGateResult(
        expected_cases=("project:case",),
        runs=3,
        required_passes=2,
        case_runs=(
            CaseRunResult(case="project:case", run=1, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=2, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=3, complete=True, found=2),
        ),
    )

    assert result.recall == 1.0
    assert _emit(result, None) == 1
    assert "CASE GATE FAILED" in capsys.readouterr().out
