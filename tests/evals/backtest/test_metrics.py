"""Backtest metrics aggregate complete workspace cost and timing records."""

from __future__ import annotations

import json


def _arm(
    workspace,
    *,
    errors=0,
    verify_errors=0,
    incomplete=0,
    unlocatable=0,
    complete=True,
    requests=100,
    seconds=60.0,
):
    leaf = workspace / "leaf"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": errors,
                "verify_errors": verify_errors,
                "incomplete": incomplete,
                "unlocatable": unlocatable,
                "complete": complete,
                "timing": {"total_seconds": seconds},
                "usage": {
                    "model_requests": requests,
                    "total_input_tokens": requests * 100,
                    "output_tokens": requests * 10,
                    "unit_review_calls": 20,
                },
            }
        ),
        encoding="utf-8",
    )
    return workspace


def test_with_arms_folds_in_each_arm_cost_and_marks_a_clean_pair_comparable(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", requests=700))
    assert d["comparable"] is True
    assert d["before_cost"]["model_requests"] == 100
    assert d["after_cost"]["model_requests"] == 700
    assert d["before_cost"]["seconds"] == 60.0


def test_a_failed_review_in_either_arm_disqualifies_the_comparison(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", errors=2))
    assert d["comparable"] is False
    assert any("after arm records 2 errors" in r for r in d["not_comparable_because"])


def test_a_finding_kept_without_a_completed_verification_disqualifies_too(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a", incomplete=1), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 incomplete" in r for r in d["not_comparable_because"])


def test_an_incomplete_run_status_disqualifies_an_arm(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a", complete=False), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 run_incomplete" in r for r in d["not_comparable_because"])


def test_incomplete_run_status_counts_each_run_record(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", complete=False)
    _arm(ws / "nested", complete=False)
    got = _arm_artifacts(ws)
    assert got["completeness"]["run_incomplete"] == 2


def test_an_arm_that_wrote_no_record_is_not_read_as_a_clean_zero(tmp_path):
    from evals.backtest.metrics import with_arms

    empty = tmp_path / "empty"
    empty.mkdir()
    d = with_arms({}, _arm(tmp_path / "a"), empty)
    assert d["comparable"] is False
    assert any("wrote no _run.json" in r for r in d["not_comparable_because"])


def test_both_stages_spend_is_summed_rather_than_one_overwriting_the_other(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", requests=100)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 0, "incomplete": 2, "usage": {"model_requests": 40}}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)
    assert got["cost"]["model_requests"] == 140
    assert got["completeness"]["incomplete"] == 2


def test_a_failed_call_counts_once_per_stage_but_a_kept_finding_counts_once(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", verify_errors=2, incomplete=1, unlocatable=1)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 2, "incomplete": 1, "unlocatable": 1}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)["completeness"]
    assert got["verify_errors"] == 4
    assert got["incomplete"] == 1
    assert got["unlocatable"] == 1


def test_the_displayed_cost_components_account_for_the_displayed_total(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    leaf = tmp_path / "a" / "leaf"
    leaf.mkdir(parents=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": 0,
                "usage": {
                    "model_requests": 10,
                    "total_input_tokens": 1000,
                    "uncached_input_tokens": 200,
                    "cache_read_tokens": 750,
                    "cache_write_tokens": 50,
                    "output_tokens": 100,
                },
            }
        ),
        encoding="utf-8",
    )
    rendered = format_arms(with_arms({}, tmp_path / "a", None)).splitlines()
    line = next(row for row in rendered if "total_input_tokens=" in row)
    shown = dict(p.split("=") for p in line.split() if "=" in p)
    components = ("uncached_input_tokens", "cache_read_tokens", "cache_write_tokens")
    assert int(shown["total_input_tokens"]) == sum(int(shown[k]) for k in components)


def test_a_stage_elapsed_falls_back_to_its_own_record_when_no_timeline_exists(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    text = format_arms(with_arms({}, _arm(tmp_path / "a", seconds=60.0), _arm(tmp_path / "b", seconds=90.0)))
    assert "60.0s" in text
    assert "90.0s" in text
    assert "?s" not in text
    assert "seconds x1.50" in text


def test_format_arms_reports_the_cost_ratio_and_the_verdict(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    d = with_arms({}, _arm(tmp_path / "a", requests=100), _arm(tmp_path / "b", requests=800))
    text = format_arms(d)
    assert "model_requests x8.00" in text
    assert "the comparison stands" in text
