"""Lightweight telemetry reports progress and stage timings on stderr."""

import pytest

from cyberjury.telemetry import progress, stage_timer


def test_progress_writes_to_stderr_not_stdout(capsys):
    progress("halfway there")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "halfway there" in captured.err


def test_stage_timer_prints_elapsed(capsys):
    with stage_timer("diff"):
        pass
    err = capsys.readouterr().err
    assert "diff done in" in err
    assert err.strip().endswith("s")


def test_stage_timer_reports_a_failed_stage_and_reraises(capsys):
    with pytest.raises(ValueError, match="boom"), stage_timer("run"):
        raise ValueError("boom")
    assert "run failed after" in capsys.readouterr().err
