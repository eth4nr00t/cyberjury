"""Lightweight telemetry reports progress and records nonblocking stage timelines."""

import json

import pytest

from cyberjury.telemetry import TIMELINE_FILE, progress, read_timeline, stage_timer


def test_progress_writes_to_stderr_not_stdout(capsys):
    """Progress writes to stderr not stdout."""
    progress("halfway there")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "halfway there" in captured.err


def test_stage_timer_prints_elapsed_and_no_workspace_writes_no_file(capsys, tmp_path):
    """Stage timer prints elapsed and no workspace writes no file."""
    with stage_timer("diff"):
        pass
    err = capsys.readouterr().err
    assert "diff done in" in err
    assert err.strip().endswith("s")
    assert not (tmp_path / TIMELINE_FILE).exists()


def test_stage_timer_records_one_timeline_entry_per_stage_in_order(tmp_path):
    """Stage timer records one timeline entry per stage in order."""
    for name in ("scaffold", "run", "finalize", "gate"):
        with stage_timer(name, tmp_path):
            pass
    timeline = json.loads((tmp_path / TIMELINE_FILE).read_text())
    assert [r["stage"] for r in timeline] == ["scaffold", "run", "finalize", "gate"]
    for r in timeline:
        assert r["ok"] is True
        assert isinstance(r["seconds"], (int, float))
        assert r["seconds"] >= 0
        assert r["started_at"].endswith("Z")


def test_stage_timer_records_a_failed_stage_and_reraises(tmp_path, capsys):
    """Stage timer records a failed stage and reraises."""
    with pytest.raises(ValueError, match="boom"), stage_timer("run", tmp_path):
        raise ValueError("boom")
    assert "run failed after" in capsys.readouterr().err
    timeline = json.loads((tmp_path / TIMELINE_FILE).read_text())
    assert timeline[-1]["stage"] == "run"
    assert timeline[-1]["ok"] is False


def test_a_corrupt_timeline_is_rebuilt_not_raised(tmp_path):
    """Corrupt timeline is rebuilt not raised."""
    (tmp_path / TIMELINE_FILE).write_text("not json at all")
    with stage_timer("gate", tmp_path):
        pass
    timeline = json.loads((tmp_path / TIMELINE_FILE).read_text())
    assert [r["stage"] for r in timeline] == ["gate"]


def test_read_timeline_returns_records_and_empty_when_missing(tmp_path):
    """Read timeline returns records and empty when missing."""
    assert read_timeline(tmp_path) == []
    with stage_timer("run", tmp_path):
        pass
    assert [r["stage"] for r in read_timeline(tmp_path)] == ["run"]
