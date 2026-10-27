"""CLI tests cover argument handling and the exit code of each review outcome."""

from __future__ import annotations

from pathlib import Path

import pytest

import cyberjury.cli as climod
from cyberjury.cli import _default_workspace, main
from cyberjury.record import Record, RecordError
from cyberjury.review.command import ReviewCommand
from cyberjury.review.recorder import INTERRUPTED, TERMINATED
from cyberjury.review.request import TargetInput
from cyberjury.workspace import new_attempt_id


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    """The default state workspace resolves to ~/.cyberjury under the user's home directory."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".cyberjury")


def test_no_command_prints_help_on_stderr_and_exits_with_the_usage_code(capsys):
    """Running without a command prints usage to stderr, nothing to stdout, and exits 2."""
    assert main([]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: cyberjury" in captured.err


def test_an_abbreviated_flag_is_rejected(tmp_path):
    """Argparse prefix matching is disabled, so --conc 2 exits with usage code 2."""
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--conc", "2"])
    assert exc.value.code == 2


@pytest.mark.parametrize("flag", [("--concurrency", "0"), ("--concurrency", "two")])
def test_diff_rejects_invalid_cli_values(flag, capsys):
    """A --concurrency of 0 or 'two' exits with usage code 2 and names the flag on stderr."""
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", "--repository", "repo", "--git-range", "base..HEAD", *flag])
    assert exc.value.code == 2
    assert flag[0] in capsys.readouterr().err


def test_review_arguments_become_one_review_command(monkeypatch, tmp_path):
    """Diff and repository arguments resolve their paths, and only the repository command carries --fresh."""
    seen = []

    def record(command, **_streams):
        seen.append(command)
        return Record(id=new_attempt_id(), status="ok", started_at="2026-01-01T00:00:00Z", duration_seconds=0.0)

    monkeypatch.setattr(climod, "run_review_command", record)
    workspace = str(tmp_path / "state")

    main(["review", "diff", "--repository", str(tmp_path), "--git-range", "a..b", "--workspace", workspace])
    main(["review", "repository", str(tmp_path), "--workspace", workspace, "--fresh", "--concurrency", "3"])

    assert seen == [
        ReviewCommand(
            target=TargetInput(kind="diff", repository=str(tmp_path.resolve()), git_range="a..b"),
            workspace=workspace,
            fresh=None,
            concurrency=None,
        ),
        ReviewCommand(
            target=TargetInput(kind="repository", repository=str(tmp_path.resolve())),
            workspace=workspace,
            fresh=True,
            concurrency=3,
        ),
    ]


@pytest.mark.parametrize(
    ("status", "code", "reason", "expected"),
    [
        ("ok", None, None, 0),
        ("incomplete", "model", None, 1),
        ("failed", "internal", None, 3),
        ("failed", "busy", None, 1),
        ("failed", "config", None, 2),
        ("failed", "input", None, 2),
        ("interrupted", None, INTERRUPTED, 130),
        ("interrupted", None, TERMINATED, 143),
    ],
)
def test_each_review_outcome_exits_with_its_code(monkeypatch, tmp_path, status, code, reason, expected):
    """Ok 0, incomplete or busy 1, config or input failure 2, internal failure 3, an interrupt 130, and SIGTERM 143."""
    attempt = Record(
        id=new_attempt_id(),
        status=status,
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=0.0,
        attributes={"reason": reason} if reason is not None else {},
        error=RecordError(code=code, message="reason") if code is not None else None,
    )
    monkeypatch.setattr(climod, "run_review_command", lambda _command, **_streams: attempt)

    assert main(["review", "repository", str(tmp_path), "--workspace", str(tmp_path / "state")]) == expected
