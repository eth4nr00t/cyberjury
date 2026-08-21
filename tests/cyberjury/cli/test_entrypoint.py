"""Package entry points expose the supported command surface."""

import subprocess

import pytest

from cyberjury.cli import main


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "cyberjury" in capsys.readouterr().out


def test_old_audit_command_is_gone(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--dry-run"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_python_dash_m_cyberjury_runs():
    import sys

    r = subprocess.run([sys.executable, "-m", "cyberjury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "cyberjury" in r.stdout.lower()
