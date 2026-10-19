"""The working-directory .env loader the CLI runs at startup."""

import ast
import os
import re
from pathlib import Path

from cyberjury.envfile import load_env_file
from cyberjury.providers.configuration import provider_configuration_from_env

_ROOT = Path(__file__).resolve().parents[1]

_ENV_NAME = re.compile(r"\b(?:CYBERJURY|OPENAI|ANTHROPIC)_[A-Z_]*[A-Z]\b")


def _environment_names_read_by_the_cli() -> set[str]:
    names: set[str] = set()
    for path in (_ROOT / "src" / "cyberjury").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.update(_ENV_NAME.findall(node.value))
    return names


def _forget_after_test(monkeypatch, *names):
    for name in names:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def test_env_example_documents_cli_runtime_environment():
    """The operator template lists every env variable the CLI runtime reads."""
    names = _environment_names_read_by_the_cli()
    text = (_ROOT / ".env.example").read_text(encoding="utf-8")

    assert names == {
        "ANTHROPIC_API_KEY",
        "CYBERJURY_API_BASE",
        "CYBERJURY_MODEL",
        "OPENAI_API_KEY",
    }
    assert sorted(name for name in names if f"{name}=" not in text) == []


def test_the_example_copied_as_is_selects_the_defaults(tmp_path, monkeypatch):
    """Loading an unedited .env.example copy selects provider anthropic, model claude-opus-5, no api_base."""
    (tmp_path / ".env").write_text((_ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _forget_after_test(monkeypatch, *_environment_names_read_by_the_cli())

    load_env_file()
    seat = provider_configuration_from_env().seat

    assert (seat.provider, seat.model, seat.api_base) == ("anthropic", "claude-opus-5", None)


def test_load_missing_file_is_not_an_error(tmp_path, monkeypatch):
    """With no .env in the working directory, loading succeeds and leaves CYBERJURY_MODEL unset."""
    monkeypatch.chdir(tmp_path)

    load_env_file()

    assert "CYBERJURY_MODEL" not in os.environ


def test_load_reads_only_the_working_directory_file(tmp_path, monkeypatch):
    """A quoted export line in subdir/.env is loaded while a parent directory .env is ignored."""
    working = tmp_path / "project" / "subdir"
    working.mkdir(parents=True)
    (tmp_path / "project" / ".env").write_text("CYBERJURY_API_BASE=https://parent.example.test\n", encoding="utf-8")
    (working / ".env").write_text("export CYBERJURY_MODEL='from-file'\n# a comment\n", encoding="utf-8")
    monkeypatch.chdir(working)
    _forget_after_test(monkeypatch, "CYBERJURY_MODEL", "CYBERJURY_API_BASE")

    load_env_file()

    assert os.environ["CYBERJURY_MODEL"] == "from-file"
    assert "CYBERJURY_API_BASE" not in os.environ


def test_an_exported_value_wins_over_the_file(tmp_path, monkeypatch):
    """A CYBERJURY_MODEL already set in the shell keeps from-shell over the from-file value in .env."""
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    (tmp_path / ".env").write_text("CYBERJURY_MODEL=from-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    load_env_file()

    assert os.environ["CYBERJURY_MODEL"] == "from-shell"
