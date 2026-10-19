"""The working-directory .env loader the CLI runs at startup."""

import ast
import os
import re
from pathlib import Path

from cyberjury.envfile import load_env_file, parse_env

_ROOT = Path(__file__).resolve().parents[1]

_ENV_NAME = re.compile(r"\b(?:CYBERJURY|OPENAI|ANTHROPIC)_[A-Z_]*[A-Z]\b")


def _environment_names_read_by_the_cli() -> set[str]:
    """Collect every environment name spelled in the product source."""
    names: set[str] = set()
    for path in (_ROOT / "src" / "cyberjury").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.update(_ENV_NAME.findall(node.value))
    return names


def test_parse_skips_blanks_and_comments_and_strips_quotes_and_export():
    parsed = parse_env(
        "\n"
        f"{chr(35)} a comment\n"
        "CYBERJURY_MODEL=gpt-5.6\n"
        "export CYBERJURY_PROVIDER=anthropic\n"
        'CYBERJURY_API_KEY="sk-quoted"\n'
        "CYBERJURY_API_BASE='https://example.test'\n"
        "a stray note with no equals\n"
    )
    assert parsed == {
        "CYBERJURY_MODEL": "gpt-5.6",
        "CYBERJURY_PROVIDER": "anthropic",
        "CYBERJURY_API_KEY": "sk-quoted",
        "CYBERJURY_API_BASE": "https://example.test",
    }


def test_env_example_documents_cli_runtime_environment():
    """The operator template lists every env variable the CLI runtime reads."""
    names = _environment_names_read_by_the_cli()
    text = (_ROOT / ".env.example").read_text(encoding="utf-8")

    assert {"CYBERJURY_HOME", "CYBERJURY_WIRE_API", "OPENAI_API_KEY"} <= names
    assert sorted(name for name in names if f"{name}=" not in text) == []


def test_load_missing_file_is_not_an_error(tmp_path):
    assert load_env_file(tmp_path / "absent.env") == []


def test_load_sets_unset_keys_and_reports_them(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERJURY_MODEL", raising=False)
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == ["CYBERJURY_MODEL"]
    assert os.environ["CYBERJURY_MODEL"] == "from-file"


def test_an_exported_value_wins_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == []
    assert os.environ["CYBERJURY_MODEL"] == "from-shell"
