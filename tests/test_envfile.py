"""The working-directory .env loader the CLI runs at startup."""

import os
from pathlib import Path

from cyberjury.envfile import load_env_file, parse_env

_ROOT = Path(__file__).resolve().parents[1]

_CLI_ENV_TEMPLATE_KEYS = {
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CYBERJURY_PROVIDER",
    "CYBERJURY_MODEL",
    "CYBERJURY_API_KEY",
    "CYBERJURY_API_BASE",
    "CYBERJURY_WIRE_API",
    "CYBERJURY_FINDER_PROVIDER",
    "CYBERJURY_FINDER_MODEL",
    "CYBERJURY_FINDER_API_KEY",
    "CYBERJURY_FINDER_API_BASE",
    "CYBERJURY_FINDER_WIRE_API",
    "CYBERJURY_CHALLENGER_PROVIDER",
    "CYBERJURY_CHALLENGER_MODEL",
    "CYBERJURY_CHALLENGER_API_KEY",
    "CYBERJURY_CHALLENGER_API_BASE",
    "CYBERJURY_CHALLENGER_WIRE_API",
    "CYBERJURY_JUDGE_PROVIDER",
    "CYBERJURY_JUDGE_MODEL",
    "CYBERJURY_JUDGE_API_KEY",
    "CYBERJURY_JUDGE_API_BASE",
    "CYBERJURY_JUDGE_WIRE_API",
    "CYBERJURY_RETRIES",
    "CYBERJURY_TIMEOUT",
    "CYBERJURY_ETHERSCAN_API_KEY",
}


def test_parse_skips_blanks_and_comments_and_strips_quotes_and_export():
    """Parse skips blanks and comments and strips quotes and export."""
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
    text = (_ROOT / ".env.example").read_text(encoding="utf-8")
    missing = sorted(key for key in _CLI_ENV_TEMPLATE_KEYS if f"{key}=" not in text)
    assert missing == []


def test_load_missing_file_is_not_an_error(tmp_path):
    """Load missing file is not an error."""
    assert load_env_file(tmp_path / "absent.env") == []


def test_load_sets_unset_keys_and_reports_them(tmp_path, monkeypatch):
    """Load sets unset keys and reports them."""
    monkeypatch.delenv("CYBERJURY_MODEL", raising=False)
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == ["CYBERJURY_MODEL"]
    assert os.environ["CYBERJURY_MODEL"] == "from-file"


def test_an_exported_value_wins_over_the_file(tmp_path, monkeypatch):
    """Exported value wins over the file."""
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == []
    assert os.environ["CYBERJURY_MODEL"] == "from-shell"


def test_override_replaces_an_existing_value(tmp_path, monkeypatch):
    """Override replaces an existing value."""
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p, override=True)
    assert loaded == ["CYBERJURY_MODEL"]
    assert os.environ["CYBERJURY_MODEL"] == "from-file"
