"""The working-directory .env loader the CLI runs at startup."""

import os

from cyberjury.envfile import load_env_file, parse_env


def test_parse_skips_blanks_and_comments_and_strips_quotes_and_export():
    """Exercise the parse skips blanks and comments and strips quotes and export case."""
    parsed = parse_env(
        "\n"
        f"{chr(35)} a comment\n"
        "CYBERJURY_MODEL=claude-opus-4-8\n"
        "export CYBERJURY_PROVIDER=anthropic\n"
        'CYBERJURY_API_KEY="sk-quoted"\n'
        "CYBERJURY_API_BASE='https://example.test'\n"
        "a stray note with no equals\n"
    )
    assert parsed == {
        "CYBERJURY_MODEL": "claude-opus-4-8",
        "CYBERJURY_PROVIDER": "anthropic",
        "CYBERJURY_API_KEY": "sk-quoted",
        "CYBERJURY_API_BASE": "https://example.test",
    }


def test_load_missing_file_is_not_an_error(tmp_path):
    """Exercise the load missing file is not an error case."""
    assert load_env_file(tmp_path / "absent.env") == []


def test_load_sets_unset_keys_and_reports_them(tmp_path, monkeypatch):
    """Exercise the load sets unset keys and reports them case."""
    monkeypatch.delenv("CYBERJURY_MODEL", raising=False)
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == ["CYBERJURY_MODEL"]
    assert os.environ["CYBERJURY_MODEL"] == "from-file"


def test_an_exported_value_wins_over_the_file(tmp_path, monkeypatch):
    """Exercise an exported value wins over the file."""
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p)
    assert loaded == []
    assert os.environ["CYBERJURY_MODEL"] == "from-shell"


def test_override_replaces_an_existing_value(tmp_path, monkeypatch):
    """Exercise the override replaces an existing value case."""
    monkeypatch.setenv("CYBERJURY_MODEL", "from-shell")
    p = tmp_path / ".env"
    p.write_text("CYBERJURY_MODEL=from-file\n")
    loaded = load_env_file(p, override=True)
    assert loaded == ["CYBERJURY_MODEL"]
    assert os.environ["CYBERJURY_MODEL"] == "from-file"
