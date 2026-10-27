"""Language files declare their grammar and syntax queries, inheriting a parent's queries."""

import pytest

from cyberjury.review import languages


@pytest.fixture
def language_files(tmp_path, monkeypatch):
    """Load languages from files written under a temporary directory instead of the shipped contract."""

    def install(**files: str):
        for name, text in files.items():
            (tmp_path / f"{name}.yaml").write_text(text, encoding="utf-8")
        monkeypatch.setattr(languages, "LANGUAGE_FILES", tuple(sorted(tmp_path.glob("*.yaml"))))
        languages.load_languages.cache_clear()

    yield install
    languages.load_languages.cache_clear()


def test_a_language_inherits_its_parent_queries_and_overrides_its_own(language_files):
    """A child overriding calls keeps the parent's definitions query and replaces its calls query."""
    language_files(
        base="extensions: [.b]\ngrammar: [base, language]\nsyntax:\n  definitions: base defs\n  calls: base calls\n",
        child="extensions: [.c]\ngrammar: [child, language]\ninherits: base\nsyntax:\n  calls: child calls\n",
    )

    assert languages.load_languages()["child"].syntax == {"definitions": "base defs", "calls": "child calls"}


def test_a_misspelled_language_field_is_rejected(language_files):
    """A grammer field raises an unknown fields error naming it."""
    language_files(typo="extensions: [.t]\ngrammer: [typo_module, language]\n")

    with pytest.raises(ValueError, match="unknown fields: grammer"):
        languages.load_languages()
