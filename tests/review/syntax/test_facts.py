"""Syntax facts extraction coordinates analysis and graph failures."""

import pytest

from cyberjury.review.facts import Facts
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.syntax import facts as facts_module
from cyberjury.review.syntax.facts import analyzable_sources
from tests.review.syntax.support import syntax_facts


def test_an_empty_tree_yields_empty_facts(tmp_path):
    """A tree holding only notes.md produces facts equal to an empty Facts()."""
    (tmp_path / "notes.md").write_text("no code here\n")
    facts = syntax_facts(tmp_path)
    assert facts == Facts()


def test_a_graph_failure_no_single_file_explains_still_fails_extraction(tmp_path, monkeypatch):
    """A graph error that appears only with both files together is not hidden as a file limitation."""
    (tmp_path / "one.py").write_text("def one():\n    return 1\n")
    (tmp_path / "two.py").write_text("def two():\n    return 2\n")
    build = facts_module.facts_from_repository

    def failing_build(repository):
        if len({definition.file for definition in repository.definitions}) > 1:
            raise ValueError("cross file evidence conflict")
        return build(repository)

    monkeypatch.setattr(facts_module, "facts_from_repository", failing_build)

    with pytest.raises(BackendUnavailable, match="cross file evidence conflict"):
        syntax_facts(tmp_path)


def test_analyzer_input_pairs_each_review_file_of_a_grammar_language_with_its_analyzer(tmp_path):
    """Of app.py, notes.txt, and web/app.ts, only the Python and TypeScript files become analyzer input."""
    sources = analyzable_sources(tmp_path, ("app.py", "notes.txt", "web/app.ts"))

    assert [(rel, spec.name) for _path, rel, spec in sources] == [("app.py", "python"), ("web/app.ts", "typescript")]
