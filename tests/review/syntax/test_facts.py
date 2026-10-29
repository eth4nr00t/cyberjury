"""Syntax facts extraction coordinates analysis and graph failures."""

from cyberjury.review.facts import Facts
from cyberjury.review.syntax.facts import analyzable_sources
from tests.review.syntax.support import syntax_facts


def test_an_empty_tree_yields_empty_facts(tmp_path):
    """A tree holding only notes.md produces facts equal to an empty Facts()."""
    (tmp_path / "notes.md").write_text("no code here\n")
    facts = syntax_facts(tmp_path)
    assert facts == Facts()


def test_analyzer_input_pairs_each_review_file_of_a_grammar_language_with_its_analyzer(tmp_path):
    """Of app.py, notes.txt, and web/app.ts, only the Python and TypeScript files become analyzer input."""
    sources = analyzable_sources(tmp_path, ("app.py", "notes.txt", "web/app.ts"))

    assert [(rel, spec.name) for _path, rel, spec in sources] == [("app.py", "python"), ("web/app.ts", "typescript")]
