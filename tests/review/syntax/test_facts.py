"""A tree without analyzable source has empty facts, and only review files of grammar languages reach the analyzer."""

from cyberjury.review.facts import Facts
from cyberjury.review.syntax.facts import analyzable_sources
from tests.review.syntax.support import syntax_facts


def test_a_tree_without_analyzable_source_yields_empty_facts(tmp_path):
    """A tree holding only notes.md produces facts equal to an empty Facts()."""
    (tmp_path / "notes.md").write_text("no code here\n", encoding="utf-8")
    facts = syntax_facts(tmp_path)
    assert facts == Facts()


def test_analyzer_input_pairs_each_review_file_of_a_grammar_language_with_its_analyzer(tmp_path):
    """Of app.py, notes.txt, and web/app.ts, only the Python and TypeScript files become analyzer input."""
    sources = analyzable_sources(tmp_path, ("app.py", "notes.txt", "web/app.ts"))

    assert [(rel, spec.name) for _path, rel, spec in sources] == [("app.py", "python"), ("web/app.ts", "typescript")]
