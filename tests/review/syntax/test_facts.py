"""Syntax facts extraction coordinates analysis, excluded files, and per-file graph failures."""

import pytest

from cyberjury.review.detection import MAX_SOURCE_BYTES, detection_for
from cyberjury.review.facts import Facts
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.selection import select_files
from cyberjury.review.syntax import facts as facts_module
from cyberjury.review.syntax.facts import extract_syntax_facts
from tests.review.syntax.support import syntax_facts


def _write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return sorted(files)


def test_an_empty_tree_yields_empty_facts(tmp_path):
    """A tree holding only notes.md produces facts equal to an empty Facts()."""
    (tmp_path / "notes.md").write_text("no code here\n")
    facts = syntax_facts(tmp_path)
    assert facts == Facts()


def test_vendored_files_are_not_parsed_into_facts(tmp_path):
    """A navigable linguist-vendored public/plugins/lib.js yields no facts, while app.py does."""
    files = _write(
        tmp_path,
        {
            ".gitattributes": "public/plugins/** linguist-vendored\n",
            "app.py": "def handler(value):\n    return value\n",
            "public/plugins/lib.js": "function helper(value) { return value }\n",
        },
    )
    detection = detection_for(tmp_path, files)

    facts = extract_syntax_facts(tmp_path, files, select_files(tmp_path, files, detection).navigation_files, detection)

    assert set(facts.by_file) == {"app.py"}


def test_oversized_files_are_left_out_of_facts_without_a_limitation(tmp_path):
    """A bindata.go over MAX_SOURCE_BYTES is not parsed and records no limitation, while app.py keeps facts."""
    files = _write(
        tmp_path,
        {
            "app.py": "def handler(value):\n    return value\n",
            "bindata.go": "package bindata\n\nvar data = `" + "a" * MAX_SOURCE_BYTES + "`\n",
        },
    )
    detection = detection_for(tmp_path, files)

    facts = extract_syntax_facts(tmp_path, files, select_files(tmp_path, files, detection).navigation_files, detection)

    assert not facts.limitations
    assert set(facts.by_file) == {"app.py"}


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
