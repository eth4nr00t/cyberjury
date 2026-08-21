"""Web facts fail loud when a grammar required by the target is unavailable."""

import pytest

from cyberjury.profiles.web.facts.analyzer import LangSpec, load_specs
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import (
    BackendUnavailable,
    FactsBackend,
)


def test_tree_sitter_call_graph_is_a_facts_backend():
    assert isinstance(TreeSitterFacts(), FactsBackend)


def test_an_empty_tree_yields_empty_facts(tmp_path):
    (tmp_path / "notes.md").write_text("no code here\n")
    assert TreeSitterFacts().extract(tmp_path).empty


def _absent(specs, name="python"):
    base = specs[name]
    return LangSpec(
        name=name,
        extensions=base.extensions,
        resolution_languages=base.resolution_languages,
        module="tree_sitter_absent_grammar",
        accessor="language",
        definitions=base.definitions,
        type_definitions=base.type_definitions,
        calls=base.calls,
        imports=base.imports,
        module_entries=base.module_entries,
    )


def test_a_language_with_no_grammar_installed_fails_when_the_target_uses_it(tmp_path):
    specs = load_specs()
    specs["python"] = _absent(specs)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    (tmp_path / "b.ts").write_text("function g() { return 1; }\n")
    with pytest.raises(BackendUnavailable, match="python"):
        TreeSitterFacts(specs).extract(tmp_path)


def test_a_missing_unused_grammar_does_not_block_other_languages(tmp_path):
    specs = load_specs()
    specs["python"] = _absent(specs)
    (tmp_path / "b.ts").write_text("function g() { return 1; }\n")
    assert set(TreeSitterFacts(specs).extract(tmp_path).data["graph"]["callgraph"]) == {"b.ts"}


def test_unavailable_when_no_grammar_at_all_is_installed(tmp_path):
    backend = TreeSitterFacts({"python": _absent(load_specs())})
    assert backend.available() is False
    with pytest.raises(BackendUnavailable):
        backend.extract(tmp_path)
