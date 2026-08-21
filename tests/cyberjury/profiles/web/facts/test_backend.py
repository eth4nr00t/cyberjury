"""Web facts backend tests cover extraction and pipeline coordination."""

import pytest

from cyberjury.profiles.web.facts.analyzer import LangSpec, load_specs
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import (
    BackendUnavailable,
    FactsBackend,
    definition_dependencies,
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


def _graph(root):
    return TreeSitterFacts().extract(root).data["graph"]["callgraph"]


def _chain(root):
    (root / "app").mkdir(parents=True)
    (root / "app" / "routes.py").write_text(
        "from app.handler import handle_request\n\n\ndef get_order(oid):\n    return handle_request(oid)\n"
    )
    (root / "app" / "handler.py").write_text(
        "from app.repository import load_order\n\n\ndef handle_request(oid):\n    return load_order(oid)\n"
    )
    (root / "app" / "repository.py").write_text("def load_order(oid):\n    return run_query(oid)\n")
    return root


def test_a_four_hop_chain_is_recovered_edge_by_edge(tmp_path):
    graph = _graph(_chain(tmp_path))
    assert graph["app/routes.py"]["get_order"][0]["calls"] == ["handle_request"]
    assert graph["app/handler.py"]["handle_request"][0]["calls"] == ["load_order"]
    assert graph["app/repository.py"]["load_order"][0]["calls"] == ["run_query"]


def test_web_backend_persists_exact_definition_dependency_endpoints(tmp_path):
    facts = TreeSitterFacts().extract(_chain(tmp_path))

    dependencies = definition_dependencies(facts.data["graph"])

    assert [
        (edge.source.file, edge.source.name, edge.target.file, edge.target.name)
        for edge in dependencies
        if edge.source is not None
    ] == [
        ("app/handler.py", "handle_request", "app/repository.py", "load_order"),
        ("app/routes.py", "get_order", "app/handler.py", "handle_request"),
    ]
