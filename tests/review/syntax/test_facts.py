"""Syntax facts extraction tests cover pipeline coordination."""

from cyberjury.review.facts import Facts
from tests.review.syntax.support import callgraph, syntax_facts


def test_an_empty_tree_yields_empty_facts(tmp_path):
    (tmp_path / "notes.md").write_text("no code here\n")
    facts = syntax_facts(tmp_path)
    assert facts == Facts()


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
    graph = callgraph(_chain(tmp_path))
    assert graph["app/routes.py"]["get_order"][0]["calls"] == ["handle_request"]
    assert graph["app/handler.py"]["handle_request"][0]["calls"] == ["load_order"]
    assert graph["app/repository.py"]["load_order"][0]["calls"] == ["run_query"]


def test_syntax_facts_persist_candidates_without_a_resolvedcallgraph(tmp_path):
    facts = syntax_facts(_chain(tmp_path))

    evidence = facts.relationships

    assert any(item.candidate_callee_definition_ids for item in evidence.call_relationships)
