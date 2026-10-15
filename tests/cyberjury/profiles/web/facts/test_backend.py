"""Web facts backend tests cover extraction and pipeline coordination."""

from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import FactsBackend


def test_tree_sitter_call_graph_is_a_facts_backend():
    assert isinstance(TreeSitterFacts(), FactsBackend)


def test_an_empty_tree_yields_empty_facts(tmp_path):
    (tmp_path / "notes.md").write_text("no code here\n")
    facts = TreeSitterFacts().extract(tmp_path)
    assert facts.empty
    assert facts.facts_resolution is not None
    assert facts.facts_resolution.definition_count == 0
    assert facts.facts_resolution.callsite_count == 0


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


def test_web_backend_persists_candidates_without_a_resolved_graph(tmp_path):
    facts = TreeSitterFacts().extract(_chain(tmp_path))

    evidence = facts.data["relationship_evidence"]

    assert "call_candidates" not in facts.data["graph"]
    assert "dependencies" not in facts.data["graph"]
    assert any(item["candidate_callee_definition_ids"] for item in evidence["call_relationships"])
    assert facts.facts_resolution is not None
    assert facts.native_analysis is not None
    assert facts.facts_resolution.native_analysis_receipt_sha256 == facts.native_analysis.receipt_sha256
    assert facts.facts_resolution.definition_count == len(evidence["definitions"])
    assert facts.facts_resolution.callsite_count == len(evidence["callsites"])
