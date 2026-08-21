"""The Web facts pipeline carries exact dependencies across every stage."""

from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import (
    definition_dependencies,
)


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
