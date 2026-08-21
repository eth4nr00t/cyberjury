"""Web graph output keeps per file evidence and ambiguity visible."""

from cyberjury.profiles.web.facts.backend import TreeSitterFacts


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


def test_by_file_carries_each_file_own_graph_as_prompt_text(tmp_path):
    _chain(tmp_path)
    block = TreeSitterFacts().extract(tmp_path).data["by_file"]["app/handler.py"]
    assert "handle_request()" in block
    assert "calls load_order" in block
    assert "imports load_order" in block
    assert "get_order" not in block


def test_the_summary_names_the_scale_and_ambiguous_edge_policy(tmp_path):
    _chain(tmp_path)
    summary = TreeSitterFacts().extract(tmp_path).summary
    assert "Call graph" in summary
    assert "Ambiguous syntax edges" in summary
