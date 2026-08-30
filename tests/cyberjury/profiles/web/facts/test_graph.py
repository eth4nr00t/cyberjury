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


def test_the_summary_names_scale_and_keeps_resolver_targets_as_clues(tmp_path):
    _chain(tmp_path)
    summary = TreeSitterFacts().extract(tmp_path).summary
    assert "Syntax evidence" in summary
    assert "candidate clues" in summary


def test_unresolved_import_remains_a_syntax_clue(tmp_path):
    (tmp_path / "views.py").write_text(
        "from package.models import Record\n\n\ndef view():\n    return Record.objects.all()\n",
        encoding="utf-8",
    )

    facts = TreeSitterFacts().extract(tmp_path)
    graph = facts.data["graph"]

    assert graph["imports"].get("views.py") is None
    assert graph["syntax_imports"]["views.py"][0]["module"] == "package.models"
    assert graph["syntax_imports"]["views.py"][0]["imported"] == "Record"
    assert graph["syntax_imports"]["views.py"][0]["local"] == "Record"
    assert "observes imports Record from package.models" in facts.data["by_file"]["views.py"]


def test_import_only_repository_keeps_module_relationship_facts(tmp_path):
    (tmp_path / "index.ts").write_text("export * from './missing';\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert not facts.empty
    assert facts.data["graph"]["syntax_imports"]["index.ts"]


def test_relationship_evidence_preserves_each_callsite_arguments_and_candidates(tmp_path):
    (tmp_path / "service.py").write_text("def load(x):\n    return x\n")
    (tmp_path / "route.py").write_text(
        "from service import load\n\ndef route(x):\n    first = load(x)\n    return load(x + 1)\n"
    )

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]

    assert [item["expression"] for item in evidence["callsites"]] == ["load(x)", "load(x + 1)"]
    assert [item["arguments"][0]["expression"] for item in evidence["callsites"]] == ["x", "x + 1"]
    target = next(item for item in evidence["definitions"] if item["name"] == "load")
    assert all(
        item["candidate_target_ids"] == [target["id"]]
        for item in evidence["observations"]
        if item["kind"] == "syntax_call"
    )


def test_relationship_definition_records_its_type_owner(tmp_path):
    (tmp_path / "service.py").write_text("class Service:\n    def load(self, x):\n        return x\n")

    definitions = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["definitions"]
    owner = next(item for item in definitions if item["name"] == "Service")
    method = next(item for item in definitions if item["name"] == "load")

    assert method["kind"] == "method"
    assert method["owner_id"] == owner["id"]


def test_relationship_evidence_keeps_a_recursive_callsite(tmp_path):
    (tmp_path / "walk.py").write_text("def walk(node):\n    if node:\n        return walk(node.parent)\n")

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]

    assert [item["expression"] for item in evidence["callsites"]] == ["walk(node.parent)"]
