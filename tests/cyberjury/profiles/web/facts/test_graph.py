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


def test_the_summary_names_scale_and_leaves_targets_for_model_analysis(tmp_path):
    _chain(tmp_path)
    summary = TreeSitterFacts().extract(tmp_path).summary
    assert "Syntax evidence" in summary
    assert "Relationship targets remain unresolved until model analysis" in summary


def test_unresolved_import_remains_a_syntax_clue(tmp_path):
    (tmp_path / "views.py").write_text(
        "from package.models import Record\n\n\ndef view():\n    return Record.objects.all()\n",
        encoding="utf-8",
    )

    facts = TreeSitterFacts().extract(tmp_path)
    graph = facts.data["graph"]

    assert "imports" not in graph
    assert graph["syntax_imports"]["views.py"][0]["module"] == "package.models"
    assert graph["syntax_imports"]["views.py"][0]["imported"] == "Record"
    assert graph["syntax_imports"]["views.py"][0]["local"] == "Record"
    assert "observes imports Record from package.models" in facts.data["by_file"]["views.py"]


def test_import_only_repository_keeps_module_relationship_facts(tmp_path):
    (tmp_path / "index.ts").write_text("export * from './missing';\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert not facts.empty
    assert facts.data["graph"]["syntax_imports"]["index.ts"]


def test_relationship_evidence_preserves_calls_but_does_not_assign_targets(tmp_path):
    (tmp_path / "service.py").write_text("def load(x):\n    return x\n")
    (tmp_path / "route.py").write_text(
        "from service import load\n\ndef route(x):\n    first = load(x)\n    return load(x + 1)\n"
    )

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]

    assert [item["expression"] for item in evidence["callsites"]] == ["load(x)", "load(x + 1)"]
    assert [item["arguments"][0]["expression"] for item in evidence["callsites"]] == ["x", "x + 1"]
    assert all(item["candidate_target_ids"] == [] for item in evidence["observations"] if item["kind"] == "syntax_call")
    assert {item["kind"] for item in evidence["observations"] if item["kind"] != "syntax_call"} == {
        "import_declaration"
    }


def test_namespace_declaration_and_concrete_use_are_distinct_relationship_questions(tmp_path):
    (tmp_path / "service.ts").write_text("export function load() { return true; }\n")
    (tmp_path / "route.ts").write_text(
        'import * as service from "./service";\nexport function route() { return service.load(); }\n'
    )

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]

    assert any(item["kind"] == "namespace_declaration" for item in evidence["observations"])
    assert [(item["kind"], item["reference"]) for item in evidence["structural_subjects"]] == [
        ("namespace", "service from ./service"),
        ("reference", "service.load"),
    ]
    assert all(not item["candidate_target_definition_ids"] for item in evidence["structural_subjects"])


def test_an_outer_local_import_is_a_declaration_clue_for_a_nested_caller(tmp_path):
    (tmp_path / "service.py").write_text("def load(value):\n    return value\n")
    (tmp_path / "route.py").write_text(
        "def outer():\n"
        "    from service import load\n"
        "    def nested(value):\n"
        "        return load(value)\n"
        "    return nested\n"
    )

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]
    nested = next(item for item in evidence["definitions"] if item["name"] == "nested")
    callsite = next(item for item in evidence["callsites"] if item["caller_definition_id"] == nested["id"])
    observations = [item for item in evidence["observations"] if callsite["id"] in item["subject_ids"]]

    assert {item["kind"] for item in observations} == {"syntax_call", "import_declaration"}


def test_a_reexport_subject_range_is_the_exact_export_statement(tmp_path):
    source = "export { load } from './service';\nexport function other() { return 1; }\n"
    (tmp_path / "index.ts").write_text(source)
    (tmp_path / "service.ts").write_text("export function load() { return 1; }\n")

    subject = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["structural_subjects"][0]
    start, end = subject["source"]["range"]

    assert source[start:end] == "export { load } from './service';"


def test_a_top_level_registration_call_uses_an_explicit_file_scope_caller(tmp_path):
    (tmp_path / "app.py").write_text("register(handler)\n\ndef handler(value):\n    return value\n")

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]
    file_scope = next(item for item in evidence["definitions"] if item["name"] == "<file>")
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "register(handler)")

    assert file_scope["kind"] == "file"
    assert callsite["caller_definition_id"] == file_scope["id"]


def test_decorator_calls_belong_to_the_decorated_definition(tmp_path):
    (tmp_path / "app.py").write_text(
        "def require_admin(handler):\n    return handler\n\n@require_admin\ndef protected(value):\n    return value\n"
    )

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]
    protected = next(item for item in evidence["definitions"] if item["name"] == "protected")
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "@require_admin")

    assert callsite["caller_definition_id"] == protected["id"]
    assert [(item["name"], item["position"]) for item in protected["parameters"]] == [("value", 0)]
    start, end = protected["source"]["range"]
    assert (tmp_path / "app.py").read_text()[start:end].startswith("@require_admin")


def test_unaliased_go_import_is_a_raw_clue_for_a_receiver_call(tmp_path):
    source = 'package app\nimport "example.com/app/client-go"\nfunc Route() { client.Target() }\n'
    (tmp_path / "route.go").write_text(source)

    evidence = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "client.Target()")
    observation = next(
        item
        for item in evidence["observations"]
        if callsite["id"] in item["subject_ids"] and item["kind"] == "namespace_declaration"
    )
    sources = {item["id"]: item for item in evidence["sources"]}
    declaration = sources[observation["provenance_source_ids"][-1]]
    start, end = declaration["range"]

    assert source[start:end] == '"example.com/app/client-go"'


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
