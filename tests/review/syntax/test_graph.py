"""Syntax graph output keeps per file evidence and ambiguity visible."""

import pytest

from tests.review.syntax.support import syntax_facts, write_call_chain


def test_by_file_carries_each_file_own_graph_as_prompt_text(tmp_path):
    """The app/handler.py block shows its own calls and imports of load_order but not get_order."""
    write_call_chain(tmp_path)
    block = syntax_facts(tmp_path).by_file["app/handler.py"]
    assert "handle_request()" in block
    assert "calls load_order" in block
    assert "imports load_order" in block
    assert "get_order" not in block


def test_unresolved_import_remains_a_syntax_clue(tmp_path):
    """An import of Record from an absent package.models is still listed as an observed import."""
    (tmp_path / "views.py").write_text(
        "from package.models import Record\n\n\ndef view():\n    return Record.objects.all()\n",
        encoding="utf-8",
    )

    facts = syntax_facts(tmp_path)

    assert facts.import_files == ("views.py",)
    assert "observes imports Record from package.models" in facts.by_file["views.py"]


def test_import_only_repository_keeps_module_relationship_facts(tmp_path):
    """A lone index.ts with export * from a missing module still counts as an import file."""
    (tmp_path / "index.ts").write_text("export * from './missing';\n")

    facts = syntax_facts(tmp_path)

    assert facts.import_files == ("index.ts",)


def test_relationship_evidence_preserves_calls_but_does_not_assign_targets(tmp_path):
    """Both load() callsites are kept as candidates of service.load, not bound targets."""
    (tmp_path / "service.py").write_text("def load(x):\n    return x\n")
    (tmp_path / "route.py").write_text(
        "from service import load\n\ndef route(x):\n    first = load(x)\n    return load(x + 1)\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()

    assert [item["expression"] for item in evidence["callsites"]] == ["load(x)", "load(x + 1)"]
    assert all(item["candidate_target_ids"] == [] for item in evidence["observations"] if item["kind"] == "syntax_call")
    load = next(item for item in evidence["definitions"] if item["name"] == "load")
    relationships = syntax_facts(tmp_path).relationships.call_relationships
    assert all(item.target_status == "candidate" for item in relationships)
    assert all(item.candidate_callee_definition_ids == (load["id"],) for item in relationships)
    assert {item["kind"] for item in evidence["observations"] if item["kind"] != "syntax_call"} == {
        "import_declaration"
    }


def test_same_name_definitions_remain_visible_as_ambiguous_call_candidates(tmp_path):
    """A load() call with load defined in one.py and two.py lists both as candidates."""
    (tmp_path / "one.py").write_text("def load(value):\n    return value\n")
    (tmp_path / "two.py").write_text("def load(value):\n    return value + 1\n")
    (tmp_path / "route.py").write_text("def route(value):\n    return load(value)\n")

    evidence = syntax_facts(tmp_path).relationships.to_data()
    candidates = {item["id"] for item in evidence["definitions"] if item["name"] == "load"}
    relationship = syntax_facts(tmp_path).relationships.call_relationships[0]

    assert relationship.target_status == "candidate"
    assert set(relationship.candidate_callee_definition_ids) == candidates


def test_missing_definition_keeps_an_explicit_unresolved_call_target(tmp_path):
    """A call to an undefined external() is marked unresolved with no candidate definitions."""
    (tmp_path / "route.py").write_text("def route(value):\n    return external(value)\n")

    relationship = syntax_facts(tmp_path).relationships.call_relationships[0]

    assert relationship.target_status == "unresolved"
    assert relationship.candidate_callee_definition_ids == ()


def test_import_alias_remains_unresolved_with_its_declaration_clue(tmp_path):
    """A call via load as selected_load stays unresolved and carries the selected_load from one clue."""
    (tmp_path / "one.py").write_text("def load(value):\n    return value\n")
    (tmp_path / "two.py").write_text("def load(value):\n    return value + 1\n")
    (tmp_path / "route.py").write_text(
        "from one import load as selected_load\n\ndef route(value):\n    return selected_load(value)\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()
    callsite = next(item for item in evidence["callsites"] if item["callee_spelling"] == "selected_load")
    relationship = next(
        item for item in syntax_facts(tmp_path).relationships.call_relationships if item.callsite_id == callsite["id"]
    )
    declaration = next(
        item
        for item in evidence["observations"]
        if item["kind"] == "import_declaration" and callsite["id"] in item["subject_ids"]
    )

    assert relationship.target_status == "unresolved"
    assert relationship.candidate_callee_definition_ids == ()
    assert declaration["label"] == "selected_load from one"


def test_namespace_declaration_and_concrete_use_are_distinct_relationship_questions(tmp_path):
    """A namespace import and its service.load() use yield separate unresolved namespace and reference facts."""
    (tmp_path / "service.ts").write_text("export function load() { return true; }\n")
    (tmp_path / "route.ts").write_text(
        'import * as service from "./service";\nexport function route() { return service.load(); }\n'
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()

    assert any(item["kind"] == "namespace_declaration" for item in evidence["observations"])
    assert [(item["kind"], item["reference"]) for item in evidence["structural_relationships"]] == [
        ("namespace", "service from ./service"),
        ("reference", "service.load"),
    ]
    assert all(not item["candidate_target_definition_ids"] for item in evidence["structural_relationships"])
    assert all(item["target_status"] == "unresolved" for item in evidence["structural_relationships"])


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("models.py", "class Base:\n    pass\n\nclass Child(Base):\n    pass\n"),
        ("models.js", "class Base {}\nclass Child extends Base {}\n"),
        ("models.ts", "class Base {}\nclass Child extends Base {}\n"),
        ("models.tsx", "class Base {}\nclass Child extends Base {}\n"),
        ("models.sol", "contract Base {}\ncontract Child is Base {}\n"),
    ],
)
def test_class_inheritance_uses_one_cross_language_structural_contract(tmp_path, name, source):
    """Child extending Base in Python, JS, TS, TSX, and Solidity gives the same Base inheritance candidate."""
    (tmp_path / name).write_text(source)

    evidence = syntax_facts(tmp_path).relationships.to_data()
    child = next(item for item in evidence["definitions"] if item["name"] == "Child")
    base = next(item for item in evidence["definitions"] if item["name"] == "Base")
    relationship = next(item for item in evidence["structural_relationships"] if item["kind"] == "inheritance")
    start, end = relationship["source"]["range"]

    assert source[start:end] == "Base"
    assert relationship["reference"] == "Base"
    assert relationship["source_definition_id"] == child["id"]
    assert relationship["candidate_target_definition_ids"] == [base["id"]]
    assert relationship["target_status"] == "candidate"


def test_inheritance_candidates_include_types_only_and_keep_a_decorated_owner(tmp_path):
    """With a class and a function named Base, only the class is a candidate, and @decorate stays in Child's range."""
    source = (
        "def decorate(value):\n    return value\n\n"
        "class Base:\n    pass\n\n"
        "def Base():\n    pass\n\n"
        "@decorate\nclass Child(Base):\n    pass\n"
    )
    (tmp_path / "models.py").write_text(source)

    evidence = syntax_facts(tmp_path).relationships.to_data()
    definitions = {item["id"]: item for item in evidence["definitions"]}
    child = next(item for item in definitions.values() if item["name"] == "Child")
    relationship = next(item for item in evidence["structural_relationships"] if item["kind"] == "inheritance")

    assert source[child["source"]["range"][0] : child["source"]["range"][1]].startswith("@decorate")
    assert relationship["source_definition_id"] == child["id"]
    assert [definitions[item]["kind"] for item in relationship["candidate_target_definition_ids"]] == ["type"]


def test_an_outer_local_import_is_a_declaration_clue_for_a_nested_caller(tmp_path):
    """A load() call in nested() is linked to the from service import load inside outer()."""
    (tmp_path / "service.py").write_text("def load(value):\n    return value\n")
    (tmp_path / "route.py").write_text(
        "def outer():\n"
        "    from service import load\n"
        "    def nested(value):\n"
        "        return load(value)\n"
        "    return nested\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()
    nested = next(item for item in evidence["definitions"] if item["name"] == "nested")
    callsite = next(item for item in evidence["callsites"] if item["caller_definition_id"] == nested["id"])
    observations = [item for item in evidence["observations"] if callsite["id"] in item["subject_ids"]]

    assert {item["kind"] for item in observations} == {"syntax_call", "import_declaration"}


def test_an_imported_receiver_is_a_declaration_clue_for_its_member_call(tmp_path):
    """GlobalSearchView.as_view() is linked to the import of GlobalSearchView from views."""
    (tmp_path / "views.py").write_text("class GlobalSearchView:\n    pass\n")
    (tmp_path / "urls.py").write_text(
        "from views import GlobalSearchView\n\ndef route():\n    return GlobalSearchView.as_view()\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "GlobalSearchView.as_view()")
    observations = [item for item in evidence["observations"] if callsite["id"] in item["subject_ids"]]

    assert {item["kind"] for item in observations} == {"syntax_call", "import_declaration"}


def test_a_reexport_subject_range_is_the_exact_export_statement(tmp_path):
    """The re-export relationship range covers exactly the export { load } from './service' statement."""
    source = "export { load } from './service';\nexport function other() { return 1; }\n"
    (tmp_path / "index.ts").write_text(source)
    (tmp_path / "service.ts").write_text("export function load() { return 1; }\n")

    subject = syntax_facts(tmp_path).relationships.to_data()["structural_relationships"][0]
    start, end = subject["source"]["range"]

    assert source[start:end] == "export { load } from './service';"


def test_a_top_level_registration_call_uses_an_explicit_file_scope_caller(tmp_path):
    """A module-level register(handler) call is attributed to a <file> definition of kind file."""
    (tmp_path / "app.py").write_text("register(handler)\n\ndef handler(value):\n    return value\n")

    evidence = syntax_facts(tmp_path).relationships.to_data()
    file_scope = next(item for item in evidence["definitions"] if item["name"] == "<file>")
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "register(handler)")

    assert file_scope["kind"] == "file"
    assert callsite["caller_definition_id"] == file_scope["id"]


def test_decorator_calls_belong_to_the_decorated_definition(tmp_path):
    """The @require_admin callsite belongs to protected(), whose range starts at the decorator."""
    (tmp_path / "app.py").write_text(
        "def require_admin(handler):\n    return handler\n\n@require_admin\ndef protected(value):\n    return value\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()
    protected = next(item for item in evidence["definitions"] if item["name"] == "protected")
    callsite = next(item for item in evidence["callsites"] if item["expression"] == "@require_admin")

    assert callsite["caller_definition_id"] == protected["id"]
    start, end = protected["source"]["range"]
    assert (tmp_path / "app.py").read_text()[start:end].startswith("@require_admin")


def test_solidity_modifier_calls_belong_to_the_modified_function(tmp_path):
    """The onlyOwner modifier on withdraw is a callsite of withdraw whose candidate is the onlyOwner modifier."""
    (tmp_path / "Vault.sol").write_text(
        "contract Vault {\n"
        "    modifier onlyOwner() { require(msg.sender == owner); _; }\n"
        "    function withdraw() external onlyOwner {}\n"
        "}\n"
    )

    relationships = syntax_facts(tmp_path).relationships
    names = {item.id: item.name for item in relationships.definitions}
    callsite = next(item for item in relationships.callsites if item.callee_spelling == "onlyOwner")
    relationship = next(item for item in relationships.call_relationships if item.callsite_id == callsite.id)

    assert names[callsite.caller_definition_id] == "withdraw"
    assert [names[item] for item in relationship.candidate_callee_definition_ids] == ["onlyOwner"]


def test_solidity_named_import_is_a_declaration_clue_for_its_alias(tmp_path):
    """A call through Auth imported as {Ownable as Auth} carries the Auth from ./Ownable.sol clue."""
    (tmp_path / "Vault.sol").write_text(
        'import {Ownable as Auth} from "./Ownable.sol";\n'
        "contract Vault {\n"
        "    function check() external { Auth(owner).verify(); }\n"
        "}\n"
    )

    evidence = syntax_facts(tmp_path).relationships.to_data()
    callsite = next(item for item in evidence["callsites"] if item["callee_spelling"] == "Auth")
    declaration = next(
        item
        for item in evidence["observations"]
        if item["kind"] == "import_declaration" and callsite["id"] in item["subject_ids"]
    )

    assert declaration["label"] == "Auth from ./Ownable.sol"


def test_unaliased_go_import_is_a_raw_clue_for_a_receiver_call(tmp_path):
    """A Go client.Target() call cites the raw "example.com/app/client-go" import as its namespace clue."""
    source = 'package app\nimport "example.com/app/client-go"\nfunc Route() { client.Target() }\n'
    (tmp_path / "route.go").write_text(source)

    evidence = syntax_facts(tmp_path).relationships.to_data()
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
    """Service.load is recorded as a method whose owner_id is the Service class."""
    (tmp_path / "service.py").write_text("class Service:\n    def load(self, x):\n        return x\n")

    definitions = syntax_facts(tmp_path).relationships.to_data()["definitions"]
    owner = next(item for item in definitions if item["name"] == "Service")
    method = next(item for item in definitions if item["name"] == "load")

    assert method["kind"] == "method"
    assert method["owner_id"] == owner["id"]


def test_relationship_evidence_keeps_a_recursive_callsite(tmp_path):
    """The walk(node.parent) call inside walk() is kept as a callsite."""
    (tmp_path / "walk.py").write_text("def walk(node):\n    if node:\n        return walk(node.parent)\n")

    evidence = syntax_facts(tmp_path).relationships.to_data()

    assert [item["expression"] for item in evidence["callsites"]] == ["walk(node.parent)"]


def test_typescript_default_import_alias_call_and_import_edge_are_kept(tmp_path):
    """Facts keep the client(value) default-import call, the route.ts import edge, and tsconfig.json as a source."""
    (tmp_path / "service.ts").write_text("export default function actual(value: number) { return value; }\n")
    (tmp_path / "route.ts").write_text(
        "import client from './service';\nexport function route(value: number) { return client(value); }\n"
    )
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"@app/*":["./*"]}}}\n')

    evidence = syntax_facts(tmp_path).relationships

    assert any(callsite.expression == "client(value)" for callsite in evidence.callsites)
    assert any(
        relationship.kind == "import" and relationship.source.path == "route.ts"
        for relationship in evidence.structural_relationships
    )
    assert "tsconfig.json" in {source.path for source in evidence.sources}
