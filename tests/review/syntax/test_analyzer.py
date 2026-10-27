"""Syntax analysis preserves source ranges, lexical owners, and parsed call identities."""

from dataclasses import replace

import pytest
from tree_sitter import Language, Query

from cyberjury.review.syntax import analyzer as analyzer_module
from cyberjury.review.syntax.analyzer import (
    AnalyzerConfigurationError,
    analyze_repository,
    grammar_for,
    load_specs,
    spec_for,
)
from tests.review.syntax.support import callgraph, syntax_facts, write_call_chain


def test_specs_ship_a_grammar_and_every_query_per_language():
    """Each spec's queries compile against its grammar and declare the captures the analyzer reads."""
    specs = load_specs()
    assert set(specs) == {"c", "cpp", "go", "java", "javascript", "python", "rust", "solidity", "tsx", "typescript"}
    for name, spec in specs.items():
        language = Language(grammar_for(spec))
        queries = (
            spec.definitions,
            spec.calls,
            *(query.query for query in spec.imports),
            *spec.namespace_imports,
            *(query for query in (spec.type_definitions, spec.receivers, spec.qualified_uses) if query),
            *(relationship.query for relationship in spec.structural_relationships),
        )
        for query in queries:
            Query(language, query)
        assert spec.extensions, name
        assert "@def" in spec.definitions, name
        assert "@name" in spec.definitions, name
        assert "@target" not in spec.definitions, name
        assert "@callee" in spec.calls, name
        assert "@member" in spec.calls, name
        for query in spec.imports:
            assert "@module" in query.query, name
            assert "@statement" in query.query, name
            assert "@imported" in query.query or query.imported, name
        for query in spec.namespace_imports:
            assert "@module" in query, name
            assert "@statement" in query, name
        for relationship in spec.structural_relationships:
            assert relationship.kind == "inheritance", name
            assert "@owner" in relationship.query, name
            assert "@owner_name" in relationship.query, name
            assert "@reference" in relationship.query, name
            assert "@target_name" in relationship.query, name


def test_python_and_javascript_family_ship_imports_queries():
    """Python, JavaScript, TypeScript, and TSX define import queries."""
    specs = load_specs()
    for name in ("python", "javascript", "typescript", "tsx"):
        assert specs[name].imports, name


def test_a_syntax_error_keeps_the_partial_graph_and_records_a_limitation(tmp_path):
    """A NUL byte inside a TS template literal keeps render.ts in the graph with a partially parsed limitation."""
    source = b"export function render(value: string) {\n  return `${value}\x00${value}`;\n}\n"
    path = tmp_path / "render.ts"
    path.write_bytes(source)
    (tmp_path / "ok.ts").write_text("export function ok() { return true; }\n")

    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"ok.ts", "render.ts"}
    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("render.ts", "typescript", "partially parsed")
    ]


def test_an_unexpected_error_in_one_file_becomes_its_limitation(tmp_path, monkeypatch):
    """A KeyError while analyzing bad.py becomes its limitation, and ok.py keeps its graph."""
    (tmp_path / "bad.py").write_text("def bad():\n    return 1\n")
    (tmp_path / "ok.py").write_text("def ok():\n    return True\n")
    parse_file = analyzer_module.parse_file

    def failing_parse(path, rel, spec):
        if rel == "bad.py":
            raise KeyError("unexpected")
        return parse_file(path, rel, spec)

    monkeypatch.setattr(analyzer_module, "parse_file", failing_parse)

    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"ok.py"}
    assert [(item.source, item.reason) for item in facts.limitations] == [("bad.py", "analysis failed (KeyError)")]


def test_a_syntax_error_placeholder_never_becomes_an_empty_name(tmp_path):
    """A Python call typo `x.(1)` yields a partially parsed limitation, and facts extraction still succeeds."""
    (tmp_path / "app.py").write_text("def run(x):\n    y = x.(1)\n    return y\n")

    facts = syntax_facts(tmp_path)

    assert [(item.source, item.reason) for item in facts.limitations] == [("app.py", "partially parsed")]
    assert [item["name"] for item in facts.relationships.to_dict()["definitions"]] == ["run"]


def test_a_three_edge_call_chain_is_recovered_edge_by_edge(tmp_path):
    """get_order calls handle_request, handle_request calls load_order, and load_order calls run_query."""
    graph = callgraph(write_call_chain(tmp_path))
    assert graph["app/routes.py"]["get_order"][0]["calls"] == ["handle_request"]
    assert graph["app/handler.py"]["handle_request"][0]["calls"] == ["load_order"]
    assert graph["app/repository.py"]["load_order"][0]["calls"] == ["run_query"]


def test_a_structural_query_missing_a_capture_is_a_configuration_error(tmp_path):
    """A Python inheritance query without @owner_name raises AnalyzerConfigurationError before any file is parsed."""
    specs = load_specs()
    configured = specs["python"].structural_relationships[0]
    specs["python"] = replace(
        specs["python"],
        structural_relationships=(replace(configured, query=configured.query.replace(" @owner_name", "")),),
    )
    (tmp_path / "app.py").write_text("class Child(Base):\n    pass\n")

    with pytest.raises(AnalyzerConfigurationError, match="lacks required captures"):
        analyze_repository([(tmp_path / "app.py", "app.py", specs["python"])])


def _functions_only_python(tmp_path, files):
    specs = load_specs()
    python = replace(specs["python"], definitions="(function_definition name: (identifier) @name) @def\n")
    inputs = []
    for name, source in files.items():
        (tmp_path / name).write_text(source)
        inputs.append((tmp_path / name, name, python))
    return analyze_repository(inputs)


def test_an_unexpected_structural_capture_in_one_file_becomes_its_limitation(tmp_path):
    """A class base whose owner is not a definition limits models.py only, and ok.py keeps its facts."""
    analyzed = _functions_only_python(
        tmp_path, {"models.py": "class Child(Base):\n    pass\n", "ok.py": "def ok():\n    return 1\n"}
    )

    assert {definition.file for definition in analyzed.definitions} == {"ok.py"}
    assert [(item.source, item.reason) for item in analyzed.limitations] == [
        ("models.py", "structural relationship has no unique definition owner")
    ]


def test_an_unexpected_structural_capture_in_a_broken_file_is_reported_at_its_syntax_error(tmp_path):
    """The same capture problem in a file with a syntax error drops models.py as analysis failed at line 3."""
    analyzed = _functions_only_python(tmp_path, {"models.py": "class Child(Base):\n    pass\ndef broken(:\n"})

    assert "models.py" not in analyzed.sources
    assert [(item.source, item.reason, item.line) for item in analyzed.limitations] == [
        ("models.py", "analysis failed after a syntax error", 3)
    ]


def _python_with_structural_query(query):
    specs = load_specs()
    configured = specs["python"].structural_relationships[0]
    return replace(specs["python"], structural_relationships=(replace(configured, query=query),))


def test_a_structural_match_missing_a_capture_becomes_a_file_limitation(tmp_path):
    """An attribute base matched without @target_name limits models.py with incomplete captures."""
    spec = _python_with_structural_query(
        "(class_definition name: (identifier) @owner_name superclasses: (argument_list"
        " [(identifier) @reference @target_name (attribute) @reference])) @owner"
    )
    (tmp_path / "models.py").write_text("class Child(base.Base):\n    pass\n")

    analyzed = analyze_repository([(tmp_path / "models.py", "models.py", spec)])

    assert [(item.source, item.reason) for item in analyzed.limitations] == [
        ("models.py", "structural relationship captures are incomplete")
    ]


def test_a_structural_reference_outside_its_owner_becomes_a_file_limitation(tmp_path):
    """A reference captured after its owning class limits models.py with a reference outside its owner."""
    spec = _python_with_structural_query(
        "(module (class_definition name: (identifier) @owner_name) @owner"
        " (expression_statement (identifier) @reference @target_name))"
    )
    (tmp_path / "models.py").write_text("class Child:\n    pass\nBase\n")

    analyzed = analyze_repository([(tmp_path / "models.py", "models.py", spec)])

    assert [(item.source, item.reason) for item in analyzed.limitations] == [
        ("models.py", "structural relationship source is outside its owner")
    ]


def test_definition_target_query_rejects_an_unknown_grammar_node(tmp_path):
    """A misspelled node type in the definitions query raises AnalyzerConfigurationError "invalid query"."""
    specs = load_specs()
    specs["python"] = replace(
        specs["python"],
        definitions="(function_declration name: (identifier) @name) @def",
    )
    (tmp_path / "app.py").write_text("def check():\n    return True\n")

    with pytest.raises(AnalyzerConfigurationError, match="invalid query"):
        analyze_repository([(tmp_path / "app.py", "app.py", specs["python"])])


@pytest.mark.parametrize(
    ("name", "source", "definitions", "calls"),
    [
        (
            "lib.rs",
            "struct User { id: u32 }\nimpl User {\n    fn load(&self) -> u32 { helper(self.id) }\n}\n"
            "fn helper(x: u32) -> u32 { x }\n",
            {"User", "load", "helper"},
            {"helper"},
        ),
        (
            "App.java",
            "class App extends Base {\n  void load() { helper(1); }\n  void helper(int x) {}\n}\n",
            {"App", "load", "helper"},
            {"helper"},
        ),
        (
            "app.c",
            "struct user { int id; };\nstatic int helper(int x) { return x; }\nint load(int x) { return helper(x); }\n",
            {"user", "helper", "load"},
            {"helper"},
        ),
        (
            "app.cpp",
            "namespace app {\nclass User : public Base {\n public:\n  int load() { return helper(1); }\n};\n}\n"
            "int helper(int x) { return x; }\n",
            {"app", "User", "load", "helper"},
            {"helper"},
        ),
    ],
)
def test_rust_java_c_and_cpp_sources_yield_definitions_and_calls(tmp_path, name, source, definitions, calls):
    """A Rust, Java, C, or C++ file parses into its named definitions and the calls between them."""
    (tmp_path / name).write_text(source, encoding="utf-8")

    facts = syntax_facts(tmp_path)

    assert not facts.limitations
    assert definitions <= {definition.name for definition in facts.relationships.definitions}
    assert calls <= {callsite.callee_spelling for callsite in facts.relationships.callsites}


def test_solidity_contracts_yield_member_value_and_library_calls(tmp_path):
    """A withdraw function's value call, interface call, and library call keep their callees and receivers."""
    (tmp_path / "Vault.sol").write_text(
        "contract Vault {\n"
        "    function withdraw(address to, uint256 a) external {\n"
        '        (bool ok, ) = to.call{value: a}("");\n'
        "        IERC20(token).safeTransfer(to, a);\n"
        "        Lib.check(a);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    facts = syntax_facts(tmp_path)

    assert not facts.limitations
    assert {(item.callee_spelling, item.receiver_expression) for item in facts.relationships.callsites} >= {
        ("call", "to"),
        ("safeTransfer", "IERC20(token)"),
        ("check", "Lib"),
    }


def test_solidity_file_level_struct_and_enum_are_type_definitions(tmp_path):
    """A file-level struct TakeResult and enum Side are searchable type definitions."""
    (tmp_path / "Types.sol").write_text(
        "struct TakeResult {\n    uint256 amount;\n}\n\nenum Side { Buy, Sell }\n",
        encoding="utf-8",
    )

    facts = syntax_facts(tmp_path)

    assert {(item.name, item.kind) for item in facts.relationships.definitions} >= {
        ("TakeResult", "type"),
        ("Side", "type"),
    }


def test_one_extension_maps_to_one_language():
    """No file extension is claimed by more than one language spec."""
    seen: dict[str, str] = {}
    for name, spec in load_specs().items():
        for ext in spec.extensions:
            assert ext not in seen, f"{ext} claimed by both {seen.get(ext)} and {name}"
            seen[ext] = name


def test_invalid_utf8_source_is_a_facts_limitation(tmp_path):
    """A 0xff byte in app.py yields a "not valid UTF-8" limitation and only ok.py keeps facts."""
    (tmp_path / "app.py").write_bytes(b"def route():\n    return 1\n# \xff\n")
    (tmp_path / "ok.py").write_text("def ok():\n    return 1\n")

    facts = syntax_facts(tmp_path)

    assert [limitation.message for limitation in facts.limitations] == ["app.py: python not valid UTF-8"]
    assert set(facts.by_file) == {"ok.py"}


def test_a_definition_range_cuts_the_whole_definition_from_its_own_source(tmp_path):
    """The range of target() slices exactly its two lines out of a file with neighbouring functions."""
    (tmp_path / "m.py").write_text(
        "def before():\n    return 0\n\n\ndef target():\n    return run_query()\n\n\ndef after():\n    return 2\n"
    )
    start, end = callgraph(tmp_path)["m.py"]["target"][0]["range"]
    cut = (tmp_path / "m.py").read_text()[start:end]
    assert cut == "def target():\n    return run_query()"


def test_a_range_is_char_offsets_even_when_an_earlier_line_is_not_ascii(tmp_path):
    """With "café" on an earlier line, the drink() range starts at its str index, not byte offset."""
    (tmp_path / "a.py").write_text('HEADER = "café"\n\n\ndef drink(x):\n    return 2\n')
    text = (tmp_path / "a.py").read_text()
    start, end = callgraph(tmp_path)["a.py"]["drink"][0]["range"]
    assert start == text.index("def drink")
    assert text[start:end].startswith("def drink")


def test_a_range_survives_crlf_line_endings(tmp_path):
    """In a CRLF file the sink() range starts at the str index of "def sink"."""
    (tmp_path / "a.py").write_text("A = 1\r\nB = 2\r\nC = 3\r\n\r\ndef sink(x):\r\n    return x\r\n", newline="")
    text = (tmp_path / "a.py").read_text()
    start, end = callgraph(tmp_path)["a.py"]["sink"][0]["range"]
    assert start == text.index("def sink")
    assert text[start:end].startswith("def sink")


def test_a_method_call_resolves_to_the_bare_callee_name(tmp_path):
    """A TS call service.readOne(key) is recorded as the callee "readOne"."""
    (tmp_path / "a.ts").write_text("function outer() {\n  return service.readOne(key);\n}\n")
    assert callgraph(tmp_path)["a.ts"]["outer"][0]["calls"] == ["readOne"]


def test_an_untyped_member_call_remains_unresolved_syntax(tmp_path):
    """A client.get() call with two classes defining get records the bare callee "get"."""
    (tmp_path / "views.py").write_text(
        "class A:\n    def get(self):\n        return 1\n\n"
        "class B:\n    def get(self):\n        return 2\n\n"
        "def view(client):\n    return client.get()\n"
    )

    assert callgraph(tmp_path)["views.py"]["view"][0]["calls"] == ["get"]


def test_a_local_receiver_call_remains_a_syntax_observation(tmp_path):
    """A self.inner() call records the bare callee "inner"."""
    (tmp_path / "service.py").write_text(
        "class Service:\n    def outer(self):\n        return self.inner()\n\n    def inner(self):\n        return 1\n"
    )

    assert callgraph(tmp_path)["service.py"]["outer"][0]["calls"] == ["inner"]


def test_python_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    """A Python walk() calling itself keeps "walk" in its own call list."""
    (tmp_path / "r.py").write_text("def walk(n):\n    return walk(n - 1)\n")
    assert callgraph(tmp_path)["r.py"]["walk"][0]["calls"] == ["walk"]


def test_typescript_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    """A TypeScript walk() calling itself keeps "walk" in its own call list."""
    (tmp_path / "r.ts").write_text("function walk(n) {\n  return walk(n - 1);\n}\n")
    assert callgraph(tmp_path)["r.ts"]["walk"][0]["calls"] == ["walk"]


def test_go_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    """A Go walk() calling itself keeps "walk" in its own call list."""
    (tmp_path / "r.go").write_text("package main\nfunc walk(n int) int { return walk(n - 1) }\n")
    assert callgraph(tmp_path)["r.go"]["walk"][0]["calls"] == ["walk"]


def test_same_name_attribute_call_is_not_filtered_as_recursion(tmp_path):
    """A memories.update_memory_by_id() call inside update_memory_by_id() stays in that function's calls."""
    (tmp_path / "route.py").write_text(
        "def update_memory_by_id(memories, memory_id):\n    return memories.update_memory_by_id(memory_id)\n"
    )
    assert callgraph(tmp_path)["route.py"]["update_memory_by_id"][0]["calls"] == ["update_memory_by_id"]


def test_same_name_member_call_is_not_filtered_as_recursion(tmp_path):
    """A store.save() call inside a TypeScript save() stays in that function's calls."""
    (tmp_path / "route.ts").write_text("function save(store) {\n  return store.save();\n}\n")
    assert callgraph(tmp_path)["route.ts"]["save"][0]["calls"] == ["save"]


def test_same_name_go_selector_call_is_not_filtered_as_recursion(tmp_path):
    """A store.save() call inside a Go save() stays in that function's calls."""
    (tmp_path / "route.go").write_text("package main\nfunc save(store Store) { store.save() }\n")
    assert callgraph(tmp_path)["route.go"]["save"][0]["calls"] == ["save"]


def test_two_definitions_sharing_a_name_in_one_file_both_survive(tmp_path):
    """Two __init__ methods in classes A and B yield two entries, each ranging over its own body."""
    (tmp_path / "m.py").write_text(
        "class A:\n    def __init__(self):\n        self.a = 1\n\n\n"
        "class B:\n    def __init__(self):\n        self.b = 2\n"
    )
    entries = callgraph(tmp_path)["m.py"]["__init__"]
    assert len(entries) == 2
    text = (tmp_path / "m.py").read_text()
    assert [text[e["range"][0] : e["range"][1]].count("self.a") for e in entries] == [1, 0]


def test_a_callee_comes_from_the_parsed_node_not_a_re_parse_of_its_source(tmp_path):
    """An async TS class method post() records its call to save rather than a misparsed name."""
    (tmp_path / "a.ts").write_text("class Svc {\n  async post(k) { return save(k); }\n}\n")
    assert callgraph(tmp_path)["a.ts"]["post"][0]["calls"] == ["save"]


def test_a_class_counts_as_a_definition_so_its_methods_ride_along(tmp_path):
    """The range of class Resp includes the text of its set_status method."""
    (tmp_path / "m.py").write_text("class Resp:\n    def set_status(self, s):\n        self.s = s\n")
    start, end = callgraph(tmp_path)["m.py"]["Resp"][0]["range"]
    assert "set_status" in (tmp_path / "m.py").read_text()[start:end]


def test_references_inside_a_decorated_definition_keep_their_owner(tmp_path):
    """An os.path.join reference under an @route-decorated handler is owned by handler, as it is in plain."""
    (tmp_path / "app.py").write_text(
        'import os\n\n@route("/x")\ndef handler(name):\n    return os.path.join("a", name)\n\n'
        'def plain(name):\n    return os.path.join("b", name)\n'
    )
    evidence = syntax_facts(tmp_path).relationships
    names = {definition.id: definition.name for definition in evidence.definitions}

    owners = sorted(
        names.get(relationship.source_definition_id, "")
        for relationship in evidence.structural_relationships
        if relationship.kind == "reference" and relationship.reference == "os.path.join"
    )

    assert owners == ["handler", "plain"]


def test_a_syntactically_broken_file_preserves_other_facts(tmp_path):
    """A broken.py yields a limitation with line and column while ok.py keeps its call graph."""
    (tmp_path / "broken.py").write_text("def f(:\n  ???\n")
    (tmp_path / "ok.py").write_text("def g():\n    return 1\n")
    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"ok.py"}
    assert facts.limitations[0].source == "broken.py"
    assert facts.limitations[0].line is not None
    assert facts.limitations[0].column is not None


def test_parse_limitation_column_uses_characters_after_non_ascii_text(tmp_path):
    """After "é" on line 1, the error column is the character index of "function" plus one."""
    source = 'const x = "é"; function broken( {\n'
    (tmp_path / "broken.js").write_text(source)

    limitation = syntax_facts(tmp_path).limitations[0]

    assert limitation.line == 1
    assert limitation.column == source.index("function") + 1


@pytest.mark.parametrize(
    ("name", "source", "analyzer"),
    [
        ("broken.py", "def broken(:\n", "python"),
        ("broken.js", "function broken( {\n", "javascript"),
        ("broken.ts", "function broken( {\n", "typescript"),
        ("broken.tsx", "function broken( {\n", "tsx"),
        ("broken.go", "package main\nfunc broken( {\n", "go"),
        ("broken.rs", "fn broken( {\n", "rust"),
        ("broken.java", "class Broken { void broken( { }\n", "java"),
        ("broken.c", "int broken( {\n", "c"),
        ("broken.cpp", "int broken( {\n", "cpp"),
        ("broken.sol", "contract Broken { function broken( {\n", "solidity"),
    ],
)
def test_every_tree_sitter_language_uses_one_parse_limitation_contract(tmp_path, name, source, analyzer):
    """A broken file in each language yields the same (source, analyzer, "partially parsed") limitation."""
    (tmp_path / name).write_text(source)

    limitation = syntax_facts(tmp_path).limitations[0]

    assert (limitation.source, limitation.analyzer, limitation.reason) == (name, analyzer, "partially parsed")


def test_go_receiver_function_is_a_method(tmp_path):
    """A Go func with a *Store receiver named Load is recorded with kind "method"."""
    (tmp_path / "service.go").write_text(
        "package service\ntype Store struct{}\nfunc (store *Store) Load(value int) int { return value }\n"
    )

    definitions = syntax_facts(tmp_path).relationships.to_dict()["definitions"]
    method = next(item for item in definitions if item["name"] == "Load")

    assert method["kind"] == "method"


def test_an_unsupported_typescript_export_does_not_abort_other_files(tmp_path):
    """A barrel.ts with "export type * from" yields one typescript limitation while ok.ts keeps facts."""
    (tmp_path / "barrel.ts").write_text("export type * from './model';\n")
    (tmp_path / "model.ts").write_text("export interface Model { id: string }\n")
    (tmp_path / "ok.ts").write_text("export function ok() { return true; }\n")

    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"ok.ts"}
    assert [(item.source, item.analyzer) for item in facts.limitations] == [("barrel.ts", "typescript")]


def test_native_analyzer_recovers_the_cross_language_structure(tmp_path):
    """Python, JS, TS, and Go sources yield the expected definitions, callsites, and Go receivers."""
    sources = {
        "service.py": (
            "class Service:\n"
            "    def load(self, value):\n"
            "        return helper(value)\n\n"
            "def helper(value):\n"
            "    return value\n"
        ),
        "route.js": "export function route(input) { return service.load(input); }\n",
        "save.ts": "export function save(value: string) { return helper(value); }\n",
        "store.go": (
            "package store\n"
            "type Store struct{}\n"
            "func (store *Store) Load(value int) int { return helper(value) }\n"
            "func helper(value int) int { return value }\n"
        ),
    }
    specs = load_specs()
    analyzer_inputs = []
    for name, source in sources.items():
        path = tmp_path / name
        path.write_text(source)
        spec = spec_for(specs, name)
        assert spec is not None
        analyzer_inputs.append((path, name, spec))

    analyzed = analyze_repository(list(reversed(analyzer_inputs)))
    definitions = {(item.file, item.name): item for item in analyzed.definitions}

    assert set(definitions) == {
        ("service.py", "Service"),
        ("service.py", "load"),
        ("service.py", "helper"),
        ("route.js", "route"),
        ("save.ts", "save"),
        ("store.go", "Store"),
        ("store.go", "Load"),
        ("store.go", "helper"),
    }
    expected_calls = {
        ("service.py", "load"): ("helper", "helper(value)"),
        ("route.js", "route"): ("load", "service.load(input)"),
        ("save.ts", "save"): ("helper", "helper(value)"),
        ("store.go", "Load"): ("helper", "helper(value)"),
    }
    for identity, (callee, expression) in expected_calls.items():
        definition = definitions[identity]
        assert definition.calls == (callee,)
        assert [(call.callee, call.expression) for call in definition.callsites] == [(callee, expression)]
    assert definitions[("store.go", "Load")].has_receiver
    assert not definitions[("store.go", "helper")].has_receiver
    for (file, _name), definition in definitions.items():
        body = analyzed.sources[file][definition.start : definition.end]
        assert body


def test_native_analyzer_output_does_not_depend_on_input_enumeration(tmp_path):
    """Analyzing a.py and b.py in either order returns equal results."""
    specs = load_specs()
    inputs = []
    for name, source in (
        ("b.py", "def second():\n    return first()\n"),
        ("a.py", "def first():\n    return 1\n"),
    ):
        path = tmp_path / name
        path.write_text(source)
        spec = spec_for(specs, name)
        assert spec is not None
        inputs.append((path, name, spec))

    assert analyze_repository(inputs) == analyze_repository(list(reversed(inputs)))
