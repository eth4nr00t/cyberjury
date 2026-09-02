"""Web analysis preserves source ranges, lexical owners, and parsed call identities."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.profiles.web.facts.analyzer import MAX_SOURCE_BYTES, analyze_repository, load_specs, spec_for
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import BackendUnavailable


def _graph(root):
    return TreeSitterFacts().extract(root).data["graph"]["callgraph"]


def test_specs_ship_a_grammar_and_every_query_per_language():
    specs = load_specs()
    assert {"python", "javascript", "typescript", "tsx", "go"} <= set(specs)
    for name, spec in specs.items():
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


def test_every_language_whose_imports_name_a_symbol_ships_an_imports_query():
    specs = load_specs()
    for name in ("python", "javascript", "typescript", "tsx"):
        assert specs[name].imports, name
    assert specs["go"].imports == ()


def test_language_specs_contain_syntax_configuration_only():
    specs = load_specs()

    forbidden = {
        "resolution_languages",
        "unqualified_call_scope",
        "package_name_query",
        "module_entries",
        "local_receivers",
        "default_exports",
        "namespace_resolves_directory",
        "namespace_binds",
    }
    assert all(not forbidden.intersection(vars(spec)) for spec in specs.values())


def test_nul_parse_failure_becomes_a_source_limitation(tmp_path):
    source = b"export function render(value: string) {\n  return `${value}\x00${value}`;\n}\n"
    path = tmp_path / "render.ts"
    path.write_bytes(source)
    (tmp_path / "ok.ts").write_text("export function ok() { return true; }\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert set(facts.data["graph"]["callgraph"]) == {"ok.ts"}
    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("render.ts", "typescript", "unparsable")
    ]
    assert facts.complete is False


def test_nul_in_code_uses_the_same_source_limitation_contract(tmp_path):
    (tmp_path / "render.ts").write_bytes(b"export function \x00render() { return true; }\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert facts.limitations[0].source == "render.ts"
    assert facts.limitations[0].reason == "unparsable"


def test_definition_query_requires_the_name_capture(tmp_path):
    config = tmp_path / "queries.yaml"
    config.write_text(
        "python:\n"
        "  extensions: ['.py']\n"
        "  grammar: [tree_sitter_python, language]\n"
        "  definitions: '(function_definition) @def'\n"
        "  calls: '(call function: (identifier) @callee arguments: (argument_list) @arguments) @call'\n"
    )

    with pytest.raises(ValueError, match="definitions must declare captures: @name"):
        load_specs(config)


def test_definition_query_does_not_require_a_relationship_target_capture(tmp_path):
    config = tmp_path / "queries.yaml"
    config.write_text(
        "python:\n"
        "  extensions: ['.py']\n"
        "  grammar: [tree_sitter_python, language]\n"
        "  definitions: '(function_definition name: (identifier) @name) @def'\n"
        "  calls: '(call function: (identifier) @callee arguments: (argument_list) @arguments) @call'\n"
    )

    assert load_specs(config)["python"].definitions.endswith("@def")


def test_definition_target_query_rejects_an_unknown_grammar_node(tmp_path):
    specs = load_specs()
    specs["python"] = replace(
        specs["python"],
        definitions="(function_declration name: (identifier) @name) @def",
    )
    (tmp_path / "app.py").write_text("def check():\n    return True\n")

    with pytest.raises(BackendUnavailable, match="invalid query"):
        TreeSitterFacts(specs).extract(tmp_path)


def test_one_extension_maps_to_one_language():
    seen: dict[str, str] = {}
    for name, spec in load_specs().items():
        for ext in spec.extensions:
            assert ext not in seen, f"{ext} claimed by both {seen.get(ext)} and {name}"
            seen[ext] = name


def test_query_loader_rejects_cross_language_extension_collisions(tmp_path):
    config = tmp_path / "queries.yaml"
    language = (
        "  extensions: ['.x']\n"
        "  grammar: [tree_sitter_python, language]\n"
        "  definitions: '(function_definition name: (identifier) @name) @def'\n"
        "  calls: '(call function: (identifier) @callee arguments: (argument_list) @arguments) @call'\n"
    )
    config.write_text("one:\n" + language.format(name="one") + "two:\n" + language.format(name="two"))

    with pytest.raises(ValueError, match="owned by both"):
        load_specs(config)


def test_query_loader_rejects_calls_without_supported_captures(tmp_path):
    config = tmp_path / "queries.yaml"
    config.write_text(
        "python:\n"
        "  extensions: ['.py']\n"
        "  grammar: [tree_sitter_python, language]\n"
        "  definitions: '(function_definition name: (identifier) @name) @def'\n"
        "  calls: '(call function: (identifier))'\n"
    )

    with pytest.raises(ValueError, match="callee or member"):
        load_specs(config)


def test_query_loader_rejects_optional_queries_without_required_captures(tmp_path):
    config = tmp_path / "queries.yaml"
    config.write_text(
        "python:\n"
        "  extensions: ['.py']\n"
        "  grammar: [tree_sitter_python, language]\n"
        "  definitions: '(function_definition name: (identifier) @name) @def'\n"
        "  type_definitions: '(class_definition) @type'\n"
        "  calls: '(call function: (identifier) @callee) @call'\n"
    )

    with pytest.raises(ValueError, match=r"type_definitions must declare captures: @name"):
        load_specs(config)


def test_invalid_utf8_source_fails_extraction_loudly(tmp_path):
    (tmp_path / "app.py").write_bytes(b"def route():\n    return 1\n# \xff\n")

    with pytest.raises(BackendUnavailable, match="not valid UTF-8"):
        TreeSitterFacts().extract(tmp_path)


def test_a_definition_range_cuts_the_whole_definition_from_its_own_source(tmp_path):
    (tmp_path / "m.py").write_text(
        "def before():\n    return 0\n\n\ndef target():\n    return run_query()\n\n\ndef after():\n    return 2\n"
    )
    start, end = _graph(tmp_path)["m.py"]["target"][0]["range"]
    cut = (tmp_path / "m.py").read_text()[start:end]
    assert cut == "def target():\n    return run_query()"


def test_a_range_is_char_offsets_even_when_an_earlier_line_is_not_ascii(tmp_path):
    (tmp_path / "a.py").write_text('HEADER = "café"\n\n\ndef drink(x):\n    return 2\n')
    text = (tmp_path / "a.py").read_text()
    start, end = _graph(tmp_path)["a.py"]["drink"][0]["range"]
    assert start == text.index("def drink")
    assert text[start:end].startswith("def drink")


def test_a_range_survives_crlf_line_endings(tmp_path):
    (tmp_path / "a.py").write_text("A = 1\r\nB = 2\r\nC = 3\r\n\r\ndef sink(x):\r\n    return x\r\n", newline="")
    text = (tmp_path / "a.py").read_text()
    start, end = _graph(tmp_path)["a.py"]["sink"][0]["range"]
    assert start == text.index("def sink")
    assert text[start:end].startswith("def sink")


def test_a_method_call_resolves_to_the_bare_callee_name(tmp_path):
    (tmp_path / "a.ts").write_text("function outer() {\n  return service.readOne(key);\n}\n")
    assert _graph(tmp_path)["a.ts"]["outer"][0]["calls"] == ["readOne"]


def test_an_untyped_member_call_remains_unresolved_syntax(tmp_path):
    (tmp_path / "views.py").write_text(
        "class A:\n    def get(self):\n        return 1\n\n"
        "class B:\n    def get(self):\n        return 2\n\n"
        "def view(client):\n    return client.get()\n"
    )

    facts = TreeSitterFacts().extract(tmp_path)
    graph = facts.data["graph"]
    observations = facts.data["relationship_evidence"]["observations"]

    assert graph["callgraph"]["views.py"]["view"][0]["calls"] == ["get"]
    assert all(item["candidate_target_ids"] == [] for item in observations)


def test_a_local_receiver_call_remains_a_syntax_observation(tmp_path):
    (tmp_path / "service.py").write_text(
        "class Service:\n    def outer(self):\n        return self.inner()\n\n    def inner(self):\n        return 1\n"
    )

    facts = TreeSitterFacts().extract(tmp_path)

    assert facts.data["graph"]["callgraph"]["service.py"]["outer"][0]["calls"] == ["inner"]
    assert all(item["candidate_target_ids"] == [] for item in facts.data["relationship_evidence"]["observations"])


def test_python_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    (tmp_path / "r.py").write_text("def walk(n):\n    return walk(n - 1)\n")
    assert _graph(tmp_path)["r.py"]["walk"][0]["calls"] == ["walk"]


def test_typescript_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    (tmp_path / "r.ts").write_text("function walk(n) {\n  return walk(n - 1);\n}\n")
    assert _graph(tmp_path)["r.ts"]["walk"][0]["calls"] == ["walk"]


def test_go_recursion_is_preserved_as_an_unresolved_call_clue(tmp_path):
    (tmp_path / "r.go").write_text("package main\nfunc walk(n int) int { return walk(n - 1) }\n")
    assert _graph(tmp_path)["r.go"]["walk"][0]["calls"] == ["walk"]


def test_same_name_attribute_call_is_not_filtered_as_recursion(tmp_path):
    (tmp_path / "route.py").write_text(
        "def update_memory_by_id(memories, memory_id):\n    return memories.update_memory_by_id(memory_id)\n"
    )
    assert _graph(tmp_path)["route.py"]["update_memory_by_id"][0]["calls"] == ["update_memory_by_id"]


def test_same_name_member_call_is_not_filtered_as_recursion(tmp_path):
    (tmp_path / "route.ts").write_text("function save(store) {\n  return store.save();\n}\n")
    assert _graph(tmp_path)["route.ts"]["save"][0]["calls"] == ["save"]


def test_same_name_go_selector_call_is_not_filtered_as_recursion(tmp_path):
    (tmp_path / "route.go").write_text("package main\nfunc save(store Store) { store.save() }\n")
    assert _graph(tmp_path)["route.go"]["save"][0]["calls"] == ["save"]


def test_two_definitions_sharing_a_name_in_one_file_both_survive(tmp_path):
    (tmp_path / "m.py").write_text(
        "class A:\n    def __init__(self):\n        self.a = 1\n\n\n"
        "class B:\n    def __init__(self):\n        self.b = 2\n"
    )
    entries = _graph(tmp_path)["m.py"]["__init__"]
    assert len(entries) == 2
    text = (tmp_path / "m.py").read_text()
    assert [text[e["range"][0] : e["range"][1]].count("self.a") for e in entries] == [1, 0]


def test_a_callee_comes_from_the_parsed_node_not_a_re_parse_of_its_source(tmp_path):
    (tmp_path / "a.ts").write_text("class Svc {\n  async post(k) { return save(k); }\n}\n")
    assert _graph(tmp_path)["a.ts"]["post"][0]["calls"] == ["save"]


def test_a_class_counts_as_a_definition_so_its_methods_ride_along(tmp_path):
    (tmp_path / "m.py").write_text("class Resp:\n    def set_status(self, s):\n        self.s = s\n")
    start, end = _graph(tmp_path)["m.py"]["Resp"][0]["range"]
    assert "set_status" in (tmp_path / "m.py").read_text()[start:end]


def test_tests_and_noise_directories_are_left_out(tmp_path):
    (tmp_path / "keep.py").write_text("def keep():\n    return 1\n")
    (tmp_path / "test_skip.py").write_text("def test_skip():\n    return 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("function dep() {}\n")
    assert set(_graph(tmp_path)) == {"keep.py"}


def test_a_file_over_the_parse_cap_preserves_other_facts(tmp_path):
    limit = MAX_SOURCE_BYTES
    (tmp_path / "huge.py").write_text("def f():\n    return 1\n" + "PAD = 1\n" * (limit // 8))
    (tmp_path / "small.py").write_text("def g():\n    return 1\n")
    facts = TreeSitterFacts().extract(tmp_path)

    assert set(facts.data["graph"]["callgraph"]) == {"small.py"}
    assert [(item.source, item.reason) for item in facts.limitations] == [("huge.py", "over the parse cap")]


def test_an_unreadable_source_fails_facts_extraction(monkeypatch, tmp_path):
    source = tmp_path / "unreadable.py"
    source.write_text("def value():\n    return 1\n")
    open_path = Path.open

    def fail_selected_path(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise OSError("permission denied")
        return open_path(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_selected_path)

    with pytest.raises(BackendUnavailable, match=r"cannot read source unreadable\.py"):
        TreeSitterFacts().extract(tmp_path)


def test_a_syntactically_broken_file_preserves_other_facts(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n  ???\n")
    (tmp_path / "ok.py").write_text("def g():\n    return 1\n")
    facts = TreeSitterFacts().extract(tmp_path)

    assert set(facts.data["graph"]["callgraph"]) == {"ok.py"}
    assert facts.limitations[0].source == "broken.py"
    assert facts.limitations[0].line is not None
    assert facts.limitations[0].column is not None


def test_parse_limitation_column_uses_characters_after_non_ascii_text(tmp_path):
    source = 'const x = "é"; function broken( {\n'
    (tmp_path / "broken.js").write_text(source)

    limitation = TreeSitterFacts().extract(tmp_path).limitations[0]

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
    ],
)
def test_every_tree_sitter_language_uses_one_parse_limitation_contract(tmp_path, name, source, analyzer):
    (tmp_path / name).write_text(source)

    limitation = TreeSitterFacts().extract(tmp_path).limitations[0]

    assert (limitation.source, limitation.analyzer, limitation.reason) == (name, analyzer, "unparsable")


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        ("target.py", "def target(value, flag=False):\n    return value\n", ["value", "flag"]),
        (
            "target.js",
            "export function target(value, flag = false) { return value; }\n",
            ["value", "flag"],
        ),
        (
            "target.ts",
            "export function target(value: string, flag: boolean = false) { return value; }\n",
            ["value", "flag"],
        ),
        (
            "target.tsx",
            "export function target(value: string, flag: boolean = false) { return <div>{value}</div>; }\n",
            ["value", "flag"],
        ),
        (
            "target.go",
            "package sample\nfunc target(value string, flag bool) string { return value }\n",
            ["value", "flag"],
        ),
    ],
)
def test_every_tree_sitter_language_emits_the_same_parameter_evidence_contract(
    tmp_path,
    name,
    source,
    expected,
):
    (tmp_path / name).write_text(source)

    definitions = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["definitions"]
    target = next(item for item in definitions if item["name"] == "target")

    assert [item["name"] for item in target["parameters"]] == expected
    assert [item["position"] for item in target["parameters"]] == list(range(len(expected)))
    assert all(item["source"]["content_sha256"] for item in target["parameters"])


def test_python_keeps_declared_self_as_argument_evidence(tmp_path):
    (tmp_path / "service.py").write_text("class Service:\n    def load(self, value):\n        return value\n")

    definitions = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["definitions"]
    method = next(item for item in definitions if item["name"] == "load")

    assert [(item["name"], item["position"]) for item in method["parameters"]] == [
        ("self", 0),
        ("value", 1),
    ]


def test_go_method_keeps_receiver_and_declared_parameters_in_source_order(tmp_path):
    (tmp_path / "service.go").write_text(
        "package service\ntype Store struct{}\nfunc (store *Store) Load(value int) int { return value }\n"
    )

    definitions = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["definitions"]
    method = next(item for item in definitions if item["name"] == "Load")

    assert method["kind"] == "method"
    assert method["receiver"]["name"] == "store"
    assert method["receiver"]["type_name"] == "*Store"
    assert [(item["name"], item["position"]) for item in method["parameters"]] == [("value", 0)]


def test_go_grouped_and_unnamed_parameters_are_not_dropped(tmp_path):
    (tmp_path / "service.go").write_text(
        "package service\nfunc Load(first, second int, string) int { return first + second }\n"
    )

    definitions = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]["definitions"]
    function = next(item for item in definitions if item["name"] == "Load")

    assert [(item["name"], item["position"], item["type_name"]) for item in function["parameters"]] == [
        ("first", 0, "int"),
        ("second", 1, "int"),
        ("", 2, "string"),
    ]


def test_an_unsupported_typescript_export_does_not_abort_other_files(tmp_path):
    (tmp_path / "barrel.ts").write_text("export type * from './model';\n")
    (tmp_path / "model.ts").write_text("export interface Model { id: string }\n")
    (tmp_path / "ok.ts").write_text("export function ok() { return true; }\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert set(facts.data["graph"]["callgraph"]) == {"ok.ts"}
    assert [(item.source, item.analyzer) for item in facts.limitations] == [("barrel.ts", "typescript")]


def test_native_web_analyzer_matches_the_cross_language_structure_oracle(tmp_path):
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
    assert [parameter.name for parameter in definitions[("service.py", "load")].parameters] == ["self", "value"]
    assert definitions[("store.go", "Load")].receiver is not None
    for (file, _name), definition in definitions.items():
        body = analyzed.sources[file][definition.start : definition.end]
        assert body

    facts = TreeSitterFacts().extract(tmp_path)
    assert facts.native_analysis is not None
    assert facts.native_analysis.source_count == 4
    assert facts.native_analysis.definition_count == 8
    assert facts.native_analysis.callsite_count == 4
    assert facts.native_analysis.limitation_count == 0


def test_native_web_analyzer_output_does_not_depend_on_input_enumeration(tmp_path):
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
