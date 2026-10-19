"""Syntax analysis preserves source ranges, lexical owners, and parsed call identities."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.prepare import extract_facts
from cyberjury.review.selection import FileSelection
from cyberjury.review.syntax.analyzer import (
    MAX_SOURCE_BYTES,
    AnalyzerConfigurationError,
    analyze_repository,
    grammar_for,
    load_specs,
    spec_for,
)
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.syntax.support import callgraph, syntax_facts


def test_specs_ship_a_grammar_and_every_query_per_language():
    """Each spec's queries compile against its grammar and declare the captures the analyzer reads."""
    from tree_sitter import Language, Query

    specs = load_specs()
    assert {"python", "javascript", "typescript", "tsx", "go"} <= set(specs)
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


def test_every_language_whose_imports_name_a_symbol_ships_an_imports_query():
    """Python, JavaScript, TypeScript, and TSX define import queries, and Go defines none."""
    specs = load_specs()
    for name in ("python", "javascript", "typescript", "tsx"):
        assert specs[name].imports, name
    assert specs["go"].imports == ()


def test_nul_parse_failure_becomes_a_source_limitation(tmp_path):
    """A NUL byte inside a TS template literal marks render.ts unparsable while ok.ts keeps its graph."""
    source = b"export function render(value: string) {\n  return `${value}\x00${value}`;\n}\n"
    path = tmp_path / "render.ts"
    path.write_bytes(source)
    (tmp_path / "ok.ts").write_text("export function ok() { return true; }\n")

    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"ok.ts"}
    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("render.ts", "typescript", "unparsable")
    ]


def test_nul_in_code_uses_the_same_source_limitation_contract(tmp_path):
    """A NUL byte inside a TS function name yields an unparsable limitation for render.ts."""
    (tmp_path / "render.ts").write_bytes(b"export function \x00render() { return true; }\n")

    facts = syntax_facts(tmp_path)

    assert facts.limitations[0].source == "render.ts"
    assert facts.limitations[0].reason == "unparsable"


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
    """A client.get() call with two classes defining get records "get" but no candidate target ids."""
    (tmp_path / "views.py").write_text(
        "class A:\n    def get(self):\n        return 1\n\n"
        "class B:\n    def get(self):\n        return 2\n\n"
        "def view(client):\n    return client.get()\n"
    )

    observations = syntax_facts(tmp_path).relationships.to_data()["observations"]

    assert callgraph(tmp_path)["views.py"]["view"][0]["calls"] == ["get"]
    assert all(item["candidate_target_ids"] == [] for item in observations)


def test_a_local_receiver_call_remains_a_syntax_observation(tmp_path):
    """A self.inner() call records the callee "inner" without resolving it to Service.inner."""
    (tmp_path / "service.py").write_text(
        "class Service:\n    def outer(self):\n        return self.inner()\n\n    def inner(self):\n        return 1\n"
    )

    facts = syntax_facts(tmp_path)

    assert callgraph(tmp_path)["service.py"]["outer"][0]["calls"] == ["inner"]
    assert all(item["candidate_target_ids"] == [] for item in facts.relationships.to_data()["observations"])


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


def test_tests_and_noise_directories_are_left_out(tmp_path):
    """Only keep.py appears in the call graph, and test_skip.py and node_modules/dep.js are excluded."""
    (tmp_path / "keep.py").write_text("def keep():\n    return 1\n")
    (tmp_path / "test_skip.py").write_text("def test_skip():\n    return 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("function dep() {}\n")
    assert set(callgraph(tmp_path)) == {"keep.py"}


def test_a_file_over_the_parse_cap_preserves_other_facts(tmp_path):
    """A huge.py beyond MAX_SOURCE_BYTES gets an "over the parse cap" limitation while small.py keeps facts."""
    limit = MAX_SOURCE_BYTES
    (tmp_path / "huge.py").write_text("def f():\n    return 1\n" + "PAD = 1\n" * (limit // 8))
    (tmp_path / "small.py").write_text("def g():\n    return 1\n")
    facts = syntax_facts(tmp_path)

    assert set(callgraph(tmp_path)) == {"small.py"}
    assert [(item.source, item.reason) for item in facts.limitations] == [("huge.py", "over the parse cap")]


def test_an_unreadable_source_fails_facts_extraction(monkeypatch, tmp_path):
    """An OSError opening a snapshot file raises BackendUnavailable "cannot read source unreadable.py"."""
    source = tmp_path / "unreadable.py"
    source.write_text("def value():\n    return 1\n")
    snapshot = capture_source_snapshot(tmp_path)
    open_path = Path.open

    def fail_selected_path(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise OSError("permission denied")
        return open_path(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_selected_path)

    with pytest.raises(BackendUnavailable, match=r"cannot read source unreadable\.py"):
        extract_facts(snapshot, FileSelection(review_files=(), navigation_files=(), skipped_files=()))


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
    ],
)
def test_every_tree_sitter_language_uses_one_parse_limitation_contract(tmp_path, name, source, analyzer):
    """A broken file in each language yields the same (source, analyzer, "unparsable") limitation."""
    (tmp_path / name).write_text(source)

    limitation = syntax_facts(tmp_path).limitations[0]

    assert (limitation.source, limitation.analyzer, limitation.reason) == (name, analyzer, "unparsable")


def test_go_receiver_function_is_a_method(tmp_path):
    """A Go func with a *Store receiver named Load is recorded with kind "method"."""
    (tmp_path / "service.go").write_text(
        "package service\ntype Store struct{}\nfunc (store *Store) Load(value int) int { return value }\n"
    )

    definitions = syntax_facts(tmp_path).relationships.to_data()["definitions"]
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


def test_native_analyzer_matches_the_cross_language_structure_oracle(tmp_path):
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
