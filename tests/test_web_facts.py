"""The web facts pipeline resolves specs, calls, imports, and missing grammars."""

import pytest

from cyberjury.profiles.web.facts.analyzer import MAX_SOURCE_BYTES, LangSpec, load_specs
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.profiles.web.facts.resolver import (
    resolve_specifiers,
    scope_prefixes,
)
from cyberjury.review.facts import (
    BackendUnavailable,
    FactsBackend,
    definition_dependencies,
    unresolved_dependencies,
)


def _extensions():
    return tuple(sorted({e for s in load_specs().values() for e in s.extensions}))


def _specs():
    return tuple(load_specs().values())


def _graph(root):
    return TreeSitterFacts().extract(root).data["graph"]["callgraph"]


def test_tree_sitter_call_graph_is_a_facts_backend():
    assert isinstance(TreeSitterFacts(), FactsBackend)


def test_specs_ship_a_grammar_and_every_query_per_language():
    specs = load_specs()
    assert {"python", "javascript", "typescript", "tsx", "go"} <= set(specs)
    for name, spec in specs.items():
        assert spec.extensions, name
        assert spec.name in spec.resolution_languages, name
        assert isinstance(spec.module_entries, tuple), name
        assert "@def" in spec.definitions, name
        assert "@name" in spec.definitions, name
        assert "@callee" in spec.calls, name
        assert "@member" in spec.calls, name
        for query in spec.imports:
            assert "@module" in query.query, name
            assert "@imported" in query.query or query.imported, name


def test_every_language_whose_imports_name_a_symbol_ships_an_imports_query():
    specs = load_specs()
    for name in ("python", "javascript", "typescript", "tsx"):
        assert specs[name].imports, name
    assert specs["go"].imports == ()


def test_resolution_language_compatibility_is_declarative():
    specs = load_specs()

    assert specs["python"].resolution_languages == ("python",)
    assert specs["javascript"].resolution_languages == ("javascript",)
    assert specs["typescript"].resolution_languages == ("typescript", "tsx", "javascript")
    assert specs["tsx"].resolution_languages == ("tsx", "typescript", "javascript")
    assert specs["go"].resolution_languages == ("go",)
    assert specs["go"].namespace_resolves_directory is True
    assert all(specs[name].default_exports for name in ("javascript", "typescript", "tsx"))


def test_one_extension_maps_to_one_language():
    seen: dict[str, str] = {}
    for name, spec in load_specs().items():
        for ext in spec.extensions:
            assert ext not in seen, f"{ext} claimed by both {seen.get(ext)} and {name}"
            seen[ext] = name


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


def test_an_untyped_member_call_does_not_bind_every_same_file_method(tmp_path):
    (tmp_path / "views.py").write_text(
        "class A:\n    def get(self):\n        return 1\n\n"
        "class B:\n    def get(self):\n        return 2\n\n"
        "def view(client):\n    return client.get()\n"
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    edges = definition_dependencies(graph)

    assert graph["callgraph"]["views.py"]["view"][0]["calls"] == ["get"]
    assert not [edge for edge in edges if edge.kind == "call" and edge.reference == "get"]


def test_a_local_receiver_call_keeps_its_same_file_dependency(tmp_path):
    (tmp_path / "service.py").write_text(
        "class Service:\n    def outer(self):\n        return self.inner()\n\n    def inner(self):\n        return 1\n"
    )

    edges = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        edge.target.name
        for edge in edges
        if edge.source is not None and edge.source.name == "outer" and edge.kind == "call"
    ] == ["inner"]


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (
            ".py",
            "class A:\n"
            "    def outer(self):\n"
            "        return self.inner()\n"
            "    def inner(self):\n"
            "        return 1\n\n"
            "class B:\n"
            "    def inner(self):\n"
            "        return 2\n",
        ),
        (
            ".ts",
            "class A { outer() { return this.inner(); } inner() { return 1; } }\nclass B { inner() { return 2; } }\n",
        ),
    ],
)
def test_local_receiver_calls_stay_with_their_lexical_owner(tmp_path, extension, source):
    path = tmp_path / f"service{extension}"
    path.write_text(source)

    edges = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])
    target = next(edge.target for edge in edges if edge.source is not None and edge.source.name == "outer")

    text = path.read_text()
    assert text[target.start : target.end].count("return 1") == 1
    assert len([edge for edge in edges if edge.source is not None and edge.source.name == "outer"]) == 1


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (
            ".py",
            "class A:\n"
            "    def outer(self):\n"
            "        def nested():\n"
            "            return self.inner()\n"
            "        return nested()\n"
            "    def inner(self):\n"
            "        return 1\n\n"
            "class B:\n"
            "    def inner(self):\n"
            "        return 2\n",
        ),
        (
            ".js",
            "class A { outer() { const nested = () => this.inner(); return nested(); } "
            "inner() { return 1; } }\nclass B { inner() { return 2; } }\n",
        ),
        (
            ".ts",
            "class A { outer() { const nested = () => this.inner(); return nested(); } "
            "inner() { return 1; } }\nclass B { inner() { return 2; } }\n",
        ),
    ],
)
def test_closure_local_receiver_calls_keep_the_enclosing_type_owner(tmp_path, extension, source):
    path = tmp_path / f"service{extension}"
    path.write_text(source)

    edges = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])
    targets = [edge.target for edge in edges if edge.source is not None and edge.source.name == "nested"]

    text = path.read_text()
    assert len(targets) == 1
    assert text[targets[0].start : targets[0].end].count("return 1") == 1


@pytest.mark.parametrize("extension", [".js", ".ts"])
def test_dynamic_this_in_a_nested_function_does_not_bind_the_enclosing_type(tmp_path, extension):
    (tmp_path / f"service{extension}").write_text(
        "class A { outer() { function nested() { return this.inner(); } return nested(); } inner() { return 1; } }\n"
    )

    edges = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert not [
        edge
        for edge in edges
        if edge.source is not None and edge.source.name == "nested" and edge.target.name == "inner"
    ]


def test_recursion_is_not_reported_as_a_call_to_itself(tmp_path):
    (tmp_path / "r.py").write_text("def walk(n):\n    return walk(n - 1)\n")
    assert _graph(tmp_path)["r.py"]["walk"][0]["calls"] == []


def test_javascript_recursion_is_not_reported_as_a_call_to_itself(tmp_path):
    (tmp_path / "r.ts").write_text("function walk(n) {\n  return walk(n - 1);\n}\n")
    assert _graph(tmp_path)["r.ts"]["walk"][0]["calls"] == []


def test_go_recursion_is_not_reported_as_a_call_to_itself(tmp_path):
    (tmp_path / "r.go").write_text("package main\nfunc walk(n int) int { return walk(n - 1) }\n")
    assert _graph(tmp_path)["r.go"]["walk"][0]["calls"] == []


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


def test_a_file_over_the_parse_cap_fails_facts_extraction(tmp_path):
    limit = MAX_SOURCE_BYTES
    (tmp_path / "huge.py").write_text("def f():\n    return 1\n" + "PAD = 1\n" * (limit // 8))
    (tmp_path / "small.py").write_text("def g():\n    return 1\n")
    with pytest.raises(BackendUnavailable, match=r"huge\.py: over the parse cap"):
        _graph(tmp_path)


def test_a_syntactically_broken_file_fails_facts_extraction(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n  ???\n")
    (tmp_path / "ok.py").write_text("def g():\n    return 1\n")
    with pytest.raises(BackendUnavailable, match=r"broken\.py: unparsable"):
        _graph(tmp_path)


def test_an_import_edge_records_the_names_a_file_brings_in(tmp_path):
    _chain(tmp_path)
    imports = TreeSitterFacts().extract(tmp_path).data["graph"]["imports"]
    assert imports["app/routes.py"] == ["handle_request"]
    assert imports["app/handler.py"] == ["load_order"]


def test_import_targets_record_the_file_an_import_statement_resolves_to(tmp_path):
    _chain(tmp_path)
    targets = TreeSitterFacts().extract(tmp_path).data["graph"]["import_targets"]
    assert targets["app/routes.py"] == ["app/handler.py"]
    assert targets["app/handler.py"] == ["app/repository.py"]


def test_a_re_export_is_an_import_edge(tmp_path):
    (tmp_path / "index.ts").write_text(
        "export { ItemsService } from './items';\nexport { readOne as read } from './query';\n"
    )
    (tmp_path / "items.ts").write_text("export class ItemsService {\n  readOne(k) { return k; }\n}\n")
    (tmp_path / "query.ts").write_text("export function readOne(k) { return k; }\n")
    imports = TreeSitterFacts().extract(tmp_path).data["graph"]["imports"]
    assert sorted(imports["index.ts"]) == ["ItemsService", "readOne"]


def test_export_star_imports_the_target_module_level_definitions(tmp_path):
    (tmp_path / "index.js").write_text("export * from './store';\n")
    (tmp_path / "store.js").write_text(
        "export function load(k) { return k; }\nexport class Store { read(k) { return k; } }\n"
    )
    imports = TreeSitterFacts().extract(tmp_path).data["graph"]["imports"]
    assert sorted(imports["index.js"]) == ["Store", "load"]


def test_a_symbol_resolves_through_every_re_export_facade(tmp_path):
    (tmp_path / "route.ts").write_text("import { load } from './one';\nfunction handle() { return load(); }\n")
    (tmp_path / "one.ts").write_text("export { load } from './two';\n")
    (tmp_path / "two.ts").write_text("export { load } from './three';\n")
    (tmp_path / "three.ts").write_text("export { load } from './store';\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    dependencies = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.file, edge.source.name, edge.target.file, edge.target.name)
        for edge in dependencies
        if edge.source is not None and edge.source.name == "handle"
    ] == [("route.ts", "handle", "store.ts", "load")]


@pytest.mark.parametrize(
    ("extension", "import_line"),
    [
        (".py", "from store import load as fetch"),
        (".js", "import { load as fetch } from './store';"),
        (".ts", "import { load as fetch } from './store';"),
    ],
)
def test_a_named_import_alias_resolves_the_local_call_to_the_remote_definition(tmp_path, extension, import_line):
    route = tmp_path / f"route{extension}"
    store = tmp_path / f"store{extension}"
    if extension == ".py":
        route.write_text(f"{import_line}\n\ndef handle():\n    return fetch()\n")
        store.write_text("def load():\n    return 1\n")
    else:
        route.write_text(f"{import_line}\nfunction handle() {{ return fetch(); }}\n")
        store.write_text("export function load() { return 1; }\n")

    dependencies = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.name, edge.target.file, edge.target.name, edge.reference)
        for edge in dependencies
        if edge.source is not None and edge.source.name == "handle"
    ] == [("handle", f"store{extension}", "load", "fetch")]


def test_re_export_aliases_resolve_each_local_name_in_the_chain(tmp_path):
    (tmp_path / "route.ts").write_text(
        "import { read as fetch } from './facade';\nfunction handle() { return fetch(); }\n"
    )
    (tmp_path / "facade.ts").write_text("export { load as read } from './store';\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    dependencies = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.name, edge.target.file, edge.target.name, edge.reference)
        for edge in dependencies
        if edge.source is not None and edge.source.name == "handle"
    ] == [("handle", "store.ts", "load", "fetch")]


def test_a_re_export_cycle_terminates_without_losing_a_reachable_symbol(tmp_path):
    (tmp_path / "route.ts").write_text("import { load } from './one';\nfunction handle() { return load(); }\n")
    (tmp_path / "one.ts").write_text("export { load } from './two';\n")
    (tmp_path / "two.ts").write_text("export { load } from './one';\nexport { load } from './store';\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    dependencies = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [edge.target.file for edge in dependencies if edge.source is not None and edge.source.name == "handle"] == [
        "store.ts"
    ]


@pytest.mark.parametrize("extension", [".js", ".cjs", ".ts", ".tsx"])
def test_commonjs_require_edges_are_import_edges(tmp_path, extension):
    route = f"route{extension}"
    store = f"store{extension}"
    (tmp_path / route).write_text(
        "const { load, save: persist } = require('./store');\n"
        "const store = require('./store');\n"
        "function handle(k) { return store.find(load(k), persist(k)); }\n"
    )
    (tmp_path / store).write_text(
        "function load(k) { return k; }\nfunction save(k) { return k; }\nfunction find(k) { return k; }\n"
    )
    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    assert sorted(graph["imports"][route]) == ["load", "save"]
    assert graph["references"][route] == ["find"]
    dependencies = definition_dependencies(graph)
    assert [
        (edge.target.file, edge.target.name, edge.reference)
        for edge in dependencies
        if edge.source is not None and edge.source.name == "handle"
    ] == [(store, "load", "load"), (store, "save", "persist")]


def test_commonjs_require_from_outside_the_tree_binds_nothing(tmp_path):
    (tmp_path / "route.cjs").write_text(
        "const { readFile } = require('fs');\n"
        "const fs = require('fs');\n"
        "function handle(k) { return fs.readFileSync(readFile, k); }\n"
    )
    assert TreeSitterFacts().extract(tmp_path).data["graph"]["imports"] == {}


def test_commonjs_export_assignments_are_definitions(tmp_path):
    (tmp_path / "store.cjs").write_text(
        "exports.load = function (k) { return k; };\nmodule.exports.save = () => load();\n"
    )
    graph = _graph(tmp_path)
    assert sorted(graph["store.cjs"]) == ["load", "save"]
    assert graph["store.cjs"]["save"][0]["calls"] == ["load"]


def test_a_namespace_import_binds_the_names_used_through_it(tmp_path):
    (tmp_path / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "plain.py").write_text("import store\nimport os\n\n\ndef h():\n    return store.load(os.getcwd())\n")
    (tmp_path / "alias.py").write_text("import store as st\n\n\ndef h():\n    return st.load(1)\n")
    references = TreeSitterFacts().extract(tmp_path).data["graph"]["references"]
    assert references["plain.py"] == ["load"]
    assert references["alias.py"] == ["load"]


def test_a_namespace_reference_in_a_class_base_binds_the_base_definition(tmp_path):
    (tmp_path / "domain.py").write_text("class OwnedRecord:\n    pass\n")
    (tmp_path / "rules.py").write_text("import domain as records\n\nclass AccessRule(records.OwnedRecord):\n    pass\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["references"]["rules.py"] == ["OwnedRecord"]
    assert graph["import_targets"]["rules.py"] == ["domain.py"]


def test_a_namespace_from_outside_the_tree_binds_nothing(tmp_path):
    (tmp_path / "a.py").write_text("import os\n\n\ndef h():\n    return os.getcwd()\n")
    assert TreeSitterFacts().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_qualifier_that_was_never_imported_binds_nothing(tmp_path):
    (tmp_path / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "a.py").write_text("def h(client):\n    return client.load(2)\n")
    assert TreeSitterFacts().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_dotted_namespace_binds_under_its_whole_specifier(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "use.py").write_text("import app.store\n\n\ndef h():\n    return app.store.load(1)\n")
    assert TreeSitterFacts().extract(tmp_path).data["graph"]["references"]["use.py"] == ["load"]


def test_a_go_package_import_resolves_by_directory(tmp_path):
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "db.go").write_text("package store\nfunc Load(k int) int { return k }\n")
    (tmp_path / "main.go").write_text(
        'package main\nimport (\n "example.com/app/store"\n "fmt"\n)\nfunc h() { store.Load(1); fmt.Println("x") }\n'
    )
    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    references = graph["references"]
    assert references["main.go"] == ["Load"]
    assert graph["import_targets"]["main.go"] == ["store/db.go"]
    assert [
        (edge.kind, edge.target.file, edge.target.name, edge.reference) for edge in definition_dependencies(graph)
    ] == [("reference", "store/db.go", "Load", "store.Load")]


@pytest.mark.parametrize(
    ("route", "store", "route_source", "store_source", "target_name"),
    [
        (
            "route.py",
            "store.py",
            "import store as records\n\ndef handle():\n    return records.load()\n",
            "def load():\n    return 1\n",
            "load",
        ),
        (
            "route.js",
            "store.js",
            "import * as records from './store';\nfunction handle() { return records.load(); }\n",
            "export function load() { return 1; }\n",
            "load",
        ),
        (
            "route.ts",
            "store.ts",
            "import * as records from './store';\nfunction handle() { return records.load(); }\n",
            "export function load() { return 1; }\n",
            "load",
        ),
        (
            "route.cjs",
            "store.cjs",
            "const records = require('./store');\nfunction handle() { return records.load(); }\n",
            "exports.load = function () { return 1; };\n",
            "load",
        ),
    ],
)
def test_namespace_imports_create_typed_definition_dependencies(
    tmp_path,
    route,
    store,
    route_source,
    store_source,
    target_name,
):
    (tmp_path / route).write_text(route_source)
    (tmp_path / store).write_text(store_source)

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    edges = [edge for edge in definition_dependencies(graph) if edge.kind == "reference"]

    assert [(edge.source_file, edge.target.file, edge.target.name, edge.resolution) for edge in edges] == [
        (route, store, target_name, "exact")
    ]


@pytest.mark.parametrize("extension", [".js", ".ts", ".tsx"])
def test_renamed_default_imports_resolve_the_exported_definition(tmp_path, extension):
    (tmp_path / f"store{extension}").write_text("export default function load() { return 1; }\n")
    (tmp_path / f"route{extension}").write_text("import fetch from './store';\nfunction handle() { return fetch(); }\n")

    edges = definition_dependencies(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.name, edge.target.name, edge.reference)
        for edge in edges
        if edge.kind == "call" and edge.source is not None
    ] == [("handle", "load", "fetch")]


def test_an_unrepresented_first_party_default_export_is_an_unresolved_call(tmp_path):
    (tmp_path / "store.ts").write_text("export default function () { return 1; }\n")
    (tmp_path / "route.ts").write_text("import fetch from './store';\nfunction handle() { return fetch(); }\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert [(item.kind, item.source.name, item.reference) for item in unresolved_dependencies(graph)] == [
        ("call", "handle", "fetch")
    ]


def test_a_third_party_import_is_dropped_since_it_names_no_file_in_the_tree(tmp_path):
    (tmp_path / "a.py").write_text("from django.http import HttpResponse\n\n\ndef f():\n    return 1\n")
    assert TreeSitterFacts().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_relative_import_climbing_a_package_resolves(tmp_path):
    (tmp_path / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "pkg" / "shared.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "pkg" / "sub" / "use.py").write_text("from ..shared import helper\n\n\ndef f():\n    return 1\n")
    imports = TreeSitterFacts().extract(tmp_path).data["graph"]["imports"]
    assert imports["pkg/sub/use.py"] == ["helper"]


def test_a_package_absolute_import_resolves_when_the_review_root_is_inside_the_package(tmp_path):
    scope = tmp_path / "apps" / "webui"
    (scope / "models").mkdir(parents=True)
    (scope / "routers").mkdir()
    (tmp_path / ".git").mkdir()
    (scope / "models" / "files.py").write_text("def insert_new_file(x):\n    return x\n")
    (scope / "routers" / "files.py").write_text(
        "from apps.webui.models.files import insert_new_file\n\n\ndef upload(r):\n    return insert_new_file(r)\n"
    )
    imports = TreeSitterFacts().extract(scope).data["graph"]["imports"]
    assert imports["routers/files.py"] == ["insert_new_file"]


def test_the_stripped_prefix_stops_at_the_repository(tmp_path):
    repository = tmp_path / "data" / "proj"
    scope = repository / "apps" / "webui"
    scope.mkdir(parents=True)
    (repository / ".git").mkdir()
    assert scope_prefixes(scope) == ("apps/webui", "webui")


def test_a_tree_with_no_repository_strips_nothing(tmp_path):
    scope = tmp_path / "apps" / "webui"
    scope.mkdir(parents=True)
    assert scope_prefixes(scope) == ()


def test_a_specifier_naming_another_package_still_misses(tmp_path):
    scope = tmp_path / "apps" / "webui"
    (scope / "models").mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (scope / "models" / "files.py").write_text("def helper():\n    return 1\n")
    (scope / "use.py").write_text("from other.pkg.models.files import helper\n\n\ndef f():\n    return 1\n")
    assert TreeSitterFacts().extract(scope).data["graph"]["imports"] == {}


@pytest.mark.parametrize(
    ("src", "spec", "expected"),
    [
        ("web.py", ".web_response", "web_response.py"),
        ("pkg/sub/use.py", "..shared", "pkg/shared.py"),
        ("pkg/a.py", ".b", "pkg/b.py"),
        ("api/items.ts", "../services/items.js", "services/items.ts"),
        ("api/items.ts", "./helper", "api/helper.ts"),
        ("pkg/a.py", "pkg.b", "pkg/b.py"),
        ("a.py", ".absent", None),
        ("a.py", "requests", None),
        ("a.py", "../web_response", None),
        ("a.py", "..web_response", None),
        ("pkg/a.py", "../../web_response", None),
    ],
)
def test_a_specifier_resolves_to_the_file_it_names(src, spec, expected):
    known = {
        "web.py",
        "web_response.py",
        "pkg/shared.py",
        "pkg/a.py",
        "pkg/b.py",
        "api/items.ts",
        "api/helper.ts",
        "services/items.ts",
    }
    matches = resolve_specifiers(src, spec, known, _specs())
    assert matches == ((expected,) if expected else ())


def test_a_specifier_naming_a_package_directory_resolves_through_its_index(tmp_path):
    assert resolve_specifiers("a.ts", "./svc", {"svc/index.ts"}, _specs()) == ("svc/index.ts",)
    assert resolve_specifiers("a.py", ".pkg", {"pkg/__init__.py"}, _specs()) == ("pkg/__init__.py",)


def test_a_custom_module_entry_convention_is_loaded_from_the_language_spec():
    base = load_specs()["python"]
    spec = LangSpec(
        name="custom",
        extensions=(".custom",),
        resolution_languages=("custom",),
        module="tree_sitter_custom",
        accessor="language",
        definitions=base.definitions,
        type_definitions=base.type_definitions,
        calls=base.calls,
        imports=base.imports,
        module_entries=("module.custom",),
    )

    assert resolve_specifiers("app.custom", "./pkg", {"pkg/module.custom"}, (spec,)) == ("pkg/module.custom",)


def test_common_project_root_aliases_resolve_inside_the_tree():
    """Root aliases enter the source tree after ordinary module resolution misses."""
    known = {"utils/index.ts", "utils/dataStore.ts"}

    assert resolve_specifiers("controllers/request.controller.ts", "~/utils", known, _specs()) == ("utils/index.ts",)
    assert resolve_specifiers("controllers/request.controller.ts", "@/utils/dataStore", known, _specs()) == (
        "utils/dataStore.ts",
    )


def test_repository_absolute_import_resolves_below_an_arbitrary_source_root():
    known = {"source/domain/models.py", "vendor/domain/models.py"}

    assert resolve_specifiers("source/api/routes.py", "domain.models", known, _specs()) == (
        "source/domain/models.py",
        "vendor/domain/models.py",
    )


def test_ambiguous_repository_imports_remain_typed_candidates(tmp_path):
    for prefix in ("source", "packages"):
        (tmp_path / prefix / "domain").mkdir(parents=True)
        (tmp_path / prefix / "domain" / "models.py").write_text("class Record:\n    pass\n")
    (tmp_path / "route.py").write_text("from domain.models import Record\n\ndef handle():\n    return Record()\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    record_edges = [edge for edge in definition_dependencies(graph) if edge.target.name == "Record"]

    assert len({edge.target.file for edge in record_edges}) == 2
    assert {edge.resolution for edge in record_edges} == {"ambiguous"}


def test_unresolved_relative_import_is_preserved_for_completion(tmp_path):
    (tmp_path / "route.py").write_text("from .missing import policy\n\ndef handle():\n    return policy()\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert [item.reference for item in unresolved_dependencies(graph)] == [".missing"]


def test_every_declared_extension_resolves_for_its_own_language():
    specs = load_specs()
    for spec in specs.values():
        source = f"route{spec.extensions[0]}"
        for extension in spec.extensions:
            target = f"svc{extension}"
            assert resolve_specifiers(source, "./svc", {target}, tuple(specs.values())) == (target,)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("route.py", "svc.py"),
        ("route.ts", "svc.ts"),
        ("route.go", "svc.go"),
    ],
)
def test_extensionless_import_prefers_the_importing_language(source, expected):
    known = {"svc.py", "svc.ts", "svc.go"}

    assert resolve_specifiers(source, "./svc", known, _specs()) == (expected,)


def test_typescript_directory_import_uses_a_compatible_module_entry():
    known = {"pkg/__init__.py", "pkg/index.ts", "pkg/index.js"}

    assert resolve_specifiers("route.ts", "./pkg", known, _specs()) == ("pkg/index.ts",)
    assert resolve_specifiers("route.go", "./pkg", known, _specs()) == ()


@pytest.mark.parametrize("source", ["route.ts", "route.tsx"])
def test_typescript_can_resolve_javascript_source(source):
    assert resolve_specifiers(source, "./svc", {"svc.js"}, _specs()) == ("svc.js",)
    assert resolve_specifiers(source, "./pkg", {"pkg/index.js"}, _specs()) == ("pkg/index.js",)


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [("./svc.ts", "svc.ts"), ("./view.tsx", "view.tsx")],
)
def test_javascript_can_resolve_explicit_typescript_source(specifier, expected):
    known = {"svc.js", "svc.ts", "view.jsx", "view.tsx"}

    assert resolve_specifiers("route.js", specifier, known, _specs()) == (expected,)


def test_javascript_extensionless_import_does_not_fall_back_to_typescript():
    known = {"svc.ts", "view.tsx", "pkg/index.ts", "component/index.tsx"}

    assert resolve_specifiers("route.js", "./svc", known, _specs()) == ()
    assert resolve_specifiers("route.js", "./view", known, _specs()) == ()
    assert resolve_specifiers("route.js", "./pkg", known, _specs()) == ()
    assert resolve_specifiers("route.js", "./component", known, _specs()) == ()


def test_mixed_language_collisions_prefer_explicit_then_importing_language():
    known = {"svc.js", "svc.ts", "svc.tsx"}

    assert resolve_specifiers("route.js", "./svc.ts", known, _specs()) == ("svc.ts",)
    assert resolve_specifiers("route.ts", "./svc.js", known, _specs()) == ("svc.js",)
    assert resolve_specifiers("route.js", "./svc", known, _specs()) == ("svc.js",)
    assert resolve_specifiers("route.ts", "./svc", known, _specs()) == ("svc.ts",)


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


def test_an_empty_tree_yields_empty_facts(tmp_path):
    (tmp_path / "notes.md").write_text("no code here\n")
    assert TreeSitterFacts().extract(tmp_path).empty


def _absent(specs, name="python"):
    base = specs[name]
    return LangSpec(
        name=name,
        extensions=base.extensions,
        resolution_languages=base.resolution_languages,
        module="tree_sitter_absent_grammar",
        accessor="language",
        definitions=base.definitions,
        type_definitions=base.type_definitions,
        calls=base.calls,
        imports=base.imports,
        module_entries=base.module_entries,
    )


def test_a_language_with_no_grammar_installed_fails_when_the_target_uses_it(tmp_path):
    specs = load_specs()
    specs["python"] = _absent(specs)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    (tmp_path / "b.ts").write_text("function g() { return 1; }\n")
    with pytest.raises(BackendUnavailable, match="python"):
        TreeSitterFacts(specs).extract(tmp_path)


def test_a_missing_unused_grammar_does_not_block_other_languages(tmp_path):
    specs = load_specs()
    specs["python"] = _absent(specs)
    (tmp_path / "b.ts").write_text("function g() { return 1; }\n")
    assert set(TreeSitterFacts(specs).extract(tmp_path).data["graph"]["callgraph"]) == {"b.ts"}


def test_unavailable_when_no_grammar_at_all_is_installed(tmp_path):
    backend = TreeSitterFacts({"python": _absent(load_specs())})
    assert backend.available() is False
    with pytest.raises(BackendUnavailable):
        backend.extract(tmp_path)
