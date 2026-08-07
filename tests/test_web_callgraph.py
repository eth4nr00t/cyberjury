"""The web domain's tree-sitter call-graph backend.

language specs, extraction, the name-based callee match, import-edge resolution, and the
degrade when a grammar is absent. The grammars ship in the base install, so these tests
do not skip on a missing one, an absent grammar is a broken install rather than an
optional feature.
"""

import pytest

from cyberjury.domains.base import BackendUnavailable, FactsBackend
from cyberjury.domains.web.facts.callgraph import (
    LangSpec,
    TreeSitterCallGraph,
    load_specs,
    resolve_specifier,
)


def _extensions():
    return tuple(sorted({e for s in load_specs().values() for e in s.extensions}))


def _graph(root):
    return TreeSitterCallGraph().extract(root).data["graph"]["callgraph"]


def test_it_is_a_facts_backend():
    """TreeSitterCallGraph satisfies the facts backend contract."""
    assert isinstance(TreeSitterCallGraph(), FactsBackend)


def test_specs_ship_a_grammar_and_every_query_per_language():
    """Each language spec ships its grammar and required queries."""
    specs = load_specs()
    assert {"python", "javascript", "typescript", "tsx", "go"} <= set(specs)
    for name, spec in specs.items():
        assert spec.extensions, name
        assert "@def" in spec.definitions, name
        assert "@name" in spec.definitions, name
        assert "@callee" in spec.calls, name
        for query in spec.imports:
            assert "@module" in query, name
            assert "@imported" in query, name


def test_every_language_whose_imports_name_a_symbol_ships_an_imports_query():
    """Symbol importing languages declare direct import queries."""
    specs = load_specs()
    for name in ("python", "javascript", "typescript", "tsx"):
        assert specs[name].imports, name
    assert specs["go"].imports == ()


def test_one_extension_maps_to_one_language():
    """Each source extension belongs to one language spec."""
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
    """Four hop chain is recovered edge by edge."""
    graph = _graph(_chain(tmp_path))
    assert graph["app/routes.py"]["get_order"][0]["calls"] == ["handle_request"]
    assert graph["app/handler.py"]["handle_request"][0]["calls"] == ["load_order"]
    assert graph["app/repository.py"]["load_order"][0]["calls"] == ["run_query"]


def test_a_definition_range_cuts_the_whole_definition_from_its_own_source(tmp_path):
    """Definition range cuts the whole definition from its own source."""
    (tmp_path / "m.py").write_text(
        "def before():\n    return 0\n\n\ndef target():\n    return run_query()\n\n\ndef after():\n    return 2\n"
    )
    start, end = _graph(tmp_path)["m.py"]["target"][0]["range"]
    cut = (tmp_path / "m.py").read_text()[start:end]
    assert cut == "def target():\n    return run_query()"


def test_a_range_is_char_offsets_even_when_an_earlier_line_is_not_ascii(tmp_path):
    """Range is char offsets even when an earlier line is not ASCII."""
    (tmp_path / "a.py").write_text('HEADER = "café"\n\n\ndef drink(x):\n    return 2\n')
    text = (tmp_path / "a.py").read_text()
    start, end = _graph(tmp_path)["a.py"]["drink"][0]["range"]
    assert start == text.index("def drink")
    assert text[start:end].startswith("def drink")


def test_a_range_survives_crlf_line_endings(tmp_path):
    """Range survives CRLF line endings."""
    (tmp_path / "a.py").write_text("A = 1\r\nB = 2\r\nC = 3\r\n\r\ndef sink(x):\r\n    return x\r\n", newline="")
    text = (tmp_path / "a.py").read_text()
    start, end = _graph(tmp_path)["a.py"]["sink"][0]["range"]
    assert start == text.index("def sink")
    assert text[start:end].startswith("def sink")


def test_a_method_call_resolves_to_the_bare_callee_name(tmp_path):
    """Method call resolves to the bare callee name."""
    (tmp_path / "a.ts").write_text("function outer() {\n  return service.readOne(key);\n}\n")
    assert _graph(tmp_path)["a.ts"]["outer"][0]["calls"] == ["readOne"]


def test_recursion_is_not_reported_as_a_call_to_itself(tmp_path):
    """Recursion is not reported as a call to itself."""
    (tmp_path / "r.py").write_text("def walk(n):\n    return walk(n - 1)\n")
    assert _graph(tmp_path)["r.py"]["walk"][0]["calls"] == []


def test_two_definitions_sharing_a_name_in_one_file_both_survive(tmp_path):
    """Two definitions sharing a name in one file both survive."""
    (tmp_path / "m.py").write_text(
        "class A:\n    def __init__(self):\n        self.a = 1\n\n\n"
        "class B:\n    def __init__(self):\n        self.b = 2\n"
    )
    entries = _graph(tmp_path)["m.py"]["__init__"]
    assert len(entries) == 2
    text = (tmp_path / "m.py").read_text()
    assert [text[e["range"][0] : e["range"][1]].count("self.a") for e in entries] == [1, 0]


def test_a_callee_comes_from_the_parsed_node_not_a_re_parse_of_its_source(tmp_path):
    """Callee comes from the parsed node not a re parse of its source."""
    (tmp_path / "a.ts").write_text("class Svc {\n  async post(k) { return save(k); }\n}\n")
    assert _graph(tmp_path)["a.ts"]["post"][0]["calls"] == ["save"]


def test_a_class_counts_as_a_definition_so_its_methods_ride_along(tmp_path):
    """Class counts as a definition so its methods ride along."""
    (tmp_path / "m.py").write_text("class Resp:\n    def set_status(self, s):\n        self.s = s\n")
    start, end = _graph(tmp_path)["m.py"]["Resp"][0]["range"]
    assert "set_status" in (tmp_path / "m.py").read_text()[start:end]


def test_tests_and_noise_directories_are_left_out(tmp_path):
    """Tests and noise directories are left out."""
    (tmp_path / "keep.py").write_text("def keep():\n    return 1\n")
    (tmp_path / "test_skip.py").write_text("def test_skip():\n    return 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("function dep() {}\n")
    assert set(_graph(tmp_path)) == {"keep.py"}


def test_a_file_over_the_parse_cap_is_skipped_rather_than_parsed(tmp_path):
    """File over the parse cap is skipped rather than parsed."""
    from cyberjury.domains.web.facts import callgraph as mod

    (tmp_path / "huge.py").write_text("def f():\n    return 1\n" + "PAD = 1\n" * (mod._MAX_PARSE_BYTES // 8))
    (tmp_path / "small.py").write_text("def g():\n    return 1\n")
    assert set(_graph(tmp_path)) == {"small.py"}


def test_a_syntactically_broken_file_is_skipped_rather_than_failing_the_pass(tmp_path):
    """Syntactically broken file is skipped rather than failing the pass."""
    (tmp_path / "broken.py").write_text("def f(:\n  ???\n")
    (tmp_path / "ok.py").write_text("def g():\n    return 1\n")
    assert "ok.py" in _graph(tmp_path)


def test_an_import_edge_records_the_names_a_file_brings_in(tmp_path):
    """Import edge records the names a file brings in."""
    _chain(tmp_path)
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert imports["app/routes.py"] == ["handle_request"]
    assert imports["app/handler.py"] == ["load_order"]


def test_a_re_export_is_an_import_edge(tmp_path):
    """Re export is an import edge."""
    (tmp_path / "index.ts").write_text(
        "export { ItemsService } from './items';\nexport { readOne as read } from './query';\n"
    )
    (tmp_path / "items.ts").write_text("export class ItemsService {\n  readOne(k) { return k; }\n}\n")
    (tmp_path / "query.ts").write_text("export function readOne(k) { return k; }\n")
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert sorted(imports["index.ts"]) == ["ItemsService", "readOne"]


def test_export_star_imports_the_target_module_level_definitions(tmp_path):
    """Star exports pack only module level target definitions."""
    (tmp_path / "index.js").write_text("export * from './store';\n")
    (tmp_path / "store.js").write_text(
        "export function load(k) { return k; }\nexport class Store { read(k) { return k; } }\n"
    )
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert sorted(imports["index.js"]) == ["Store", "load"]


@pytest.mark.parametrize("extension", [".js", ".cjs", ".ts", ".tsx"])
def test_commonjs_require_edges_are_import_edges(tmp_path, extension):
    """CommonJS require imports first party names across JavaScript grammar variants."""
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
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert sorted(imports[route]) == ["find", "load", "save"]


def test_commonjs_require_from_outside_the_tree_binds_nothing(tmp_path):
    """CommonJS require ignores modules outside the reviewed tree."""
    (tmp_path / "route.cjs").write_text(
        "const { readFile } = require('fs');\n"
        "const fs = require('fs');\n"
        "function handle(k) { return fs.readFileSync(readFile, k); }\n"
    )
    assert TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"] == {}


def test_commonjs_export_assignments_are_definitions(tmp_path):
    """CommonJS export assignments become definition records with calls."""
    (tmp_path / "store.cjs").write_text(
        "exports.load = function (k) { return k; };\nmodule.exports.save = () => load();\n"
    )
    graph = _graph(tmp_path)
    assert sorted(graph["store.cjs"]) == ["load", "save"]
    assert graph["store.cjs"]["save"][0]["calls"] == ["load"]


def test_a_namespace_import_binds_the_names_used_through_it(tmp_path):
    """Namespace import binds the names used through it."""
    (tmp_path / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "plain.py").write_text("import store\nimport os\n\n\ndef h():\n    return store.load(os.getcwd())\n")
    (tmp_path / "alias.py").write_text("import store as st\n\n\ndef h():\n    return st.load(1)\n")
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert imports["plain.py"] == ["load"]
    assert imports["alias.py"] == ["load"]


def test_a_namespace_from_outside_the_tree_binds_nothing(tmp_path):
    """Namespace from outside the tree binds nothing."""
    (tmp_path / "a.py").write_text("import os\n\n\ndef h():\n    return os.getcwd()\n")
    assert TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_qualifier_that_was_never_imported_binds_nothing(tmp_path):
    """Qualifier that was never imported binds nothing."""
    (tmp_path / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "a.py").write_text("def h(client):\n    return client.load(2)\n")
    assert TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_dotted_namespace_binds_under_its_whole_specifier(tmp_path):
    """Dotted namespace binds under its whole specifier."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "store.py").write_text("def load(k):\n    return k\n")
    (tmp_path / "use.py").write_text("import app.store\n\n\ndef h():\n    return app.store.load(1)\n")
    assert TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]["use.py"] == ["load"]


def test_a_go_package_import_resolves_by_directory(tmp_path):
    """Go package import resolves by directory."""
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "db.go").write_text("package store\nfunc Load(k int) int { return k }\n")
    (tmp_path / "main.go").write_text(
        'package main\nimport (\n "example.com/app/store"\n "fmt"\n)\nfunc h() { store.Load(1); fmt.Println("x") }\n'
    )
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert imports["main.go"] == ["Load"]


def test_a_third_party_import_is_dropped_since_it_names_no_file_in_the_tree(tmp_path):
    """Third party import is dropped since it names no file in the tree."""
    (tmp_path / "a.py").write_text("from django.http import HttpResponse\n\n\ndef f():\n    return 1\n")
    assert TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"] == {}


def test_a_relative_import_climbing_a_package_resolves(tmp_path):
    """Relative import climbing a package resolves."""
    (tmp_path / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "pkg" / "shared.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "pkg" / "sub" / "use.py").write_text("from ..shared import helper\n\n\ndef f():\n    return 1\n")
    imports = TreeSitterCallGraph().extract(tmp_path).data["graph"]["imports"]
    assert imports["pkg/sub/use.py"] == ["helper"]


def test_a_package_absolute_import_resolves_when_the_review_root_is_inside_the_package(tmp_path):
    """Package absolute import resolves when the review root is inside the package."""
    scope = tmp_path / "apps" / "webui"
    (scope / "models").mkdir(parents=True)
    (scope / "routers").mkdir()
    (tmp_path / ".git").mkdir()
    (scope / "models" / "files.py").write_text("def insert_new_file(x):\n    return x\n")
    (scope / "routers" / "files.py").write_text(
        "from apps.webui.models.files import insert_new_file\n\n\ndef upload(r):\n    return insert_new_file(r)\n"
    )
    imports = TreeSitterCallGraph().extract(scope).data["graph"]["imports"]
    assert imports["routers/files.py"] == ["insert_new_file"]


def test_the_stripped_prefix_stops_at_the_repository(tmp_path):
    """Stripped prefix stops at the repository."""
    from cyberjury.domains.web.facts.callgraph import _scope_prefixes

    repository = tmp_path / "data" / "proj"
    scope = repository / "apps" / "webui"
    scope.mkdir(parents=True)
    (repository / ".git").mkdir()
    assert _scope_prefixes(scope) == ("apps/webui", "webui")


def test_a_tree_with_no_repository_strips_nothing(tmp_path):
    """Tree with no repository strips nothing."""
    from cyberjury.domains.web.facts.callgraph import _scope_prefixes

    scope = tmp_path / "apps" / "webui"
    scope.mkdir(parents=True)
    assert _scope_prefixes(scope) == ()


def test_a_specifier_naming_another_package_still_misses(tmp_path):
    """Specifier naming another package still misses."""
    scope = tmp_path / "apps" / "webui"
    (scope / "models").mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (scope / "models" / "files.py").write_text("def helper():\n    return 1\n")
    (scope / "use.py").write_text("from other.pkg.models.files import helper\n\n\ndef f():\n    return 1\n")
    assert TreeSitterCallGraph().extract(scope).data["graph"]["imports"] == {}


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
    """Specifier resolves to the file it names."""
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
    assert resolve_specifier(src, spec, known, _extensions()) == expected


def test_a_specifier_naming_a_package_directory_resolves_through_its_index(tmp_path):
    """Specifier naming a package directory resolves through its index."""
    assert resolve_specifier("a.ts", "./svc", {"svc/index.ts"}, _extensions()) == "svc/index.ts"
    assert resolve_specifier("a.py", ".pkg", {"pkg/__init__.py"}, _extensions()) == "pkg/__init__.py"


def test_every_declared_extension_resolves(tmp_path):
    """Every declared extension resolves."""
    for ext in _extensions():
        target = f"svc{ext}"
        assert resolve_specifier("a.py", "./svc", {target}, _extensions()) == target, ext


def test_by_file_carries_each_file_own_graph_as_prompt_text(tmp_path):
    """The by_file map carries each file graph as prompt text."""
    _chain(tmp_path)
    block = TreeSitterCallGraph().extract(tmp_path).data["by_file"]["app/handler.py"]
    assert "handle_request()" in block
    assert "calls load_order" in block
    assert "imports load_order" in block
    assert "get_order" not in block


def test_the_summary_names_the_scale_and_the_name_match_caveat(tmp_path):
    """Summary names the scale and the name match caveat."""
    _chain(tmp_path)
    summary = TreeSitterCallGraph().extract(tmp_path).summary
    assert "Call graph" in summary
    assert "matched by name" in summary


def test_an_empty_tree_yields_empty_facts(tmp_path):
    """Empty tree yields empty facts."""
    (tmp_path / "notes.md").write_text("no code here\n")
    assert TreeSitterCallGraph().extract(tmp_path).empty


def _absent(specs, name="python"):
    base = specs[name]
    return LangSpec(
        name=name,
        extensions=base.extensions,
        module="tree_sitter_absent_grammar",
        accessor="language",
        definitions=base.definitions,
        calls=base.calls,
        imports=base.imports,
    )


def test_a_language_with_no_grammar_installed_is_not_extracted(tmp_path):
    """Language with no grammar installed is not extracted."""
    specs = load_specs()
    specs["python"] = _absent(specs)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    (tmp_path / "b.ts").write_text("function g() { return 1; }\n")
    assert set(TreeSitterCallGraph(specs).extract(tmp_path).data["graph"]["callgraph"]) == {"b.ts"}


def test_unavailable_when_no_grammar_at_all_is_installed(tmp_path):
    """Unavailable when no grammar at all is installed."""
    backend = TreeSitterCallGraph({"python": _absent(load_specs())})
    assert backend.available() is False
    with pytest.raises(BackendUnavailable):
        backend.extract(tmp_path)
