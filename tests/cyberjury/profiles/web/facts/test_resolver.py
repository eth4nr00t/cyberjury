"""Web resolution follows declarative language, alias, and package rules."""

import pytest

from cyberjury.profiles.web.facts.analyzer import LangSpec, load_specs
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.profiles.web.facts.resolver import (
    resolve_specifiers,
    scope_prefixes,
)
from cyberjury.review.facts import (
    definition_call_candidates,
    definition_structural_candidates,
    definition_structural_gaps,
)


def _specs():
    return tuple(load_specs().values())


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

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.file, edge.source.name, edge.target.file, edge.target.name)
        for edge in dependencies
        if edge.source.name == "handle"
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

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.name, edge.target.file, edge.target.name, edge.reference)
        for edge in dependencies
        if edge.source.name == "handle"
    ] == [("handle", f"store{extension}", "load", "fetch")]


def test_re_export_aliases_resolve_each_local_name_in_the_chain(tmp_path):
    (tmp_path / "route.ts").write_text(
        "import { read as fetch } from './facade';\nfunction handle() { return fetch(); }\n"
    )
    (tmp_path / "facade.ts").write_text("export { load as read } from './store';\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.name, edge.target.file, edge.target.name, edge.reference)
        for edge in dependencies
        if edge.source.name == "handle"
    ] == [("handle", "store.ts", "load", "fetch")]


def test_a_re_export_cycle_terminates_without_losing_a_reachable_symbol(tmp_path):
    (tmp_path / "route.ts").write_text("import { load } from './one';\nfunction handle() { return load(); }\n")
    (tmp_path / "one.ts").write_text("export { load } from './two';\n")
    (tmp_path / "two.ts").write_text("export { load } from './one';\nexport { load } from './store';\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [edge.target.file for edge in dependencies if edge.source.name == "handle"] == ["store.ts"]


def test_a_private_import_is_not_treated_as_a_re_export(tmp_path):
    (tmp_path / "route.ts").write_text("import { load } from './facade';\nfunction handle() { return load(); }\n")
    (tmp_path / "facade.ts").write_text("import { load } from './store';\nexport function other() { return load(); }\n")
    (tmp_path / "store.ts").write_text("export function load() { return 1; }\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert not [
        edge
        for edge in definition_call_candidates(graph)
        if edge.source.name == "handle" and edge.target.file == "store.ts"
    ]
    assert [(edge.source.name, edge.target.file, edge.target.name) for edge in definition_call_candidates(graph)] == [
        ("other", "store.ts", "load")
    ]


def test_a_workspace_package_name_resolves_without_a_path_guess(tmp_path):
    (tmp_path / "packages" / "store" / "src").mkdir(parents=True)
    (tmp_path / "app").mkdir()
    (tmp_path / "package.json").write_text('{"private":true,"workspaces":["packages/*"]}')
    (tmp_path / "packages" / "store" / "package.json").write_text('{"name":"@acme/store","source":"src/index.ts"}')
    (tmp_path / "packages" / "store" / "src" / "index.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "app" / "route.ts").write_text(
        "import { load } from '@acme/store';\nfunction handle() { return load(); }\n"
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["app/route.ts"] == ["packages/store/src/index.ts"]
    assert [edge.target.file for edge in definition_call_candidates(graph) if edge.source.name == "handle"] == [
        "packages/store/src/index.ts"
    ]


def test_a_sibling_package_is_not_shared_without_a_workspace_declaration(tmp_path):
    (tmp_path / "packages" / "store" / "src").mkdir(parents=True)
    (tmp_path / "app").mkdir()
    (tmp_path / "packages" / "store" / "package.json").write_text('{"name":"@acme/store","source":"src/index.ts"}')
    (tmp_path / "packages" / "store" / "src" / "index.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "app" / "route.ts").write_text(
        "import { load } from '@acme/store';\nfunction handle() { return load(); }\n"
    )

    facts = TreeSitterFacts().extract(tmp_path)

    assert facts.data["graph"]["import_targets"] == {}
    assert definition_structural_gaps(facts.data["graph"]) == ()


def test_nested_aliases_apply_only_inside_their_owning_project(tmp_path):
    for project in ("a", "b"):
        (tmp_path / project / "src").mkdir(parents=True)
        (tmp_path / project / "tsconfig.json").write_text(
            '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}'
        )
        (tmp_path / project / "src" / "store.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "b" / "src" / "route.ts").write_text(
        "import { load } from '@/store';\nfunction handle() { return load(); }\n"
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["b/src/route.ts"] == ["b/src/store.ts"]


def test_web_sources_exclude_file_symlinks_outside_the_repository(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("def outside():\n    return 1\n")
    (tmp_path / "linked.py").symlink_to(outside)

    facts = TreeSitterFacts().extract(tmp_path)

    assert facts.empty


def test_setup_cfg_package_dir_declares_python_source_root(tmp_path):
    (tmp_path / "src" / "domain").mkdir(parents=True)
    (tmp_path / "src" / "api").mkdir()
    (tmp_path / "setup.cfg").write_text("[options]\npackage_dir =\n    =src\n")
    (tmp_path / "src" / "domain" / "models.py").write_text("class Record:\n    pass\n")
    (tmp_path / "src" / "api" / "routes.py").write_text(
        "from domain.models import Record\n\ndef handle():\n    return Record()\n"
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["src/api/routes.py"] == ["src/domain/models.py"]


def test_nested_python_source_roots_apply_only_inside_their_owning_project(tmp_path):
    for project in ("a", "b"):
        (tmp_path / project / "src" / "domain").mkdir(parents=True)
        (tmp_path / project / "src" / "api").mkdir()
        (tmp_path / project / "pyproject.toml").write_text('[tool.setuptools.package-dir]\n"" = "src"\n')
        (tmp_path / project / "src" / "domain" / "models.py").write_text("class Record:\n    pass\n")
        (tmp_path / project / "src" / "api" / "routes.py").write_text(
            "from domain.models import Record\n\ndef handle():\n    return Record()\n"
        )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["a/src/api/routes.py"] == ["a/src/domain/models.py"]
    assert graph["import_targets"]["b/src/api/routes.py"] == ["b/src/domain/models.py"]


def test_nested_go_modules_apply_only_inside_their_owning_project(tmp_path):
    for project in ("a", "b"):
        (tmp_path / project / "store").mkdir(parents=True)
        (tmp_path / project / "go.mod").write_text("module example.com/app\n")
        (tmp_path / project / "store" / "db.go").write_text("package store\nfunc Load(k int) int { return k }\n")
        (tmp_path / project / "main.go").write_text(
            'package main\nimport "example.com/app/store"\nfunc Handle() int { return store.Load(1) }\n'
        )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    dependencies = definition_structural_candidates(graph)

    assert {(edge.source_file, edge.target.file) for edge in dependencies if edge.reference == "store.Load"} == {
        ("a/main.go", "a/store/db.go"),
        ("b/main.go", "b/store/db.go"),
    }


@pytest.mark.parametrize("import_line", ["from external import load", "from external import *"])
def test_an_external_import_does_not_hide_a_later_local_definition(tmp_path, import_line):
    (tmp_path / "route.py").write_text(
        f"{import_line}\n\ndef load():\n    return 1\n\ndef handle():\n    return load()\n"
    )

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [(edge.source.name, edge.target.file, edge.target.name) for edge in dependencies] == [
        ("handle", "route.py", "load")
    ]


def test_a_function_local_import_does_not_bind_a_separate_function(tmp_path):
    (tmp_path / "store.py").write_text("def load():\n    return 2\n")
    (tmp_path / "route.py").write_text(
        "def load():\n"
        "    return 1\n\n"
        "def owner():\n"
        "    from store import load\n"
        "    return load()\n\n"
        "def other():\n"
        "    return load()\n"
    )

    dependencies = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert {(edge.source.name, edge.target.file, edge.target.name) for edge in dependencies} == {
        ("owner", "store.py", "load"),
        ("other", "route.py", "load"),
    }


def test_malformed_module_configuration_is_a_facts_limitation(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.setuptools.package-dir\n")
    (tmp_path / "source" / "domain").mkdir(parents=True)
    (tmp_path / "source" / "api").mkdir()
    (tmp_path / "source" / "domain" / "models.py").write_text("class Record:\n    pass\n")
    (tmp_path / "source" / "api" / "routes.py").write_text(
        "from domain.models import Record\n\ndef handle():\n    return Record()\n"
    )

    facts = TreeSitterFacts().extract(tmp_path)

    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("pyproject.toml", "web-resolver", "could not read Python module declarations")
    ]


def test_malformed_configuration_without_owned_sources_does_not_limit_other_projects(tmp_path):
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "package.json").write_text("{")
    (tmp_path / "app.py").write_text("def handle():\n    return 1\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert facts.limitations == ()


def test_malformed_package_manifest_with_owned_sources_is_a_facts_limitation(tmp_path):
    (tmp_path / "package.json").write_text("{")
    (tmp_path / "route.ts").write_text("function handle() { return 1; }\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("package.json", "web-resolver", "could not read JavaScript package declarations")
    ]


def test_go_module_without_a_module_declaration_is_a_facts_limitation(tmp_path):
    (tmp_path / "go.mod").write_text("go 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc Handle() int { return 1 }\n")

    facts = TreeSitterFacts().extract(tmp_path)

    assert [(item.source, item.analyzer, item.reason) for item in facts.limitations] == [
        ("go.mod", "web-resolver", "Go module declaration is missing")
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
    candidates = definition_call_candidates(graph)
    assert [
        (edge.target.file, edge.target.name, edge.reference) for edge in candidates if edge.source.name == "handle"
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
    (tmp_path / "go.mod").write_text("module example.com/app\n")
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
        (edge.kind, edge.target.file, edge.target.name, edge.reference)
        for edge in definition_structural_candidates(graph)
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
def test_namespace_imports_create_typed_structural_candidates(
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
    edges = [edge for edge in definition_structural_candidates(graph) if edge.kind == "reference"]

    assert [(edge.source_file, edge.target.file, edge.target.name) for edge in edges] == [(route, store, target_name)]


@pytest.mark.parametrize("extension", [".js", ".ts", ".tsx"])
def test_renamed_default_imports_resolve_the_exported_definition(tmp_path, extension):
    (tmp_path / f"store{extension}").write_text("export default function load() { return 1; }\n")
    (tmp_path / f"route{extension}").write_text("import fetch from './store';\nfunction handle() { return fetch(); }\n")

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [(edge.source.name, edge.target.name, edge.reference) for edge in edges if edge.reference == "fetch"] == [
        ("handle", "load", "fetch")
    ]


def test_an_unrepresented_first_party_default_export_keeps_an_unresolved_callsite(tmp_path):
    (tmp_path / "store.ts").write_text("export default function () { return 1; }\n")
    (tmp_path / "route.ts").write_text("import fetch from './store';\nfunction handle() { return fetch(); }\n")

    facts = TreeSitterFacts().extract(tmp_path)
    graph = facts.data["graph"]

    assert definition_call_candidates(graph) == ()
    assert [item["expression"] for item in facts.data["relationship_evidence"]["callsites"]] == ["fetch()"]


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
        unqualified_call_scope="file",
        module_entries=("module.custom",),
    )

    assert resolve_specifiers("app.custom", "./pkg", {"pkg/module.custom"}, (spec,)) == ("pkg/module.custom",)


def test_declared_project_aliases_resolve_inside_the_tree(tmp_path):
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"baseUrl":".","paths":{"~/*":["*"],"@/*":["*"]}}}')
    (tmp_path / "controllers").mkdir()
    (tmp_path / "utils").mkdir()
    (tmp_path / "controllers" / "request.controller.ts").write_text(
        "import { load } from '~/utils';\nimport { save } from '@/utils/dataStore';\n"
        "function handle() { return load() + save(); }\n"
    )
    (tmp_path / "utils" / "index.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "utils" / "dataStore.ts").write_text("export function save() { return 2; }\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["controllers/request.controller.ts"] == [
        "utils/index.ts",
        "utils/dataStore.ts",
    ]


def test_more_specific_typescript_alias_wins_independent_of_config_order(tmp_path):
    (tmp_path / "generic" / "admin").mkdir(parents=True)
    (tmp_path / "specific").mkdir()
    (tmp_path / "route.ts").write_text("import { load } from '@/admin/auth';\nfunction handle() { return load(); }\n")
    (tmp_path / "generic" / "admin" / "auth.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "specific" / "auth.ts").write_text("export function load() { return 2; }\n")
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"paths":{"@/*":["generic/*"],"@/admin/*":["specific/*"]}}}'
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["route.ts"] == ["specific/auth.ts"]


def test_typescript_base_url_resolves_without_paths(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"baseUrl":"src"}}')
    (tmp_path / "src" / "store.ts").write_text("export function load() { return 1; }\n")
    (tmp_path / "src" / "route.ts").write_text("import { load } from 'store';\nfunction handle() { return load(); }\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["src/route.ts"] == ["src/store.ts"]


def test_undeclared_project_aliases_do_not_guess_repository_targets(tmp_path):
    (tmp_path / "utils").mkdir()
    (tmp_path / "route.ts").write_text("import { load } from '~/utils';\nfunction handle() { return load(); }\n")
    (tmp_path / "utils" / "index.ts").write_text("export function load() { return 1; }\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"] == {}
    assert definition_structural_gaps(graph) == ()


def test_project_alias_configuration_cannot_escape_the_repository(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "utils").mkdir()
    (root / "route.ts").write_text("import { load } from '~/utils';\nfunction handle() { return load(); }\n")
    (root / "utils" / "index.ts").write_text("export function load() { return 1; }\n")
    config = tmp_path / "outside-tsconfig.json"
    config.write_text('{"compilerOptions":{"baseUrl":".","paths":{"~/*":["*"]}}}')
    (root / "tsconfig.json").symlink_to(config)

    graph = TreeSitterFacts().extract(root).data["graph"]

    assert graph["import_targets"] == {}
    assert definition_structural_gaps(graph) == ()


def test_repository_absolute_import_resolves_below_a_declared_source_root(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.setuptools.package-dir]\n"" = "source"\n')
    (tmp_path / "source" / "domain").mkdir(parents=True)
    (tmp_path / "source" / "api").mkdir()
    (tmp_path / "source" / "domain" / "models.py").write_text("class Record:\n    pass\n")
    (tmp_path / "source" / "api" / "routes.py").write_text(
        "from domain.models import Record\n\ndef handle():\n    return Record()\n"
    )

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"]["source/api/routes.py"] == ["source/domain/models.py"]


def test_ambiguous_repository_imports_remain_typed_candidates(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.setuptools.packages.find]\nwhere = ["source", "packages"]\n')
    for prefix in ("source", "packages"):
        (tmp_path / prefix / "domain").mkdir(parents=True)
        (tmp_path / prefix / "domain" / "__init__.py").write_text("")
        (tmp_path / prefix / "domain" / "models.py").write_text("class Record:\n    pass\n")
    (tmp_path / "route.py").write_text("from domain.models import Record\n\ndef handle():\n    return Record()\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    record_edges = [edge for edge in definition_structural_candidates(graph) if edge.target.name == "Record"]

    assert len({edge.target.file for edge in record_edges}) == 2


def test_a_third_party_module_does_not_bind_a_deep_same_name_file(tmp_path):
    (tmp_path / "internal" / "adapters").mkdir(parents=True)
    (tmp_path / "internal" / "__init__.py").write_text("")
    (tmp_path / "internal" / "adapters" / "__init__.py").write_text("")
    (tmp_path / "internal" / "adapters" / "fastapi.py").write_text(
        "class FastAPI:\n    pass\n\nclass FastAPIAdapter:\n    pass\n"
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n\ndef create():\n    return FastAPI()\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert graph["import_targets"] == {}
    assert definition_structural_gaps(graph) == ()


def test_a_confirmed_internal_module_with_a_missing_symbol_remains_unresolved(tmp_path):
    (tmp_path / "fastapi.py").write_text("class FastAPIAdapter:\n    pass\n")
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n\ndef create():\n    return FastAPI()\n")

    facts = TreeSitterFacts().extract(tmp_path)
    graph = facts.data["graph"]

    assert graph["import_targets"]["app.py"] == ["fastapi.py"]
    assert definition_call_candidates(graph) == ()
    assert [item["expression"] for item in facts.data["relationship_evidence"]["callsites"]] == ["FastAPI()"]


def test_unresolved_relative_import_is_preserved_for_completion(tmp_path):
    (tmp_path / "route.py").write_text("from .missing import policy\n\ndef handle():\n    return policy()\n")

    graph = TreeSitterFacts().extract(tmp_path).data["graph"]

    assert [item.reference for item in definition_structural_gaps(graph)] == [".missing"]


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


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (
            ".py",
            "def owner():\n"
            "    def check():\n"
            "        return True\n"
            "    return check()\n\n"
            "def other():\n"
            "    return check()\n",
        ),
        (
            ".js",
            "function owner() { function check() { return true; } return check(); }\n"
            "function other() { return check(); }\n",
        ),
        (
            ".ts",
            "function owner() { function check() { return true; } return check(); }\n"
            "function other() { return check(); }\n",
        ),
    ],
)
def test_unqualified_calls_do_not_escape_a_nested_definition_scope(tmp_path, extension, source):
    (tmp_path / f"app{extension}").write_text(source)

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])
    calls = [(edge.source.name, edge.target.name) for edge in edges if edge.reference == "check"]

    assert calls == [("owner", "check")]


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (
            ".py",
            "def owner():\n"
            "    def check():\n"
            "        return True\n"
            "    def use():\n"
            "        return check()\n"
            "    return use()\n",
        ),
        (
            ".js",
            "function owner() { function check() { return true; } function use() { return check(); } return use(); }\n",
        ),
        (
            ".ts",
            "function owner() { function check() { return true; } function use() { return check(); } return use(); }\n",
        ),
    ],
)
def test_unqualified_calls_can_use_a_definition_from_an_enclosing_function(tmp_path, extension, source):
    (tmp_path / f"app{extension}").write_text(source)

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [(edge.source.name, edge.target.name) for edge in edges if edge.reference == "check"] == [("use", "check")]


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (
            ".py",
            "class Policy:\n    def check(self):\n        return True\n\ndef use():\n    return check()\n",
        ),
        (
            ".js",
            "class Policy { check() { return true; } }\nfunction use() { return check(); }\n",
        ),
        (
            ".ts",
            "class Policy { check() { return true; } }\nfunction use() { return check(); }\n",
        ),
    ],
)
def test_unqualified_calls_do_not_treat_class_methods_as_file_bindings(tmp_path, extension, source):
    (tmp_path / f"app{extension}").write_text(source)

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert not [edge for edge in edges if edge.source.name == "use"]


def test_go_unqualified_calls_resolve_across_files_in_one_package(tmp_path):
    (tmp_path / "policy.go").write_text("package service\nfunc CheckPolicy() bool { return true }\n")
    (tmp_path / "handler.go").write_text("package service\nfunc ApplyPolicy() bool { return CheckPolicy() }\n")

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert [
        (edge.source.file, edge.source.name, edge.target.file, edge.target.name)
        for edge in edges
        if edge.reference == "CheckPolicy"
    ] == [("handler.go", "ApplyPolicy", "policy.go", "CheckPolicy")]


def test_go_package_scope_keeps_equal_names_in_other_directories_isolated(tmp_path):
    for directory in ("one", "two"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "helper.go").write_text("package shared\nfunc Check() bool { return true }\n")
    (tmp_path / "one" / "caller.go").write_text("package shared\nfunc Use() bool { return Check() }\n")

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])
    use_edges = [edge for edge in edges if edge.source.name == "Use"]

    assert [edge.target.file for edge in use_edges] == ["one/helper.go"]


def test_go_package_scope_does_not_cross_package_declarations(tmp_path):
    (tmp_path / "helper.go").write_text("package helper\nfunc Check() bool { return true }\n")
    (tmp_path / "caller.go").write_text("package caller\nfunc Use() bool { return Check() }\n")

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert not [edge for edge in edges if edge.source.name == "Use"]


def test_go_package_scope_does_not_treat_methods_as_unqualified_targets(tmp_path):
    (tmp_path / "model.go").write_text("package app\ntype Model struct{}\nfunc (Model) Check() bool { return true }\n")
    (tmp_path / "caller.go").write_text("package app\nfunc Use() bool { return Check() }\n")

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert not [edge for edge in edges if edge.source.name == "Use"]


def test_go_file_scope_does_not_treat_methods_as_unqualified_targets(tmp_path):
    (tmp_path / "model.go").write_text(
        "package app\n"
        "type Model struct{}\n"
        "func (Model) Check() bool { return true }\n"
        "func Use() bool { return Check() }\n"
    )

    edges = definition_call_candidates(TreeSitterFacts().extract(tmp_path).data["graph"])

    assert not [edge for edge in edges if edge.source.name == "Use"]
