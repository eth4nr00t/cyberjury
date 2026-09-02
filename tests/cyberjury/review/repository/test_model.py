"""Repository model tests cover file mapping and review unit construction."""

import pytest

from cyberjury.review.facts import FactFragment, FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository.context import gather, gather_context
from cyberjury.review.repository.model import (
    RepositorySourceError,
    build_repository_model,
    build_repository_model_from_dir,
    build_units,
    candidate_entrypoint_files,
    char_spans,
    files_with_exported_symbols,
    repository_unit_plan_receipt,
)


def _facts_resolution() -> FactsResolutionReceipt:
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    return FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def test_build_lists_files_sorted():
    m = build_repository_model("/repository", ["b/x.py", "a.py", "a/y.js"])
    assert m.root == "/repository"
    assert m.files == ("a.py", "a/y.js", "b/x.py")


def test_candidate_entrypoint_files_by_glob():
    files = ["app/urls.py", "app/views.py", "manage.py", "README.md"]
    assert candidate_entrypoint_files(files, globs=["*urls.py"]) == ["app/urls.py"]
    assert candidate_entrypoint_files(files, globs=["*urls.py", "manage.py"]) == ["app/urls.py", "manage.py"]
    assert candidate_entrypoint_files(files, globs=[]) == []


def test_candidate_entrypoint_files_by_content_markers(tmp_path):
    (tmp_path / "handlers.py").write_text("class TokenViewSet(ViewSet):\n    pass\n")
    (tmp_path / "notes.md").write_text("ViewSet mentioned in prose, not code\n")
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    got = candidate_entrypoint_files(["handlers.py", "notes.md", "util.py"], root=tmp_path, markers=["ViewSet"])
    assert got == ["handlers.py"]


def test_candidate_entrypoint_markers_normalize_extension_case(tmp_path):
    (tmp_path / "HANDLER.PY").write_text("class TokenViewSet(ViewSet):\n    pass\n")

    got = candidate_entrypoint_files(["HANDLER.PY"], root=tmp_path, markers=["ViewSet"])

    assert got == ["HANDLER.PY"]


def test_candidate_entrypoint_files_sorted_and_deduped(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "urls.py").write_text("class ViewSet:\n    pass\n")
    (tmp_path / "b" / "urls.py").write_text("x = 1\n")
    files = ["b/urls.py", "a/urls.py", "a/urls.py"]
    got = candidate_entrypoint_files(files, root=tmp_path, globs=["*urls.py"], markers=["ViewSet"])
    assert got == ["a/urls.py", "b/urls.py"]


def test_files_with_exported_symbols_selects_exports_and_skips_private_only(tmp_path):
    (tmp_path / "exported.go").write_text("package p\nfunc Handle(r *R) error {\n return nil\n}\n")
    (tmp_path / "private.go").write_text("package p\nfunc helper() int {\n return 1\n}\n")
    files = ["exported.go", "private.go"]
    got = files_with_exported_symbols(files, root=tmp_path, patterns=["^func [A-Z]"])
    assert got == ["exported.go"]


def test_files_with_exported_symbols_skips_tests_and_needs_patterns(tmp_path):
    (tmp_path / "api.go").write_text("package p\nfunc Do() {}\n")
    (tmp_path / "api_test.go").write_text("package p\nfunc TestDo() {}\n")
    files = ["api.go", "api_test.go"]
    assert files_with_exported_symbols(files, root=tmp_path, patterns=["^func [A-Z]"]) == ["api.go"]
    assert files_with_exported_symbols(files, root=tmp_path, patterns=[]) == []
    assert files_with_exported_symbols(files, patterns=["^func [A-Z]"]) == []


def test_candidate_discovery_fails_loud_on_an_oversized_source(tmp_path):
    (tmp_path / "handlers.py").write_text("x" * 2_000_001 + "\n@app.route('/admin')\n")

    with pytest.raises(RepositorySourceError, match="exceeds"):
        candidate_entrypoint_files(["handlers.py"], root=tmp_path, markers=["@app.route"])


def test_build_from_dir_walks_tree_and_skips_noise(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "urls.py").write_text("x = 1")
    (tmp_path / "go.mod").write_text("module x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1")
    (tmp_path / "build" / "lib" / "pkg").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "pkg" / "urls.py").write_text("x = 1")

    m = build_repository_model_from_dir(tmp_path)
    assert {"app.py", "pkg/urls.py", "go.mod"} <= set(m.files)
    assert all("__pycache__" not in f for f in m.files)
    assert all(not f.startswith("build/") for f in m.files)


def test_build_is_deterministic():
    assert build_repository_model("/r", ["b.py", "a.py"]) == build_repository_model("/r", ["a.py", "b.py"])


def _dependency(
    source_file: str,
    target: tuple[str, str, int, int],
    source: tuple[str, str, int, int] | None = None,
) -> dict[str, object]:
    def record(fragment: tuple[str, str, int, int]) -> dict[str, object]:
        file, name, start, end = fragment
        return {"file": file, "name": name, "range": [start, end]}

    return {
        "source_file": source_file,
        "source": record(source) if source is not None else None,
        "target": record(target),
    }


def test_build_units_appends_fact_unit_specs(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 500)
    specs = [{"name": "V.sol#V.liquidate", "files": ["V.sol"], "fragments": [["V.sol", 10, 50], ["V.sol", 60, 120]]}]
    units = build_units(str(tmp_path), ["V.sol"], [], specs)
    assert "V.sol" in [u.name for u in units]
    cp = [u for u in units if u.kind == "focused"]
    assert len(cp) == 1
    assert cp[0].name == "focused:V.sol"
    assert cp[0].kind == "focused"
    assert cp[0].labels == ("V.sol#V.liquidate",)
    assert cp[0].files == ("V.sol",)
    assert cp[0].fragments == (("V.sol", 10, 50), ("V.sol", 60, 120))
    source = next(unit for unit in units if unit.kind == "source")
    source_ranges = {(start, end) for _file, start, end in source.fragments}
    focused_ranges = {(start, end) for _file, start, end in cp[0].fragments}
    assert source_ranges == {(0, 10), (50, 60), (120, 500)}
    assert source_ranges.isdisjoint(focused_ranges)


def test_build_units_without_fact_unit_specs_is_unchanged(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 500)
    units = build_units(str(tmp_path), ["V.sol"], [])
    assert not any(u.fragments for u in units)


def _graph():
    return {
        "callgraph": {
            "web.py": {"run_app": [{"range": [0, 100], "calls": []}]},
            "web_response.py": {
                "StreamResponse": [{"range": [200, 900], "calls": []}],
                "json_response": [{"range": [900, 1000], "calls": []}],
                "unexported": [{"range": [1000, 1100], "calls": []}],
            },
        },
        "imports": {"web.py": ["StreamResponse", "json_response", "run_app"]},
        "dependencies": [
            _dependency("web.py", ("web_response.py", "StreamResponse", 200, 900)),
            _dependency("web.py", ("web_response.py", "json_response", 900, 1000)),
        ],
    }


def _materialize_graph_sources(root, graph):
    for file, definitions in graph.get("callgraph", {}).items():
        end = max(entry["range"][1] for entries in definitions.values() for entry in entries)
        path = root / file
        existing = path.read_text() if path.is_file() else ""
        if len(existing) < end:
            path.write_text(existing + "x" * (end - len(existing)))


def test_build_units_packs_the_definitions_a_candidate_imports(tmp_path):
    (tmp_path / "web.py").write_text("StreamResponse()\njson_response()\n" + "x" * 70)
    graph = _graph()
    _materialize_graph_sources(tmp_path, graph)
    units = build_units(str(tmp_path), ["web.py"], [], None, graph)
    closure = [u for u in units if u.fragments]
    assert len(closure) == 1
    assert closure[0].name == "relationships:web.py"
    assert closure[0].files == ("web.py", "web_response.py")
    assert closure[0].owned_paths == ("web.py",)
    assert closure[0].fragments == (
        ("web.py", 0, 100),
        ("web_response.py", 200, 900),
        ("web_response.py", 900, 1000),
    )


def test_build_units_packs_two_import_hops_from_a_candidate(tmp_path):
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": []}]},
            "service.py": {"load": [{"range": [20, 40], "calls": []}]},
            "models.py": {"read_owner": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["read_owner"]},
        "dependencies": [
            _dependency("route.py", ("service.py", "load", 20, 40)),
            _dependency(
                "service.py",
                ("models.py", "read_owner", 60, 90),
                ("service.py", "load", 20, 40),
            ),
        ],
    }
    (tmp_path / "route.py").write_text("load()\n" + "x" * 94)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:route.py"]
    assert units[0].fragments == (("route.py", 0, 10), ("service.py", 20, 40), ("models.py", 60, 90))


def test_build_units_excludes_unrelated_sibling_edges_from_a_reached_file(tmp_path):
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 20], "calls": ["load"]}]},
            "service.py": {
                "load": [{"range": [20, 50], "calls": ["read"]}],
                "admin": [{"range": [60, 90], "calls": ["wipe"]}],
            },
            "store.py": {
                "read": [{"range": [0, 30], "calls": []}],
                "wipe": [{"range": [40, 70], "calls": []}],
            },
        },
        "dependencies": [
            _dependency("route.py", ("service.py", "load", 20, 50), ("route.py", "handle", 0, 20)),
            _dependency("service.py", ("store.py", "read", 0, 30), ("service.py", "load", 20, 50)),
            _dependency("service.py", ("store.py", "wipe", 40, 70), ("service.py", "admin", 60, 90)),
        ],
    }
    for path in ("route.py", "service.py", "store.py"):
        (tmp_path / path).write_text("x" * 100)

    units = [unit for unit in build_units(tmp_path, ["route.py"], [], None, graph) if unit.fragments]

    assert len(units) == 1
    assert units[0].fragments == (
        ("route.py", 0, 20),
        ("service.py", 20, 50),
        ("store.py", 0, 30),
    )


def test_build_units_does_not_repeat_candidate_definitions_without_relationships(tmp_path):
    source = "def route(value):\n    return value\n"
    (tmp_path / "route.py").write_text(source)
    graph = {
        "callgraph": {
            "route.py": {"route": [{"range": [0, len(source)], "calls": []}]},
        },
        "dependencies": [],
        "unresolved_dependencies": [],
    }

    units = build_units(tmp_path, ["route.py"], [], facts_graph=graph)

    assert [(unit.name, unit.files, unit.fragments) for unit in units] == [
        ("route.py", ("route.py",), ()),
    ]
    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("route.py",),
    )
    assert receipt.expected_seed_ids == ("source:route.py",)
    assert receipt.unowned_seed_ids == ()
    assert receipt.multi_unit_seed_ids == ()
    assert receipt.units[0].kind == "source"


def test_repository_unit_plan_excludes_empty_sources_without_creating_work(tmp_path):
    (tmp_path / "empty.py").write_text("")

    units = build_units(tmp_path, ["empty.py"], [])
    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("empty.py",),
    )

    assert units == []
    assert receipt.excluded_empty_paths == ("empty.py",)
    assert receipt.unowned_paths == ()
    assert receipt.expected_seed_ids == ()


def test_repository_unit_plan_rejects_an_uncovered_source_range(tmp_path):
    (tmp_path / "large.py").write_text("x" * 30_000)
    units = build_units(tmp_path, ["large.py"], [])

    with pytest.raises(ValueError, match="left source range"):
        repository_unit_plan_receipt(
            tmp_path,
            units[:1],
            _facts_resolution(),
            expected_owned_paths=("large.py",),
        )


def test_repository_unit_plan_records_intentional_hard_split_overlap(tmp_path):
    (tmp_path / "large.py").write_text(" " * 30_000)
    units = build_units(tmp_path, ["large.py"], [])

    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("large.py",),
    )

    assert receipt.overlapping_source_chars == 2_000
    assert receipt.multi_unit_seed_ids == ("source:large.py",)


def test_build_units_namespaces_focused_units_away_from_source_names(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 100)
    specs = [{"name": "V.sol", "files": ["V.sol"], "fragments": [["V.sol", 10, 50]]}]

    units = build_units(tmp_path, ["V.sol"], [], specs)

    assert [unit.name for unit in units] == ["V.sol", "focused:V.sol"]
    assert units[1].labels == ("V.sol",)


def test_build_units_rejects_overlapping_focused_ownership(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 100)
    specs = [
        {"name": "first", "files": ["V.sol"], "fragments": [["V.sol", 10, 50]]},
        {"name": "second", "files": ["V.sol"], "fragments": [["V.sol", 40, 80]]},
    ]

    with pytest.raises(ValueError, match="focused unit fragments overlap"):
        build_units(tmp_path, ["V.sol"], [], specs)


def test_build_units_packs_same_file_focused_specs_within_the_source_budget(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 1_000)
    specs = [
        {"name": "V.first", "files": ["V.sol"], "fragments": [["V.sol", 100, 200]]},
        {"name": "V.second", "files": ["V.sol"], "fragments": [["V.sol", 400, 500]]},
    ]

    units = build_units(tmp_path, ["V.sol"], [], specs)
    focused = [unit for unit in units if unit.kind == "focused"]

    assert len(focused) == 1
    assert focused[0].labels == ("V.first", "V.second")
    assert focused[0].fragments == (("V.sol", 100, 200), ("V.sol", 400, 500))


def test_build_units_fails_loud_when_a_focused_source_is_missing(tmp_path):
    (tmp_path / "entry.py").write_text("entry")
    specs = [{"name": "missing", "files": ["gone.py"], "fragments": [["gone.py", 0, 10]]}]

    with pytest.raises(RepositorySourceError, match=r"could not read source gone\.py"):
        build_units(tmp_path, ["entry.py"], [], specs)


def test_build_units_packs_called_definitions_from_imported_target_files(tmp_path):
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": ["read_owner"]}]},
            "store.py": {
                "StoreTable": [{"range": [20, 40], "calls": []}],
                "read_owner": [{"range": [60, 90], "calls": []}],
            },
            "other.py": {"read_owner": [{"range": [100, 130], "calls": []}]},
        },
        "imports": {"route.py": ["Store"]},
        "import_targets": {"route.py": ["store.py"]},
        "dependencies": [
            _dependency(
                "route.py",
                ("store.py", "read_owner", 60, 90),
                ("route.py", "handle", 0, 10),
            )
        ],
    }
    (tmp_path / "route.py").write_text("load()\n" + "x" * 93)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:route.py"]
    assert units[0].fragments == (("route.py", 0, 10), ("store.py", 60, 90))


def test_build_units_packs_an_evm_call_chain_without_import_edges(tmp_path):
    (tmp_path / "Vault.sol").write_text("x" * 100)
    (tmp_path / "Token.sol").write_text("x" * 100)
    graph = {
        "callgraph": {
            "Vault.sol": {"withdraw": [{"range": [0, 40], "calls": ["transfer"]}]},
            "Token.sol": {"transfer": [{"range": [40, 80], "calls": []}]},
        },
        "imports": {},
        "import_targets": {},
        "dependencies": [
            _dependency(
                "Vault.sol",
                ("Token.sol", "transfer", 40, 80),
                ("Vault.sol", "withdraw", 0, 40),
            )
        ],
    }

    units = [unit for unit in build_units(str(tmp_path), ["Vault.sol"], [], None, graph) if unit.fragments]

    assert len(units) == 1
    assert units[0].fragments == (("Vault.sol", 0, 40), ("Token.sol", 40, 80))


def test_build_units_adds_callsite_windows_for_imported_target_calls(tmp_path):
    route = "\n".join(
        [
            "def helper():",
            "    pass",
            "",
            "def handle(user_id):",
            "    if not current_user:",
            "        raise Exception()",
            "    return read_owner(user_id)",
            "",
            "def unrelated():",
            "    pass",
        ]
    )
    store = "x" * 100
    (tmp_path / "route.py").write_text(route)
    (tmp_path / "store.py").write_text(store)
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [20, 140], "calls": ["read_owner"]}]},
            "store.py": {"read_owner": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["Store"]},
        "import_targets": {"route.py": ["store.py"]},
        "dependencies": [
            _dependency(
                "route.py",
                ("store.py", "read_owner", 60, 90),
                ("route.py", "handle", 20, 140),
            )
        ],
    }
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert units[0].files == ("route.py", "store.py")
    assert units[0].fragments[-1] == ("store.py", 60, 90)
    assert "read_owner(user_id)" in gather(units[0])


def test_build_units_stops_import_closure_after_two_hops(tmp_path):
    graph = {
        "callgraph": {
            "service.py": {"load": [{"range": [0, 10], "calls": []}]},
            "models.py": {"read_owner": [{"range": [20, 40], "calls": []}]},
            "driver.py": {"query": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["read_owner"], "models.py": ["query"]},
        "dependencies": [
            _dependency("route.py", ("service.py", "load", 0, 10)),
            _dependency(
                "service.py",
                ("models.py", "read_owner", 20, 40),
                ("service.py", "load", 0, 10),
            ),
            _dependency(
                "models.py",
                ("driver.py", "query", 60, 90),
                ("models.py", "read_owner", 20, 40),
            ),
        ],
    }
    (tmp_path / "route.py").write_text("load()\n" + "x" * 93)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:route.py"]
    assert units[0].fragments == (("service.py", 0, 10), ("models.py", 20, 40))


def test_build_units_does_not_repack_the_candidate_on_an_import_cycle(tmp_path):
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": []}]},
            "service.py": {"load": [{"range": [20, 40], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["handle"]},
        "dependencies": [
            _dependency("route.py", ("service.py", "load", 20, 40)),
            _dependency(
                "service.py",
                ("route.py", "handle", 0, 10),
                ("service.py", "load", 20, 40),
            ),
        ],
    }
    (tmp_path / "route.py").write_text("load()\n" + "x" * 93)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:route.py"]
    assert len(units[0].fragments) == len(set(units[0].fragments))


def test_build_units_leaves_out_a_definition_the_candidate_does_not_import(tmp_path):
    (tmp_path / "web.py").write_text("x" * 100)
    units = build_units(str(tmp_path), ["web.py"], [], None, _graph())
    packed = {f for u in units if u.fragments for f in u.fragments}
    assert ("web_response.py", 1000, 1100) not in packed


def test_build_units_keeps_the_candidate_seed_with_its_dependencies(tmp_path):
    graph = _graph()
    assert "run_app" in graph["imports"]["web.py"]
    assert "run_app" in graph["callgraph"]["web.py"]
    (tmp_path / "web.py").write_text("StreamResponse()\njson_response()\n" + "x" * 70)
    _materialize_graph_sources(tmp_path, graph)
    units = build_units(str(tmp_path), ["web.py"], [], None, graph)
    assert any("web.py" in u.files for u in units if u.fragments)


@pytest.mark.parametrize("extension", [".go", ".sol"])
def test_build_units_keeps_an_unchanged_caller_with_a_candidate_callee(tmp_path, extension):
    helper = "x" * 40
    caller = "y" * 60
    helper_path = f"helper{extension}"
    caller_path = f"caller{extension}"
    (tmp_path / helper_path).write_text(helper)
    (tmp_path / caller_path).write_text(caller)
    changed = (helper_path, "check", 0, len(helper))
    source = (caller_path, "authorize", 0, len(caller))
    graph = {
        "callgraph": {
            helper_path: {"check": [{"range": [0, len(helper)], "calls": []}]},
            caller_path: {"authorize": [{"range": [0, len(caller)], "calls": ["check"]}]},
        },
        "dependencies": [_dependency(caller_path, changed, source)],
    }

    units = [unit for unit in build_units(tmp_path, [helper_path], [], facts_graph=graph) if unit.definition_plan]

    assert len(units) == 1
    assert units[0].files == (helper_path, caller_path)
    assert units[0].fragment_identities == (
        f"{helper_path}:check:0:{len(helper)}",
        f"{caller_path}:authorize:0:{len(caller)}",
    )


def test_build_units_keeps_base_source_coverage_when_dependency_graphs_exist(tmp_path):
    source = "POLICY = load_policy()\n\ndef route():\n    return serve()\n\nregister(route)\n"
    (tmp_path / "app.py").write_text(source)
    (tmp_path / "service.py").write_text("def serve():\n    return 1\n")
    graph = {
        "callgraph": {
            "app.py": {"route": [{"range": [24, 55], "calls": ["serve"]}]},
            "service.py": {"serve": [{"range": [0, 26], "calls": []}]},
        },
        "dependencies": [_dependency("app.py", ("service.py", "serve", 0, 26), ("app.py", "route", 24, 55))],
    }

    units = build_units(tmp_path, ["app.py"], [], None, graph)

    base = next(unit for unit in units if unit.name == "app.py")
    dependency = next(unit for unit in units if unit.name == "relationships:app.py")
    assert base.fragments == ()
    assert base.span is None
    assert dependency.relationships


def test_build_units_keeps_an_isolated_seed_beside_a_dependency_unit(tmp_path):
    isolated_size = 130_000
    graph = {
        "callgraph": {
            "isolated.py": {"standalone": [{"range": [0, isolated_size], "calls": []}]},
            "route.py": {"handle": [{"range": [0, 40], "calls": ["load"]}]},
            "service.py": {"load": [{"range": [0, 40], "calls": []}]},
        },
        "dependencies": [_dependency("route.py", ("service.py", "load", 0, 40), ("route.py", "handle", 0, 40))],
    }
    (tmp_path / "isolated.py").write_text("x" * isolated_size)
    (tmp_path / "route.py").write_text("x" * 40)
    (tmp_path / "service.py").write_text("x" * 40)
    specs = [
        {
            "name": "isolated-risk",
            "files": ["isolated.py"],
            "fragments": [["isolated.py", 0, isolated_size]],
        }
    ]

    units = [unit for unit in build_units(tmp_path, ["route.py"], [], specs, graph) if unit.fragments]

    assert any(unit.fragments == (("isolated.py", 0, isolated_size),) for unit in units)
    assert any(("service.py", 0, 40) in unit.fragments for unit in units)


def test_build_units_keeps_a_mixed_fact_spec_not_represented_by_one_graph_unit(tmp_path):
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 40], "calls": ["load"]}]},
            "service.py": {"load": [{"range": [0, 40], "calls": []}]},
        },
        "dependencies": [_dependency("route.py", ("service.py", "load", 0, 40), ("route.py", "handle", 0, 40))],
    }
    specs = [
        {
            "name": "manual-risk",
            "files": ["route.py", "manual.py"],
            "fragments": [["route.py", 0, 40], ["manual.py", 5, 25]],
        }
    ]
    (tmp_path / "route.py").write_text("x" * 40)
    (tmp_path / "service.py").write_text("x" * 40)
    (tmp_path / "manual.py").write_text("x" * 30)

    units = build_units(tmp_path, ["route.py"], [], specs, graph)

    assert any(
        unit.kind == "focused"
        and unit.labels == ("manual-risk",)
        and unit.fragments == (("route.py", 0, 40), ("manual.py", 5, 25))
        for unit in units
    )


def test_build_units_keeps_an_import_closure_beyond_the_packing_target(tmp_path):
    big = 24_000
    graph = {
        "callgraph": {"m.py": {f"f{i}": [{"range": [i * big, (i + 1) * big], "calls": []}] for i in range(3)}},
        "imports": {"a.py": ["f0", "f1", "f2"]},
        "dependencies": [_dependency("a.py", ("m.py", f"f{i}", i * big, (i + 1) * big)) for i in range(3)],
    }
    (tmp_path / "a.py").write_text("f0(); f1(); f2()\n" + "x" * 82)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["a.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:a.py"]
    assert units[0].fragments == tuple(("m.py", i * big, (i + 1) * big) for i in range(3))


def test_build_units_keeps_one_definition_larger_than_the_packing_target_whole(tmp_path):
    body = "class Big {\n" + "  const x = 1;\n" * 6000 + "}\n"
    (tmp_path / "m.ts").write_text(body)
    (tmp_path / "a.ts").write_text("Big\n" + "x" * 96)
    graph = {
        "callgraph": {"m.ts": {"Big": [{"range": [0, len(body)], "calls": []}]}},
        "imports": {"a.ts": ["Big"]},
        "dependencies": [_dependency("a.ts", ("m.ts", "Big", 0, len(body)))],
    }
    units = [u for u in build_units(str(tmp_path), ["a.ts"], [], None, graph) if u.fragments]
    assert len(units) == 1
    assert units[0].fragments == (("m.ts", 0, len(body)),)


def test_build_units_fails_loud_when_a_relationship_fragment_cannot_be_read(tmp_path):
    over = 24_001
    graph = {
        "callgraph": {"gone.py": {"big": [{"range": [0, over], "calls": []}]}},
        "imports": {"a.py": ["big"]},
        "dependencies": [_dependency("a.py", ("gone.py", "big", 0, over))],
    }
    (tmp_path / "a.py").write_text("x" * 100)
    with pytest.raises(RepositorySourceError, match=r"could not read source gone\.py"):
        build_units(str(tmp_path), ["a.py"], [], None, graph)


def test_build_units_reviews_a_closure_two_candidates_share_only_once(tmp_path):
    graph = {
        "callgraph": {"m.py": {"shared": [{"range": [0, 10], "calls": []}]}},
        "imports": {"a.py": ["shared"], "b.py": ["shared"]},
        "dependencies": [
            _dependency("a.py", ("m.py", "shared", 0, 10)),
            _dependency("b.py", ("m.py", "shared", 0, 10)),
        ],
    }
    (tmp_path / "a.py").write_text("x" * 100)
    (tmp_path / "b.py").write_text("x" * 100)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["a.py", "b.py"], [], None, graph) if u.fragments]
    assert len(units) == 1


def test_build_units_merges_shared_callee_graphs_when_they_fit(tmp_path):
    graph = {
        "callgraph": {
            "a.py": {"a": [{"range": [0, 40], "calls": ["shared"]}]},
            "b.py": {"b": [{"range": [0, 40], "calls": ["shared"]}]},
            "m.py": {"shared": [{"range": [0, 10], "calls": []}]},
        },
        "imports": {"a.py": ["shared"], "b.py": ["shared"]},
        "import_targets": {"a.py": ["m.py"], "b.py": ["m.py"]},
        "dependencies": [
            _dependency("a.py", ("m.py", "shared", 0, 10), ("a.py", "a", 0, 40)),
            _dependency("b.py", ("m.py", "shared", 0, 10), ("b.py", "b", 0, 40)),
        ],
    }
    (tmp_path / "a.py").write_text("def a():\n    return shared('a')\n")
    (tmp_path / "b.py").write_text("def b():\n    return shared('b')\n")
    (tmp_path / "m.py").write_text("x" * 100)
    _materialize_graph_sources(tmp_path, graph)
    units = [u for u in build_units(str(tmp_path), ["a.py", "b.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["relationships:combined"]
    assert units[0].files == ("a.py", "m.py", "b.py")


def test_build_units_without_a_facts_graph_is_unchanged(tmp_path):
    (tmp_path / "web.py").write_text("x" * 100)
    assert not any(u.fragments for u in build_units(str(tmp_path), ["web.py"], []))


def test_load_facts_graph_reads_the_graph_empty_and_fails_loud_on_corrupt(tmp_path):
    from cyberjury.review.repository.context import load_facts_graph

    assert load_facts_graph(tmp_path) == {}
    (tmp_path / "_facts_graph.json").write_text('{"imports": {"a.py": ["f"]}}')
    assert load_facts_graph(tmp_path)["imports"] == {"a.py": ["f"]}
    (tmp_path / "_facts_graph.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_graph(tmp_path)


def test_load_facts_unit_specs_reads_specs_empty_and_fails_loud_on_corrupt(tmp_path):
    from cyberjury.review.repository.context import load_facts_unit_specs

    assert load_facts_unit_specs(tmp_path) == []
    (tmp_path / "_facts_units.json").write_text('[{"name": "u", "files": ["a.sol"], "fragments": [["a.sol", 0, 10]]}]')
    spec = load_facts_unit_specs(tmp_path)[0]
    assert spec["name"] == "u"
    assert spec["fragments"] == [FactFragment(file="a.sol", start=0, end=10)]
    (tmp_path / "_facts_units.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_unit_specs(tmp_path)


def test_load_facts_unit_specs_rejects_malformed_entries(tmp_path):
    from cyberjury.review.repository.context import load_facts_unit_specs

    (tmp_path / "_facts_units.json").write_text('["not a unit spec"]')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_unit_specs(tmp_path)
    (tmp_path / "_facts_units.json").write_text('{"not": "a list"}')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_unit_specs(tmp_path)
    (tmp_path / "_facts_units.json").write_text('[{"fragments": [["a.sol", 10, 2]]}]')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_unit_specs(tmp_path)


def test_build_units_keeps_trace_targets_as_independent_owned_sources(tmp_path):
    paths = (
        "accounts/views/api.py",
        "authorization/views/web.py",
        "accounts/managers/m.py",
        "authorization/dao/d.py",
    )
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("source")
    units = build_units(
        tmp_path,
        ["accounts/views/api.py", "authorization/views/web.py"],
        ["accounts/managers/m.py", "authorization/dao/d.py"],
    )
    units_by_name = {u.name: u for u in units}
    assert units_by_name["accounts/views/api.py"].files == ("accounts/views/api.py",)
    assert units_by_name["accounts/managers/m.py"].files == ("accounts/managers/m.py",)
    assert units_by_name["authorization/dao/d.py"].files == ("authorization/dao/d.py",)


def test_build_units_keeps_root_level_trace_targets_separate(tmp_path):
    (tmp_path / "app.py").write_text("entry")
    (tmp_path / "services.py").write_text("service")

    units = build_units(tmp_path, ["app.py"], ["services.py"])

    assert [(unit.name, unit.files) for unit in units] == [
        ("app.py", ("app.py",)),
        ("services.py", ("services.py",)),
    ]


def test_build_units_covers_each_trace_target_once(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "entry.py").write_text("entry")
    targets = []
    for index in range(25):
        rel = f"pkg/service_{index:02d}.py"
        (tmp_path / rel).write_text("x" * 24_000)
        targets.append(rel)

    units = [unit for unit in build_units(tmp_path, ["pkg/entry.py"], targets) if not unit.fragments]
    covered = {unit.files[0] for unit in units if unit.name != "pkg/entry.py"}

    assert covered == set(targets)
    assert len(units) == 26
    assert all(gather_context(unit).coverage.complete for unit in units)


def test_build_units_splits_a_large_file_into_overlapping_windows(tmp_path):
    (tmp_path / "views.py").write_text("x" * 60_000)
    units = build_units(str(tmp_path), ["views.py"], [])
    assert [u.name for u in units] == ["views.py#1", "views.py#2", "views.py#3"]
    assert units[0].span[0] == 0
    assert units[1].span[0] < units[0].span[1]
    assert units[-1].span[1] == 60_000


def test_spans_snaps_a_window_to_a_top_level_construct_boundary():
    a = "def f():\n" + "    x = 1\n" * 2000
    text = a + "def g():\n" + "    y = 2\n" * 2000
    spans = char_spans(text)
    assert spans[0][0] == 0
    assert text[spans[0][1] :].startswith("def g")


def test_spans_keep_a_decorator_with_its_definition():
    prefix = "x = 1\n" * 3_300
    text = prefix + "@require_admin\ndef sensitive():\n" + "    x = 1\n" * 500

    spans = char_spans(text)
    second = text[spans[1][0] : spans[1][1]]

    assert second.startswith("@require_admin\ndef sensitive")


def test_build_units_keeps_a_small_file_whole(tmp_path):
    (tmp_path / "v.py").write_text("x" * 1_000)
    units = build_units(str(tmp_path), ["v.py"], [])
    assert [u.name for u in units] == ["v.py"]
    assert units[0].span is None
