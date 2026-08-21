"""Web analysis preserves source ranges, lexical owners, and parsed call identities."""

import pytest

from cyberjury.profiles.web.facts.analyzer import MAX_SOURCE_BYTES, load_specs
from cyberjury.profiles.web.facts.backend import TreeSitterFacts
from cyberjury.review.facts import (
    BackendUnavailable,
    definition_dependencies,
)


def _graph(root):
    return TreeSitterFacts().extract(root).data["graph"]["callgraph"]


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
