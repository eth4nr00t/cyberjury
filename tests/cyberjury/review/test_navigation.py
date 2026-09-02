"""Source navigation keeps search clues separate from read evidence."""

import re

import pytest

from cyberjury.review.context import SourceSpan
from cyberjury.review.navigation import SourceNavigationError, SourceNavigator


def _graph(*, first_end: int, second_end: int) -> dict[str, object]:
    return {
        "callgraph": {
            "src/one.py": {"Record": [{"range": [0, first_end], "calls": []}]},
            "plugins/two.py": {"Record": [{"range": [0, second_end], "calls": []}]},
        },
        "imports": {},
        "references": {},
        "import_targets": {},
        "dependencies": [],
        "unresolved_dependencies": [],
    }


def test_symbol_search_returns_every_real_candidate_without_evidence(tmp_path):
    first = "class Record:\n    owner = 'first'\n"
    second = "class Record:\n    owner = 'second'\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "plugins").mkdir()
    (tmp_path / "src/one.py").write_text(first, encoding="utf-8")
    (tmp_path / "plugins/two.py").write_text(second, encoding="utf-8")
    navigator = SourceNavigator.from_graph(tmp_path, _graph(first_end=len(first), second_end=len(second)))

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert "src/one.py:Record" in result.text
    assert "plugins/two.py:Record" in result.text
    source_ids = re.findall(r"`(src-[0-9a-f]+)`", result.text)
    assert len(source_ids) == 2
    assert "not resolved bindings or finding evidence" in result.text
    assert result.coverage.included == ()


def test_unique_symbol_search_delivers_exact_source_in_the_same_exchange(tmp_path):
    source = "class Record:\n    owner = 'user'\n"
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {"model.py": {"Record": [{"range": [0, len(source)], "calls": []}]}}},
    )

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert "Unique exact symbol match" in result.text
    assert "owner = 'user'" in result.text
    assert result.coverage.included == (f"model.py:Record:0:{len(source)}",)
    assert len(result.source_evidence) == 1


def test_last_symbol_page_is_not_mistaken_for_a_unique_result(tmp_path):
    source = "value = 1\n" * 21
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    definitions = [{"range": [index * 10, index * 10 + 9], "calls": []} for index in range(21)]
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {"model.py": {"Repeated": definitions}}},
    )

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Repeated", "page": 1}],
        target_chars=10_000,
    )

    assert "Unique exact symbol match" not in result.text
    assert result.coverage.included == ()


def test_source_target_ids_are_stable_across_sessions_and_query_order(tmp_path):
    source = "class Record:\n    pass\n\nclass Other:\n    pass\n"
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    first_end = source.index("\n\n")
    graph = {
        "callgraph": {
            "model.py": {
                "Record": [{"range": [0, first_end], "calls": []}],
                "Other": [{"range": [first_end + 2, len(source)], "calls": []}],
            }
        },
        "imports": {},
        "references": {},
        "import_targets": {},
    }
    navigator = SourceNavigator.from_graph(tmp_path, graph)
    assert navigator is not None

    first = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )
    second_session = navigator.session()
    second_session.execute(
        [{"kind": "search_symbols", "query": "Other", "page": 0}],
        target_chars=10_000,
    )
    second = second_session.execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert re.findall(r"`(src-[0-9a-f]+)`", first.text) == re.findall(r"`(src-[0-9a-f]+)`", second.text)


def test_navigation_rejects_more_than_eight_queries_per_batch(tmp_path):
    source = "class Record:\n    pass\n"
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"model.py": {"Record": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    assert navigator is not None

    with pytest.raises(SourceNavigationError, match="more than 8"):
        navigator.session().execute(
            [{"kind": "search_text", "query": f"q{index}", "page": 0} for index in range(9)],
            target_chars=10_000,
        )


def test_navigation_fails_when_source_changes_after_snapshot(tmp_path):
    source = "class Record:\n    pass\n"
    path = tmp_path / "model.py"
    path.write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"model.py": {"Record": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    assert navigator is not None
    path.write_text(source + "changed = True\n", encoding="utf-8")

    with pytest.raises(SourceNavigationError, match="changed after snapshot"):
        navigator.session().execute(
            [{"kind": "search_symbols", "query": "Record", "page": 0}],
            target_chars=10_000,
        )


def test_large_definition_search_publishes_bounded_page_targets(tmp_path):
    source = "def large():\n" + "    value = 1\n" * 5_000
    (tmp_path / "large.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"large.py": {"large": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    assert navigator is not None
    session = navigator.session()

    result = session.execute(
        [{"kind": "search_symbols", "query": "large", "page": 0}],
        target_chars=10_000,
    )
    target_ids = re.findall(r"`(src-[0-9a-f]+)`", result.text)

    assert len(target_ids) >= 2
    assert "page 1/" in result.text
    first_page = session.read([target_ids[0]], target_chars=48_000)
    assert len(first_page.text) <= 48_000


def test_navigation_labels_test_source(tmp_path):
    source = "def test_policy():\n    pass\n"
    (tmp_path / "test_policy.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"test_policy.py": {"test_policy": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
        test_files=("test_policy.py",),
    )
    assert navigator is not None

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "test_policy", "page": 0}],
        target_chars=10_000,
    )

    assert "[test] test_policy.py:test_policy" in result.text


def test_search_requires_the_documented_page_field(tmp_path):
    source = "class Record:\n    pass\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "src/one.py").write_text(source, encoding="utf-8")
    graph = _graph(first_end=len(source), second_end=len(source))
    graph["callgraph"] = {"src/one.py": graph["callgraph"]["src/one.py"]}
    navigator = SourceNavigator.from_graph(tmp_path, graph)

    assert navigator is not None
    with pytest.raises(SourceNavigationError, match="must include page"):
        navigator.session().execute(
            [{"kind": "search_symbols", "query": "Record"}],
            target_chars=10_000,
        )


def test_read_source_requires_a_target_returned_by_the_same_session(tmp_path):
    source = "class Record:\n    owner = 'user'\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "src/one.py").write_text(source, encoding="utf-8")
    graph = _graph(first_end=len(source), second_end=len(source))
    graph["callgraph"] = {"src/one.py": graph["callgraph"]["src/one.py"]}
    navigator = SourceNavigator.from_graph(tmp_path, graph)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text)
    assert target is not None
    assert session.can_read(target.group(1)) is True
    assert session.can_read("src-invented") is False

    repeated = session.execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )
    assert f"`{target.group(1)}`" in repeated.text

    with pytest.raises(SourceNavigationError, match="unknown kind 'read_source'"):
        session.execute(
            [{"kind": "read_source", "target": target.group(1)}],
            target_chars=10_000,
        )

    read = session.read([target.group(1)], target_chars=10_000)

    assert "owner = 'user'" in read.text
    assert read.coverage.included == (f"src/one.py:Record:0:{len(source)}",)
    with pytest.raises(SourceNavigationError, match="unknown target"):
        session.read(["src-invented"], target_chars=10_000)


def test_definition_navigation_uses_normalized_character_ranges(tmp_path):
    prefix = "owner = 'é'\n"
    definition = "def target():\n    return 'ok'\n"
    source = prefix + definition
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    start = len(prefix)
    end = start + len(definition)
    graph = {
        "callgraph": {"app.py": {"target": [{"range": [start, end], "calls": []}]}},
        "imports": {},
        "references": {},
        "import_targets": {},
    }
    navigator = SourceNavigator.from_graph(tmp_path, graph)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "target", "page": 0}],
        target_chars=10_000,
    )
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text)
    assert target is not None

    read = session.read([target.group(1)], target_chars=10_000)

    assert "2 | def target():" in read.text
    assert "return 'ok'" in read.text
    assert prefix.strip() not in read.text
    assert read.coverage.included == (f"app.py:target:{start}:{end}",)
    assert read.source_evidence[0].source_span is not None
    assert read.source_evidence[0].source_span.file == "app.py"
    assert (read.source_evidence[0].source_span.start_line, read.source_evidence[0].source_span.end_line) == (2, 3)


def test_definition_navigation_uses_normalized_newlines(tmp_path):
    raw = b"header = 1\r\ndef target():\r\n    return 'ok'\r\n"
    normalized = raw.decode().replace("\r\n", "\n")
    definition = "def target():\n    return 'ok'\n"
    start = normalized.index(definition)
    end = start + len(definition)
    (tmp_path / "app.py").write_bytes(raw)
    graph = {
        "callgraph": {"app.py": {"target": [{"range": [start, end], "calls": []}]}},
        "dependencies": [],
    }
    navigator = SourceNavigator.from_graph(tmp_path, graph)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "target", "page": 0}],
        target_chars=10_000,
    )
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text)
    assert target is not None
    read = session.read([target.group(1)], target_chars=10_000)

    assert "2 | def target():" in read.text
    assert "3 |     return 'ok'" in read.text
    assert "header" not in read.text
    assert read.source_evidence[0].source_span == SourceSpan(file="app.py", start_line=2, end_line=3)


def test_navigation_rejects_the_removed_resolved_relationship_query(tmp_path):
    source = "def caller():\n    return 1\n"
    (tmp_path / "caller.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {"caller.py": {"caller": [{"range": [0, len(source)], "calls": []}]}}},
    )

    assert navigator is not None
    with pytest.raises(SourceNavigationError, match="unknown kind 'related_sources'"):
        navigator.session().execute(
            [{"kind": "related_sources", "target": "src-1", "direction": "callees", "page": 0}],
            target_chars=10_000,
        )


def test_navigation_ignores_obsolete_resolved_dependency_data(tmp_path):
    source = "def caller():\n    return 1\n"
    (tmp_path / "caller.py").write_text(source, encoding="utf-8")
    graph = {
        "callgraph": {"caller.py": {"caller": [{"range": [0, len(source)], "calls": []}]}},
        "dependencies": {},
    }

    assert SourceNavigator.from_graph(tmp_path, graph) is not None


def test_navigation_excludes_graph_paths_that_escape_the_source_root(tmp_path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("def leaked(): pass\n", encoding="utf-8")
    graph = {
        "callgraph": {"../outside.py": {"leaked": [{"range": [0, len(outside.read_text())], "calls": []}]}},
        "imports": {},
        "references": {},
        "import_targets": {},
    }

    navigator = SourceNavigator.from_graph(tmp_path, graph)

    assert navigator is None


def test_text_search_includes_verified_source_without_a_graph_definition(tmp_path):
    (tmp_path / "routes.yaml").write_text("handler: dynamic_route\n", encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {},
        source_files=("routes.yaml",),
    )

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_text", "query": "dynamic_route", "page": 0}],
        target_chars=10_000,
    )

    assert "routes.yaml:text line 1" in result.text
    assert result.coverage.included == ()


def test_call_candidate_navigation_keeps_binding_with_the_model(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relationships import relationship_evidence_from_data

    service = "def target(value):\n    return value\n"
    route = "from service import target\n\ndef route(value):\n    return target(value)\n"
    (tmp_path / "service.py").write_text(service, encoding="utf-8")
    (tmp_path / "route.py").write_text(route, encoding="utf-8")
    facts = TreeSitterFacts().extract(tmp_path).data
    relationships = relationship_evidence_from_data(facts["relationship_evidence"])
    navigator = SourceNavigator.from_graph(
        tmp_path,
        facts["graph"],
        relationship_evidence=relationships,
    )

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "route", "page": 0}],
        target_chars=10_000,
    )
    route_id = re.search(r"definition `(def-[0-9a-f]+)`", searched.text)
    assert route_id is not None

    candidates = session.execute(
        [
            {
                "kind": "search_call_candidates",
                "definition_id": route_id.group(1),
                "direction": "callees",
                "page": 0,
            }
        ],
        target_chars=10_000,
    )

    assert "not established call relationships" in candidates.text
    assert "target(value)" in candidates.text
    assert "service.py:target" in candidates.text


def test_overloaded_signature_search_keeps_its_shared_definition_id(tmp_path):
    from cyberjury.review.relationships import DefinitionEvidence, RelationshipEvidenceBundle, SourceReference

    source = "function withdraw(uint256 amount) external {}"
    (tmp_path / "Vault.sol").write_text(source, encoding="utf-8")
    definition = DefinitionEvidence.create(
        source=SourceReference.create(path="Vault.sol", start=0, end=len(source), content=source),
        kind="function",
        name="withdraw",
        signature="withdraw(uint256)",
    )
    relationships = RelationshipEvidenceBundle.create(definitions=(definition,))
    graph = {
        "callgraph": {
            "Vault.sol": {
                "withdraw(uint256)": [{"range": [0, len(source)], "calls": []}],
            }
        }
    }
    navigator = SourceNavigator.from_graph(tmp_path, graph, relationship_evidence=relationships)

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "withdraw(uint256)", "page": 0}],
        target_chars=10_000,
    )

    assert f"definition `{definition.id}`" in result.text
