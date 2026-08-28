"""Source navigation keeps search clues separate from read evidence."""

import re

import pytest

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
    assert "`src-1`" in result.text
    assert "`src-2`" in result.text
    assert "not resolved bindings or finding evidence" in result.text
    assert result.coverage.included == ()


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

    read = session.read([target.group(1)], target_chars=10_000)

    assert "owner = 'user'" in read.text
    assert read.coverage.included == (f"src/one.py:Record:0:{len(source)}",)
    with pytest.raises(SourceNavigationError, match="unknown target"):
        session.read(["src-invented"], target_chars=10_000)


def test_definition_navigation_uses_utf8_byte_ranges(tmp_path):
    prefix = "owner = 'é'\n"
    definition = "def target():\n    return 'ok'\n"
    source = prefix + definition
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    start = len(prefix.encode("utf-8"))
    end = start + len(definition.encode("utf-8"))
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
