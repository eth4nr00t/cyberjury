"""Source navigation keeps search clues separate from read evidence."""

import re

import pytest

from cyberjury.review import navigation as navigation_module
from cyberjury.review.context import SourceEvidence, SourceSpan
from cyberjury.review.navigation import (
    SourceNavigationError,
    SourceNavigator,
    SourceQueryLimitError,
    navigation_instructions,
    parse_source_queries,
)
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)
from tests.review.support import navigator_from_callgraph
from tests.review.syntax.support import syntax_facts


def _graph(*, first_end: int, second_end: int) -> dict[str, object]:
    return {
        "callgraph": {
            "src/one.py": {"Record": [{"range": [0, first_end], "calls": []}]},
            "plugins/two.py": {"Record": [{"range": [0, second_end], "calls": []}]},
        },
    }


def _record_navigator(tmp_path, source: str) -> SourceNavigator:
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    navigator = navigator_from_callgraph(
        tmp_path, {"callgraph": {"model.py": {"Record": [{"range": [0, len(source)], "calls": []}]}}}
    )
    assert navigator is not None
    return navigator


def test_default_navigation_contract_publishes_the_query_batch_limit():
    """Default instructions tell the model to send at most 8 source_queries per batch."""
    assert "Send at most 8 `source_queries`" in navigation_instructions()


def test_navigation_contract_states_the_exact_search_semantics():
    """Instructions describe exact-name symbol match, literal one-line text match, and 20-result pages from 0."""
    instructions = navigation_instructions()

    assert "whose name equals `query` exactly" in instructions
    assert "literal, case-sensitive substring of one line" in instructions
    assert "Regular expressions, wildcards, and multi-line text are not supported" in instructions
    assert "at most 20 results per page. `page` starts at 0" in instructions


def test_dependency_text_hits_are_labeled_and_bounded_on_minified_lines(tmp_path):
    """A hit in a one-line 200,000 character vendor bundle is [dependency], third-party, and read in 24,000 chars."""
    (tmp_path / "app.py").write_text("def app(): pass\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    bundle = "a" * 100_000 + "innerHTML=cell" + "b" * 100_000
    (tmp_path / "vendor" / "notebook.min.js").write_text(bundle, encoding="utf-8")
    navigator = SourceNavigator.from_facts(
        tmp_path,
        source_files=("app.py", "vendor/notebook.min.js"),
        relationship_evidence=RelationshipEvidenceBundle(),
        dependency_files=("vendor/notebook.min.js",),
    )
    assert navigator is not None

    result = navigator.session().execute(
        [{"kind": "search_text", "query": "innerHTML=cell", "page": 0}],
        target_chars=48_000,
    )

    assert "[dependency] vendor/notebook.min.js" in result.text
    assert "Read third-party source" in result.text
    assert "innerHTML=cell" in result.text
    assert len(result.text) < 30_000


def test_documentation_navigation_preserves_its_source_kind(tmp_path):
    """A text hit in docs/development.md is labeled [documentation] and read as documentation, line 1."""
    (tmp_path / "app.py").write_text("def app(): pass\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "development.md").write_text("Use start_services.sh only for development.\n", encoding="utf-8")
    navigator = SourceNavigator.from_facts(
        tmp_path,
        source_files=("app.py", "docs/development.md"),
        relationship_evidence=RelationshipEvidenceBundle(),
        documentation_files=("docs/development.md",),
    )
    assert navigator is not None

    session = navigator.session()
    result = session.execute(
        [{"kind": "search_text", "query": "start_services.sh", "page": 0}],
        target_chars=1_000,
    )

    assert "[documentation] docs/development.md" in result.text
    assert "Read documentation" in result.text
    assert result.source_evidence[0].source_span == SourceSpan(file="docs/development.md", start_line=1, end_line=1)


def _navigator_with_calls(tmp_path, source: str, spans: tuple[tuple[int, int], ...]) -> SourceNavigator:
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    definition = DefinitionEvidence.create(
        source=SourceReference.create(path="app.py", start=0, end=len(source), content=source),
        kind="function",
        name="reviewed",
    )
    callsites = tuple(
        CallsiteEvidence.create(
            caller_definition_id=definition.id,
            source=SourceReference.create(
                path="app.py",
                start=start,
                end=end,
                content=source[start:end],
            ),
            expression=source[start:end],
            callee_spelling=f"call-{index}",
        )
        for index, (start, end) in enumerate(spans)
    )
    navigator = SourceNavigator.from_facts(
        tmp_path,
        relationship_evidence=RelationshipEvidenceBundle(
            definitions=(definition,),
            callsites=callsites,
        ),
    )
    assert navigator is not None
    return navigator


def test_source_operation_identity_maps_nested_multiline_calls_to_the_outer_call(tmp_path):
    """Lines 2 and 3 of search(compile(pattern), text) share the outer call's operation id."""
    source = "def reviewed():\n    return search(\n        compile(pattern), text\n    )\n"
    outer = (source.index("search("), source.rindex(")") + 1)
    inner = (source.index("compile("), source.index("), text") + 1)
    session = _navigator_with_calls(tmp_path, source, (outer, inner)).session()

    assert session.source_operation_id("app.py", 2)
    assert session.source_operation_id("app.py", 2) == session.source_operation_id("app.py", 3)


def test_source_operation_identity_rejects_ambiguous_sibling_calls_on_one_line(tmp_path):
    """A line holding two calls and the call-free def line both get an empty operation id."""
    source = "def reviewed():\n    first(); second()\n"
    first = (source.index("first()"), source.index("first()") + len("first()"))
    second = (source.index("second()"), source.index("second()") + len("second()"))
    session = _navigator_with_calls(tmp_path, source, (first, second)).session()

    assert session.source_operation_id("app.py", 2) == ""
    assert session.source_operation_id("app.py", 1) == ""


def test_symbol_search_returns_every_real_candidate_without_evidence(tmp_path):
    """Record defined in src/one.py and plugins/two.py lists two targets and reads no source."""
    first = "class Record:\n    owner = 'first'\n"
    second = "class Record:\n    owner = 'second'\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "plugins").mkdir()
    (tmp_path / "src/one.py").write_text(first, encoding="utf-8")
    (tmp_path / "plugins/two.py").write_text(second, encoding="utf-8")
    navigator = navigator_from_callgraph(tmp_path, _graph(first_end=len(first), second_end=len(second)))

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert "src/one.py:Record" in result.text
    assert "plugins/two.py:Record" in result.text
    source_ids = re.findall(r"`(src-[0-9a-f]+)`", result.text)
    assert len(source_ids) == 2
    assert result.coverage.included == ()


def test_unique_symbol_search_delivers_exact_source_in_the_same_exchange(tmp_path):
    """A single Record definition is read inline with one receipt and coverage for model.py:Record."""
    source = "class Record:\n    owner = 'user'\n"
    navigator = _record_navigator(tmp_path, source)

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert "Unique exact symbol match" in result.text
    assert "owner = 'user'" in result.text
    assert f"Read source `{result.source_evidence[0].id}` model.py:Record:\n```\n# file: model.py" in result.text
    assert result.coverage.included == (f"model.py:Record:0:{len(source)}",)
    assert len(result.source_evidence) == 1


def _extracted_navigator(tmp_path, files: dict[str, str]) -> SourceNavigator:
    for path, source in files.items():
        (tmp_path / path).write_text(source, encoding="utf-8")
    facts = syntax_facts(tmp_path)
    navigator = SourceNavigator.from_facts(
        tmp_path,
        import_files=facts.import_files,
        relationship_evidence=facts.relationships,
    )
    assert navigator is not None
    return navigator


def test_dotted_symbol_search_is_exact_only_for_the_enclosing_definition_name(tmp_path):
    """Repo.save reads only the save under class Repo, not the same-named method on Other."""
    navigator = _extracted_navigator(
        tmp_path,
        {
            "store.py": (
                "class Repo:\n    def save(self):\n        return 1\n\n"
                "class Other:\n    def save(self):\n        return 2\n"
            ),
        },
    )

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Repo.save", "page": 0}],
        target_chars=10_000,
    )

    assert "Unique exact symbol match" in result.text
    assert "return 1" in result.text
    assert "return 2" not in result.text
    assert "unverified candidates" not in result.text


def test_dotted_symbol_search_lists_last_segment_matches_as_unread_candidates(tmp_path):
    """Repo.save with only a top-level save() lists store.py:save as a candidate and reads nothing."""
    navigator = _extracted_navigator(tmp_path, {"store.py": "def save():\n    return 3\n"})

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Repo.save", "page": 0}],
        target_chars=10_000,
    )

    assert "No definition matches the qualified name exactly" in result.text
    assert "store.py:save" in result.text
    assert "Unique exact symbol match" not in result.text
    assert result.source_evidence == ()


def test_symbol_search_without_a_definition_lists_the_aliased_import_that_binds_it(tmp_path):
    """S imported as an alias of requests.Session has no local definition, so the search names its import."""
    navigator = _extracted_navigator(
        tmp_path, {"client.py": "from requests import Session as S\n\ndef fetch():\n    return S()\n"}
    )

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "S", "page": 0}],
        target_chars=10_000,
    )

    assert "client.py:1 | `from requests import Session as S`" in result.text
    assert result.source_evidence == ()


def test_dotted_symbol_search_without_a_definition_lists_the_module_import_of_its_first_segment(tmp_path):
    """np.array with numpy imported as np names the import statement that binds np."""
    navigator = _extracted_navigator(
        tmp_path, {"calc.py": "import numpy as np\n\ndef total(values):\n    return np.array(values).sum()\n"}
    )

    result = navigator.session().execute(
        [{"kind": "search_symbols", "query": "np.array", "page": 0}],
        target_chars=10_000,
    )

    assert "calc.py:1 | `import numpy as np`" in result.text


def test_last_symbol_page_is_not_mistaken_for_a_unique_result(tmp_path):
    """Page 1 of 21 Repeated definitions holds one item yet is not auto-read as a unique match."""
    source = "value = 1\n" * 21
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    definitions = [{"range": [index * 10, index * 10 + 9], "calls": []} for index in range(21)]
    navigator = navigator_from_callgraph(
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


def test_navigation_cannot_read_a_target_that_was_not_published_on_the_requested_page(tmp_path):
    """A session that saw only page 0 cannot read or expand source and definition ids from page 1."""
    source = "value = 1\n" * 21
    (tmp_path / "model.py").write_text(source, encoding="utf-8")
    definitions = tuple(
        DefinitionEvidence.create(
            source=SourceReference.create(
                path="model.py",
                start=index * 10,
                end=index * 10 + 9,
                content=source[index * 10 : index * 10 + 9],
            ),
            kind="function",
            name="Repeated",
        )
        for index in range(21)
    )
    navigator = SourceNavigator.from_facts(
        tmp_path,
        relationship_evidence=RelationshipEvidenceBundle(definitions=definitions),
    )
    assert navigator is not None
    first_page_session = navigator.session()
    first_page_session.execute(
        [{"kind": "search_symbols", "query": "Repeated", "page": 0}],
        target_chars=10_000,
    )
    last_page = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Repeated", "page": 1}],
        target_chars=10_000,
    )
    unpublished = re.search(r"`(src-[0-9a-f]+)`", last_page.text)
    unpublished_definition = re.search(r"definition `(def-[0-9a-f]+)`", last_page.text)
    assert unpublished is not None
    assert unpublished_definition is not None

    assert first_page_session.can_read(unpublished.group(1)) is False
    with pytest.raises(SourceNavigationError, match="unknown target"):
        first_page_session.read([unpublished.group(1)], target_chars=10_000)
    with pytest.raises(SourceNavigationError, match="undiscovered definition"):
        first_page_session.execute(
            [
                {
                    "kind": "search_call_candidates",
                    "definition_id": unpublished_definition.group(1),
                    "direction": "both",
                    "page": 0,
                }
            ],
            target_chars=10_000,
        )


def test_source_target_ids_are_stable_across_sessions_and_query_order(tmp_path):
    """Searching Record yields identical text, coverage, and evidence in fresh and reused sessions."""
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
    }
    navigator = navigator_from_callgraph(tmp_path, graph)
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
    third = navigator.session().execute(
        [{"kind": "search_symbols", "query": "Record", "page": 0}],
        target_chars=10_000,
    )

    assert first.text == second.text == third.text
    assert first.coverage == second.coverage == third.coverage
    assert first.source_evidence == second.source_evidence == third.source_evidence


def test_navigation_rejects_more_than_eight_queries_per_batch():
    """A batch of nine search_text queries raises SourceQueryLimitError naming the limit of 8."""
    with pytest.raises(SourceQueryLimitError, match="more than 8"):
        parse_source_queries([{"kind": "search_text", "query": f"q{index}", "page": 0} for index in range(9)])


def test_navigation_rejects_more_than_the_session_query_budget(tmp_path):
    """After eight batches of eight unique queries, a 65th query raises the 64-query budget error."""
    source = "class Record:\n    pass\n"
    navigator = _record_navigator(tmp_path, source)
    session = navigator.session()
    for batch in range(8):
        session.execute(
            [{"kind": "search_text", "query": f"q{batch * 8 + index}", "page": 0} for index in range(8)],
            target_chars=50_000,
        )

    with pytest.raises(SourceNavigationError, match="64 unique queries"):
        session.execute(
            [{"kind": "search_text", "query": "overflow", "page": 0}],
            target_chars=50_000,
        )


def test_navigation_rejects_a_repeated_query_in_one_session(tmp_path):
    """Re-sending the same search_symbols Record query in one session raises a repeat error."""
    source = "class Record:\n    pass\n"
    navigator = _record_navigator(tmp_path, source)
    session = navigator.session()
    query = [{"kind": "search_symbols", "query": "Record", "page": 0}]
    session.execute(query, target_chars=10_000)

    with pytest.raises(SourceNavigationError, match="repeats an earlier query"):
        session.execute(query, target_chars=10_000)


def test_navigation_rejects_a_duplicate_batch_before_committing_any_query(tmp_path):
    """A batch with the same query twice fails, and the query still runs afterwards in that session."""
    source = "class Record:\n    pass\n"
    navigator = _record_navigator(tmp_path, source)
    session = navigator.session()
    query = {"kind": "search_symbols", "query": "Record", "page": 0}

    with pytest.raises(SourceNavigationError, match="repeats an earlier query"):
        session.execute([query, query], target_chars=10_000)

    result = session.execute([query], target_chars=10_000)

    assert "model.py:Record" in result.text


def test_large_definition_search_publishes_bounded_page_targets(tmp_path):
    """A 5,000-line function is split into paged targets, and reading page 0 stays within 48,000 chars."""
    source = "def large():\n" + "    value = 1\n" * 5_000
    (tmp_path / "large.py").write_text(source, encoding="utf-8")
    navigator = navigator_from_callgraph(
        tmp_path,
        {
            "callgraph": {"large.py": {"large": [{"range": [0, len(source)], "calls": []}]}},
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


def test_reading_requires_a_target_published_by_the_same_session(tmp_path):
    """A target id returned by this session's search is readable, and an invented id raises unknown target."""
    source = "class Record:\n    owner = 'user'\n"
    (tmp_path / "src").mkdir()
    (tmp_path / "src/one.py").write_text(source, encoding="utf-8")
    graph = _graph(first_end=len(source), second_end=len(source))
    graph["callgraph"] = {"src/one.py": graph["callgraph"]["src/one.py"]}
    navigator = navigator_from_callgraph(tmp_path, graph)

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
    with pytest.raises(SourceNavigationError, match="unknown target"):
        session.read(["src-invented"], target_chars=10_000)


def test_definition_navigation_uses_normalized_character_ranges(tmp_path):
    """Character ranges after a non-ASCII prefix line map target() to lines 2-3 without the prefix."""
    prefix = "owner = 'é'\n"
    definition = "def target():\n    return 'ok'\n"
    source = prefix + definition
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    start = len(prefix)
    end = start + len(definition)
    graph = {
        "callgraph": {"app.py": {"target": [{"range": [start, end], "calls": []}]}},
    }
    navigator = navigator_from_callgraph(tmp_path, graph)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "target", "page": 0}],
        target_chars=10_000,
    )
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text)
    assert target is not None

    read = session.read([target.group(1)], target_chars=10_000)

    assert "2 | def target():" in searched.text
    assert "return 'ok'" in searched.text
    assert prefix.strip() not in searched.text
    assert "return 'ok'" not in read.text
    assert read.coverage.included == (f"app.py:target:{start}:{end}",)
    assert read.source_evidence[0].source_span is not None
    assert read.source_evidence[0].source_span.file == "app.py"
    assert (read.source_evidence[0].source_span.start_line, read.source_evidence[0].source_span.end_line) == (2, 3)


def test_definition_navigation_uses_normalized_newlines(tmp_path):
    """Ranges over CRLF source resolve against LF-normalized text, mapping target() to lines 2-3."""
    raw = b"header = 1\r\ndef target():\r\n    return 'ok'\r\n"
    normalized = raw.decode().replace("\r\n", "\n")
    definition = "def target():\n    return 'ok'\n"
    start = normalized.index(definition)
    end = start + len(definition)
    (tmp_path / "app.py").write_bytes(raw)
    graph = {
        "callgraph": {"app.py": {"target": [{"range": [start, end], "calls": []}]}},
    }
    navigator = navigator_from_callgraph(tmp_path, graph)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "target", "page": 0}],
        target_chars=10_000,
    )
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text)
    assert target is not None
    read = session.read([target.group(1)], target_chars=10_000)

    assert "2 | def target():" in searched.text
    assert "3 |     return 'ok'" in searched.text
    assert "header" not in searched.text
    assert read.source_evidence[0].source_span == SourceSpan(file="app.py", start_line=2, end_line=3)


def test_unique_text_search_delivers_verified_source_without_a_graph_definition(tmp_path):
    """A single text hit in routes.yaml is read inline as line 1 with no call graph definition."""
    (tmp_path / "routes.yaml").write_text("handler: dynamic_route\n", encoding="utf-8")
    navigator = SourceNavigator.from_facts(
        tmp_path,
        source_files=("routes.yaml",),
        relationship_evidence=RelationshipEvidenceBundle(),
    )

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_text", "query": "dynamic_route", "page": 0}],
        target_chars=10_000,
    )

    assert "routes.yaml:text line 1" in result.text
    assert "Unique exact text match" in result.text
    assert result.coverage.included == ("routes.yaml:text line 1:0:23",)
    assert result.source_evidence[0].source_span == SourceSpan(file="routes.yaml", start_line=1, end_line=1)


def test_ambiguous_text_search_publishes_choices_without_reading_them(tmp_path):
    """The same text in one.txt and two.txt is listed with no coverage and no source evidence."""
    (tmp_path / "one.txt").write_text("handler: dynamic_route\n", encoding="utf-8")
    (tmp_path / "two.txt").write_text("handler: dynamic_route\n", encoding="utf-8")
    navigator = SourceNavigator.from_facts(
        tmp_path,
        source_files=("one.txt", "two.txt"),
        relationship_evidence=RelationshipEvidenceBundle(),
    )

    assert navigator is not None
    result = navigator.session().execute(
        [{"kind": "search_text", "query": "dynamic_route", "page": 0}],
        target_chars=10_000,
    )

    assert "Unique exact text match" not in result.text
    assert result.coverage.included == ()
    assert result.source_evidence == ()


def test_call_candidate_navigation_keeps_binding_with_the_model(tmp_path):
    """Callees of route() list the target(value) callsite and service.py:target as a candidate."""
    navigator = _extracted_navigator(
        tmp_path,
        {
            "service.py": "def target(value):\n    return value\n",
            "route.py": "from service import target\n\ndef route(value):\n    return target(value)\n",
        },
    )
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

    assert "target(value)" in candidates.text
    assert "service.py:target" in candidates.text


def test_structural_candidate_navigation_keeps_binding_with_the_model(tmp_path):
    """Child(Base) lists Base as an outgoing inheritance candidate and Child as Base's incoming owner."""
    navigator = _extracted_navigator(tmp_path, {"models.py": "class Base:\n    pass\n\nclass Child(Base):\n    pass\n"})
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "Child", "page": 0}],
        target_chars=10_000,
    )
    child_id = re.search(r"definition `(def-[0-9a-f]+)`", searched.text)
    assert child_id is not None

    candidates = session.execute(
        [
            {
                "kind": "search_structural_candidates",
                "definition_id": child_id.group(1),
                "direction": "outgoing",
                "page": 0,
            }
        ],
        target_chars=10_000,
    )

    assert "kind `inheritance` reference `Base`" in candidates.text
    assert "models.py:Base" in candidates.text
    source_id = re.search(r"syntax source `(src-[0-9a-f]+)`", candidates.text)
    assert source_id is not None
    assert session.can_read(source_id.group(1))
    base_id = re.search(r"candidate `(def-[0-9a-f]+)`", candidates.text)
    assert base_id is not None

    incoming = session.execute(
        [
            {
                "kind": "search_structural_candidates",
                "definition_id": base_id.group(1),
                "direction": "incoming",
                "page": 0,
            }
        ],
        target_chars=10_000,
    )

    assert "kind `inheritance` reference `Base`" in incoming.text
    assert f"owner `{child_id.group(1)}`" in incoming.text
    assert "models.py:Child" in incoming.text


def test_inheritance_without_a_local_target_stays_an_unbound_source_clue(tmp_path):
    """Child(ExternalBase) reports no repository candidate but keeps a readable syntax source."""
    navigator = _extracted_navigator(tmp_path, {"models.py": "class Child(ExternalBase):\n    pass\n"})
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "Child", "page": 0}],
        target_chars=10_000,
    )
    child_id = re.search(r"definition `(def-[0-9a-f]+)`", searched.text)
    assert child_id is not None

    candidates = session.execute(
        [
            {
                "kind": "search_structural_candidates",
                "definition_id": child_id.group(1),
                "direction": "outgoing",
                "page": 0,
            }
        ],
        target_chars=10_000,
    )

    assert "kind `inheritance` reference `ExternalBase`" in candidates.text
    assert "candidates: no repository definition candidate" in candidates.text
    source_id = re.search(r"syntax source `(src-[0-9a-f]+)`", candidates.text)
    assert source_id is not None
    assert session.can_read(source_id.group(1))


def test_structural_candidate_navigation_pages_expanded_same_name_candidates(tmp_path):
    """Inheritance from 21 same-named Base classes pages as 20 candidates on page 0 and 1 on page 1."""
    child_source = "class Child(Base):\n    pass\n"
    (tmp_path / "child.py").write_text(child_source, encoding="utf-8")
    child_reference = SourceReference.create(
        path="child.py",
        start=0,
        end=len(child_source),
        content=child_source,
    )
    child = DefinitionEvidence.create(source=child_reference, kind="type", name="Child")
    bases = []
    for index in range(21):
        path = f"base_{index:02}.py"
        source = "class Base:\n    pass\n"
        (tmp_path / path).write_text(source, encoding="utf-8")
        bases.append(
            DefinitionEvidence.create(
                source=SourceReference.create(path=path, start=0, end=len(source), content=source),
                kind="type",
                name="Base",
            )
        )
    base_start = child_source.index("Base")
    relationship = StructuralRelationshipEvidence.create(
        kind="inheritance",
        source=SourceReference.create(
            path="child.py",
            start=base_start,
            end=base_start + len("Base"),
            content="Base",
        ),
        reference="Base",
        source_definition_id=child.id,
        candidate_target_definition_ids=tuple(item.id for item in bases),
    )
    relationships = RelationshipEvidenceBundle(
        sources=(relationship.source,),
        definitions=(child, *bases),
        structural_relationships=(relationship,),
    )
    navigator = SourceNavigator.from_facts(tmp_path, relationship_evidence=relationships)

    assert navigator is not None
    session = navigator.session()
    searched = session.execute(
        [{"kind": "search_symbols", "query": "Child", "page": 0}],
        target_chars=20_000,
    )
    child_id = re.search(r"definition `(def-[0-9a-f]+)`", searched.text)
    assert child_id is not None
    first = session.execute(
        [
            {
                "kind": "search_structural_candidates",
                "definition_id": child_id.group(1),
                "direction": "outgoing",
                "page": 0,
            }
        ],
        target_chars=20_000,
    )
    second = session.execute(
        [
            {
                "kind": "search_structural_candidates",
                "definition_id": child_id.group(1),
                "direction": "outgoing",
                "page": 1,
            }
        ],
        target_chars=20_000,
    )

    assert len(re.findall(r"candidate `def-", first.text)) == 20
    assert "more results are available on page 1" in first.text
    assert len(re.findall(r"candidate `def-", second.text)) == 1
    assert "more results" not in second.text


def test_navigation_transaction_rolls_back_an_oversized_query(tmp_path):
    """A query over a 10-char target inside a transaction is not recorded and can run again."""
    source = "class Record:\n    value = 1\n"
    navigator = _record_navigator(tmp_path, source)
    session = navigator.session()
    query = {"kind": "search_symbols", "query": "Record", "page": 0}

    with pytest.raises(SourceNavigationError, match="character target"), session.transaction():
        session.execute([query], target_chars=10)

    assert session.query_was_executed(query) is False
    assert "Record" in session.execute([query], target_chars=10_000).text


def _target_navigator(tmp_path, body: str = ""):
    prefix = "header = 1\n"
    definition = f"def target():\n{body}    return 'ok'\n"
    (tmp_path / "app.py").write_text(prefix + definition, encoding="utf-8")
    start = len(prefix)
    graph = {"callgraph": {"app.py": {"target": [{"range": [start, start + len(definition)], "calls": []}]}}}
    navigator = navigator_from_callgraph(tmp_path, graph)
    assert navigator is not None
    return navigator


def test_navigation_lists_source_inside_the_seed_as_delivered_with_its_own_receipt(tmp_path):
    """A definition inside seed lines 1-3 is marked delivered in seed with a receipt for lines 2-3."""
    session = _target_navigator(tmp_path).session()
    session.record_delivered((), seed_spans=(SourceSpan(file="app.py", start_line=1, end_line=3),))

    searched = session.execute([{"kind": "search_symbols", "query": "target", "page": 0}], target_chars=10_000)

    assert "| already delivered in `seed`" in searched.text
    assert "Unique exact symbol match" not in searched.text
    assert "return 'ok'" not in searched.text
    [receipt] = searched.source_evidence
    assert receipt.id in searched.coverage.references
    assert (receipt.source_span.start_line, receipt.source_span.end_line) == (2, 3)


def test_navigation_never_delivers_initial_or_earlier_source_again(tmp_path):
    """Text found in initial evidence src-000000000001 is marked delivered and not re-read."""
    session = _target_navigator(tmp_path).session()
    initial = SourceEvidence(
        id="src-000000000001",
        identity="app.py:lines 1-3:0:39",
        text="# file: app.py lines 1-3\n1 | header = 1\n2 | def target():\n3 |     return 'ok'",
        source_span=SourceSpan(file="app.py", start_line=1, end_line=3),
    )
    session.record_delivered((initial,))

    searched = session.execute([{"kind": "search_text", "query": "return 'ok'", "page": 0}], target_chars=10_000)
    target = re.search(r"`(src-[0-9a-f]+)`", searched.text).group(1)
    read = session.read([target], target_chars=10_000)

    assert f"| already delivered in `{initial.id}`" in searched.text
    assert "Unique exact text match" not in searched.text
    assert "already delivered" in read.text
    assert "header = 1" not in read.text


def test_an_auto_read_source_is_not_delivered_again_by_a_later_search(tmp_path):
    """A text search hitting a function auto-read by symbol search reports it as already delivered."""
    session = _target_navigator(tmp_path, body="    value = 1\n" * 10).session()

    first = session.execute([{"kind": "search_symbols", "query": "target", "page": 0}], target_chars=10_000)
    second = session.execute([{"kind": "search_text", "query": "return 'ok'", "page": 0}], target_chars=10_000)

    assert "Unique exact symbol match" in first.text
    assert "Unique exact text match" not in second.text
    assert "already delivered in `src-" in second.text


def test_caller_search_returns_the_go_function_calling_a_definition(tmp_path):
    """Searching callers of Go CheckPolicy returns ApplyPolicy and its CheckPolicy(value) call on page 0."""
    (tmp_path / "policy.go").write_text(
        'package app\n\nfunc CheckPolicy(value string) bool {\n    return value != ""\n}\n'
    )
    (tmp_path / "service.go").write_text(
        "package app\n\nfunc ApplyPolicy(value string) bool {\n    return CheckPolicy(value)\n}\n"
    )
    facts = syntax_facts(tmp_path)
    target = next(item for item in facts.relationships.definitions if item.name == "CheckPolicy")
    navigator = SourceNavigator.from_facts(
        tmp_path, import_files=facts.import_files, relationship_evidence=facts.relationships
    )
    assert navigator is not None
    session = navigator.session()
    session.execute([{"kind": "search_symbols", "query": "CheckPolicy", "page": 0}], target_chars=10_000)

    candidates = session.execute(
        [{"kind": "search_call_candidates", "definition_id": target.id, "direction": "callers", "page": 0}],
        target_chars=10_000,
    )

    assert "ApplyPolicy" in candidates.text
    assert "CheckPolicy(value)" in candidates.text
    assert "page 0" in candidates.text


def test_text_search_builds_only_the_requested_page_and_one_look_ahead(tmp_path, monkeypatch):
    """A query matching 500 lines builds 21 targets for page 0 and still reports that a next page exists."""
    (tmp_path / "big.py").write_text("".join(f"value_{index} = self.x\n" for index in range(500)), encoding="utf-8")
    navigator = SourceNavigator.from_facts(
        tmp_path, source_files=("big.py",), relationship_evidence=RelationshipEvidenceBundle()
    )
    assert navigator is not None
    created = []
    create = navigation_module.SourceTarget.create

    def counted(**fields):
        created.append(fields["name"])
        return create(**fields)

    monkeypatch.setattr(navigation_module.SourceTarget, "create", counted)

    result = navigator.session().execute([{"kind": "search_text", "query": "self", "page": 0}], target_chars=50_000)

    assert len(created) == 21
    assert "more results are available on page 1" in result.text
