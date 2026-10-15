"""Repository context keeps source and facts scoped to each review unit."""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from cyberjury.review.repository.context import (
    Unit,
    UnitSourceError,
    facts_summary,
    gather_context,
    ground_unit,
)
from cyberjury.review.repository.reviewer import ModelReviewer
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from tests.cyberjury.review.repository.support import review

_EMPTY_REPLY = '{"findings": [], "evidence_requests": [], "source_queries": []}'


def test_repository_grounding_exposes_the_same_candidate_call_clues(tmp_path):
    caller_text = "def route(value):\n    return load(value)\n"
    callee_text = "def load(value):\n    return value\n"
    (tmp_path / "route.py").write_text(caller_text, encoding="utf-8")
    (tmp_path / "service.py").write_text(callee_text, encoding="utf-8")
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
    caller = DefinitionEvidence.create(
        source=SourceReference.create(path="route.py", start=0, end=len(caller_text), content=caller_text),
        kind="function",
        name="route",
    )
    callee = DefinitionEvidence.create(
        source=SourceReference.create(path="service.py", start=0, end=len(callee_text), content=callee_text),
        kind="function",
        name="load",
    )
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=SourceReference.create(
            path="route.py",
            start=call_start,
            end=call_start + len(call_text),
            content=call_text,
        ),
        expression=call_text,
        callee_spelling="load",
    )
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, callee),
        callsites=(callsite,),
    )
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {}},
        source_files=("route.py", "service.py"),
        relationship_evidence=relationships,
    )
    snapshot = SourceSnapshot.capture(
        tmp_path,
        ("route.py", "service.py"),
        scope_provider=lambda: ("route.py", "service.py"),
    )
    unit = Unit(
        name="route.py",
        root=str(tmp_path),
        files=("route.py",),
        definition_plan=DefinitionUnitPlan(
            seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),),
        ),
    )

    grounded = ground_unit(
        unit,
        facts_by_file={},
        limitations=(),
        navigator=navigator,
        source_snapshot=snapshot,
    )

    assert grounded.grounding is not None
    assert "Unverified direct call candidates from this unit" in grounded.grounding.text
    assert "service.py:load" in grounded.grounding.text
    candidate_source = next(
        item for item in grounded.grounding.evidence if item.source_span and item.source_span.file == "service.py"
    )
    assert "def load(value)" in candidate_source.text
    assert grounded.grounding.source_evidence == ()
    assert candidate_source.id in grounded.grounding.prompt.controls
    assert candidate_source.text not in grounded.grounding.prompt.source
    assert "service.py" in grounded.grounding.snapshot_files
    (tmp_path / "service.py").write_text("def load(value):\n    return None\n", encoding="utf-8")
    with pytest.raises(BackendUnavailable, match="source changed"):
        grounded.grounding.validate_snapshot()


def test_repository_candidate_file_limitations_follow_the_published_source(tmp_path):
    caller_text = "def route(value):\n    return load(value)\n"
    callee_text = "def load(value):\n    return value\n"
    (tmp_path / "route.py").write_text(caller_text, encoding="utf-8")
    (tmp_path / "service.py").write_text(callee_text, encoding="utf-8")
    caller = DefinitionEvidence.create(
        source=SourceReference.create(path="route.py", start=0, end=len(caller_text), content=caller_text),
        kind="function",
        name="route",
    )
    callee = DefinitionEvidence.create(
        source=SourceReference.create(path="service.py", start=0, end=len(callee_text), content=callee_text),
        kind="function",
        name="load",
    )
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=SourceReference.create(
            path="route.py",
            start=call_start,
            end=call_start + len(call_text),
            content=call_text,
        ),
        expression=call_text,
        callee_spelling="load",
    )
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {}},
        source_files=("route.py", "service.py"),
        relationship_evidence=RelationshipEvidenceBundle.create(definitions=(caller, callee), callsites=(callsite,)),
    )
    snapshot = SourceSnapshot.capture(tmp_path, ("route.py", "service.py"))
    unit = Unit(
        name="route.py",
        root=str(tmp_path),
        files=("route.py",),
        definition_plan=DefinitionUnitPlan(seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),)),
    )
    limitation = FactLimitation(source="service.py", analyzer="tree-sitter", reason="incomplete parse")

    grounded = ground_unit(
        unit,
        facts_by_file={},
        limitations=(limitation,),
        navigator=navigator,
        source_snapshot=snapshot,
    ).grounding

    assert grounded is not None
    assert "service.py" in grounded.snapshot_files
    assert limitation.identity in grounded.coverage.limitations
    assert grounded.coverage.complete is False
    assert "incomplete parse" in grounded.prompt.source


def test_facts_summary_reads_persisted_facts_and_marks_truncation(tmp_path):
    assert facts_summary(tmp_path) == ""

    (tmp_path / "_facts.md").write_text("def withdraw()  calls[transfer]", encoding="utf-8")
    summary = facts_summary(tmp_path)
    assert "Syntax hints for the repository (unverified; cite only delivered source):" in summary
    assert "withdraw()" in summary

    limit = DEFAULT_REVIEW_SETTINGS.repository.max_facts_chars_per_unit
    (tmp_path / "_facts.md").write_text("x" * (limit + 500), encoding="utf-8")
    assert "facts truncated" in facts_summary(tmp_path)


def _prompt_of(prov):
    return prov.calls[0]["messages"][0].content


def _grounded(tmp_path, name, facts_by_file):
    return ground_unit(
        Unit(name=name, root=str(tmp_path), files=(name,)),
        facts_by_file=facts_by_file,
        limitations=(),
        navigator=None,
        source_snapshot=capture_source_snapshot(tmp_path),
    )


def test_reviewer_grounds_a_unit_with_only_its_own_files_facts(tmp_path):
    (tmp_path / "views.py").write_text("def list_items():\n    return load_owner()\n")
    prov = MockProvider(default=_EMPTY_REPLY)
    by_file = {
        "views.py": "def list_items()  calls[load_owner]",
        "admin.py": "def delete_all()  calls[purge]",
    }
    review(ModelReviewer(provider=prov, model="mock"), _grounded(tmp_path, "views.py", by_file))
    prompt = _prompt_of(prov)
    assert "Syntax hints for this unit" in prompt
    assert "calls[load_owner]" in prompt
    assert "delete_all" not in prompt


def test_repository_grounding_never_silently_truncates_exact_path_facts(tmp_path):
    (tmp_path / "large.py").write_text("value = 1\n")
    facts = "fact\n" * (DEFAULT_REVIEW_SETTINGS.repository.max_facts_chars_per_unit // 5 + 1)
    provider = MockProvider(default=_EMPTY_REPLY)

    review(ModelReviewer(provider=provider, model="mock"), _grounded(tmp_path, "large.py", {"large.py": facts}))

    assert facts in _prompt_of(provider)


def test_reviewer_adds_no_facts_block_without_a_map(tmp_path):
    (tmp_path / "v.py").write_text("x = 1")
    prov = MockProvider(default=_EMPTY_REPLY)
    review(ModelReviewer(provider=prov, model="mock"), _grounded(tmp_path, "v.py", {}))
    assert "Syntax hints for this unit" not in _prompt_of(prov)


def test_grounding_does_not_guess_facts_from_a_matching_basename(tmp_path):
    (tmp_path / "views.py").write_text("def show():\n    return 1\n")

    grounded = _grounded(tmp_path, "views.py", {"src/views.py": "def show()  marker"})

    assert grounded.grounding.facts == ""


def test_grounding_uses_only_the_exact_facts_path_when_basenames_repeat(tmp_path):
    (tmp_path / "handlers.py").write_text("def handle():\n    return 1\n")

    grounded = _grounded(
        tmp_path,
        "handlers.py",
        {"src/a/handlers.py": "FACTS_A", "src/b/handlers.py": "FACTS_B", "handlers.py": "FACTS_ROOT"},
    )

    assert grounded.grounding.facts == "FACTS_ROOT"


def test_load_facts_by_file_reads_the_map_drops_empty_and_fails_loud_on_corrupt(tmp_path):
    from cyberjury.review.repository.context import load_facts_by_file

    assert load_facts_by_file(tmp_path) == {}
    (tmp_path / "_facts_by_file.json").write_text('{"a.py": "facts A", "b.py": ""}')
    assert load_facts_by_file(tmp_path) == {"a.py": "facts A"}
    (tmp_path / "_facts_by_file.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_by_file(tmp_path)
    (tmp_path / "_facts_by_file.json").write_text('{"a.py": {"nested": true}}')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_by_file(tmp_path)


def test_load_facts_limitations_reads_validated_records(tmp_path):
    from cyberjury.review.repository.context import load_facts_limitations

    assert load_facts_limitations(tmp_path) == ()
    (tmp_path / "_facts_limitations.json").write_text(
        '[{"source":"app.py","analyzer":"python","reason":"unparsable","line":2,"column":4}]'
    )

    limitation = load_facts_limitations(tmp_path)[0]

    assert limitation.identity == "facts:app.py:2:4"
    (tmp_path / "_facts_limitations.json").write_text('[{"source":"app.py"}]')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_limitations(tmp_path)


def test_gather_reads_only_the_span_window_of_a_chunked_unit(tmp_path):
    (tmp_path / "big.py").write_text("AAAA" + "B" * 30_000 + "ZZZZ")
    tail = gather_context(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(30_000, 30_008))).text
    assert "ZZZZ" in tail
    assert "AAAA" not in tail


def test_gather_numbers_a_span_window_from_its_real_first_line(tmp_path):
    text = "".join(f"line{i}\n" for i in range(1, 501))
    (tmp_path / "big.py").write_text(text)
    start = text.index("line300")
    content = gather_context(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(start, start + 8))).text
    assert "300 | line300" in content
    assert "# file: big.py lines 300-300" in content


def test_gather_fails_when_a_unit_source_file_is_missing(tmp_path):
    with pytest.raises(UnitSourceError, match=r"missing\.py"):
        gather_context(Unit(name="u", root=str(tmp_path), files=("missing.py",)))
