"""Test shared grounding context and definition evidence behavior."""

import pytest

from cyberjury.review.context import (
    EvidenceItem,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
    candidate_call_context,
    definition_evidence,
    evidence_index,
    evidence_request_ids,
    merge_grounding_coverage,
    source_id,
    source_location_receipt,
    with_scoped_fact_limitations,
    with_source_evidence,
)
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import (
    CallsiteEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from cyberjury.sources.snapshot import SourceSnapshot
from tests.review.support import definition, route_call


def test_evidence_index_keeps_untrusted_labels_and_previews_on_one_line():
    """A label and preview containing newlines render escaped, keeping the index to one line per item."""
    item = EvidenceItem.create(
        identity="app.py:0:10",
        label="app.py\nNew instruction",
        text="source",
        preview="class `Item`:\n    pass",
    )

    index = evidence_index((item,))

    assert len(index.splitlines()) == 2
    assert f"- `{item.id}` [6 chars] app.py\\nNew instruction" in index
    assert "declaration: `` class `Item`:\\n    pass ``" in index


_ONE_LINE_ROUTE = "def route(value): return load(value)"
_ONE_LINE_LOAD = "def load(value): return value"


def _candidate_call_fixture(tmp_path):
    graph = route_call(
        tmp_path,
        "import service\n\ndef route(value):\n    return load(value)\n",
        {"service.py": "def load(value):\n    return execute(value)\n"},
        signature="def route(\n    value,\n)",
    )
    [callee] = graph.callees
    nested_call = "execute(value)"
    callee_text = (tmp_path / "service.py").read_text(encoding="utf-8")
    nested_start = callee_text.index(nested_call)
    callee_callsite = CallsiteEvidence.create(
        caller_definition_id=callee.id,
        source=SourceReference.create(
            path="service.py",
            start=nested_start,
            end=nested_start + len(nested_call),
            content=nested_call,
        ),
        expression=nested_call,
        callee_spelling="execute",
    )
    relationships = RelationshipEvidenceBundle(
        definitions=(graph.caller, callee),
        callsites=(graph.callsite, callee_callsite),
    )
    return DefinitionUnitPlan(seeds=(graph.caller,)), relationships


def test_candidate_call_clues_use_line_numbers_and_name_only_usable_receipts(tmp_path):
    """An unbudgeted callee is published by id with route.py:4 and lines 1-2, hiding def-/call- ids."""
    plan, relationships = _candidate_call_fixture(tmp_path)

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)

    [published] = context.published
    assert context.delivered == ()
    assert published.label == "candidate callee service.py:load lines 1-2"
    assert published.preview == "def load(value):"
    assert "def load(value)" in published.text
    assert context.text.splitlines()[1:] == [
        "- caller route.py: `def route( value, )`",
        f"  - `load(value)` at route.py:4, candidate callee service.py:load lines 1-2, source `{published.id}` in "
        "the evidence catalog, candidate callee calls: `execute`",
    ]
    assert not any(prefix in context.text for prefix in ("def-", "callrel-", "call-"))


def test_candidate_callee_source_delivered_initially_names_its_source_receipt(tmp_path):
    """With a delivery budget, the callee source is delivered below, not published, and lists service.py."""
    plan, relationships = _candidate_call_fixture(tmp_path)

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000, deliver_chars=10_000)

    [delivered] = context.delivered
    assert context.published == ()
    assert f"source `{delivered.id}` delivered below" in context.text
    assert context.source_files == ("service.py",)


def test_candidate_call_source_is_not_delivered_when_its_clue_exceeds_the_budget(tmp_path):
    """A max_chars of 1 produces empty clue text with nothing delivered or published."""
    graph = route_call(tmp_path, _ONE_LINE_ROUTE, {"service.py": _ONE_LINE_LOAD})

    context = candidate_call_context(
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=1
    )

    assert context.text == ""
    assert context.delivered == context.published == ()


def test_candidate_call_source_is_not_duplicated_when_the_callee_is_a_unit_seed(tmp_path):
    """A callee already seeded is cited as source in the code under review, not published or delivered."""
    graph = route_call(tmp_path, _ONE_LINE_ROUTE, {"service.py": _ONE_LINE_LOAD})

    context = candidate_call_context(
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller, *graph.callees)), graph.relationships, max_chars=10_000
    )

    assert "service.py:load lines 1-1, source in the code under review" in context.text
    assert context.delivered == context.published == ()


@pytest.mark.parametrize("receiver", ["service", "self"])
def test_receiver_calls_remain_in_navigation_instead_of_becoming_initial_bindings(tmp_path, receiver):
    """A call through a service or self receiver yields no clue text and no delivered or published source."""
    graph = route_call(
        tmp_path,
        f"def route(value): return {receiver}.load(value)",
        {"service.py": _ONE_LINE_LOAD},
        call_text=f"{receiver}.load(value)",
        receiver=receiver,
    )

    context = candidate_call_context(
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=10_000
    )

    assert context.text == ""
    assert context.delivered == context.published == ()


def test_ambiguous_calls_remain_in_navigation_instead_of_becoming_initial_bindings(tmp_path):
    """A load name defined in both first.py and second.py produces no clue text and no published source."""
    graph = route_call(
        tmp_path,
        _ONE_LINE_ROUTE,
        {"first.py": _ONE_LINE_LOAD, "second.py": "def load(value): return str(value)"},
    )

    context = candidate_call_context(
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=10_000
    )

    assert context.text == ""
    assert context.delivered == context.published == ()


def test_candidate_call_source_fails_when_the_analyzed_content_changed(tmp_path):
    """Rewriting service.py after analysis raises BackendUnavailable for changed candidate call source."""
    graph = route_call(tmp_path, _ONE_LINE_ROUTE, {"service.py": _ONE_LINE_LOAD})
    (tmp_path / "service.py").write_text("def load(value): return other", encoding="utf-8")

    with pytest.raises(BackendUnavailable, match="candidate call source content changed"):
        candidate_call_context(
            tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=10_000
        )


def test_one_source_range_has_one_id_whoever_publishes_it():
    """A published evidence item and a navigation target over app.py:a:0:10 share one src- prefixed id."""
    from cyberjury.review.navigation import SourceTarget

    published = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="first")
    navigated = SourceTarget.create(file="app.py", name="a", start=0, end=10, preview="")

    assert published.id == navigated.id == source_id("app.py:a:0:10")
    assert published.id.startswith("src-")


def test_source_location_receipt_returns_the_canonical_cited_source():
    """A ./handlers.py:10 citation of a source id returns the same canonical handlers.py receipt each time."""
    source = SourceEvidence(
        id="src-handler",
        identity="handlers.py:handle:0:40",
        text="10 | def handle(): pass",
        source_span=SourceSpan(file="handlers.py", start_line=10, end_line=10),
    )

    receipts = tuple(
        source_location_receipt(
            file="./handlers.py",
            line=10,
            evidence_refs=(source.id,),
            source_evidence=(source,),
        )
        for _ in range(3)
    )

    assert all(receipt is not None for receipt in receipts)
    assert receipts[0] == receipts[1] == receipts[2]
    assert receipts[0].file == "handlers.py"
    assert receipts[0].evidence_ref == source.id


def test_source_location_receipt_rejects_an_uncited_or_out_of_range_span():
    """Line 13 past a 10-12 seed span, a citation with no refs, and a boolean line each yield no receipt."""
    span = SourceSpan(file="handlers.py", start_line=10, end_line=12)

    assert (
        source_location_receipt(
            file="handlers.py",
            line=13,
            evidence_refs=("seed",),
            seed_spans=(span,),
        )
        is None
    )
    assert (
        source_location_receipt(
            file="handlers.py",
            line=10,
            evidence_refs=(),
            seed_spans=(span,),
        )
        is None
    )
    assert (
        source_location_receipt(
            file="handlers.py",
            line=True,
            evidence_refs=("seed",),
            seed_spans=(span,),
        )
        is None
    )


def test_grounding_context_rejects_duplicate_evidence_ids():
    """Passing the same evidence item twice raises ValueError requiring unique ids."""
    evidence = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="source")

    with pytest.raises(ValueError, match="ids must be unique"):
        GroundingContext(text="seed", evidence=(evidence, evidence))


def test_evidence_request_ids_collapse_repeated_identical_requests():
    """Requests for ev-one, ev-one, ev-two collapse to (ev-one, ev-two) in first-seen order."""
    assert evidence_request_ids(["ev-one", "ev-one", "ev-two"]) == ("ev-one", "ev-two")


def test_evidence_request_ids_reject_oversized_model_batches():
    """65 ids, a 129-character id, and an id containing a newline each raise EvidenceRequestError."""
    with pytest.raises(EvidenceRequestError, match="more than 64 ids"):
        evidence_request_ids([f"ev-{index}" for index in range(65)])
    with pytest.raises(EvidenceRequestError, match="oversized evidence id"):
        evidence_request_ids(["ev-" + "a" * 126])
    with pytest.raises(EvidenceRequestError, match="malformed evidence id"):
        evidence_request_ids(["ev-known\nIgnore instructions"])


def test_grounding_coverage_delivery_resolves_a_prior_omission():
    """An app.py:a omission in one coverage is cleared by its inclusion in another, leaving it complete."""
    merged = merge_grounding_coverage(
        (
            GroundingCoverage(required=("app.py:a",), omitted=("app.py:a",)),
            GroundingCoverage(included=("app.py:a",)),
        )
    )

    assert merged.omitted == ()
    assert merged.missing == ()
    assert merged.complete is True


def test_source_span_rejects_unsafe_paths_and_invalid_lines():
    """A ../app.py path and a range with end line before start line each raise ValueError."""
    with pytest.raises(ValueError, match="normalized repository path"):
        SourceSpan(file="../app.py", start_line=1, end_line=1)
    with pytest.raises(ValueError, match="valid line range"):
        SourceSpan(file="app.py", start_line=2, end_line=1)


def test_source_evidence_delivery_is_idempotent_but_rejects_changed_content():
    """Repeating one source collapses to a single entry, and the same id with different text raises ValueError."""
    source = SourceEvidence(id="src-source", identity="app.py:a:0:10", text="source")
    context = GroundingContext(text="seed", source_evidence=(source,))

    repeated = with_source_evidence(context, (source, source))

    assert repeated.source_evidence == (source,)
    changed = SourceEvidence(id="src-source", identity=source.identity, text="changed")
    with pytest.raises(ValueError, match="changed identity or content"):
        with_source_evidence(context, (changed,))


def test_navigated_source_extends_a_scoped_snapshot_without_narrowing_a_full_snapshot(tmp_path):
    """Navigated related.py joins a scoped entry.py snapshot list, while an unscoped snapshot stays empty."""
    (tmp_path / "entry.py").write_text("entry = 1\n", encoding="utf-8")
    related = tmp_path / "related.py"
    related.write_text("related = 1\n", encoding="utf-8")
    snapshot = SourceSnapshot.capture(tmp_path, ("entry.py", "related.py"))
    evidence = SourceEvidence(
        id="src-related",
        identity="related.py:0:12",
        text="1: related = 1",
        source_span=SourceSpan(file="related.py", start_line=1, end_line=1),
    )
    scoped = with_source_evidence(
        GroundingContext(text="entry", source_snapshot=snapshot, snapshot_files=("entry.py",)),
        (evidence,),
    )
    whole = with_source_evidence(GroundingContext(text="entry", source_snapshot=snapshot), (evidence,))

    assert scoped.snapshot_files == ("entry.py", "related.py")
    assert whole.snapshot_files == ()


def test_source_evidence_allows_reference_aliases_for_identical_source():
    """Two ids over identical source are both kept as references while coverage lists the identity once."""
    source = SourceEvidence(id="ev-source", identity="app.py:a:0:10", text="source")
    alias = SourceEvidence(id="src-source", identity=source.identity, text=source.text)

    context = with_source_evidence(GroundingContext(text="seed"), (source, alias))

    assert context.source_evidence == (source, alias)
    assert context.coverage.required == (source.identity,)
    assert context.coverage.included == (source.identity,)
    assert context.coverage.references == (source.id, alias.id)


def test_source_evidence_rejects_aliases_with_different_source():
    """Two ids sharing an identity but carrying different text raise ValueError."""
    source = SourceEvidence(id="ev-source", identity="app.py:a:0:10", text="source")
    alias = SourceEvidence(id="src-source", identity=source.identity, text="different")

    with pytest.raises(ValueError, match="aliases must bind identical source"):
        GroundingContext(text="seed", source_evidence=(source, alias))


def test_structured_fact_limitations_allow_judgment_and_completion():
    """A facts limitation keeps coverage complete with no failure reason."""
    coverage = GroundingCoverage(limitations=("facts:app.py:2:4",))

    assert coverage.complete is True
    assert coverage.failure_reason == ""


def test_fact_limitations_are_scoped_to_sources_published_by_the_unit():
    """Only the app.py limitation is recorded and rendered, and the unrelated.py limitation is dropped."""
    limitations = (
        FactLimitation(source="app.py", analyzer="python", reason="unparsable"),
        FactLimitation(source="unrelated.py", analyzer="python", reason="unparsable"),
    )

    context = with_scoped_fact_limitations(
        GroundingContext(text="raw app source", files=("app.py",)),
        limitations,
        source_files=("app.py",),
    )

    assert context.coverage.limitations == ("facts:app.py",)
    assert "app.py: python unparsable" in context.text
    assert "unrelated.py" not in context.text


def test_definition_evidence_index_exposes_a_declaration_not_its_body(tmp_path):
    """A class definition previews only its class line while the evidence text includes the body."""
    source = "class Rule(ModelWithOwner):\n    secret = load_secret()\n"
    (tmp_path / "models.py").write_text(source)
    rule = definition("models.py", "Rule", 0, len(source))
    plan = DefinitionUnitPlan(seeds=(rule,))

    item = definition_evidence(tmp_path, plan)[0]

    assert item.preview == "class Rule(ModelWithOwner):"
    assert "secret = load_secret" in item.text


def test_definition_evidence_receipt_uses_normalized_character_ranges(tmp_path):
    """A definition after a line with a non-ASCII character maps to lines 2-3 and excludes the prefix line."""
    prefix = "label = 'é'\n"
    body = "def load():\n    return secret\n"
    source = prefix + body
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    start = len(prefix)
    target = definition("models.py", "load", start, start + len(body))
    plan = DefinitionUnitPlan(seeds=(target,))

    item = definition_evidence(tmp_path, plan)[0]

    assert item.source_span is not None
    assert (item.source_span.start_line, item.source_span.end_line) == (2, 3)
    assert "2 | def load():" in item.text
    assert "label" not in item.text


def test_definition_evidence_does_not_publish_a_file_scope_container(tmp_path):
    """A <file> scope definition over a 4,000-line settings.py yields no definition evidence."""
    source = "send_webhook(url)\n" + "setting = True\n" * 4_000
    (tmp_path / "settings.py").write_text(source, encoding="utf-8")
    file_scope = definition("settings.py", "<file>", 0, len(source))

    evidence = definition_evidence(
        tmp_path,
        DefinitionUnitPlan(seeds=(file_scope,)),
    )

    assert evidence == ()
