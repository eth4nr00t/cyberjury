"""Seed source evidence publishes complete seed definitions and bounded candidate callee sources."""

import pytest

from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.relationships import (
    CallsiteEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from cyberjury.review.seed_sources import candidate_call_context, definition_evidence
from tests.review.support import definition, route_call

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

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000, deliver_chars=0)

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


def test_candidate_call_source_is_not_duplicated_when_the_callee_is_a_unit_seed(tmp_path):
    """A callee already seeded is cited as source in the code under review, not published or delivered."""
    graph = route_call(tmp_path, _ONE_LINE_ROUTE, {"service.py": _ONE_LINE_LOAD})

    context = candidate_call_context(
        tmp_path,
        DefinitionUnitPlan(seeds=(graph.caller, *graph.callees)),
        graph.relationships,
        max_chars=10_000,
        deliver_chars=0,
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
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=10_000, deliver_chars=0
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
        tmp_path, DefinitionUnitPlan(seeds=(graph.caller,)), graph.relationships, max_chars=10_000, deliver_chars=0
    )

    assert context.text == ""
    assert context.delivered == context.published == ()


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
