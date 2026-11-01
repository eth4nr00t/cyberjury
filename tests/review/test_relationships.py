"""Relationship evidence keeps stable ids, explicit source hashes, and derived call candidates."""

from cyberjury.canonical import text_sha256
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from tests.review.support import definition


def _whole(path: str, name: str, text: str) -> DefinitionEvidence:
    return definition(path, name, 0, len(text), source=text)


def _call(caller: DefinitionEvidence, callee: str) -> CallsiteEvidence:
    expression = f"{callee}(value)"
    source = SourceReference.create(path=caller.source.path, start=0, end=len(expression), content=expression)
    return CallsiteEvidence.create(
        caller_definition_id=caller.id, source=source, expression=expression, callee_spelling=callee
    )


def _bundle():
    caller_text = "def route(x):\n    return load(x)"
    target_text = "def load(x):\n    return x"
    call_text = "load(x)"
    call_start = caller_text.index(call_text)
    call_source = SourceReference.create(
        path="route.py",
        start=call_start,
        end=call_start + len(call_text),
        content=call_text,
    )
    caller = _whole("route.py", "route", caller_text)
    target = _whole("service.py", "load", target_text)
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=call_source,
        expression="load(x)",
        callee_spelling="load",
    )
    observation = AnalysisObservation.create(
        producer="tree-sitter",
        producer_version="0.26.0",
        kind="syntax_call",
        subject_ids=(callsite.id,),
        provenance_source_ids=(call_source.id, target.source.id),
        label="direct imported name",
    )
    return RelationshipEvidenceBundle(
        definitions=(caller, target),
        callsites=(callsite,),
        observations=(observation,),
    )


def test_relationship_evidence_has_stable_ids_and_explicit_source_hashes():
    """Rebuilding the route-to-load bundle gives equal ids, a candidate callee, and the sha256 of each source."""
    bundle = _bundle()

    assert bundle == _bundle()
    data = bundle.to_dict()
    assert list(bundle.call_candidates.values()) == [
        (next(item.id for item in bundle.definitions if item.name == "load"),)
    ]
    route = next(item for item in bundle.definitions if item.name == "route")
    assert route.source.content_sha256 == text_sha256("def route(x):\n    return load(x)")
    assert {item["source"]["content_sha256"] for item in data["definitions"]} == {
        definition.source.content_sha256 for definition in bundle.definitions
    }


def test_same_name_definitions_are_all_call_candidates():
    """A load() call with load defined in one.py and two.py lists both definitions as candidates."""
    route = _whole("route.py", "route", "def route(value):\n    return load(value)")
    first = _whole("one.py", "load", "def load(value):\n    return value")
    second = _whole("two.py", "load", "def load(value):\n    return value + 1")
    call = _call(route, "load")

    bundle = RelationshipEvidenceBundle(definitions=(route, first, second), callsites=(call,))

    assert set(bundle.call_candidates[call.id]) == {first.id, second.id}


def test_a_call_without_a_matching_definition_has_no_candidates():
    """A call to an undefined external() has an empty candidate list."""
    route = _whole("route.py", "route", "def route(value):\n    return external(value)")
    call = _call(route, "external")

    assert RelationshipEvidenceBundle(definitions=(route,), callsites=(call,)).call_candidates == {call.id: ()}
