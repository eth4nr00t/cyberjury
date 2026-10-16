"""Relationship evidence stays deterministic and model results stay attributable."""

import pytest


def _bundle():
    from cyberjury.review.relationships import (
        AnalysisObservation,
        CallsiteEvidence,
        DefinitionEvidence,
        RelationshipEvidenceBundle,
        SourceReference,
    )

    caller_text = "def route(x):\n    return load(x)"
    target_text = "def load(x):\n    return x"
    call_text = "load(x)"
    call_start = caller_text.index(call_text)
    caller_source = SourceReference.create(path="route.py", start=0, end=len(caller_text), content=caller_text)
    target_source = SourceReference.create(path="service.py", start=0, end=len(target_text), content=target_text)
    call_source = SourceReference.create(
        path="route.py",
        start=call_start,
        end=call_start + len(call_text),
        content=call_text,
    )
    caller = DefinitionEvidence.create(source=caller_source, kind="function", name="route")
    target = DefinitionEvidence.create(source=target_source, kind="function", name="load")
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
        candidate_target_ids=(target.id,),
        provenance_source_ids=(call_source.id, target_source.id),
        label="direct imported name",
    )
    return RelationshipEvidenceBundle.create(
        definitions=(caller, target),
        callsites=(callsite,),
        observations=(observation,),
    )


def test_relationship_evidence_has_stable_ids_and_explicit_source_hashes():
    bundle = _bundle()

    assert bundle == _bundle()
    data = bundle.to_data()
    assert data["schema"] == "cyberjury.relationship-evidence/v1"
    assert bundle.call_relationships[0].target_status == "candidate"
    assert bundle.call_relationships[0].candidate_callee_definition_ids == (
        next(item.id for item in bundle.definitions if item.name == "load"),
    )
    assert len(data["definitions"][0]["source"]["content_sha256"]) == 64
    assert bundle.canonical().to_data() == data


def test_relationship_evidence_rejects_conflicting_content_at_one_coordinate():
    from cyberjury.review.relationships import RelationshipEvidenceBundle, SourceReference

    first = SourceReference.create(path="app.py", start=0, end=1, content="a")
    second = SourceReference.create(path="app.py", start=0, end=1, content="b")

    with pytest.raises(ValueError, match="conflicting source content"):
        RelationshipEvidenceBundle(sources=(first, second))


def test_relationship_evidence_rejects_a_callsite_outside_its_caller():
    from cyberjury.review.relationships import CallsiteEvidence, DefinitionEvidence, RelationshipEvidenceBundle

    bundle = _bundle()
    caller = next(item for item in bundle.definitions if item.name == "route")
    target = next(item for item in bundle.definitions if item.name == "load")
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=target.source,
        expression="def load(x):\n    return x",
        callee_spelling="load",
    )

    with pytest.raises(ValueError, match="outside its caller source"):
        RelationshipEvidenceBundle.create(
            definitions=(caller, DefinitionEvidence.create(source=target.source, kind="function", name="load")),
            callsites=(callsite,),
        )
