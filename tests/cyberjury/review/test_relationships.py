"""Relationship evidence stays deterministic and model results stay attributable."""

import pytest


def _bundle():
    from cyberjury.review.relationships import (
        AnalysisObservation,
        ArgumentEvidence,
        CallsiteEvidence,
        DefinitionEvidence,
        ParameterEvidence,
        RelationshipEvidenceBundle,
        SourceReference,
    )

    caller_text = "def route(x):\n    return load(x)"
    target_text = "def load(x):\n    return x"
    call_text = "load(x)"
    call_start = caller_text.index(call_text)
    argument_start = caller_text.index("x", call_start)
    caller_source = SourceReference.create(path="route.py", start=0, end=len(caller_text), content=caller_text)
    target_source = SourceReference.create(path="service.py", start=0, end=len(target_text), content=target_text)
    call_source = SourceReference.create(
        path="route.py",
        start=call_start,
        end=call_start + len(call_text),
        content=call_text,
    )
    argument_source = SourceReference.create(
        path="route.py",
        start=argument_start,
        end=argument_start + 1,
        content="x",
    )
    caller = DefinitionEvidence.create(source=caller_source, kind="function", name="route")
    target_parameter_start = target_text.index("x")
    target_parameter_source = SourceReference.create(
        path="service.py",
        start=target_parameter_start,
        end=target_parameter_start + 1,
        content="x",
    )
    target_parameter = ParameterEvidence.create(
        position=0,
        name="x",
        source=target_parameter_source,
        declaration="x",
    )
    target = DefinitionEvidence.create(
        source=target_source,
        kind="function",
        name="load",
        parameters=(target_parameter,),
    )
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=call_source,
        expression="load(x)",
        callee_spelling="load",
        arguments=(ArgumentEvidence(position=0, expression="x", source=argument_source),),
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
    from cyberjury.review.relationships import relationship_evidence_from_data

    bundle = _bundle()

    assert bundle == _bundle()
    data = bundle.to_data()
    assert data["schema"] == "cyberjury.relationship-evidence/v1"
    assert data["callsites"][0]["arguments"][0]["position"] == 0
    assert data["call_relationships"][0]["target_status"] == "candidate"
    assert data["call_relationships"][0]["candidate_callee_definition_ids"] == [
        next(item.id for item in bundle.definitions if item.name == "load")
    ]
    assert data["definitions"][0]["source"]["offset_unit"] == "normalized_character"
    assert len(data["definitions"][0]["source"]["content_sha256"]) == 64
    assert relationship_evidence_from_data(data) == bundle


def test_relationship_evidence_loader_rejects_tampered_source_identity():
    from cyberjury.review.facts import BackendUnavailable
    from cyberjury.review.relationships import relationship_evidence_from_data

    data = _bundle().to_data()
    data["callsites"][0]["source"]["range"][0] += 1

    with pytest.raises(BackendUnavailable, match="id does not match"):
        relationship_evidence_from_data(data)


def test_relationship_evidence_loader_rejects_an_unsafe_source_path():
    from cyberjury.review.facts import BackendUnavailable
    from cyberjury.review.relationships import relationship_evidence_from_data

    data = _bundle().to_data()
    data["definitions"][0]["source"]["path"] = "../route.py"

    with pytest.raises(BackendUnavailable, match="normalized repository path"):
        relationship_evidence_from_data(data)


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


def test_relationship_evidence_loader_rejects_a_forged_target_status():
    from cyberjury.review.facts import BackendUnavailable
    from cyberjury.review.relationships import relationship_evidence_from_data

    data = _bundle().to_data()
    data["call_relationships"][0]["target_status"] = "unresolved"

    with pytest.raises(BackendUnavailable, match="target status"):
        relationship_evidence_from_data(data)


def test_relationship_evidence_rebases_paths_and_every_referenced_id(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relationships import (
        rebase_relationship_evidence,
        relationship_evidence_from_data,
    )

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "service.py").write_text("def load(x):\n    return x\n")
    (package / "route.py").write_text("from service import load\n\ndef route(x):\n    return load(x)\n")
    bundle = relationship_evidence_from_data(TreeSitterFacts().extract(package).data["relationship_evidence"])

    rebased = rebase_relationship_evidence(
        bundle,
        "pkg",
        lambda rel: (tmp_path / rel).read_text(),
    )

    assert all(definition.source.path.startswith("pkg/") for definition in rebased.definitions)
    assert all(callsite.source.path.startswith("pkg/") for callsite in rebased.callsites)
    assert rebased.callsites[0].caller_definition_id in {item.id for item in rebased.definitions}
    source_ids = {
        *(item.id for item in rebased.sources),
        *(item.source.id for item in rebased.definitions),
        *(item.source.id for item in rebased.callsites),
        *(
            argument.source.id
            for item in rebased.callsites
            for argument in item.arguments
            if argument.source is not None
        ),
    }
    assert all(set(observation.provenance_source_ids) <= source_ids for observation in rebased.observations)
