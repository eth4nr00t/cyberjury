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
    definition_plan_source_files,
    merge_grounding_coverage,
    select_evidence,
    source_location_receipt,
    with_scoped_fact_limitations,
    with_source_evidence,
)
from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    DefinitionUnitPlan,
    dependencies_data,
    plan_definition_units,
)
from cyberjury.review.facts import FactLimitation
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)


def test_grounding_context_marks_its_source_boundary():
    context = GroundingContext(text="source", files=("app.py",), source="diff")
    assert context.source == "diff"
    assert context.files == ("app.py",)


def test_candidate_call_relationships_remain_clues_with_searchable_callees(tmp_path):
    caller_text = "def route(value): return load(value)"
    callee_text = "def load(value): return value"
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
    (tmp_path / "route.py").write_text(caller_text, encoding="utf-8")
    (tmp_path / "service.py").write_text(callee_text, encoding="utf-8")
    caller_source = SourceReference.create(
        path="route.py",
        start=0,
        end=len(caller_text),
        content=caller_text,
    )
    callee_source = SourceReference.create(
        path="service.py",
        start=0,
        end=len(callee_text),
        content=callee_text,
    )
    caller = DefinitionEvidence.create(source=caller_source, kind="function", name="route")
    callee = DefinitionEvidence.create(source=callee_source, kind="function", name="load")
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
    plan = DefinitionUnitPlan(
        seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),),
    )

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)
    rendered = context.text

    assert "not established call bindings" in rendered
    assert f"caller `{caller.id}`" in rendered
    assert f"relationship `{relationships.call_relationships[0].id}`" in rendered
    assert f"callsite `{callsite.id}`" in rendered
    assert f"`{callee.id}`" in rendered
    assert "service.py:load" in rendered
    assert len(context.source_evidence) == 1
    assert "def load(value)" in context.source_evidence[0].text


def test_candidate_call_source_is_not_delivered_when_its_clue_exceeds_the_budget(tmp_path):
    caller_text = "def route(value): return load(value)"
    callee_text = "def load(value): return value"
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
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
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, callee),
        callsites=(
            CallsiteEvidence.create(
                caller_definition_id=caller.id,
                source=SourceReference.create(
                    path="route.py",
                    start=call_start,
                    end=call_start + len(call_text),
                    content=call_text,
                ),
                expression=call_text,
                callee_spelling="load",
            ),
        ),
    )
    plan = DefinitionUnitPlan(seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),))

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=1)

    assert context.text == ""
    assert context.source_evidence == ()


def test_candidate_call_source_is_not_duplicated_when_the_callee_is_a_unit_seed(tmp_path):
    caller_text = "def route(value): return load(value)"
    callee_text = "def load(value): return value"
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
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
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, callee),
        callsites=(
            CallsiteEvidence.create(
                caller_definition_id=caller.id,
                source=SourceReference.create(
                    path="route.py",
                    start=call_start,
                    end=call_start + len(call_text),
                    content=call_text,
                ),
                expression=call_text,
                callee_spelling="load",
            ),
        ),
    )
    plan = DefinitionUnitPlan(
        seeds=(
            DefinitionFragment("route.py", "route", 0, len(caller_text)),
            DefinitionFragment("service.py", "load", 0, len(callee_text)),
        ),
    )

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)

    assert "service.py:load" in context.text
    assert context.source_evidence == ()


@pytest.mark.parametrize("receiver", ["service", "self"])
def test_receiver_calls_remain_in_navigation_instead_of_becoming_initial_bindings(tmp_path, receiver):
    caller_text = f"def route(value): return {receiver}.load(value)"
    callee_text = "def load(value): return value"
    call_text = f"{receiver}.load(value)"
    call_start = caller_text.index(call_text)
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
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, callee),
        callsites=(
            CallsiteEvidence.create(
                caller_definition_id=caller.id,
                source=SourceReference.create(
                    path="route.py",
                    start=call_start,
                    end=call_start + len(call_text),
                    content=call_text,
                ),
                expression=call_text,
                callee_spelling="load",
                receiver_expression=receiver,
            ),
        ),
    )
    plan = DefinitionUnitPlan(seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),))

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)

    assert context.text == ""
    assert context.source_evidence == ()


def test_ambiguous_calls_remain_in_navigation_instead_of_becoming_initial_bindings(tmp_path):
    caller_text = "def route(value): return load(value)"
    first_text = "def load(value): return value"
    second_text = "def load(value): return str(value)"
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
    for path, text in (("route.py", caller_text), ("first.py", first_text), ("second.py", second_text)):
        (tmp_path / path).write_text(text, encoding="utf-8")
    caller = DefinitionEvidence.create(
        source=SourceReference.create(path="route.py", start=0, end=len(caller_text), content=caller_text),
        kind="function",
        name="route",
    )
    callees = tuple(
        DefinitionEvidence.create(
            source=SourceReference.create(path=path, start=0, end=len(text), content=text),
            kind="function",
            name="load",
        )
        for path, text in (("first.py", first_text), ("second.py", second_text))
    )
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, *callees),
        callsites=(
            CallsiteEvidence.create(
                caller_definition_id=caller.id,
                source=SourceReference.create(
                    path="route.py",
                    start=call_start,
                    end=call_start + len(call_text),
                    content=call_text,
                ),
                expression=call_text,
                callee_spelling="load",
            ),
        ),
    )
    plan = DefinitionUnitPlan(seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),))

    context = candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)

    assert context.text == ""
    assert context.source_evidence == ()


def test_candidate_call_source_fails_when_the_analyzed_content_changed(tmp_path):
    caller_text = "def route(value): return load(value)"
    callee_text = "def load(value): return value"
    call_text = "load(value)"
    call_start = caller_text.index(call_text)
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
    relationships = RelationshipEvidenceBundle.create(
        definitions=(caller, callee),
        callsites=(
            CallsiteEvidence.create(
                caller_definition_id=caller.id,
                source=SourceReference.create(
                    path="route.py",
                    start=call_start,
                    end=call_start + len(call_text),
                    content=call_text,
                ),
                expression=call_text,
                callee_spelling="load",
            ),
        ),
    )
    plan = DefinitionUnitPlan(seeds=(DefinitionFragment("route.py", "route", 0, len(caller_text)),))
    (tmp_path / "service.py").write_text("def load(value): return other", encoding="utf-8")

    with pytest.raises(BackendUnavailable, match="candidate call source content changed"):
        candidate_call_context(tmp_path, plan, relationships, max_chars=10_000)


def test_evidence_revision_changes_with_every_model_visible_input():
    evidence = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="def a(): pass")
    source = SourceEvidence(id="src-a", identity="app.py:a:0:10", text="1 | def a(): pass")
    base = GroundingContext(text="seed", evidence=(evidence,))

    assert base.revision.id == GroundingContext(text="seed", evidence=(evidence,)).revision.id
    assert base.revision.id != GroundingContext(text="changed", evidence=(evidence,)).revision.id
    assert base.revision.id != GroundingContext(text="seed", evidence=(evidence,), controls="policy").revision.id
    assert (
        base.revision.id
        != GroundingContext(
            text="seed",
            evidence=(evidence,),
            source_evidence=(source,),
        ).revision.id
    )


def test_evidence_id_changes_when_exact_content_changes():
    first = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="first")
    second = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="other")

    assert first.id != second.id


def test_source_location_receipt_returns_the_canonical_cited_source():
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
    evidence = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="source")

    with pytest.raises(ValueError, match="ids must be unique"):
        GroundingContext(text="seed", evidence=(evidence, evidence))

    with pytest.raises(EvidenceRequestError, match="duplicate ids or identities"):
        select_evidence((evidence, evidence), [evidence.id], target_chars=1_000)


def test_grounding_coverage_delivery_resolves_a_prior_omission():
    merged = merge_grounding_coverage(
        (
            GroundingCoverage(required=("app.py:a",), omitted=("app.py:a",)),
            GroundingCoverage(included=("app.py:a",)),
        )
    )

    assert merged.omitted == ()
    assert merged.missing == ()
    assert merged.reviewable is True


def test_source_span_rejects_unsafe_paths_and_invalid_lines():
    with pytest.raises(ValueError, match="normalized repository path"):
        SourceSpan(file="../app.py", start_line=1, end_line=1)
    with pytest.raises(ValueError, match="valid line range"):
        SourceSpan(file="app.py", start_line=2, end_line=1)


def test_source_evidence_delivery_is_idempotent_but_rejects_changed_content():
    source = SourceEvidence(id="src-source", identity="app.py:a:0:10", text="source")
    context = GroundingContext(text="seed", source_evidence=(source,))

    repeated = with_source_evidence(context, (source, source))

    assert repeated.source_evidence == (source,)
    changed = SourceEvidence(id="src-source", identity=source.identity, text="changed")
    with pytest.raises(ValueError, match="changed identity or content"):
        with_source_evidence(context, (changed,))


def test_source_evidence_allows_reference_aliases_for_identical_source():
    source = SourceEvidence(id="ev-source", identity="app.py:a:0:10", text="source")
    alias = SourceEvidence(id="src-source", identity=source.identity, text=source.text)

    context = with_source_evidence(GroundingContext(text="seed"), (source, alias))

    assert context.source_evidence == (source, alias)
    assert context.coverage.required == (source.identity,)
    assert context.coverage.included == (source.identity,)
    assert context.coverage.references == (source.id, alias.id)


def test_source_evidence_rejects_aliases_with_different_source():
    source = SourceEvidence(id="ev-source", identity="app.py:a:0:10", text="source")
    alias = SourceEvidence(id="src-source", identity=source.identity, text="different")

    with pytest.raises(ValueError, match="aliases must bind identical source"):
        GroundingContext(text="seed", source_evidence=(source, alias))


def test_grounding_selection_sees_exact_evidence_without_eager_prompt_delivery():
    evidence = EvidenceItem.create(
        identity="app.py:handler:10:40",
        label="app.py:handler",
        text="def handler():\n    return sensitive_operation()\n",
        preview="def handler():",
    )
    context = GroundingContext(text="initial source", evidence=(evidence,))

    assert "sensitive_operation" in context.selection_text
    assert "sensitive_operation" not in context.prompt_text
    assert evidence.id in context.prompt_text


def test_structured_fact_limitations_allow_judgment_but_block_completion():
    coverage = GroundingCoverage(limitations=("facts:app.py:2:4",))

    assert coverage.reviewable is True
    assert coverage.complete is False
    assert "structured facts unavailable" in coverage.failure_reason


def test_fact_limitations_are_scoped_to_sources_published_by_the_unit():
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


def test_definition_plan_source_scope_includes_relationship_and_evidence_files():
    source = DefinitionFragment("app.py", "route", 0, 20)
    target = DefinitionFragment("service.py", "load", 0, 20)
    plan = plan_definition_units(
        (source,),
        {"dependencies": dependencies_data((DefinitionDependency("app.py", target, source, "call"),))},
        depth=1,
        max_chars=1,
    )[0]

    assert definition_plan_source_files(plan) == ("app.py", "service.py")


def test_definition_evidence_index_exposes_a_declaration_not_its_body(tmp_path):
    source = "class Rule(ModelWithOwner):\n    secret = load_secret()\n"
    (tmp_path / "models.py").write_text(source)
    entry = DefinitionFragment("views.py", "view", 0, 20)
    rule = DefinitionFragment("models.py", "Rule", 0, len(source))
    plan = plan_definition_units(
        (entry,),
        {"dependencies": dependencies_data((DefinitionDependency("views.py", rule, entry, "import"),))},
        depth=1,
        max_chars=1,
    )[0]

    item = definition_evidence(tmp_path, plan)[0]

    assert item.preview == "class Rule(ModelWithOwner):"
    assert "secret = load_secret" in item.text


def test_definition_evidence_receipt_uses_normalized_character_ranges(tmp_path):
    prefix = "label = 'é'\n"
    definition = "def load():\n    return secret\n"
    source = prefix + definition
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    start = len(prefix)
    target = DefinitionFragment("models.py", "load", start, start + len(definition))
    seed = DefinitionFragment("views.py", "view", 0, 20)
    plan = plan_definition_units(
        (seed,),
        {"dependencies": dependencies_data((DefinitionDependency("views.py", target, seed, "call"),))},
        depth=1,
        max_chars=1,
    )[0]

    item = definition_evidence(tmp_path, plan)[0]

    assert item.source_span is not None
    assert (item.source_span.start_line, item.source_span.end_line) == (2, 3)
    assert "2 | def load():" in item.text
    assert "label" not in item.text


def test_definition_evidence_does_not_publish_a_file_scope_container(tmp_path):
    source = "send_webhook(url)\n" + "setting = True\n" * 4_000
    (tmp_path / "settings.py").write_text(source, encoding="utf-8")
    file_scope = DefinitionFragment("settings.py", "<file>", 0, len(source))

    evidence = definition_evidence(
        tmp_path,
        DefinitionUnitPlan(seeds=(file_scope,), evidence=(file_scope,)),
        include_seeds=True,
    )

    assert evidence == ()
