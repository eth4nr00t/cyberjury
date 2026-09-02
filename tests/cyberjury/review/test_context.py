"""Test shared grounding context and definition evidence behavior."""

import pytest

from cyberjury.review.context import (
    EvidenceItem,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
    definition_evidence,
    definition_plan_source_files,
    merge_grounding_coverage,
    select_evidence,
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


def test_grounding_context_marks_its_source_boundary():
    context = GroundingContext(text="source", files=("app.py",), source="diff")
    assert context.source == "diff"
    assert context.files == ("app.py",)


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
