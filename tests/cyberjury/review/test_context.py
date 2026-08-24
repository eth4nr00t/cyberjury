"""Test shared grounding context and definition evidence behavior."""

from cyberjury.review.context import EvidenceItem, GroundingContext, definition_evidence
from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    dependencies_data,
    plan_definition_units,
)


def test_grounding_context_marks_its_source_boundary():
    context = GroundingContext(text="source", files=("app.py",), source="diff")
    assert context.source == "diff"
    assert context.files == ("app.py",)


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
