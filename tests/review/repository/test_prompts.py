"""Repository prompts keep the review contract and every output field in the system prompt."""

from cyberjury.review.navigation import navigation_instructions
from cyberjury.review.repository.prompts import (
    FINDER_RESPONSE_SCHEMA,
    REPOSITORY_FINDING_SCHEMA,
    repository_finder_system,
)


def test_repository_system_carries_the_review_contract_and_field_meanings():
    """The system prompt embeds the brief, rubric, navigation section, and backticks every schema field."""
    system = repository_finder_system(
        review_brief="# Security Reasoning Kernel\nKERNEL-X",
        severity_rubric="# Severity Rubric\nRUBRIC-X",
        navigation=navigation_instructions(),
    )

    for text in (
        "one repository review unit",
        "attacker-reachable, exploitable violation",
        "KERNEL-X",
        "RUBRIC-X",
        "Cite it directly and do not request it again",
        "# Source Navigation",
        "where the fix must be applied",
    ):
        assert text in system
    for field in (*REPOSITORY_FINDING_SCHEMA["properties"], "evidence_requests", "source_queries"):
        assert f"`{field}`" in system
    assert system.count("Cite it directly and do not request it again") == 1


def test_repository_system_explains_each_schema_field_without_an_example():
    """The repository finder prompt names every response and finding field in backticks and gives no JSON example."""
    system = repository_finder_system(review_brief="", severity_rubric="", navigation="")
    root = FINDER_RESPONSE_SCHEMA.schema["properties"]

    for field in (*root, *root["findings"]["items"]["properties"]):
        assert f"`{field}`" in system
    assert '{"findings"' not in system
