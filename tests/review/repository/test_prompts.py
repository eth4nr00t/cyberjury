"""Repository prompts keep the review contract and every output field in the system prompt."""

from cyberjury.review.navigation import navigation_instructions
from cyberjury.review.repository.prompts import (
    FINDER_RESPONSE_SCHEMA,
    repository_finder_system,
)


def test_repository_system_carries_the_review_contract_and_field_meanings():
    """The system prompt embeds the kernel, rubric, and navigation, backticks every field, and has no JSON example."""
    system = repository_finder_system(
        security_kernel="# Security Kernel\nKERNEL-X",
        severity_rubric="# Severity Rubric\nRUBRIC-X",
        navigation=navigation_instructions(),
    )

    for text in (
        "one repository unit",
        "attacker-reachable, exploitable violation",
        "KERNEL-X",
        "RUBRIC-X",
        "Cite it directly and do not request it again",
        "# Source Navigation",
        "where the fix must be applied",
    ):
        assert text in system
    root = FINDER_RESPONSE_SCHEMA.schema["properties"]
    for field in (*root, *root["findings"]["items"]["properties"]):
        assert f"`{field}`" in system
    assert '{"findings"' not in system
    assert system.count("Cite it directly and do not request it again") == 1
