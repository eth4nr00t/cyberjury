"""Repository prompts keep the review contract and every output field in the system prompt."""

from cyberjury.review.navigation import navigation_instructions
from cyberjury.review.repository.prompts import (
    FINDER_RESPONSE_SCHEMA,
    repository_finder_system,
)


def test_repository_system_carries_the_review_contract_and_field_meanings():
    """The repository system names its unit scope, embeds kernel, rubric, and navigation, and backticks fields."""
    system = repository_finder_system(
        security_kernel="# Security Kernel\nKERNEL-X",
        severity_rubric="# Severity Rubric\nRUBRIC-X",
        navigation=navigation_instructions(),
    )

    for text in ("one repository unit", "KERNEL-X", "RUBRIC-X", "# Source Navigation"):
        assert text in system
    root = FINDER_RESPONSE_SCHEMA.schema["properties"]
    for field in (*root, *root["findings"]["items"]["properties"]):
        assert f"`{field}`" in system
    assert '{"findings"' not in system
