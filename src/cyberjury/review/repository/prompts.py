"""Finder contract for repository review units."""

from __future__ import annotations

from cyberjury.review.prompts import finder_system, finding_fields, finding_schema
from cyberjury.review.schemas import finder_response_schema

REPOSITORY_FINDING_SCHEMA = finding_schema()
FINDER_RESPONSE_SCHEMA = finder_response_schema("repository_finder_reply", REPOSITORY_FINDING_SCHEMA)

_REPOSITORY_SCOPE = """The user message contains one repository review unit as numbered source, cited as `seed`, \
followed by repository context for tracing inputs, controls, and effects: unverified call candidates, delivered \
source, syntax hints, and an evidence catalog. Review the unit's code."""


def repository_finder_system(*, review_brief: str, severity_rubric: str, navigation: str) -> str:
    """Render the repository finder contract shared by every unit of one run."""
    return finder_system(
        target="one repository review unit",
        scope=_REPOSITORY_SCOPE,
        output_fields=finding_fields(),
        review_brief=review_brief,
        severity_rubric=severity_rubric,
        navigation=navigation,
    )
