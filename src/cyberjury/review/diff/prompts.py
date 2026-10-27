"""Bounded diff evidence rendering and the diff finder contract."""

from __future__ import annotations

from cyberjury.numbering import numbered_diff
from cyberjury.review.prompts import (
    CHANGE_ANCHOR_SCHEMA,
    fenced_source,
    finder_system,
    finding_fields,
    finding_schema,
)
from cyberjury.review.schemas import finder_response_schema

DIFF_FINDING_SCHEMA = finding_schema(change_anchor=CHANGE_ANCHOR_SCHEMA)
FINDER_RESPONSE_SCHEMA = finder_response_schema("diff_finder_reply", DIFF_FINDING_SCHEMA)

_DIFF_SCOPE = """The user message contains one code change as a numbered unified diff, cited as `seed`, followed \
by repository context for tracing inputs, controls, and effects: unverified call candidates, delivered source, syntax \
hints, and an evidence catalog.
- Each patch gutter is `old:new`. A blank side means the line does not exist on that side.
- Report a vulnerability only when an exact changed line introduces it, exposes it, or removes the control behind \
it. Unchanged context and repository source support the analysis but are never change anchors.
- A deletion is vulnerable when surviving code loses a security control. Locate the finding in surviving code and \
anchor it on the removed line."""

_CHANGE_ANCHOR_FIELD = (
    "- `change_anchor`: the exact changed line that introduces, exposes, or removes the control behind the "
    "vulnerability. `side` is `new` with the new line number for a `+` line and `old` with the old line number for a "
    "`-` line."
)


def diff_finder_system(*, review_brief: str, severity_rubric: str, navigation: str) -> str:
    """Render the diff finder contract shared by every unit of one run."""
    return finder_system(
        target="a code change",
        scope=_DIFF_SCOPE,
        output_fields=finding_fields(_CHANGE_ANCHOR_FIELD),
        review_brief=review_brief,
        severity_rubric=severity_rubric,
        navigation=navigation,
    )


def diff_seed(diff: str) -> str:
    """Render one diff unit as the numbered code under review."""
    return f"Code under review, cited as `seed` (numbered unified diff):\n{fenced_source(numbered_diff(diff), 'diff')}"
