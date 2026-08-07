"""Severity stabilization: a median across the grades a finding was given.

Recall, the union, and precision, the verifier, are stabilized by code and by multiple
votes, but a finding's severity is a single model judgment, so the same finding could be
graded CRITICAL on one run and MEDIUM on the next. That jitter does not change what is
found, only how it is ranked, but it makes the report's priority order unreliable.
`median` damps it: when a finding was graded several times, across passes or across
duplicate issue files, take the middle grade instead of whichever was seen first. The
grade itself stays the model's, read against the severity rubric on the code in front of
it. The rubric's firm rules, replay is at least HIGH, a disclosed live credential is
HIGH, live in that rubric and in the verifier, not in a keyword rule here, since a
keyword in a freeform title cannot see whether a key is live or a replay is privileged.
Pure functions, no model calls, fully testable.
"""

from __future__ import annotations

from cyberjury.severity import SEVERITIES, normalize

LEVELS = tuple(reversed(SEVERITIES))
_RANK = {s: i for i, s in enumerate(LEVELS)}


def rank(severity: str) -> int:
    """Return the ordering rank for a severity label."""
    return _RANK[normalize(severity)]


def median(severities: list[str]) -> str:
    """The middle severity of several votes, upper-middle on an even count.

    so a finding graded a few times converges to a stable level instead of first-seen.
    """
    if not severities:
        return "MEDIUM"
    ordered = sorted(rank(s) for s in severities)
    return LEVELS[ordered[len(ordered) // 2]]
