"""The single source of truth for severity levels and their order.

Both review paths grade on the same four levels, so the canonical tuple and rank order
live here once. The diff report and
the repository calibration both import from this module, so the level names and their
ordering cannot drift apart.
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


def index(severity: str) -> int:
    """The rank of a severity, 0 for CRITICAL down to 3 for LOW.

    so a smaller index is more severe. Sorting by it puts CRITICAL first.
    """
    return _INDEX[severity]


def median(severities: list[str]) -> str:
    """Stabilize repeated grades with the upper middle severity."""
    if not severities:
        return "MEDIUM"
    ordered = sorted(index(severity) for severity in severities)
    return SEVERITIES[ordered[(len(ordered) - 1) // 2]]
