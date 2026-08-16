"""The single source of truth for severity levels and their order.

Both review paths grade on the same four levels, so the canonical tuple, the free-text
normalizer, the rank order, and the SARIF mapping live here once. The diff report and
the repository calibration both import from this module, so the level names and their
ordering cannot drift apart.
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


def normalize(severity: str) -> str:
    """Return the canonical severity named anywhere in free text.

    It takes the most severe one mentioned and defaults to MEDIUM when none is.
    """
    s = (severity or "").strip().upper()
    return next((level for level in SEVERITIES if level in s), "MEDIUM")


def index(severity: str) -> int:
    """The rank of a severity, 0 for CRITICAL down to 3 for LOW.

    so a smaller index is more severe. Sorting by it puts CRITICAL first.
    """
    return _INDEX[normalize(severity)]


def median(severities: list[str]) -> str:
    """Stabilize repeated grades with the upper middle severity."""
    if not severities:
        return "MEDIUM"
    ordered = sorted(index(severity) for severity in severities)
    return SEVERITIES[ordered[(len(ordered) - 1) // 2]]
