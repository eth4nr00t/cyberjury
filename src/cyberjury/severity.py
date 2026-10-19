"""The single source of truth for severity levels and their order.

Findings, prompts, and results read the same four levels and their rank from here, so the
level names and their ordering cannot drift apart.
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


def index(severity: str) -> int:
    """Return the rank of a severity, 0 for CRITICAL through 3 for LOW, so sorting by it puts CRITICAL first."""
    return _INDEX[severity]
