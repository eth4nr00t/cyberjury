"""The single source of truth for severity levels and their order."""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_INDEX = {severity: rank for rank, severity in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    """Return the rank of a severity, 0 for CRITICAL through 3 for LOW, so sorting by it puts CRITICAL first."""
    return _INDEX[severity]
