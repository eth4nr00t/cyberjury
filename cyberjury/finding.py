"""Finding: the unit a diff audit reports.

A single, flat record of one security problem with its location, an exploit
scenario, and a confidence. The audit engine asks the model for findings and maps
its JSON onto these.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from cyberjury.severity import SEVERITIES


@dataclass(frozen=True, kw_only=True)
class Finding:
    file: str
    line: int | None = None
    severity: str = "MEDIUM"
    category: str = ""
    description: str = ""
    exploit_scenario: str = ""
    recommendation: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _to_float(value: object, default: float) -> float:
    # bool is an int subclass, so reject it explicitly or True would pass as confidence 1.0
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return default
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if 0.0 <= f <= 1.0 else default


def _to_line(value: object) -> int | None:
    # bool is an int subclass, so reject it or True would read as line 1
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def finding_from_dict(data: dict[str, Any]) -> Finding | None:
    """Map one loosely-typed model finding onto a Finding, or None if it has no
    location, since every finding carries a file, that is the invariant."""
    if not isinstance(data, dict):
        return None
    file = data.get("file")
    if not isinstance(file, str) or not file.strip():
        return None
    file = file.strip()
    severity = str(data.get("severity", "MEDIUM")).upper()
    return Finding(
        file=file,
        line=_to_line(data.get("line")),
        severity=severity if severity in SEVERITIES else "MEDIUM",
        category=str(data.get("category", "")).strip(),
        description=str(data.get("description", "")),
        exploit_scenario=str(data.get("exploit_scenario", "")),
        recommendation=str(data.get("recommendation", "")),
        confidence=_to_float(data.get("confidence"), 0.5),
    )


def findings_from_list(items: object) -> list[Finding]:
    if not isinstance(items, list):
        return []
    return [f for f in (finding_from_dict(d) for d in items) if f is not None]
