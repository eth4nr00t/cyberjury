"""Finding records and their optional diff change location."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from cyberjury.review.identity import attack_path_identity, candidate_identity
from cyberjury.severity import SEVERITIES


@dataclass(frozen=True, kw_only=True)
class ChangeAnchor:
    """The exact patch line that introduced or removed relevant behavior."""

    file: str
    line: int
    side: Literal["old", "new"]

    def to_dict(self) -> dict[str, str | int]:
        """Return the stable patch location wire form."""
        return {"file": self.file, "line": self.line, "side": self.side}


@dataclass(frozen=True, kw_only=True)
class Finding:
    """Normalized finding data before adapter-specific reportability checks."""

    file: str
    line: int | None = None
    severity: str = "MEDIUM"
    category: str = ""
    entrypoint: str = ""
    description: str = ""
    exploit_scenario: str = ""
    recommendation: str = ""
    confidence: float = 0.5
    change_anchor: ChangeAnchor | None = None
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)
    found_by: tuple[str, ...] = field(default=(), repr=False, compare=False)

    @property
    def attack_path_id(self) -> str:
        """Return the shared path identity independent from vulnerability class."""
        return attack_path_identity(target="diff", path_anchor=self.entrypoint)

    @property
    def candidate_id(self) -> str:
        """Return one security violation identity on the shared attack path."""
        anchor = (
            (self.change_anchor.file, self.change_anchor.line, self.change_anchor.side)
            if self.change_anchor is not None
            else None
        )
        return candidate_identity(
            target="diff",
            file=self.file,
            line=self.line,
            category=self.category,
            path_anchor=self.entrypoint,
            anchor=anchor,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the stable wire form consumed by reports and persisted state."""
        data = asdict(self)
        data.pop("evidence_refs", None)
        data.pop("found_by", None)
        if self.change_anchor is None:
            data.pop("change_anchor", None)
        return data


def _to_float(value: object, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return default
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if 0.0 <= f <= 1.0 else default


def _to_line(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _change_anchor(value: object) -> ChangeAnchor | None:
    if not isinstance(value, dict):
        return None
    file = value.get("file")
    line = _to_line(value.get("line"))
    side = value.get("side")
    if not isinstance(file, str) or not file.strip() or line is None or side not in ("old", "new"):
        return None
    return ChangeAnchor(file=file.strip(), line=line, side=side)


def _evidence_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    if not all(isinstance(ref, str) and ref for ref in value):
        return ()
    return tuple(value)


def finding_from_dict(data: dict[str, Any]) -> Finding | None:
    """Map one loose model object when it names the file required by every finding."""
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
        entrypoint=str(data.get("entrypoint", "")).strip(),
        description=str(data.get("description", "")),
        exploit_scenario=str(data.get("exploit_scenario", "")),
        recommendation=str(data.get("recommendation", "")),
        confidence=_to_float(data.get("confidence"), 0.5),
        change_anchor=_change_anchor(data.get("change_anchor")),
        evidence_refs=_evidence_refs(data.get("evidence_refs", ())),
    )


def finding_role_dict(finding: Finding) -> dict[str, Any]:
    """Return one finding with its model evidence references."""
    data = finding.to_dict()
    data["attack_path_id"] = finding.attack_path_id
    data["candidate_id"] = finding.candidate_id
    data["evidence_refs"] = list(finding.evidence_refs)
    return data


def finding_memory_dict(finding: Finding) -> dict[str, Any]:
    """Return the stable minimum needed to recognize an established violation."""
    return {
        "candidate_id": finding.candidate_id,
        "attack_path_id": finding.attack_path_id,
        "category": finding.category,
        "file": finding.file,
        "line": finding.line,
        "entrypoint": finding.entrypoint,
    }


def findings_from_list(items: object) -> list[Finding]:
    """Parse a list of loose model objects into reportable findings."""
    if not isinstance(items, list):
        return []
    return [f for f in (finding_from_dict(d) for d in items) if f is not None]
