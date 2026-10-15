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
    source_operation_id: str = field(default="", repr=False, compare=False)
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
        """Return the shared path identity independent from security category."""
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
            root_cause=self.description,
            source_operation_id=self.source_operation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the stable wire form consumed by reports and persisted state."""
        data = asdict(self)
        data.pop("source_operation_id", None)
        data.pop("evidence_refs", None)
        data.pop("found_by", None)
        if self.change_anchor is None:
            data.pop("change_anchor", None)
        return data


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
    """Map one finding object when it names the file required by every finding.

    Severity and confidence must already be valid; invalid values raise instead of
    being replaced with defaults.
    """
    if not isinstance(data, dict):
        return None
    file = data.get("file")
    if not isinstance(file, str) or not file.strip():
        return None
    severity = data.get("severity")
    if severity not in SEVERITIES:
        raise ValueError("finding severity is invalid")
    confidence = data.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
        raise ValueError("finding confidence must be a number between 0 and 1")
    finding = Finding(
        file=file.strip(),
        line=_to_line(data.get("line")),
        severity=severity,
        category=str(data.get("category", "")).strip(),
        entrypoint=str(data.get("entrypoint", "")).strip(),
        description=str(data.get("description", "")),
        exploit_scenario=str(data.get("exploit_scenario", "")),
        recommendation=str(data.get("recommendation", "")),
        confidence=float(confidence),
        change_anchor=_change_anchor(data.get("change_anchor")),
        evidence_refs=_evidence_refs(data.get("evidence_refs", ())),
    )
    return finding
