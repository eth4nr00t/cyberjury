"""The one finding record every review target produces, with its optional diff change location."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Literal

from cyberjury.review.identity import candidate_identity
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
    """One reported vulnerability before cross-unit accumulation and verification.

    Every target fills the same fields; only a Diff finding carries a change anchor.
    """

    title: str
    category: str
    severity: str
    entrypoint: str
    file: str
    line: int
    evidence: str
    attack_path: str
    change_anchor: ChangeAnchor | None = None
    source_operation_id: str = field(default="", repr=False, compare=False)
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)
    found_by: tuple[str, ...] = field(default=(), repr=False, compare=False)

    @property
    def candidate_id(self) -> str:
        """Return one security violation identity on the shared attack path."""
        anchor = self.change_anchor
        return candidate_identity(
            target="diff" if anchor is not None else "repository",
            file=self.file,
            line=self.line,
            category=self.category,
            path_anchor=self.entrypoint or f"{self.file}:{self.line}",
            anchor=(anchor.file, anchor.line, anchor.side) if anchor is not None else None,
            root_cause=self.title,
            source_operation_id=self.source_operation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the complete checkpoint form."""
        data = asdict(self)
        data["evidence_refs"] = list(self.evidence_refs)
        data["found_by"] = list(self.found_by)
        return data

    @classmethod
    def from_dict(cls, value: object) -> Finding:
        """Parse one checkpointed finding written by `to_dict`."""
        names = {item.name for item in fields(cls)}
        if not isinstance(value, dict) or set(value) != names:
            raise ValueError("finding fields are invalid")
        text = names - {"line", "change_anchor", "evidence_refs", "found_by"}
        if not all(isinstance(value[name], str) for name in text) or value["severity"] not in SEVERITIES:
            raise ValueError("finding text fields are invalid")
        line = value["line"]
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError("finding line must be a positive integer")
        for name in ("evidence_refs", "found_by"):
            if not isinstance(value[name], list) or not all(isinstance(item, str) for item in value[name]):
                raise ValueError(f"finding {name} must be a list of strings")
        anchor = value["change_anchor"]
        if anchor is not None:
            if not isinstance(anchor, dict) or set(anchor) != {"file", "line", "side"}:
                raise ValueError("finding change anchor is invalid")
            anchor = ChangeAnchor(file=anchor["file"], line=anchor["line"], side=anchor["side"])
        return cls(
            **{name: value[name] for name in text},
            line=line,
            change_anchor=anchor,
            evidence_refs=tuple(value["evidence_refs"]),
            found_by=tuple(value["found_by"]),
        )
