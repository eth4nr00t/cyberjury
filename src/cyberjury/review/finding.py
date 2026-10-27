"""The one finding record every review target produces, with its optional diff change anchor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Literal

from cyberjury.review.context import SourceSpan
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
    """One reported vulnerability before cross-unit accumulation and issue grouping."""

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
    cited_spans: tuple[SourceSpan, ...] = field(default=(), repr=False, compare=False)
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)

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

    def reply_record(self) -> dict[str, object]:
        """Return the finding in the exact reply shape the model can return again."""
        record: dict[str, object] = {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "entrypoint": self.entrypoint,
            "file": self.file,
            "line": self.line,
        }
        if self.change_anchor is not None:
            record["change_anchor"] = self.change_anchor.to_dict()
        return {
            **record,
            "evidence": self.evidence,
            "attack_path": self.attack_path,
            "evidence_refs": list(self.evidence_refs),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the complete form a unit findings record stores."""
        data = asdict(self)
        data["evidence_refs"] = list(self.evidence_refs)
        data["cited_spans"] = [
            {"file": span.file, "start_line": span.start_line, "end_line": span.end_line} for span in self.cited_spans
        ]
        return data

    @classmethod
    def from_dict(cls, value: object) -> Finding:
        """Parse one finding restored from a unit findings record written by `to_dict`."""
        names = {item.name for item in fields(cls)}
        if not isinstance(value, dict) or set(value) != names:
            raise ValueError("finding fields are invalid")
        text = names - {"line", "change_anchor", "evidence_refs", "cited_spans"}
        if not all(isinstance(value[name], str) for name in text) or value["severity"] not in SEVERITIES:
            raise ValueError("finding text fields are invalid")
        line = value["line"]
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError("finding line must be a positive integer")
        refs = value["evidence_refs"]
        if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
            raise ValueError("finding evidence_refs must be a list of strings")
        spans = value["cited_spans"]
        if not isinstance(spans, list) or not all(
            isinstance(span, dict) and set(span) == {"file", "start_line", "end_line"} for span in spans
        ):
            raise ValueError("finding cited spans are invalid")
        anchor = value["change_anchor"]
        if anchor is not None:
            if not isinstance(anchor, dict) or set(anchor) != {"file", "line", "side"}:
                raise ValueError("finding change anchor is invalid")
            anchor = ChangeAnchor(file=anchor["file"], line=anchor["line"], side=anchor["side"])
        return cls(
            **{name: value[name] for name in text},
            line=line,
            change_anchor=anchor,
            evidence_refs=tuple(refs),
            cited_spans=tuple(SourceSpan(**span) for span in spans),
        )
