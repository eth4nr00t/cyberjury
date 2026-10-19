"""Versioned benchmark check contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, kw_only=True)
class Location:
    """One source location hint for a benchmark check."""

    file: str
    line: int | None = None
    symbol: str = ""


@dataclass(frozen=True, kw_only=True)
class ChangeAnchor:
    """One exact changed line that establishes a diff check identity."""

    file: str
    line: int
    side: Literal["old", "new"]


@dataclass(frozen=True, kw_only=True)
class Check:
    """One expected finding of a benchmark case."""

    id: str
    root_cause: str
    locations: tuple[Location, ...] = ()
    change_anchors: tuple[ChangeAnchor, ...] = ()

    def to_dict(self) -> dict:
        """Return the check in its benchmark.yaml form, without unset location fields or absent anchors."""
        data: dict = {
            "id": self.id,
            "root_cause": self.root_cause,
            "locations": [
                {"file": item.file} | ({"line": item.line} if item.line is not None else {"symbol": item.symbol})
                for item in self.locations
            ],
        }
        if self.change_anchors:
            data["change_anchors"] = [
                {"file": item.file, "line": item.line, "side": item.side} for item in self.change_anchors
            ]
        return data


def case_checks(rows: Sequence[Mapping]) -> tuple[Check, ...]:
    """Construct the checks of one case that its JSON Schema already accepted."""
    return tuple(
        Check(
            id=row["id"],
            root_cause=row["root_cause"],
            locations=tuple(
                Location(file=item["file"], line=item.get("line"), symbol=item.get("symbol", ""))
                for item in row["locations"]
            ),
            change_anchors=tuple(
                ChangeAnchor(file=item["file"], line=item["line"], side=item["side"])
                for item in row.get("change_anchors", ())
            ),
        )
        for row in rows
    )
