"""Versioned answer key contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, kw_only=True)
class ExpectedLocation:
    """One source location hint for a benchmark check."""

    file: str
    line: int | None = None
    symbol: str = ""


@dataclass(frozen=True, kw_only=True)
class ExpectedChange:
    """One exact changed line that establishes a diff check identity."""

    file: str
    line: int
    side: Literal["old", "new"]


@dataclass(frozen=True, kw_only=True)
class KeyCheck:
    """One expected finding or clean check from an answer key."""

    id: str
    expectation: str
    applies_to: tuple[str, ...] = ()
    locations: tuple[ExpectedLocation, ...] = ()
    changes: tuple[ExpectedChange, ...] = ()


def key_checks(answer_key: Mapping[str, Sequence[Mapping]]) -> tuple[KeyCheck, ...]:
    """Construct checks from an answer key document that its JSON Schema already accepted."""
    return tuple(
        KeyCheck(
            id=row["id"],
            expectation=row["expectation"],
            applies_to=tuple(row["applies_to"]),
            locations=tuple(
                ExpectedLocation(file=item["file"], line=item.get("line"), symbol=item.get("symbol", ""))
                for item in row["locations"]
            ),
            changes=tuple(
                ExpectedChange(file=item["file"], line=item["line"], side=item["side"])
                for item in row.get("changes", ())
            ),
        )
        for row in answer_key["checks"]
    )
