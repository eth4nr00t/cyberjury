"""Shared context envelope used by Diff Review and Repository Review."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, kw_only=True)
class GroundingContext:
    """Prompt context with an explicit source boundary and reviewed files."""

    text: str
    files: tuple[str, ...] = ()
    source: Literal["diff", "repository"] = "repository"
