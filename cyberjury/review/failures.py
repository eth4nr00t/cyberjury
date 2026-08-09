"""Shared review unit failure records for diff and repository paths."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ReviewUnitFailure:
    """One review unit that did not produce a complete judgment."""

    index: int
    total: int
    paths: tuple[str, ...]
    reason: str
