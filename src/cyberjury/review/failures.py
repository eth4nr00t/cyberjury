"""Shared review unit failure records for diff and repository paths."""

from __future__ import annotations

from dataclasses import dataclass


class BackendUnavailable(RuntimeError):
    """A required facts or source backend cannot run."""


@dataclass(frozen=True, kw_only=True)
class ReviewUnitFailure:
    """One review unit that did not produce a complete judgment."""

    index: int
    total: int
    paths: tuple[str, ...]
    reason: str
