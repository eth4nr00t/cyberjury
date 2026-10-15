"""Shared role provenance helpers for review engines."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace


def found_by_tuple(*groups: Iterable[str]) -> tuple[str, ...]:
    """Return one stable role provenance tuple with empty labels removed."""
    labels: set[str] = set()
    for group in groups:
        labels.update(label for label in group if label)
    return tuple(sorted(labels))


def tag_found_by[T](items: Iterable[T], *labels: str) -> list[T]:
    """Attach role provenance to findings or candidates without changing their shape."""
    source_labels = found_by_tuple(labels)
    return [replace(item, found_by=found_by_tuple(getattr(item, "found_by", ()), source_labels)) for item in items]
