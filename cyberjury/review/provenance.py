"""Shared role provenance helpers for review engines."""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
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


def label_judged[T](
    judged: Iterable[T],
    finder_findings: Iterable[T],
    challenger_findings: Iterable[T],
    *,
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    finder_label: str,
    challenger_label: str,
    judge_label: str,
) -> list[T]:
    """Label judge-kept findings with the role that first surfaced each one."""
    finder = list(finder_findings)
    challenger = list(challenger_findings)
    finder_keys = {key(item) for item in finder}
    finder_titles = {title(item) for item in finder}
    challenger_keys = {key(item) for item in challenger}
    challenger_titles = {title(item) for item in challenger}
    out = []
    for item in judged:
        labels: set[str] = set(getattr(item, "found_by", ()))
        if key(item) in finder_keys or title(item) in finder_titles:
            labels.add(finder_label)
        if key(item) in challenger_keys or title(item) in challenger_titles:
            labels.add(challenger_label)
        if not labels and judge_label:
            labels.add(judge_label)
        out.append(replace(item, found_by=found_by_tuple(labels)))
    return out
