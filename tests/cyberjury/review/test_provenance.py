"""Shared provenance helpers keep diff and repository review seat labels aligned."""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberjury.review.provenance import found_by_tuple, tag_found_by


@dataclass(frozen=True)
class _Item:
    title: str
    key_value: tuple
    found_by: tuple[str, ...] = field(default_factory=tuple)


def test_found_by_tuple_is_stable_and_omits_empty_labels():
    """Role provenance has one stable representation across both review paths."""
    assert found_by_tuple(("seat-b", ""), ("seat-a", "seat-b")) == ("seat-a", "seat-b")


def test_tag_found_by_preserves_existing_roles():
    """Adding one role never erases earlier provenance."""
    tagged = tag_found_by([_Item("x", ("file", 1), found_by=("seat-a",))], "seat-b")

    assert tagged[0].found_by == ("seat-a", "seat-b")
