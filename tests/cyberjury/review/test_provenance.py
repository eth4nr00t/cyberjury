"""Shared provenance helpers keep diff and repository review role logic aligned."""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberjury.review.provenance import found_by_tuple, label_judged, tag_found_by


@dataclass(frozen=True)
class _Item:
    title: str
    key_value: tuple
    found_by: tuple[str, ...] = field(default_factory=tuple)


def test_found_by_tuple_is_stable_and_omits_empty_labels():
    """Role provenance has one stable representation across both review paths."""
    assert found_by_tuple(("judge", ""), ("finder", "judge")) == ("finder", "judge")


def test_tag_found_by_preserves_existing_roles():
    """Adding one role never erases earlier provenance."""
    tagged = tag_found_by([_Item("x", ("file", 1), found_by=("finder",))], "judge")

    assert tagged[0].found_by == ("finder", "judge")


def test_label_judged_assigns_finder_challenger_or_judge_roles():
    """Judge-kept findings are labeled by the role that surfaced them."""
    finder = [_Item("same title", ("a.py", 1))]
    challenger = [_Item("missed", ("b.py", 2))]
    judged = [
        _Item("same title", ("renamed.py", 99)),
        _Item("other title", ("b.py", 2)),
        _Item("judge-only", ("c.py", 3)),
    ]

    labeled = label_judged(
        judged,
        finder,
        challenger,
        key=lambda item: item.key_value,
        title=lambda item: item.title,
        finder_label="finder",
        challenger_label="challenger",
        judge_label="judge",
    )

    assert [item.found_by for item in labeled] == [("finder",), ("challenger",), ("judge",)]
