"""Build repository grounded units for isolated Diff Review tests."""

from collections.abc import Callable
from dataclasses import replace

from cyberjury.review.context import GroundingContext
from cyberjury.review.diff.model import DiffUnit, diff_units


def repository_prepare(
    context: GroundingContext | str = "repository source",
) -> Callable[[str], list[DiffUnit]]:
    grounding = (
        context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="repository")
    )

    def prepare(diff: str) -> list[DiffUnit]:
        return [replace(unit, grounding=grounding) for unit in diff_units(diff)]

    return prepare
