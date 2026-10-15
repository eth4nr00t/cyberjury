"""Build repository grounded units for isolated Diff Review tests."""

from collections.abc import Callable

from cyberjury.review.context import GroundingContext
from cyberjury.review.diff.model import DiffUnit, batch_paths, pack_diff_chunks
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def diff_units(
    diff: str,
    grounding: GroundingContext | None = None,
    *,
    max_chars: int = DEFAULT_REVIEW_SETTINGS.diff.target_patch_chars_per_unit,
) -> list[DiffUnit]:
    """Pack a test diff into ordered units without repository planning."""
    batches = pack_diff_chunks(diff, max_chars) if diff.strip() else []
    return [
        DiffUnit(index=index, total=len(batches), diff=batch, paths=batch_paths(batch), grounding=grounding)
        for index, batch in enumerate(batches, 1)
    ]


def repository_prepare(
    context: GroundingContext | str = "repository source",
    *,
    max_chars: int = DEFAULT_REVIEW_SETTINGS.diff.target_patch_chars_per_unit,
) -> Callable[[str], list[DiffUnit]]:
    grounding = (
        context if isinstance(context, GroundingContext) else GroundingContext(text=context, source="repository")
    )

    def prepare(diff: str) -> list[DiffUnit]:
        return diff_units(diff, grounding, max_chars=max_chars)

    return prepare
