"""Grounded units and finder replies for isolated diff review tests."""

import json
from dataclasses import replace
from pathlib import Path

from cyberjury.review.context import GroundingContext
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.diff.model import DiffUnit, diff_paths, pack_diff_chunks
from cyberjury.review.diff.prompts import diff_seed
from cyberjury.review.finder import UnitFinder
from cyberjury.review.run import ReviewRun
from cyberjury.review.seats import ReviewSeats
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from tests.review.support import StubIssueJudge, prepared_units, run_prepared

SQL_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

FILE_A_DIFF = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

FILE_B_DIFF = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def diff_units(
    diff: str,
    grounding: GroundingContext | None = None,
    *,
    max_chars: int = DEFAULT_REVIEW_SETTINGS.diff.target_patch_chars_per_unit,
) -> list[DiffUnit]:
    """Pack a test diff into ordered units without repository planning."""
    batches = pack_diff_chunks(diff, max_chars) if diff.strip() else []
    return [
        DiffUnit(
            index=index,
            diff=batch,
            paths=diff_paths(batch),
            id=f"diff-unit-{index}",
            definition_plan=DefinitionUnitPlan(seed_files=diff_paths(batch)),
            grounding=replace(grounding, seed=grounding.seed or diff_seed(batch)) if grounding is not None else None,
        )
        for index, batch in enumerate(batches, 1)
    ]


def diff_unit(diff: str, grounding: GroundingContext | str = "") -> DiffUnit:
    """Return the one unit of a small test diff, grounded in the given context."""
    [unit] = diff_units(
        diff, grounding if isinstance(grounding, GroundingContext) else GroundingContext(text=grounding)
    )
    return unit


def finder(provider) -> UnitFinder[DiffUnit]:
    """Return the diff finder bound to one test provider."""
    return UnitFinder(DIFF_TARGET, provider=provider, model="m")


def reply(findings: list[dict[str, object]]) -> str:
    """Serialize one reply whose findings are completed copies carrying the required finder fields."""
    completed = []
    for finding in findings:
        item = {
            "evidence_refs": ["seed"],
            "title": "unsafe changed operation",
            "evidence": "concrete exploitable path",
            **finding,
        }
        item["entrypoint"] = item.get("entrypoint") or "changed code path"
        item["attack_path"] = item.get("attack_path") or "attacker input reaches the vulnerable operation"
        if "file" in item and "line" in item:
            item.setdefault("change_anchor", {"file": item["file"], "line": item["line"], "side": "new"})
        completed.append(item)
    return json.dumps({"findings": completed, "evidence_requests": [], "source_queries": []})


def review(
    diff_or_units: str | list[DiffUnit],
    *,
    provider,
    context: GroundingContext | str = "repository source",
    max_chars: int = DEFAULT_REVIEW_SETTINGS.diff.target_patch_chars_per_unit,
    issue_judge=None,
    root: Path = Path("."),
    **options,
) -> ReviewRun:
    """Review a test diff, or prepared units, with one finder seat and an issue judge that links no pair by default."""
    if isinstance(diff_or_units, str):
        grounding = context if isinstance(context, GroundingContext) else GroundingContext(text=context)
        units = diff_units(diff_or_units, grounding, max_chars=max_chars)
    else:
        units = diff_or_units
    seats = ReviewSeats(
        finder=provider, finder_model="m", issue_judge=issue_judge or StubIssueJudge(lambda _pair: False)
    )
    values = {"concurrency": 1, **options}
    return run_prepared(prepared_units(units, root), target=DIFF_TARGET, seats=seats, **values)
