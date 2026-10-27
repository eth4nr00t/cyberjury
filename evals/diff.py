"""Benchmark diff case runs through the product Diff Review command, recorded as adjudicable attempts."""

from __future__ import annotations

import io
import time
from collections.abc import Callable
from pathlib import Path

from cyberjury.review.command import ReviewCommand, run_review_command
from cyberjury.review.request import TargetInput
from cyberjury.review.target import resolve_diff_target
from evals.attempts import recorded_attempt
from evals.benchmarks.cases import BenchmarkCase, validate_change_anchors
from evals.benchmarks.targets import ensure_git_target_refs, git_target_root

type Progress = Callable[[str], None]


def case_state_dir(state_dir: Path, case: BenchmarkCase, number: int) -> Path:
    """Return the review state directory of one case run."""
    project, case_id = case.name.split(":", 1)
    return state_dir / project / case_id / f"run-{number:02d}"


def run(
    cases: list[BenchmarkCase],
    *,
    runs: int,
    state_dir: Path,
    progress: Progress,
    on_attempt: Callable[[dict[str, object]], None],
) -> list[dict[str, object]]:
    """Review each diff case once per run and return one attempt record per case and run."""
    records = []
    for number in range(1, runs + 1):
        for index, case in enumerate(cases, 1):
            prefix = f"{f'run {number}/{runs} ' if runs > 1 else ''}[{index}/{len(cases)}] {case.name}"
            progress(f"{prefix} started")
            started = time.monotonic()
            record = _review_case(case, number, case_state_dir(state_dir, case, number))
            seconds = round(time.monotonic() - started, 3)
            if record["complete"]:
                progress(f"{prefix} finished in {seconds}s, reports {len(record['findings'])}")
            else:
                progress(f"{prefix} failed after {seconds}s: {record['error']}")
            records.append(record)
            on_attempt(record)
    return records


def _review_case(
    case: BenchmarkCase,
    number: int,
    state_dir: Path,
) -> dict[str, object]:
    root = git_target_root(case.target)
    ensure_git_target_refs(case.target, root)
    git_range = f"{case.target['base']}..{case.target['commit']}"
    validate_change_anchors(case, resolve_diff_target(root, git_range).patch.text)
    command = ReviewCommand(
        target=TargetInput(kind="diff", repository=str(root.resolve()), git_range=git_range),
        fresh=None,
        state_dir=str(state_dir),
    )
    record = run_review_command(command, stdout=io.StringIO())
    if record.status == "interrupted":
        raise KeyboardInterrupt
    message = record.error.message if record.error is not None else ""
    if record.error is not None and record.error.code == "config":
        raise SystemExit(message)
    attempts = sorted(state_dir.glob("reviews/*/attempts/*/record.json"))
    if len(attempts) != 1:
        return recorded_attempt(case, state_dir, number, error=message or "the review recorded no attempt")
    return recorded_attempt(case, attempts[0].parent, number, error=message)
