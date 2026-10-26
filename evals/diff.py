"""Run benchmark diff cases through the product Diff Review command and record adjudicable attempts."""

from __future__ import annotations

import contextlib
import io
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury import cli
from cyberjury.review.target import resolve_diff_target
from evals.attempts import recorded_attempt
from evals.benchmarks.cases import BenchmarkCase, validate_change_anchors
from evals.benchmarks.targets import ensure_git_target_refs, git_target_root

type Progress = Callable[[str], None]


@dataclass(frozen=True, kw_only=True)
class _CaseProgress:
    progress: Progress | None
    prefix: str
    started: float

    def say(self, text: str) -> None:
        if self.progress is not None:
            self.progress(f"{self.prefix} {text}")

    def failed(self, error: str) -> None:
        self.say(f"failed after {self._elapsed()}s: {error}")

    def finished(self, reports: int) -> None:
        self.say(f"finished in {self._elapsed()}s, reports={reports}")

    def _elapsed(self) -> float:
        return round(time.monotonic() - self.started, 3)


def _final_error(output: str) -> dict[str, str]:
    decoder, position, last = json.JSONDecoder(), 0, None
    while position < len(output.rstrip()):
        last, position = decoder.raw_decode(output, position)
        while position < len(output) and output[position].isspace():
            position += 1
    error = last.get("error") if isinstance(last, dict) else None
    return error if isinstance(error, dict) else {"code": "", "message": ""}


def case_workspace(workspace: Path, case: BenchmarkCase, number: int) -> Path:
    """Return the review workspace of one case run."""
    project, case_id = case.name.split(":", 1)
    return workspace / project / case_id / f"run-{number:02d}"


def run(
    cases: list[BenchmarkCase],
    *,
    workspace: Path,
    runs: int = 1,
    concurrency: int | None = None,
    progress: Progress | None = None,
    on_attempt: Callable[[dict[str, object]], None] | None = None,
) -> list[dict[str, object]]:
    """Review each diff case once per run and return one attempt record per case and run."""
    if runs < 1:
        raise ValueError("diff benchmark runs must be at least 1")
    records = []
    for number in range(1, runs + 1):
        for index, case in enumerate(cases, 1):
            run_prefix = f"run {number}/{runs} " if runs > 1 else ""
            status = _CaseProgress(
                progress=progress,
                prefix=f"{run_prefix}[{index}/{len(cases)}] {case.name}",
                started=time.monotonic(),
            )
            status.say("started")
            record = _review_case(case, number, case_workspace(workspace, case, number), concurrency)
            if record["complete"]:
                status.finished(len(record["findings"]))
            else:
                status.failed(str(record["error"]))
            records.append(record)
            if on_attempt is not None:
                on_attempt(record)
    return records


def _review_case(
    case: BenchmarkCase,
    number: int,
    workspace: Path,
    concurrency: int | None,
) -> dict[str, object]:
    if workspace.exists():
        raise ValueError(f"diff review workspace already exists: {workspace}")
    root = git_target_root(case.target)
    ensure_git_target_refs(case.target, root)
    git_range = f"{case.target['base']}..{case.target['commit']}"
    validate_change_anchors(case, resolve_diff_target(root, git_range).patch.text)
    argv = ["review", "diff", "--repository", str(root), "--git-range", git_range, "--workspace", str(workspace)]
    if concurrency:
        argv += ["--concurrency", str(concurrency)]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = cli.main(argv)
    if code == cli.INTERRUPTED_EXIT:
        raise KeyboardInterrupt
    error = _final_error(output.getvalue())
    if error["code"] == "config":
        raise SystemExit(error["message"])
    attempts = sorted(workspace.glob("reviews/*/attempts/*/record.json"))
    if len(attempts) != 1:
        return recorded_attempt(case, workspace, number, error=error["message"] or "the review recorded no attempt")
    return recorded_attempt(case, attempts[0].parent, number, error=error["message"])
