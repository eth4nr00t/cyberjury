"""Run benchmark diff cases through the product Diff Review command and record adjudicable attempts.

Each case run is one `cyberjury review diff` of the pinned two-dot range in its own review
workspace, so acquisition, the canonical patch, the materialized head tree, and every output
artifact are the product's. The attempt is recorded from those artifacts by the same recorder
that records Repository Review attempts.
"""

from __future__ import annotations

import contextlib
import io
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury import cli
from cyberjury.review.target import resolve_diff_target
from evals.adjudication import recorded_attempt
from evals.benchmarks.cases import BenchmarkCase, ensure_git_target_refs, git_target_root, validate_change_anchors

type Progress = Callable[[str], None]


@dataclass(frozen=True, kw_only=True)
class _CaseProgress:
    """Report one benchmark case's lifecycle as progress lines."""

    progress: Progress | None
    prefix: str
    started: float

    def say(self, text: str) -> None:
        """Publish one line naming the run and case."""
        if self.progress is not None:
            self.progress(f"{self.prefix} {text}")

    def failed(self, error: str) -> None:
        """Publish a failed case without implying completion."""
        self.say(f"failed after {self._elapsed()}s: {error}")

    def finished(self, reports: int) -> None:
        """Publish a complete case with its report count."""
        self.say(f"finished in {self._elapsed()}s, reports={reports}")

    def _elapsed(self) -> float:
        return round(time.monotonic() - self.started, 3)


class _Tee(io.TextIOBase):
    """Forward command diagnostics while keeping every failure line the command printed."""

    def __init__(self, stream: io.TextIOBase) -> None:
        self._stream = stream
        self._failures: list[str] = []

    @property
    def failure(self) -> str:
        """Return the failures the command reported, in order."""
        return "; ".join(self._failures)

    def write(self, text: str) -> int:
        self._stream.write(text)
        self._failures.extend(
            line.split(": ", 1)[1]
            for line in text.splitlines()
            if line.startswith(("error: ", "cyberjury failed: ", "review failed: "))
        )
        return len(text)

    def flush(self) -> None:
        self._stream.flush()


def case_workspace(workspace: Path, case: BenchmarkCase, number: int) -> Path:
    """Return the review workspace of one case run."""
    project, case_id = case.name.split(":", 1)
    return workspace / project / case_id / f"run-{number:02d}"


def run(
    cases: list[BenchmarkCase],
    *,
    workspace: Path,
    model_override: str | None = None,
    runs: int = 1,
    concurrency: int | None = None,
    progress: Progress | None = None,
    on_attempt: Callable[[dict[str, object]], None] | None = None,
) -> list[dict[str, object]]:
    """Review each diff case once per run and return one attempt record per case and run.

    `on_attempt` receives each record as soon as its case finishes. Each run keeps its review
    session, including `model-calls.json`, under `workspace`.
    """
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
            record = _review_case(case, number, case_workspace(workspace, case, number), model_override, concurrency)
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
    model_override: str | None,
    concurrency: int | None,
) -> dict[str, object]:
    if workspace.exists():
        raise ValueError(f"diff review workspace already exists: {workspace}")
    root = git_target_root(case.target)
    ensure_git_target_refs(case.target, root)
    git_range = f"{case.target['base']}..{case.target['commit']}"
    validate_change_anchors(case, resolve_diff_target(root, git_range).patch.text)
    argv = ["review", "diff", "--repository", str(root), "--git-range", git_range, "--workspace", str(workspace)]
    if model_override:
        argv += ["--model", model_override]
    if concurrency:
        argv += ["--concurrency", str(concurrency)]
    diagnostics = _Tee(sys.stderr)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(diagnostics):
        cli.main(argv)
    attempts = sorted(workspace.glob("reviews/*/attempts/*/attempt.json"))
    if len(attempts) != 1:
        return recorded_attempt(case, workspace, number, error=diagnostics.failure or "the review recorded no attempt")
    return recorded_attempt(case, attempts[0].parent, number, error=diagnostics.failure)
