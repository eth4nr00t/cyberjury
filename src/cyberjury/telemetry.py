"""Lightweight run telemetry.

A consistent stderr progress line and a stage timer record elapsed time to a workspace
timeline, so a long review shows it is moving and its per-stage cost survives across the
separate scaffold, run, finalize, and gate commands. No logging framework and no event
stream. Progress goes to stderr, timing to a small JSON artifact, and stdout stays
reserved for the report. Telemetry never fails the review: a missing or corrupt timeline
is rebuilt, not raised, since observability must not abort work.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

TIMELINE_FILE = "_timeline.json"
type TimelineRecord = dict[str, object]


def progress(message: str) -> None:
    """Print one flushed progress line to stderr while stdout stays reserved for the report."""
    print(message, file=sys.stderr, flush=True)


def _append_timeline(workspace: Path, record: TimelineRecord, reset: bool = False) -> None:
    """Append one stage record to the workspace timeline, best effort.

    A read or write error on this observability file must never fail the review, so a
    missing or corrupt timeline is started fresh rather than raised. `reset` starts a new
    timeline, for the stage that begins a pipeline, so a re-scaffold does not carry a prior
    run's stages forward.
    """
    path = workspace / TIMELINE_FILE
    existing: list[TimelineRecord] = []
    if not reset:
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except (OSError, json.JSONDecodeError):
            existing = []
    existing.append(record)
    with contextlib.suppress(OSError):
        path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")


def read_timeline(workspace: Path | str) -> list[TimelineRecord]:
    """Return the recorded stage timeline for a workspace.

    Return an empty list when none was written or it is unreadable, so a caller summarizing
    the pipeline cost never fails on a missing file.
    """
    try:
        data = json.loads((Path(workspace) / TIMELINE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


@contextmanager
def stage_timer(name: str, workspace: Path | str | None = None, *, reset: bool = False) -> Iterator[None]:
    """Time a stage, print elapsed time, and persist it when a workspace is given.

    The timeline makes pipeline cost readable across separate review commands. The
    stage is recorded even when it raises, marked not ok, and the error propagates. `reset`
    starts a fresh timeline for the stage that begins a pipeline such as scaffold.
    """
    started = perf_counter()
    started_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    ok = False
    try:
        yield
        ok = True
    finally:
        seconds = round(perf_counter() - started, 1)
        progress(f"{name} done in {seconds}s" if ok else f"{name} failed after {seconds}s")
        if workspace is not None:
            _append_timeline(
                Path(workspace),
                {"stage": name, "started_at": started_at, "seconds": seconds, "ok": ok},
                reset=reset,
            )
