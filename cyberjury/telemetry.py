"""Lightweight run telemetry: a consistent stderr progress line and a stage timer that
records elapsed to a workspace timeline, so a long review shows it is moving and its
per-stage cost survives across the separate scaffold, run, finalize, and gate commands.

No logging framework and no event stream. Progress goes to stderr, timing to a small JSON
artifact, and stdout stays reserved for the report. Telemetry never fails the review: a
missing or corrupt timeline is rebuilt, not raised, since observability must not abort work.
"""

from __future__ import annotations

import contextlib
import json
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

TIMELINE_FILE = "_timeline.json"


def progress(message: str) -> None:
    """Print one progress line to stderr, flushed so it shows during a long run rather than
    buffering to the end. stdout is reserved for the report, so progress goes to stderr."""
    print(message, file=sys.stderr, flush=True)


def _append_timeline(workspace: Path, record: dict, reset: bool = False) -> None:
    """Append one stage record to the workspace timeline, best effort. A read or write error on
    this observability file must never fail the review, so a missing or corrupt timeline is
    started fresh rather than raised. `reset` starts a new timeline, for the stage that begins a
    pipeline, so a re-scaffold does not carry a prior run's stages forward."""
    path = workspace / TIMELINE_FILE
    existing: list = []
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


def read_timeline(workspace: Path | str) -> list[dict]:
    """The recorded stage timeline for a workspace, or empty when none was written or it is
    unreadable, so a caller summarizing the whole-pipeline cost never fails on a missing file."""
    try:
        data = json.loads((Path(workspace) / TIMELINE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


@contextmanager
def stage_timer(name: str, workspace: Path | str | None = None, *, reset: bool = False):
    """Time a stage, print its elapsed to stderr on exit, and, when a workspace is given, append
    a record to its timeline so the whole-pipeline cost is readable across the separate review
    commands. The stage is recorded even when it raises, marked not ok, and the error propagates.
    `reset` starts a fresh timeline, for the stage that begins a pipeline such as scaffold."""
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
