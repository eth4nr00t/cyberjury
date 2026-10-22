"""Lightweight run telemetry."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from time import perf_counter


def progress(message: str) -> None:
    """Print one flushed progress line to stderr while stdout stays reserved for the report."""
    print(message, file=sys.stderr, flush=True)


@contextmanager
def stage_timer(name: str) -> Iterator[None]:
    """Time a stage and print its elapsed time, marked failed when it raises."""
    started = perf_counter()
    ok = False
    try:
        yield
        ok = True
    finally:
        seconds = round(perf_counter() - started, 1)
        progress(f"{name} done in {seconds}s" if ok else f"{name} failed after {seconds}s")
