"""Measure each stage of a review attempt, write its record, and print the record line."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from threading import Lock
from typing import TextIO

from cyberjury.providers.metering import UsageMeter, usage_from_calls
from cyberjury.record import Record, RecordError, error_message, utc_timestamp

type Classify = Callable[[BaseException], RecordError]
type Bind = Callable[[object], str]
type Sink = Callable[[Record], None]
type Progress = Callable[[int, int], None]


INTERRUPTED = "operator interrupted the command"
_PROGRESS_INTERVAL_SECONDS = 10.0


def internal_error(exc: BaseException) -> RecordError:
    """Classify any exception as an internal error with its redacted message."""
    return RecordError(code="internal", message=error_message(f"{type(exc).__name__}: {exc}"))


def usage_metrics(calls: list[dict[str, object]]) -> dict[str, int]:
    """Return the model usage metrics of the given calls, zero when there were none."""
    usage = usage_from_calls(calls)
    return {
        "calls": len(calls),
        "input_tokens": usage["total_input_tokens"],
        "cached_tokens": usage["cache_read_tokens"],
        "cache_write_tokens": usage["cache_write_tokens"],
        "output_tokens": usage["output_tokens"],
    }


@dataclass(kw_only=True)
class Measure:
    """What one stage reports while it runs: progress, metrics, attributes, artifacts, and an incomplete verdict."""

    _bind: Callable[[object], str | None]
    _progress: Progress
    metrics: dict[str, int] = field(default_factory=dict)
    attributes: dict[str, str | int | float | bool | None] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    error: RecordError | None = None

    def bind(self, value: object) -> None:
        """Persist a stage artifact and list its path."""
        path = self._bind(value)
        if path is not None and path not in self.artifacts:
            self.artifacts.append(path)

    def progress(self, finished: int, items: int) -> None:
        """Report how many of the stage's items have finished."""
        self._progress(finished, items)

    def incomplete(self, message: str) -> None:
        """Finish the stage incomplete with the reason."""
        self.error = RecordError(code="model", message=error_message(message))


class Recorder:
    """Turn stages and items into records: each is written first, then printed as one line."""

    def __init__(
        self,
        *,
        meter: UsageMeter,
        stream: TextIO | None = None,
        classify: Classify = internal_error,
    ) -> None:
        """Bind usage accounting, the stream that receives record lines, and the error classifier."""
        self.meter = meter
        self._stream = stream
        self._classify = classify
        self._bind: Bind | None = None
        self._sink: Sink | None = None
        self._pending: dict[str, list[object]] = {}
        self._lock = Lock()
        self.stages: list[Record] = []

    def attach(self, *, bind: Bind, sink: Sink) -> None:
        """Start writing artifacts and records, and write the stages finished so far with their held artifacts."""
        self._bind, self._sink = bind, sink
        for index, record in enumerate(self.stages):
            held = self._pending.pop(record.id, [])
            paths = [bind(value) for value in held]
            if paths:
                record = replace(record, artifacts=tuple(dict.fromkeys((*record.artifacts, *paths))))
                self.stages[index] = record
            sink(record)

    def _bind_value(self, stage: str, value: object) -> str | None:
        if self._bind is None:
            self._pending.setdefault(stage, []).append(value)
            return None
        return self._bind(value)

    def emit(self, record: Record, *, write: bool = True) -> None:
        """Write one record when a sink is attached, then print its line."""
        if write and self._sink is not None:
            self._sink(record)
        if self._stream is not None:
            with self._lock:
                self._stream.write(record.line() + "\n")
                self._stream.flush()

    def unit_usage(self, unit_id: str) -> dict[str, int]:
        """Return the model usage metrics of the calls made for one review or link item."""
        calls = self.meter.call_snapshot()
        return usage_metrics([call for call in calls if call.get("unit_id") == unit_id])

    def item(self, record: Record) -> None:
        """Print one item record line; the item store has written it."""
        self.emit(record, write=False)

    @contextmanager
    def stage(self, name: str, *, usage: bool = False) -> Iterator[Measure]:
        """Time one stage, add its model usage when it calls models, and record how it ended."""
        started_at, started = utc_timestamp(), time.monotonic()
        calls_before = len(self.meter.call_snapshot())
        reported = started

        def progress(finished: int, items: int) -> None:
            nonlocal reported
            now = time.monotonic()
            if now - reported < _PROGRESS_INTERVAL_SECONDS:
                return
            reported = now
            running = Record(
                id=name,
                status="running",
                started_at=started_at,
                duration_seconds=None,
                metrics={"items": items, "finished": finished},
            )
            self.emit(running, write=False)

        measure = Measure(_bind=lambda value: self._bind_value(name, value), _progress=progress)

        def finish(status: str, error: RecordError | None) -> None:
            calls = self.meter.call_snapshot()[calls_before:]
            record = Record(
                id=name,
                status=status,
                started_at=started_at,
                duration_seconds=round(time.monotonic() - started, 3),
                metrics={**measure.metrics, **(usage_metrics(calls) if usage else {})},
                attributes=measure.attributes,
                artifacts=tuple(measure.artifacts),
                error=error,
            )
            self.stages.append(record)
            self.emit(record)

        try:
            yield measure
        except KeyboardInterrupt:
            measure.attributes["reason"] = INTERRUPTED
            finish("interrupted", None)
            raise
        except BaseException as exc:
            finish("failed", self._classify(exc))
            raise
        finish("incomplete" if measure.error is not None else "ok", measure.error)
