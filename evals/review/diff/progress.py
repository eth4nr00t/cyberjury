"""Progress and trace events for Diff Review benchmark cases."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from cyberjury.review.trace import Trace, emit_trace
from evals.benchmarks.cases import DiffCase
from evals.score.result import Result

Progress = Callable[[dict[str, object]], None]


def with_run(progress: Progress | None, run: int, runs: int) -> Progress | None:
    """Attach repeated run identity to each event."""
    if progress is None:
        return None

    def write(event: dict[str, object]) -> None:
        progress({**event, "run": run, "runs": runs})

    return write


@dataclass(frozen=True, kw_only=True)
class CaseProgress:
    """Bind progress and trace metadata to one benchmark case."""

    progress: Progress | None
    trace_sink: Trace | None
    case: DiffCase
    index: int
    total: int
    model: str
    started: float

    @classmethod
    def start(
        cls,
        progress: Progress | None,
        trace: Trace | None,
        case: DiffCase,
        index: int,
        total: int,
        model: str,
    ) -> CaseProgress:
        """Create case progress state and publish the start event."""
        state = cls(
            progress=progress,
            trace_sink=trace,
            case=case,
            index=index,
            total=total,
            model=model,
            started=time.monotonic(),
        )
        state.emit("case_started")
        return state

    def emit(self, event: str, **extra: object) -> None:
        """Publish one case lifecycle event."""
        if self.progress is None:
            return
        payload: dict[str, object] = {
            "event": event,
            "case": self.case.name,
            "index": self.index,
            "total": self.total,
            "model": self.model,
            "profile": self.case.profile,
        }
        if event != "case_started":
            payload["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        payload.update(extra)
        self.progress(payload)

    def batch_finished(self, done: int, total: int, seconds: float) -> None:
        """Publish completion of one review batch."""
        self.emit(
            "case_batch_finished",
            batch=done,
            batches=total,
            batch_seconds=seconds,
        )

    def judgment_finished(self, label: str, seconds: float) -> None:
        """Publish completion of one unit review judgment."""
        self.emit(
            "case_judgment_finished",
            judgment_label=label,
            judgment_seconds=seconds,
        )

    def failed(self, error: str) -> None:
        """Publish a failed case without implying completion."""
        self.emit("case_failed", error=error)

    def scored(self, result: Result) -> None:
        """Publish answer key score counts for a completed case."""
        self.emit(
            "case_finished",
            reports=result.n_reports,
            found=len(result.found),
            missed=len(result.missed),
            false_positives=len(result.false_positives),
            extra=len(result.extra),
        )

    def trace(self) -> Trace | None:
        """Bind case identity to review trace events."""
        if self.trace_sink is None:
            return None

        def write(event: dict[str, object]) -> None:
            event_name = str(event.get("event", "trace"))
            fields = {key: value for key, value in event.items() if key not in {"event", "schema"}}
            emit_trace(
                self.trace_sink,
                event_name,
                **fields,
                case=self.case.name,
                index=self.index,
                total=self.total,
                profile=self.case.profile,
            )

        return write
