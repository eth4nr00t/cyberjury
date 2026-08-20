"""Progress events for Repository Review benchmark cases."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace

from cyberjury.review.repository.engine import RepositoryRunOptions
from evals.benchmarks.contract import RepositoryCase
from evals.score.result import Result

Progress = Callable[[dict[str, object]], None]


@dataclass(frozen=True, kw_only=True)
class CaseProgress:
    """Bind progress metadata to one repository benchmark case."""

    progress: Progress | None
    case: RepositoryCase
    mode: str
    model: str
    started: float

    @classmethod
    def start(
        cls,
        progress: Progress | None,
        case: RepositoryCase,
        mode: str,
        model: str,
    ) -> CaseProgress:
        """Create case progress state and publish the start event."""
        state = cls(progress=progress, case=case, mode=mode, model=model, started=time.monotonic())
        state.emit("case_started")
        return state

    def bind(self, options: RepositoryRunOptions) -> RepositoryRunOptions:
        """Attach repository engine callbacks without discarding caller callbacks."""
        if self.progress is None:
            return options
        execution = options.execution
        verification = options.verification

        def on_pass(pass_number: int, label: str, new: int, total: int) -> None:
            if execution.on_pass is not None:
                execution.on_pass(pass_number, label, new, total)
            self.emit("case_pass_finished", pass_number=pass_number, reviewer_label=label, new=new, union=total)

        def on_judgment(unit: str, done: int, total: int, label: str, seconds: float) -> None:
            if execution.on_judgment is not None:
                execution.on_judgment(unit, done, total, label, seconds)
            self.emit(
                "case_judgment_finished",
                unit=unit,
                judgment=done,
                judgments=total,
                judgment_label=label,
                judgment_seconds=seconds,
            )

        def on_verify(done: int, total: int, seconds: float) -> None:
            if verification.on_verify is not None:
                verification.on_verify(done, total, seconds)
            self.emit("case_verification_finished", verification=done, verifications=total, seconds=seconds)

        return replace(
            options,
            execution=replace(execution, on_pass=on_pass, on_judgment=on_judgment),
            verification=replace(verification, on_verify=on_verify),
        )

    def emit(self, event: str, **extra: object) -> None:
        """Publish one case lifecycle event."""
        if self.progress is None:
            return
        payload: dict[str, object] = {
            "event": event,
            "case": self.case.id,
            "mode": self.mode,
            "model": self.model,
            "profile": self.case.profile,
        }
        if event != "case_started":
            payload["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        payload.update(extra)
        self.progress(payload)

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
