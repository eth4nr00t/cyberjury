"""One review command run: each stage record, the attempt record, and the text the command prints."""

from __future__ import annotations

import contextlib
import signal
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from cyberjury import __version__
from cyberjury.envfile import load_env_file
from cyberjury.providers.base import ProviderAccessError
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderCredentialsError,
    provider_configuration_from_env,
)
from cyberjury.providers.metering import UsageMeter
from cyberjury.record import STAGES, Record, RecordError, error_message, render, utc_timestamp
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.diff.prepare import prepare_diff_review
from cyberjury.review.recorder import Recorder, Terminated, internal_error, interruption_reason, usage_metrics
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
)
from cyberjury.review.run import NoReviewableSourceError, run_review
from cyberjury.review.seats import ReviewSeats, provider_seat_record, review_seats
from cyberjury.review.session import ReviewAttempt, ReviewSession
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.target import (
    ResolvedTarget,
    TargetResolutionError,
    materialize_diff_target,
    resolve_diff_target,
    resolve_repository_target,
)
from cyberjury.sources.git import GitSourceError
from cyberjury.sources.paths import SourceSnapshotError
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from cyberjury.workspace import SessionBusyError, SessionConflictError, WorkspaceCorruptionError, new_attempt_id


@dataclass(frozen=True, kw_only=True)
class ReviewCommand:
    """What the operator asked one review command to do."""

    target: TargetInput
    fresh: bool | None
    concurrency: int | None
    state_dir: str


@dataclass(kw_only=True)
class _AttemptState:
    id: str
    started_at: str
    started: float
    attempt: ReviewAttempt | None = None
    source_changed: bool | None = None


def classify_error(exc: BaseException) -> RecordError:
    """Classify an exception that ended a stage as an input, config, busy, or internal error."""
    if isinstance(exc, (TargetResolutionError, GitSourceError, SourceSnapshotError, NoReviewableSourceError)):
        return RecordError(code="input", message=error_message(str(exc)))
    if isinstance(exc, (PermissionError, FileExistsError, NotADirectoryError, IsADirectoryError)):
        return RecordError(code="config", message=error_message(f"{type(exc).__name__}: {exc}"))
    if isinstance(exc, (ProviderCredentialsError, ProviderAccessError, WorkspaceCorruptionError, SessionConflictError)):
        return RecordError(code="config", message=error_message(str(exc)))
    if isinstance(exc, SessionBusyError):
        return RecordError(code="busy", message=error_message(str(exc)))
    return internal_error(exc)


def attempt_output(attempt_directory: Path) -> str:
    """Return the text one attempt prints: its stage record files in stage order, then its attempt record file."""
    files = [attempt_directory / "stages" / f"{stage}.json" for stage in STAGES]
    return "".join(
        path.read_text(encoding="utf-8") for path in (*files, attempt_directory / "record.json") if path.is_file()
    )


def run_review_command(command: ReviewCommand, *, stdout: TextIO, stderr: TextIO | None = None) -> Record:
    """Run one review attempt stage by stage, print its records, and return its attempt record."""
    meter = UsageMeter()
    recorder = Recorder(meter=meter, stream=stderr, classify=classify_error)
    state = _AttemptState(id=new_attempt_id(), started_at=utc_timestamp(), started=time.monotonic())
    failure: BaseException | None = None
    with _terminate_as_interrupt():
        try:
            _run_stages(command, state, recorder, meter)
        except BaseException as exc:
            failure = exc
        with _ignore_interrupts():
            record = _finish(state, recorder, meter, failure, stdout)
    if failure is not None and not isinstance(failure, (KeyboardInterrupt, Exception)):
        raise failure
    return record


def _run_stages(command: ReviewCommand, state: _AttemptState, recorder: Recorder, meter: UsageMeter) -> None:
    with contextlib.ExitStack() as stack:
        request, intent, seats = _configure(command, recorder, meter)
        target = _resolve(intent, command.state_dir, recorder)
        attempt = _open_attempt(command.state_dir, intent, request, state, recorder)
        snapshot, source = _capture(target, stack, recorder)
        prepared = (
            prepare_diff_review(target.patch.text, source, recorder=recorder)
            if target.kind == "diff"
            else prepare_repository_review(source, recorder=recorder)
        )
        run_review(
            prepared,
            target=DIFF_TARGET if target.kind == "diff" else REPOSITORY_TARGET,
            seats=seats,
            concurrency=request.concurrency.review,
            review=attempt.session_workspace.path,
            recorder=recorder,
        )
        state.source_changed = not snapshot.matches()


def _configure(
    command: ReviewCommand, recorder: Recorder, meter: UsageMeter
) -> tuple[ReviewAttemptRequest, ReviewIntent, ReviewSeats]:
    with recorder.stage("config") as measure:
        load_env_file()
        configuration = provider_configuration_from_env()
        request = _attempt_request(command, configuration)
        seats = review_seats(configuration, meter=meter)
        measure.attributes.update(
            provider=request.providers.seat.provider, model=request.providers.seat.model, version=__version__
        )
    return request, ReviewIntent(target=command.target), seats


def _attempt_request(command: ReviewCommand, configuration: ProviderConfiguration) -> ReviewAttemptRequest:
    return ReviewAttemptRequest(
        engine_version=__version__,
        concurrency=ConcurrencyRecord(
            review=command.concurrency or DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
        ),
        fresh=command.fresh,
        providers=ProviderPlanRecord(
            retries=configuration.retries,
            timeout_seconds=configuration.timeout,
            seat=provider_seat_record(configuration.seat),
        ),
    )


def _resolve(intent: ReviewIntent, state_dir: str, recorder: Recorder) -> ResolvedTarget:
    with recorder.stage("target") as measure:
        target = (
            resolve_diff_target(intent.target.repository, intent.target.git_range or "")
            if intent.target.kind == "diff"
            else resolve_repository_target(intent.target.repository)
        )
        state_path = Path(state_dir).expanduser().resolve()
        repository_root = Path(target.repository_root)
        if state_path == repository_root or state_path.is_relative_to(repository_root):
            raise TargetResolutionError("the state directory cannot be inside the reviewed repository")
        measure.attributes.update(
            kind=target.kind,
            repository=target.repository_root,
            range=target.git.requested_range if target.git is not None else None,
        )
        measure.bind(target)
    return target


def _open_attempt(
    state_dir: str,
    intent: ReviewIntent,
    request: ReviewAttemptRequest,
    state: _AttemptState,
    recorder: Recorder,
) -> ReviewAttempt:
    with recorder.stage("session") as measure:
        session = (
            ReviewSession.create(state_dir, intent)
            if intent.target.kind == "diff"
            else ReviewSession.select_active(state_dir, intent, reuse=request.fresh is not True)
        )
        state.attempt = session.start_attempt(request, attempt_id=state.id, started_at=state.started_at)
        measure.attributes.update(path=str(session.workspace.path))
        recorder.attach(bind=state.attempt.bind, sink=state.attempt.write_stage)
        measure.artifacts.append(f"{state.attempt.attempt_path}/request.json")
    return state.attempt


def _capture(
    target: ResolvedTarget, stack: contextlib.ExitStack, recorder: Recorder
) -> tuple[SourceSnapshot, SourceSnapshot]:
    with recorder.stage("source") as measure:
        if target.kind == "diff":
            snapshot = capture_source_snapshot(stack.enter_context(materialize_diff_target(target)))
            source = snapshot
        else:
            snapshot = capture_source_snapshot(target.repository_root)
            root = stack.enter_context(snapshot.materialize(name=Path(target.repository_root).name))
            source = SourceSnapshot(root=root, entries=snapshot.entries, snapshot_id=snapshot.snapshot_id)
        measure.metrics.update(files=len(snapshot.entries), bytes=sum(entry.size_bytes for entry in snapshot.entries))
        measure.attributes.update(snapshot=snapshot.snapshot_id)
        measure.bind(snapshot)
        measure.bind(ContractReceipt.capture())
    return snapshot, source


def _finish(
    state: _AttemptState,
    recorder: Recorder,
    meter: UsageMeter,
    failure: BaseException | None,
    stdout: TextIO,
) -> Record:
    artifacts: tuple[str, ...] = ()
    if state.attempt is not None:
        try:
            artifacts = (state.attempt.write_model_calls(meter.document()),)
        except Exception as exc:
            failure = failure or exc
    record = _attempt_record(state, recorder.stages, meter, failure, artifacts)
    if state.attempt is not None:
        state.attempt.finish(record)
    recorder.emit(record, write=False)
    stdout.write(
        attempt_output(state.attempt.workspace.path)
        if state.attempt is not None
        else "".join(render(item) for item in (*recorder.stages, record))
    )
    stdout.flush()
    return record


def _attempt_record(
    state: _AttemptState,
    stages: list[Record],
    meter: UsageMeter,
    failure: BaseException | None,
    artifacts: tuple[str, ...],
) -> Record:
    attributes: dict[str, str | int | float | bool | None] = {"source_changed": state.source_changed}
    ended = next((record for record in stages if record.status in {"failed", "interrupted"}), None)
    if isinstance(failure, KeyboardInterrupt) or (ended is not None and ended.status == "interrupted"):
        status, error = "interrupted", None
        attributes["reason"] = interruption_reason(failure)
    elif ended is not None:
        status, error = "failed", ended.error
    elif failure is not None:
        status, error = "failed", classify_error(failure)
    elif lagging := next((record for record in stages if record.status == "incomplete"), None):
        status, error = "incomplete", lagging.error
    else:
        status, error = "ok", None
    return Record(
        id=state.id,
        status=status,
        started_at=state.started_at,
        duration_seconds=round(time.monotonic() - state.started, 3),
        metrics={
            "failed": sum(record.metrics.get("failed", 0) for record in stages),
            **usage_metrics(meter.call_snapshot()),
        },
        attributes=attributes,
        artifacts=artifacts,
        error=error,
    )


def _interrupt_on_terminate(_signum: int, _frame: object) -> None:
    raise Terminated


@contextlib.contextmanager
def _terminate_as_interrupt() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.signal(signal.SIGTERM, _interrupt_on_terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextlib.contextmanager
def _ignore_interrupts() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.signal(number, signal.SIG_IGN) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
