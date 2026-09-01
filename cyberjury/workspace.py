"""Durable JSON and JSONL session storage shared by product domains."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

SESSION_SCHEMA = "cyberjury.session/v1"
LOCATOR_SCHEMA = "cyberjury.session-locator/v1"
ATTEMPT_STATUS_SCHEMA = "cyberjury.attempt-status/v1"
EVENT_SCHEMA = "cyberjury.execution-event/v1"
_SESSION_ID = re.compile(r"^[a-z][a-z0-9-]*-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^attempt-[0-9a-f]{32}$")
_LOCATOR_KEY = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATES = {"complete", "incomplete", "failed", "interrupted"}


class WorkspaceCorruptionError(RuntimeError):
    """Persisted session state cannot be trusted or resumed."""


def utc_now() -> str:
    """Return one stable second precision UTC timestamp."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_attempt_id() -> str:
    """Return one collision resistant invocation identity."""
    return f"attempt-{uuid.uuid4().hex}"


def new_session_id(kind: str) -> str:
    """Return one globally unique logical workflow identity."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*", kind):
        raise ValueError("session kind is invalid")
    return f"{kind}-{uuid.uuid4().hex}"


def _elapsed_seconds(events: tuple[dict[str, object], ...]) -> float:
    if not events:
        return 0.0
    started = datetime.strptime(events[0]["recorded_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return max(0.0, round((datetime.now(UTC) - started).total_seconds(), 3))


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _loads(value: str) -> object:
    return json.loads(value, parse_constant=_reject_json_constant)


def _event_hash(value: dict[str, object]) -> str:
    material = {key: item for key, item in value.items() if key != "event_sha256"}
    return hashlib.sha256(_canonical_json(material).encode()).hexdigest()


def _object_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _attempt_terminal_state(event: dict[str, object]) -> str | None:
    operation = event.get("operation")
    status = event.get("status")
    if not isinstance(operation, str) or not operation.startswith("attempt."):
        return None
    state = operation.removeprefix("attempt.")
    if state not in _TERMINAL_STATES:
        return None
    if status != state:
        raise WorkspaceCorruptionError("attempt terminal event operation and status disagree")
    return state


def _read_json(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise WorkspaceCorruptionError(f"{path.name} cannot be a symlink")
    try:
        value = _loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WorkspaceCorruptionError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkspaceCorruptionError(f"{path.name} must contain a JSON object")
    return value


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _safe_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"session path cannot be a symlink: {path}")
    created = not path.exists()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"session path is not a safe directory: {path}")
    if created:
        os.chmod(path, 0o700)
    elif path.stat().st_mode & 0o077:
        raise ValueError(f"session path permissions are too broad: {path}")


def _state_directory(root: str | Path, *parts: str) -> Path:
    raw_root = Path(root).expanduser()
    if raw_root.is_symlink():
        raise ValueError("state root cannot be a symlink")
    root_created = not raw_root.exists()
    raw_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not raw_root.is_dir() or raw_root.is_symlink():
        raise ValueError("state root is not a safe directory")
    if root_created:
        os.chmod(raw_root, 0o700)
    current = raw_root.resolve()
    for part in parts:
        if not re.fullmatch(r"[a-z][a-z0-9-]*", part):
            raise ValueError("state directory component is invalid")
        current /= part
        _safe_directory(current)
    return current


@dataclass(frozen=True, kw_only=True)
class SessionLocator:
    """Map one stable workflow key to its current unique session."""

    path: Path

    @classmethod
    def open(cls, root: str | Path, *, namespace: str) -> SessionLocator:
        """Open one namespace of atomic session locators."""
        return cls(path=_state_directory(root, "locators", namespace))

    def select(self, key: str, *, kind: str, reuse: bool) -> str:
        """Return the active session or atomically publish a new one."""
        session_id, _created = self.select_with_state(key, kind=kind, reuse=reuse)
        return session_id

    def select_with_state(
        self,
        key: str,
        *,
        kind: str,
        reuse: bool,
        create_if_missing: bool = True,
    ) -> tuple[str, bool]:
        """Return the selected session and whether this call published it."""
        if not _LOCATOR_KEY.fullmatch(key):
            raise ValueError("session locator key is invalid")
        locator = self.path / f"{key}.json"
        directory = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX)
            if reuse and locator.exists():
                value = _read_json(locator)
                expected = {"schema", "locator_key", "session_id"}
                if set(value) != expected or value["schema"] != LOCATOR_SCHEMA:
                    raise WorkspaceCorruptionError("session locator has an invalid schema")
                if (
                    value["locator_key"] != key
                    or not _SESSION_ID.fullmatch(str(value["session_id"]))
                    or not str(value["session_id"]).startswith(f"{kind}-")
                ):
                    raise WorkspaceCorruptionError("session locator identity is invalid")
                return str(value["session_id"]), False
            if reuse and not create_if_missing:
                raise ValueError("no active session exists for this locator")
            session_id = new_session_id(kind)
            _atomic_json(
                locator,
                {
                    "schema": LOCATOR_SCHEMA,
                    "locator_key": key,
                    "session_id": session_id,
                },
            )
            return session_id, True
        finally:
            fcntl.flock(directory, fcntl.LOCK_UN)
            os.close(directory)


@dataclass(frozen=True, kw_only=True)
class SessionWorkspace:
    """One logical workflow that may contain multiple command attempts."""

    root: Path
    namespace: str
    session_id: str
    path: Path

    @classmethod
    def open_or_create(
        cls,
        root: str | Path,
        *,
        namespace: str,
        session_id: str,
        kind: str,
    ) -> SessionWorkspace:
        """Open one matching session or create its immutable identity file."""
        if not re.fullmatch(r"[a-z][a-z0-9-]*", namespace):
            raise ValueError("workspace namespace is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", kind):
            raise ValueError("session kind is invalid")
        if not _SESSION_ID.fullmatch(session_id):
            raise ValueError("session id is invalid")
        if not session_id.startswith(f"{kind}-"):
            raise ValueError("session id does not match its kind")
        state_root = _state_directory(root)
        namespace_path = _state_directory(state_root, namespace)
        path = namespace_path / session_id
        _safe_directory(path)
        attempts = path / "attempts"
        _safe_directory(attempts)
        identity = path / "session.json"
        if identity.exists():
            data = _read_json(identity)
            expected = {"schema", "session_id", "kind", "created_at"}
            if set(data) != expected or data["schema"] != SESSION_SCHEMA:
                raise WorkspaceCorruptionError("session identity has an invalid schema")
            if data["session_id"] != session_id or data["kind"] != kind:
                raise WorkspaceCorruptionError("session identity does not match the requested workflow")
            try:
                datetime.strptime(data["created_at"], "%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError) as exc:
                raise WorkspaceCorruptionError("session identity has an invalid timestamp") from exc
        else:
            _atomic_json(
                identity,
                {
                    "schema": SESSION_SCHEMA,
                    "session_id": session_id,
                    "kind": kind,
                    "created_at": utc_now(),
                },
            )
        return cls(root=state_root, namespace=namespace, session_id=session_id, path=path)

    def write_json_once(self, name: str, value: dict[str, object]) -> None:
        """Create one immutable JSON file or verify its existing content."""
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError("session JSON name must be one local .json file")
        path = self.path / name
        if path.exists():
            if _read_json(path) != value:
                raise WorkspaceCorruptionError(f"{name} does not match the existing session")
            return
        _atomic_json(path, value)

    def read_json(self, name: str) -> dict[str, object]:
        """Read one local JSON file without allowing path traversal."""
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError("session JSON name must be one local .json file")
        return _read_json(self.path / name)

    def start_attempt(self, request: dict[str, object]) -> AttemptWorkspace:
        """Create one command attempt with its exact normalized request."""
        if not isinstance(request, dict):
            raise ValueError("attempt request must be a JSON object")
        session_lock = (self.path / "session.json").open("r", encoding="utf-8")
        try:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            session_lock.close()
            raise RuntimeError("another attempt is already running for this session") from exc
        try:
            self._clean_unpublished_attempts()
            self.interrupt_running_attempts()
        except BaseException:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_UN)
            session_lock.close()
            raise
        attempt_id = new_attempt_id()
        path = self.path / "attempts" / attempt_id
        temporary_path = Path(
            tempfile.mkdtemp(
                prefix=f".{attempt_id}.",
                dir=self.path / "attempts",
            )
        )
        try:
            os.chmod(temporary_path, 0o700)
            _atomic_json(temporary_path / "request.json", request)
            events_path = temporary_path / "events.jsonl"
            with events_path.open("x", encoding="utf-8") as stream:
                os.chmod(events_path, 0o600)
                stream.flush()
                os.fsync(stream.fileno())
            attempt = AttemptWorkspace(
                path=temporary_path,
                session_id=self.session_id,
                attempt_id=attempt_id,
                _session_lock=session_lock,
            )
            attempt._write_status(state="running", sequence=0, event_sha256="", journal_size=0)
            attempt.record(
                operation="attempt.started",
                status="running",
                payload_schema="cyberjury.attempt-started/v1",
                payload={"request_content_sha256": _object_hash(request)},
            )
            os.replace(temporary_path, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            attempt.path = path
            return attempt
        except BaseException:
            shutil.rmtree(temporary_path, ignore_errors=True)
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_UN)
            session_lock.close()
            raise

    def _clean_unpublished_attempts(self) -> None:
        """Remove unpublished initialization directories left by a dead process."""
        for path in (self.path / "attempts").glob(".attempt-*.*"):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)

    def interrupt_running_attempts(self) -> None:
        """Close attempts left running by a prior process before starting new work."""
        for attempt_path in sorted((self.path / "attempts").glob("attempt-*")):
            status_path = attempt_path / "status.json"
            if not status_path.is_file():
                raise WorkspaceCorruptionError(f"{attempt_path.name} has no status projection")
            attempt = AttemptWorkspace.open(
                attempt_path,
                session_id=self.session_id,
                repair_projection=True,
            )
            if _read_json(status_path).get("state") != "running":
                continue
            duration = _elapsed_seconds(attempt.read_events())
            attempt.finish(
                state="interrupted",
                payload_schema="cyberjury.attempt-interrupted/v1",
                payload={
                    "reason": "prior process ended without a terminal event",
                    "duration_seconds": duration,
                },
            )


@dataclass(kw_only=True)
class AttemptWorkspace:
    """One invocation with a locked hash chained event journal."""

    path: Path
    session_id: str
    attempt_id: str
    _session_lock: TextIO | None = field(default=None, repr=False)

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        session_id: str,
        repair_projection: bool = False,
    ) -> AttemptWorkspace:
        """Open and validate one existing attempt directory."""
        raw_path = Path(path)
        if raw_path.is_symlink():
            raise WorkspaceCorruptionError("attempt path is invalid")
        resolved = raw_path.resolve()
        if not _ATTEMPT_ID.fullmatch(resolved.name):
            raise WorkspaceCorruptionError("attempt path is invalid")
        attempt = cls(path=resolved, session_id=session_id, attempt_id=resolved.name)
        events_path = attempt.path / "events.jsonl"
        if events_path.is_symlink():
            raise WorkspaceCorruptionError("attempt journal cannot be a symlink")
        try:
            mode = "r+" if repair_projection else "r"
            with events_path.open(mode, encoding="utf-8") as stream:
                lock = fcntl.LOCK_EX if repair_projection else fcntl.LOCK_SH
                fcntl.flock(stream.fileno(), lock)
                try:
                    status = _read_json(attempt.path / "status.json")
                    attempt._validate_status_shape(status)
                    events = attempt._read_events(
                        stream,
                        recover_from=status if repair_projection else None,
                    )
                    attempt._validate_request_receipt(events)
                    attempt._validate_state(events, repair_projection=repair_projection)
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise WorkspaceCorruptionError(f"cannot read attempt journal: {exc}") from exc
        return attempt

    def record(
        self,
        *,
        operation: str,
        status: str,
        payload_schema: str,
        payload: dict[str, object],
        error: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Append one strict event and atomically advance attempt status."""
        if not operation or status not in {"running", "complete", "incomplete", "failed", "interrupted"}:
            raise ValueError("attempt event operation or status is invalid")
        if not payload_schema or not isinstance(payload, dict):
            raise ValueError("attempt event payload needs a schema and object data")
        if error is not None and set(error) != {"code", "type", "message"}:
            raise ValueError("attempt event error has an invalid shape")
        events_path = self.path / "events.jsonl"
        with events_path.open("a+", encoding="utf-8") as stream:
            os.chmod(events_path, 0o600)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                tail = _read_json(self.path / "status.json")
                self._validate_status_shape(tail)
                if tail["state"] in _TERMINAL_STATES:
                    raise RuntimeError("cannot append to a terminal attempt")
                stream.seek(0, os.SEEK_END)
                if stream.tell() != tail["journal_size"]:
                    raise WorkspaceCorruptionError("attempt status does not identify the journal tail")
                previous = tail["last_event_sha256"]
                event = {
                    "schema": EVENT_SCHEMA,
                    "session_id": self.session_id,
                    "attempt_id": self.attempt_id,
                    "sequence": tail["last_sequence"] + 1,
                    "previous_event_sha256": previous,
                    "recorded_at": utc_now(),
                    "operation": operation,
                    "status": status,
                    "payload": {"schema": payload_schema, "data": payload},
                    "error": error,
                    "event_sha256": "",
                }
                event["event_sha256"] = _event_hash(event)
                stream.write(_canonical_json(event) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                journal_size = os.fstat(stream.fileno()).st_size
                state = status if status in _TERMINAL_STATES and operation.startswith("attempt.") else "running"
                self._write_status(
                    state=state,
                    sequence=event["sequence"],
                    event_sha256=event["event_sha256"],
                    journal_size=journal_size,
                )
                return event
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def finish(
        self,
        *,
        state: str,
        payload_schema: str,
        payload: dict[str, object],
        error: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Append one terminal attempt event."""
        if state not in _TERMINAL_STATES:
            raise ValueError("attempt terminal state is invalid")
        try:
            self.validate()
            return self.record(
                operation=f"attempt.{state}",
                status=state,
                payload_schema=payload_schema,
                payload=payload,
                error=error,
            )
        finally:
            if self._session_lock is not None:
                fcntl.flock(self._session_lock.fileno(), fcntl.LOCK_UN)
                self._session_lock.close()
                self._session_lock = None

    def validate(self) -> None:
        """Validate the journal chain and its atomic status projection."""
        events_path = self.path / "events.jsonl"
        try:
            with events_path.open("r", encoding="utf-8") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
                try:
                    events = self._read_events(stream)
                    self._validate_request_receipt(events)
                    self._validate_state(events)
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise WorkspaceCorruptionError(f"cannot read attempt journal: {exc}") from exc

    def read_events(self) -> tuple[dict[str, object], ...]:
        """Return a fully validated immutable journal snapshot."""
        events_path = self.path / "events.jsonl"
        with events_path.open("r", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            try:
                events = self._read_events(stream)
                self._validate_request_receipt(events)
                self._validate_state(events)
                return tuple(events)
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def read_request(self) -> dict[str, object]:
        """Return the immutable request after verifying its journal receipt."""
        self.read_events()
        return _read_json(self.path / "request.json")

    def _validate_request_receipt(self, events: list[dict[str, object]]) -> None:
        """Bind the immutable request file to the first journal event."""
        if not events:
            raise WorkspaceCorruptionError("attempt journal has no start event")
        started = events[0]
        payload = started["payload"]
        if (
            started["operation"] != "attempt.started"
            or started["status"] != "running"
            or payload["schema"] != "cyberjury.attempt-started/v1"
            or set(payload["data"]) != {"request_content_sha256"}
        ):
            raise WorkspaceCorruptionError("attempt start event has an invalid schema")
        request = _read_json(self.path / "request.json")
        if payload["data"]["request_content_sha256"] != _object_hash(request):
            raise WorkspaceCorruptionError("attempt request does not match its journal receipt")

    def _validate_state(
        self,
        events: list[dict[str, object]],
        *,
        repair_projection: bool = False,
    ) -> None:
        """Check the atomic status projection against a locked journal snapshot."""
        status = _read_json(self.path / "status.json")
        self._validate_status_shape(status)
        last_sequence = events[-1]["sequence"] if events else 0
        last_hash = events[-1]["event_sha256"] if events else ""
        journal_size = (self.path / "events.jsonl").stat().st_size
        if status["attempt_id"] != self.attempt_id:
            raise WorkspaceCorruptionError("attempt status identity does not match its directory")
        expected_state = _attempt_terminal_state(events[-1]) if events else None
        expected_state = expected_state or "running"
        projection_matches = (
            status["last_sequence"] == last_sequence
            and status["last_event_sha256"] == last_hash
            and status["journal_size"] == journal_size
            and status["state"] == expected_state
        )
        if projection_matches:
            return
        if repair_projection and status["state"] == "running" and self._projection_is_journal_prefix(status, events):
            self._write_status(
                state=expected_state,
                sequence=last_sequence,
                event_sha256=last_hash,
                journal_size=journal_size,
            )
            return
        if (
            status["last_sequence"] == last_sequence
            and status["last_event_sha256"] == last_hash
            and status["journal_size"] == journal_size
        ):
            raise WorkspaceCorruptionError("attempt status state does not match its event journal")
        raise WorkspaceCorruptionError("attempt status does not match its event journal")

    def _validate_status_shape(self, status: dict[str, object]) -> None:
        fields = {"schema", "attempt_id", "state", "last_sequence", "last_event_sha256", "journal_size"}
        if set(status) != fields or status["schema"] != ATTEMPT_STATUS_SCHEMA:
            raise WorkspaceCorruptionError("attempt status has an invalid schema")
        if status["attempt_id"] != self.attempt_id:
            raise WorkspaceCorruptionError("attempt status identity does not match its directory")
        if (
            status["state"] not in {"running", *_TERMINAL_STATES}
            or isinstance(status["last_sequence"], bool)
            or not isinstance(status["last_sequence"], int)
            or status["last_sequence"] < 0
            or not isinstance(status["last_event_sha256"], str)
            or isinstance(status["journal_size"], bool)
            or not isinstance(status["journal_size"], int)
            or status["journal_size"] < 0
        ):
            raise WorkspaceCorruptionError("attempt status values are invalid")

    @staticmethod
    def _projection_is_journal_prefix(status: dict[str, object], events: list[dict[str, object]]) -> bool:
        sequence = status["last_sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0 or sequence > len(events):
            return False
        expected_hash = "" if sequence == 0 else events[sequence - 1]["event_sha256"]
        expected_size = sum(len((_canonical_json(event) + "\n").encode()) for event in events[:sequence])
        return status["last_event_sha256"] == expected_hash and status["journal_size"] == expected_size

    def _read_events(
        self,
        stream,
        *,
        recover_from: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        stream.seek(0)
        events = []
        previous = ""
        while True:
            offset = stream.tell()
            line = stream.readline()
            if not line:
                break
            index = len(events) + 1
            if events and _attempt_terminal_state(events[-1]) is not None:
                raise WorkspaceCorruptionError(f"attempt journal line {index} follows a terminal event")
            try:
                event = _loads(line)
            except ValueError as exc:
                if (
                    recover_from is not None
                    and not stream.read()
                    and self._projection_is_journal_prefix(recover_from, events)
                ):
                    stream.seek(offset)
                    stream.truncate()
                    stream.flush()
                    os.fsync(stream.fileno())
                    break
                raise WorkspaceCorruptionError(f"attempt journal line {index} is malformed") from exc
            fields = {
                "schema",
                "session_id",
                "attempt_id",
                "sequence",
                "previous_event_sha256",
                "recorded_at",
                "operation",
                "status",
                "payload",
                "error",
                "event_sha256",
            }
            if not isinstance(event, dict) or set(event) != fields or event["schema"] != EVENT_SCHEMA:
                raise WorkspaceCorruptionError(f"attempt journal line {index} has an invalid schema")
            if event["session_id"] != self.session_id or event["attempt_id"] != self.attempt_id:
                raise WorkspaceCorruptionError(f"attempt journal line {index} has the wrong identity")
            try:
                datetime.strptime(event["recorded_at"], "%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError) as exc:
                raise WorkspaceCorruptionError(f"attempt journal line {index} has an invalid timestamp") from exc
            if (
                not isinstance(event["operation"], str)
                or not event["operation"]
                or event["status"] not in {"running", "complete", "incomplete", "failed", "interrupted"}
                or isinstance(event["sequence"], bool)
                or not isinstance(event["sequence"], int)
                or not isinstance(event["previous_event_sha256"], str)
                or not isinstance(event["event_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", event["event_sha256"])
            ):
                raise WorkspaceCorruptionError(f"attempt journal line {index} has invalid operation state")
            payload = event["payload"]
            if (
                not isinstance(payload, dict)
                or set(payload) != {"schema", "data"}
                or not isinstance(payload["schema"], str)
                or not payload["schema"]
                or not isinstance(payload["data"], dict)
            ):
                raise WorkspaceCorruptionError(f"attempt journal line {index} has an invalid payload")
            error = event["error"]
            if error is not None and (
                not isinstance(error, dict)
                or set(error) != {"code", "type", "message"}
                or not all(isinstance(error[field], str) for field in error)
            ):
                raise WorkspaceCorruptionError(f"attempt journal line {index} has an invalid error")
            if event["sequence"] != index or event["previous_event_sha256"] != previous:
                raise WorkspaceCorruptionError(f"attempt journal line {index} breaks the sequence")
            if event["event_sha256"] != _event_hash(event):
                raise WorkspaceCorruptionError(f"attempt journal line {index} has an invalid hash")
            _attempt_terminal_state(event)
            previous = event["event_sha256"]
            events.append(event)
        return events

    def _write_status(
        self,
        *,
        state: str,
        sequence: object,
        event_sha256: object,
        journal_size: object,
    ) -> None:
        _atomic_json(
            self.path / "status.json",
            {
                "schema": ATTEMPT_STATUS_SCHEMA,
                "attempt_id": self.attempt_id,
                "state": state,
                "last_sequence": sequence,
                "last_event_sha256": event_sha256,
                "journal_size": journal_size,
            },
        )
