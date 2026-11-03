"""Durable JSON storage of review sessions and their command attempts."""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from cyberjury.record import Record, is_attempt_id, parse_timestamp, render, utc_timestamp

SESSION_SCHEMA = "cyberjury.session/v1"
LOCATOR_SCHEMA = "cyberjury.locator/v1"
_SESSION_KIND = "review"
_SESSIONS_DIR = "reviews"
_SESSION_ID = re.compile(r"^review-\d{8}-\d{6}-[0-9a-f]{8}$")


class WorkspaceCorruptionError(RuntimeError):
    """Persisted session state cannot be trusted or resumed."""


class WorkspacePathError(RuntimeError):
    """A state or session directory is a symlink, not a plain directory, or open to group or other users."""


class SessionConflictError(RuntimeError):
    """The session cannot take this attempt until a --fresh start: its configuration differs or it no longer exists."""


class SessionBusyError(RuntimeError):
    """Another attempt is running in the session, so this one can start once it ends."""


def _new_id(kind: str) -> str:
    return f"{kind}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"


def new_attempt_id() -> str:
    """Return one time-ordered, collision-resistant invocation identity."""
    return _new_id("attempt")


def new_session_id() -> str:
    """Return one time-ordered, collision-resistant review session identity."""
    return _new_id(_SESSION_KIND)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _loads(value: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = item
        return result

    return json.loads(
        value,
        object_pairs_hook=unique_object,
        parse_constant=_reject_json_constant,
    )


def read_json_object(path: Path) -> dict[str, object]:
    """Read one strict JSON object without following a symlink."""
    if path.is_symlink():
        raise WorkspaceCorruptionError(f"{path.name} cannot be a symlink")
    try:
        value = _loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WorkspaceCorruptionError(f"could not read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkspaceCorruptionError(f"{path.name} must contain a JSON object")
    return value


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    """Durably replace one JSON object with private file permissions."""
    _atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_record(path: Path, record: Record) -> None:
    """Durably replace one record file with the text the CLI prints for it."""
    _atomic_text(path, render(record))


def read_record(path: str | Path) -> Record:
    """Read one record file without following a symlink."""
    try:
        return Record.from_dict(read_json_object(Path(path)))
    except ValueError as exc:
        raise WorkspaceCorruptionError(f"{Path(path).name} is not a valid record: {exc}") from exc


def _safe_directory(path: Path, *, label: str = "session path", private: bool = True) -> None:
    if path.is_symlink():
        raise WorkspacePathError(f"{label} cannot be a symlink: {path}")
    created = not path.exists()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise WorkspacePathError(f"{label} is not a plain directory: {path}")
    if created:
        path.chmod(0o700)
    elif private and path.stat().st_mode & 0o077:
        raise WorkspacePathError(f"{label} permissions are too broad: {path}")


def _state_directory(root: str | Path, *parts: str) -> Path:
    raw_root = Path(root).expanduser()
    _safe_directory(raw_root, label="state directory", private=False)
    current = raw_root.resolve()
    for part in parts:
        current /= part
        _safe_directory(current, label="state namespace")
    return current


@dataclass(frozen=True, kw_only=True)
class SessionLocator:
    """The map from one stable review intent key to its current unique session."""

    path: Path

    @classmethod
    def open(cls, root: str | Path) -> SessionLocator:
        """Open the atomic session locators of one state directory."""
        return cls(path=_state_directory(root, "locators", "reviews"))

    def select_or_create(self, key: str, *, reuse: bool) -> tuple[str, bool]:
        """Return the reused or newly published session and whether this call created it."""
        locator = self.path / f"{key}.json"
        directory = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX)
            if reuse and locator.exists():
                value = read_json_object(locator)
                expected = {"schema", "locator_key", "session_id"}
                if set(value) != expected or value["schema"] != LOCATOR_SCHEMA:
                    raise WorkspaceCorruptionError("session locator has an invalid schema")
                session_id = str(value["session_id"])
                if value["locator_key"] != key or not _SESSION_ID.fullmatch(session_id):
                    raise WorkspaceCorruptionError("session locator identity is invalid")
                return session_id, False
            session_id = new_session_id()
            write_json_atomic(
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


class _JsonDirectory:
    path: Path

    def write_json_once(self, name: str, value: dict[str, object]) -> None:
        path = self.path / name
        if path.exists():
            if read_json_object(path) != value:
                raise SessionConflictError(
                    f"{name} does not match the existing {self.path.name}, start again with --fresh"
                )
            return
        write_json_atomic(path, value)

    def read_json(self, name: str) -> dict[str, object]:
        return read_json_object(self.path / name)


@dataclass(frozen=True, kw_only=True)
class SessionWorkspace(_JsonDirectory):
    """One review session that may contain multiple command attempts."""

    session_id: str
    path: Path

    @classmethod
    def open_or_create(cls, root: str | Path, *, session_id: str) -> SessionWorkspace:
        """Open one matching session or create its immutable identity file."""
        path = _state_directory(root, _SESSIONS_DIR) / session_id
        _safe_directory(path)
        attempts = path / "attempts"
        _safe_directory(attempts)
        identity = path / "session.json"
        if identity.exists():
            data = read_json_object(identity)
            expected = {"schema", "session_id", "kind", "created_at"}
            if set(data) != expected or data["schema"] != SESSION_SCHEMA:
                raise WorkspaceCorruptionError("session identity has an invalid schema")
            if data["session_id"] != session_id or data["kind"] != _SESSION_KIND:
                raise WorkspaceCorruptionError("session identity does not match its session id or review kind")
            try:
                parse_timestamp(data["created_at"])
            except (TypeError, ValueError) as exc:
                raise WorkspaceCorruptionError("session identity has an invalid timestamp") from exc
        else:
            write_json_atomic(
                identity,
                {
                    "schema": SESSION_SCHEMA,
                    "session_id": session_id,
                    "kind": _SESSION_KIND,
                    "created_at": utc_timestamp(),
                },
            )
        return cls(session_id=session_id, path=path)

    @staticmethod
    def exists(root: str | Path, *, session_id: str) -> bool:
        """Report whether a session directory exists under the state directory, without creating anything."""
        path = Path(root).expanduser() / _SESSIONS_DIR / session_id
        return path.is_dir() and not path.is_symlink()

    def start_attempt(
        self,
        request: dict[str, object],
        *,
        attempt_id: str,
        started_at: str,
        attributes: Mapping[str, str | int | float | bool | None],
    ) -> AttemptWorkspace:
        """Create one command attempt with its exact normalized request under the session lock."""
        session_lock = (self.path / "session.json").open("r", encoding="utf-8")
        try:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            session_lock.close()
            raise SessionBusyError("another attempt is already running for this session") from exc
        attempts = self.path / "attempts"
        try:
            for path in attempts.glob(".attempt-*.*"):
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
            for path in sorted(attempts.glob("attempt-*")):
                AttemptWorkspace.open(path).interrupt_stale()
            temporary_path = Path(tempfile.mkdtemp(prefix=f".{attempt_id}.", dir=attempts))
        except BaseException:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_UN)
            session_lock.close()
            raise
        try:
            temporary_path.chmod(0o700)
            write_json_atomic(temporary_path / "request.json", request)
            attempt = AttemptWorkspace(path=temporary_path, attempt_id=attempt_id, _session_lock=session_lock)
            attempt._write(
                Record(
                    id=attempt_id,
                    status="running",
                    started_at=started_at,
                    duration_seconds=None,
                    attributes=dict(attributes),
                )
            )
            path = attempts / attempt_id
            temporary_path.replace(path)
            _fsync_directory(attempts)
            attempt.path = path
            return attempt
        except BaseException:
            shutil.rmtree(temporary_path, ignore_errors=True)
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_UN)
            session_lock.close()
            raise


@dataclass(kw_only=True)
class AttemptWorkspace(_JsonDirectory):
    """One invocation whose lifecycle state is its record, one atomically replaced file."""

    path: Path
    attempt_id: str
    _session_lock: TextIO | None = field(default=None, repr=False)

    @classmethod
    def open(cls, path: str | Path) -> AttemptWorkspace:
        """Open one published attempt directory."""
        raw_path = Path(path)
        if raw_path.is_symlink() or not is_attempt_id(raw_path.name):
            raise WorkspaceCorruptionError("attempt path is invalid")
        return cls(path=raw_path.resolve(), attempt_id=raw_path.name)

    def read_record(self) -> Record:
        """Return the attempt record after checking that its id matches the directory."""
        record = read_record(self.path / "record.json")
        if record.id != self.attempt_id:
            raise WorkspaceCorruptionError("attempt record identity does not match its directory")
        return record

    def write_stage(self, record: Record) -> None:
        """Write one stage record of this attempt."""
        write_record(self.path / "stages" / f"{record.id}.json", record)

    def finish(self, record: Record) -> None:
        """Record the terminal attempt record and release the session lock."""
        try:
            self._write(record)
        finally:
            if self._session_lock is not None:
                fcntl.flock(self._session_lock.fileno(), fcntl.LOCK_UN)
                self._session_lock.close()
                self._session_lock = None

    def interrupt_stale(self) -> None:
        """Close an attempt a prior process left running. The caller holds the session lock."""
        record = self.read_record()
        if record.status != "running":
            return
        started = parse_timestamp(record.started_at)
        self._write(
            Record(
                id=self.attempt_id,
                status="interrupted",
                started_at=record.started_at,
                duration_seconds=max(0.0, round((datetime.now(UTC) - started).total_seconds(), 3)),
                metrics=record.metrics,
                attributes={**record.attributes, "reason": "prior process ended without a terminal state"},
            )
        )

    def _write(self, record: Record) -> None:
        write_record(self.path / "record.json", record)
