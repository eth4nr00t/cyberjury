"""Durable JSON session storage shared by product domains."""

from __future__ import annotations

import fcntl
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
ATTEMPT_SCHEMA = "cyberjury.attempt/v1"
_SESSION_ID = re.compile(r"^[a-z][a-z0-9-]*-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^attempt-[0-9a-f]{32}$")
_LOCATOR_KEY = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATES = {"complete", "incomplete", "failed", "interrupted"}
_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"


class WorkspaceCorruptionError(RuntimeError):
    """Persisted session state cannot be trusted or resumed."""


class UnsupportedSessionFormatError(WorkspaceCorruptionError):
    """A session or attempt was written in a format this version cannot continue."""

    def __init__(self, session_id: str, detail: str) -> None:
        """Name the session, the incompatible part, and the way forward."""
        super().__init__(
            f"session {session_id} has an unsupported session format ({detail}), "
            "it was likely written by an older cyberjury version; start a new session with --fresh"
        )


def utc_now() -> str:
    """Return one stable second precision UTC timestamp."""
    return datetime.now(UTC).strftime(_TIMESTAMP)


def new_attempt_id() -> str:
    """Return one collision resistant invocation identity."""
    return f"attempt-{uuid.uuid4().hex}"


def new_session_id(kind: str) -> str:
    """Return one globally unique logical workflow identity."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*", kind):
        raise ValueError("session kind is invalid")
    return f"{kind}-{uuid.uuid4().hex}"


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


def write_json_atomic(path: str | Path, value: dict[str, object]) -> None:
    """Durably replace one JSON object with private file permissions."""
    target = Path(path)
    if not target.parent.is_dir() or target.parent.is_symlink() or target.is_symlink():
        raise ValueError("JSON artifact path is not a safe existing directory")
    _atomic_json(target, value)


def read_json_object(path: str | Path) -> dict[str, object]:
    """Read one strict JSON object without following an artifact symlink."""
    return _read_json(Path(path))


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

    def select_with_state(
        self,
        key: str,
        *,
        kind: str,
        reuse: bool,
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


class _JsonDirectory:
    """Immutable local JSON artifacts inside one workspace directory."""

    path: Path

    def write_json_once(self, name: str, value: dict[str, object]) -> None:
        """Create one immutable JSON file or verify its existing content."""
        path = self._local(name)
        if path.exists():
            if _read_json(path) != value:
                raise WorkspaceCorruptionError(f"{name} does not match the existing {self.path.name}")
            return
        _atomic_json(path, value)

    def read_json(self, name: str) -> dict[str, object]:
        """Read one local JSON file without allowing path traversal."""
        return _read_json(self._local(name))

    def _local(self, name: str) -> Path:
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError("workspace JSON name must be one local .json file")
        return self.path / name


@dataclass(frozen=True, kw_only=True)
class SessionWorkspace(_JsonDirectory):
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
            if data.get("schema") != SESSION_SCHEMA:
                raise UnsupportedSessionFormatError(session_id, "session.json schema")
            if set(data) != expected:
                raise WorkspaceCorruptionError("session identity has an invalid schema")
            if data["session_id"] != session_id or data["kind"] != kind:
                raise WorkspaceCorruptionError("session identity does not match the requested workflow")
            try:
                datetime.strptime(data["created_at"], _TIMESTAMP)
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

    def start_attempt(self, request: dict[str, object]) -> AttemptWorkspace:
        """Create one command attempt with its exact normalized request under the session lock."""
        session_lock = (self.path / "session.json").open("r", encoding="utf-8")
        try:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            session_lock.close()
            raise RuntimeError("another attempt is already running for this session") from exc
        attempts = self.path / "attempts"
        try:
            for path in attempts.glob(".attempt-*.*"):
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
            for path in sorted(attempts.glob("attempt-*")):
                AttemptWorkspace.open(path, session_id=self.session_id).interrupt_stale()
            attempt_id = new_attempt_id()
            temporary_path = Path(tempfile.mkdtemp(prefix=f".{attempt_id}.", dir=attempts))
        except BaseException:
            fcntl.flock(session_lock.fileno(), fcntl.LOCK_UN)
            session_lock.close()
            raise
        try:
            os.chmod(temporary_path, 0o700)
            _atomic_json(temporary_path / "request.json", request)
            attempt = AttemptWorkspace(
                path=temporary_path,
                session_id=self.session_id,
                attempt_id=attempt_id,
                started_at=utc_now(),
                _session_lock=session_lock,
            )
            attempt._write_state("running")
            path = attempts / attempt_id
            os.replace(temporary_path, path)
            directory = os.open(attempts, os.O_RDONLY)
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


@dataclass(kw_only=True)
class AttemptWorkspace(_JsonDirectory):
    """One invocation whose lifecycle state is one atomically replaced file."""

    path: Path
    session_id: str
    attempt_id: str
    started_at: str
    _session_lock: TextIO | None = field(default=None, repr=False)

    @classmethod
    def open(cls, path: str | Path, *, session_id: str) -> AttemptWorkspace:
        """Open one published attempt directory and validate its state file."""
        raw_path = Path(path)
        if raw_path.is_symlink() or not _ATTEMPT_ID.fullmatch(raw_path.name):
            raise WorkspaceCorruptionError("attempt path is invalid")
        attempt = cls(path=raw_path.resolve(), session_id=session_id, attempt_id=raw_path.name, started_at="")
        attempt.started_at = str(attempt.read_state()["started_at"])
        return attempt

    def read_state(self) -> dict[str, object]:
        """Return the validated attempt state."""
        path = self.path / "attempt.json"
        if not path.exists() and not path.is_symlink():
            raise UnsupportedSessionFormatError(self.session_id, f"{self.attempt_id} has no attempt.json")
        state = _read_json(path)
        fields = {"schema", "session_id", "attempt_id", "state", "started_at", "finished_at", "detail", "error"}
        if state.get("schema") != ATTEMPT_SCHEMA:
            raise UnsupportedSessionFormatError(self.session_id, f"{self.attempt_id} attempt.json schema")
        if set(state) != fields:
            raise WorkspaceCorruptionError("attempt state has an invalid schema")
        if state["session_id"] != self.session_id or state["attempt_id"] != self.attempt_id:
            raise WorkspaceCorruptionError("attempt state identity does not match its directory")
        if state["state"] not in {"running", *_TERMINAL_STATES}:
            raise WorkspaceCorruptionError("attempt state is invalid")
        try:
            datetime.strptime(state["started_at"], _TIMESTAMP)
        except (TypeError, ValueError) as exc:
            raise WorkspaceCorruptionError("attempt state has an invalid timestamp") from exc
        return state

    def finish(
        self,
        *,
        state: str,
        detail: dict[str, object],
        error: dict[str, str] | None = None,
    ) -> None:
        """Record one terminal state and release the session lock."""
        try:
            if state not in _TERMINAL_STATES:
                raise ValueError("attempt terminal state is invalid")
            if self.read_state()["state"] != "running":
                raise RuntimeError("attempt already reached a terminal state")
            self._write_state(state, detail=detail, error=error)
        finally:
            if self._session_lock is not None:
                fcntl.flock(self._session_lock.fileno(), fcntl.LOCK_UN)
                self._session_lock.close()
                self._session_lock = None

    def interrupt_stale(self) -> None:
        """Close an attempt a prior process left running; the caller holds the session lock."""
        if self.read_state()["state"] != "running":
            return
        started = datetime.strptime(self.started_at, _TIMESTAMP).replace(tzinfo=UTC)
        self._write_state(
            "interrupted",
            detail={
                "reason": "prior process ended without a terminal state",
                "duration_seconds": max(0.0, round((datetime.now(UTC) - started).total_seconds(), 3)),
            },
        )

    def _write_state(
        self,
        state: str,
        *,
        detail: dict[str, object] | None = None,
        error: dict[str, str] | None = None,
    ) -> None:
        _atomic_json(
            self.path / "attempt.json",
            {
                "schema": ATTEMPT_SCHEMA,
                "session_id": self.session_id,
                "attempt_id": self.attempt_id,
                "state": state,
                "started_at": self.started_at,
                "finished_at": None if state == "running" else utc_now(),
                "detail": detail or {},
                "error": error,
            },
        )
