"""Generic session storage tests cover attempt records, recovery, and safe paths."""

import fcntl
import json
import stat

import pytest

from cyberjury.record import Record, RecordError
from cyberjury.workspace import (
    AttemptWorkspace,
    SessionConflictError,
    SessionLocator,
    SessionWorkspace,
    WorkspaceCorruptionError,
    read_json_object,
    write_json_atomic,
)


def _session(tmp_path, digit: str) -> SessionWorkspace:
    return SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-20260101-000000-" + digit * 8,
        kind="review",
    )


def _terminal(attempt: AttemptWorkspace, status: str = "ok", error: RecordError | None = None) -> Record:
    return Record(
        id=attempt.attempt_id, status=status, started_at=attempt.started_at, duration_seconds=1.0, error=error
    )


def _simulate_process_exit(attempt: AttemptWorkspace) -> None:
    assert attempt._session_lock is not None
    fcntl.flock(attempt._session_lock.fileno(), fcntl.LOCK_UN)
    attempt._session_lock.close()
    attempt._session_lock = None


def test_session_and_attempt_use_private_json_files_only(tmp_path):
    """A session holds only session.json, session/intent.json, attempts at 0700, and the attempt files are 0600."""
    session = _session(tmp_path, "a")
    session.write_json_once("session/intent.json", {"schema": "test.review/v1"})
    attempt = session.start_attempt({"schema": "test.request/v1"})

    assert session.path == tmp_path / "reviews" / ("review-20260101-000000-" + "a" * 8)
    assert {path.name for path in session.path.iterdir()} == {"session.json", "session", "attempts"}
    assert {path.name for path in attempt.path.iterdir()} == {"request.json", "record.json"}
    assert stat.S_IMODE(session.path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in attempt.path.iterdir())
    assert attempt.read_record().status == "running"


def test_a_second_attempt_cannot_start_while_one_is_running(tmp_path):
    """Starting an attempt while one runs raises already running, and finishing it allows the next start."""
    session = _session(tmp_path, "b")
    attempt = session.start_attempt({"schema": "test.request/v1"})

    with pytest.raises(SessionConflictError, match="already running"):
        session.start_attempt({"schema": "test.request/v1"})

    attempt.finish(_terminal(attempt))
    session.start_attempt({"schema": "test.request/v1"})


def test_reopening_session_marks_running_attempt_interrupted(tmp_path):
    """Reopening after the lock holder exits marks the old attempt interrupted with its duration set."""
    session = _session(tmp_path, "d")
    attempt = session.start_attempt({"schema": "test.request/v1"})
    _simulate_process_exit(attempt)

    reopened = _session(tmp_path, "d")
    next_attempt = reopened.start_attempt({"schema": "test.request/v1"})
    next_attempt.finish(_terminal(next_attempt))

    stale = attempt.read_record()
    assert stale.status == "interrupted"
    assert stale.attributes == {"reason": "prior process ended without a terminal state"}
    assert stale.duration_seconds is not None
    assert next_attempt.read_record().status == "ok"


def test_terminal_attempt_cannot_finish_again(tmp_path):
    """Finishing a failed attempt again raises terminal state and leaves the stored state failed."""
    attempt = _session(tmp_path, "e").start_attempt({"schema": "test.request/v1"})
    attempt.finish(_terminal(attempt, "failed", RecordError(code="internal", message="m")))

    with pytest.raises(RuntimeError, match="terminal state"):
        attempt.finish(_terminal(attempt))
    assert attempt.read_record().status == "failed"


def test_attempt_state_identity_must_match_its_directory(tmp_path):
    """A record.json whose id differs from its directory raises WorkspaceCorruptionError."""
    session = _session(tmp_path, "f")
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(_terminal(attempt))
    path = attempt.path / "record.json"
    value = json.loads(path.read_text())
    value["id"] = "attempt-20260101-000000-00000000"
    path.write_text(json.dumps(value))

    with pytest.raises(WorkspaceCorruptionError, match="identity"):
        session.start_attempt({"schema": "test.request/v1"})


def test_locator_reuses_active_session_and_can_publish_a_new_one(tmp_path):
    """Reusing returns the same session without creating it, and not reusing publishes a new active session."""
    locator = SessionLocator.open(tmp_path, namespace="reviews")
    key = "3" * 64

    first, created = locator.select_with_state(key, kind="review", reuse=True)
    reused, reused_created = locator.select_with_state(key, kind="review", reuse=True)
    second, _ = locator.select_with_state(key, kind="review", reuse=False)

    assert created is True
    assert reused_created is False
    assert reused == first
    assert second != first
    assert locator.select_with_state(key, kind="review", reuse=True) == (second, False)


def test_locator_session_id_must_match_requested_kind(tmp_path):
    """A locator entry rewritten to a fetch- session id raises WorkspaceCorruptionError for a review."""
    locator = SessionLocator.open(tmp_path, namespace="reviews")
    key = "c" * 64
    locator.select_with_state(key, kind="review", reuse=True)
    path = locator.path / f"{key}.json"
    value = json.loads(path.read_text())
    value["session_id"] = "fetch-20260101-000000-" + "d" * 8
    path.write_text(json.dumps(value))

    with pytest.raises(WorkspaceCorruptionError, match="identity"):
        locator.select_with_state(key, kind="review", reuse=True)


def test_existing_state_root_permissions_are_not_changed(tmp_path):
    """A pre-existing 0755 state root keeps its mode while the created reviews namespace is 0700."""
    root = tmp_path / "shared"
    root.mkdir(mode=0o755)

    SessionWorkspace.open_or_create(
        root,
        namespace="reviews",
        session_id="review-20260101-000000-" + "4" * 8,
        kind="review",
    )

    assert stat.S_IMODE(root.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "reviews").stat().st_mode) == 0o700


def _symlinked_state_root(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    return link


def _symlinked_namespace(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "reviews").symlink_to(elsewhere, target_is_directory=True)
    return root


@pytest.mark.parametrize("layout", [_symlinked_state_root, _symlinked_namespace])
def test_symlinked_state_directories_are_rejected(tmp_path, layout):
    """A state root or reviews namespace that is a symlink to another directory raises ValueError naming symlink."""
    with pytest.raises(ValueError, match="symlink"):
        SessionWorkspace.open_or_create(
            layout(tmp_path),
            namespace="reviews",
            session_id="review-20260101-000000-" + "5" * 8,
            kind="review",
        )


def test_session_rejects_a_traversal_session_id(tmp_path):
    """A review-../escape session id raises ValueError naming the session id."""
    with pytest.raises(ValueError, match="session id"):
        SessionWorkspace.open_or_create(
            tmp_path,
            namespace="reviews",
            session_id="review-../escape",
            kind="review",
        )


def test_public_atomic_json_round_trips_with_private_permissions(tmp_path):
    """Two atomic writes leave the second value readable in a file with mode 0600."""
    path = tmp_path / "outcome.json"

    write_json_atomic(path, {"complete": True})
    write_json_atomic(path, {"complete": False})

    assert read_json_object(path) == {"complete": False}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_public_json_helpers_reject_artifact_symlinks(tmp_path):
    """Writing via an outcome.json symlink raises ValueError, and reading it raises WorkspaceCorruptionError."""
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "outcome.json"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="safe existing directory"):
        write_json_atomic(link, {"complete": True})
    with pytest.raises(WorkspaceCorruptionError, match="symlink"):
        read_json_object(link)


def test_public_json_reader_rejects_duplicate_keys(tmp_path):
    """A file repeating the complete key raises WorkspaceCorruptionError for duplicate JSON key."""
    path = tmp_path / "outcome.json"
    path.write_text('{"complete":true,"complete":false}')

    with pytest.raises(WorkspaceCorruptionError, match="duplicate JSON key"):
        read_json_object(path)
