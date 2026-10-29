"""Session storage tests cover attempt records, recovery, and safe paths."""

import fcntl
import json
import stat

import pytest

from cyberjury.record import Record, utc_timestamp
from cyberjury.workspace import (
    AttemptWorkspace,
    SessionBusyError,
    SessionLocator,
    SessionWorkspace,
    WorkspaceCorruptionError,
    new_attempt_id,
    read_json_object,
)


def _session(tmp_path, digit: str) -> SessionWorkspace:
    return SessionWorkspace.open_or_create(tmp_path, session_id="review-20260101-000000-" + digit * 8)


def _start(session: SessionWorkspace) -> AttemptWorkspace:
    return session.start_attempt(
        {"schema": "test.request/v1"}, attempt_id=new_attempt_id(), started_at=utc_timestamp(), attributes={}
    )


def _terminal(attempt: AttemptWorkspace) -> Record:
    return Record(id=attempt.attempt_id, status="ok", started_at=attempt.read_record().started_at, duration_seconds=1.0)


def _simulate_process_exit(attempt: AttemptWorkspace) -> None:
    assert attempt._session_lock is not None
    fcntl.flock(attempt._session_lock.fileno(), fcntl.LOCK_UN)
    attempt._session_lock.close()
    attempt._session_lock = None


def test_session_and_attempt_use_private_json_files_only(tmp_path):
    """A session holds only session.json, session/intent.json, attempts at 0700, and the attempt files are 0600."""
    session = _session(tmp_path, "a")
    session.write_json_once("session/intent.json", {"schema": "test.review/v1"})
    attempt = _start(session)

    assert session.path == tmp_path / "reviews" / ("review-20260101-000000-" + "a" * 8)
    assert {path.name for path in session.path.iterdir()} == {"session.json", "session", "attempts"}
    assert {path.name for path in attempt.path.iterdir()} == {"request.json", "record.json"}
    assert stat.S_IMODE(session.path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in attempt.path.iterdir())
    assert attempt.read_record().status == "running"
    attempt.finish(_terminal(attempt))


def test_a_second_attempt_cannot_start_while_one_is_running(tmp_path):
    """Starting an attempt while one runs raises already running, and finishing it allows the next start."""
    session = _session(tmp_path, "b")
    attempt = _start(session)

    with pytest.raises(SessionBusyError, match="already running"):
        _start(session)

    attempt.finish(_terminal(attempt))
    second = _start(session)
    second.finish(_terminal(second))


def test_reopening_session_marks_running_attempt_interrupted(tmp_path):
    """Reopening after the lock holder exits marks the old attempt interrupted with its duration set."""
    session = _session(tmp_path, "d")
    attempt = _start(session)
    _simulate_process_exit(attempt)

    reopened = _session(tmp_path, "d")
    next_attempt = _start(reopened)
    next_attempt.finish(_terminal(next_attempt))

    stale = attempt.read_record()
    assert stale.status == "interrupted"
    assert stale.attributes == {"reason": "prior process ended without a terminal state"}
    assert stale.duration_seconds is not None
    assert next_attempt.read_record().status == "ok"


def test_attempt_state_identity_must_match_its_directory(tmp_path):
    """A record.json whose id differs from its directory raises WorkspaceCorruptionError."""
    session = _session(tmp_path, "f")
    attempt = _start(session)
    attempt.finish(_terminal(attempt))
    path = attempt.path / "record.json"
    value = json.loads(path.read_text())
    value["id"] = "attempt-20260101-000000-00000000"
    path.write_text(json.dumps(value))

    with pytest.raises(WorkspaceCorruptionError, match="identity"):
        _start(session)


def test_locator_reuses_active_session_and_can_publish_a_new_one(tmp_path):
    """Reusing returns the same session without creating it, and not reusing publishes a new active session."""
    locator = SessionLocator.open(tmp_path)
    key = "3" * 64

    first, created = locator.select_with_state(key, reuse=True)
    reused, reused_created = locator.select_with_state(key, reuse=True)
    second, _ = locator.select_with_state(key, reuse=False)

    assert created is True
    assert reused_created is False
    assert reused == first
    assert second != first
    assert locator.select_with_state(key, reuse=True) == (second, False)


def test_locator_session_id_must_name_a_review_session(tmp_path):
    """A locator entry rewritten to a fetch- session id raises WorkspaceCorruptionError."""
    locator = SessionLocator.open(tmp_path)
    key = "c" * 64
    locator.select_with_state(key, reuse=True)
    path = locator.path / f"{key}.json"
    value = json.loads(path.read_text())
    value["session_id"] = "fetch-20260101-000000-" + "d" * 8
    path.write_text(json.dumps(value))

    with pytest.raises(WorkspaceCorruptionError, match="identity"):
        locator.select_with_state(key, reuse=True)


def test_existing_state_root_permissions_are_not_changed(tmp_path):
    """A pre-existing 0755 state directory keeps its mode while the created reviews namespace is 0700."""
    root = tmp_path / "shared"
    root.mkdir(mode=0o755)

    SessionWorkspace.open_or_create(root, session_id="review-20260101-000000-" + "4" * 8)

    assert stat.S_IMODE(root.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "reviews").stat().st_mode) == 0o700


def _symlinked_state_dir(tmp_path):
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


@pytest.mark.parametrize("layout", [_symlinked_state_dir, _symlinked_namespace])
def test_symlinked_state_directories_are_rejected(tmp_path, layout):
    """A state directory or reviews namespace that is a symlink to another directory raises a symlink ValueError."""
    with pytest.raises(ValueError, match="symlink"):
        SessionWorkspace.open_or_create(layout(tmp_path), session_id="review-20260101-000000-" + "5" * 8)


def test_json_reader_rejects_artifact_symlinks(tmp_path):
    """Reading through an outcome.json symlink raises WorkspaceCorruptionError."""
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "outcome.json"
    link.symlink_to(target)

    with pytest.raises(WorkspaceCorruptionError, match="symlink"):
        read_json_object(link)


def test_json_reader_rejects_duplicate_keys(tmp_path):
    """A file repeating the complete key raises WorkspaceCorruptionError for duplicate JSON key."""
    path = tmp_path / "outcome.json"
    path.write_text('{"complete":true,"complete":false}')

    with pytest.raises(WorkspaceCorruptionError, match="duplicate JSON key"):
        read_json_object(path)
