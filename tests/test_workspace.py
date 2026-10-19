"""Generic session storage tests cover attempt state, recovery, and safe paths."""

import fcntl
import json
import stat

import pytest

from cyberjury.workspace import (
    AttemptWorkspace,
    SessionLocator,
    SessionWorkspace,
    UnsupportedSessionFormatError,
    WorkspaceCorruptionError,
    read_json_object,
    write_json_atomic,
)


def _session(tmp_path, digit: str) -> SessionWorkspace:
    return SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + digit * 32,
        kind="review",
    )


def _simulate_process_exit(attempt: AttemptWorkspace) -> None:
    assert attempt._session_lock is not None
    fcntl.flock(attempt._session_lock.fileno(), fcntl.LOCK_UN)
    attempt._session_lock.close()
    attempt._session_lock = None


def test_session_and_attempt_use_private_json_files_only(tmp_path):
    """A session holds only session.json, review.json, attempts at 0700, and the attempt files are 0600."""
    session = _session(tmp_path, "a")
    session.write_json_once("review.json", {"schema": "test.review/v1"})
    attempt = session.start_attempt({"schema": "test.request/v1"})

    assert session.path == tmp_path / "reviews" / ("review-" + "a" * 32)
    assert {path.name for path in session.path.iterdir()} == {"session.json", "review.json", "attempts"}
    assert {path.name for path in attempt.path.iterdir()} == {"request.json", "attempt.json"}
    assert stat.S_IMODE(session.path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in attempt.path.iterdir())
    assert attempt.read_state()["state"] == "running"


def test_a_second_attempt_cannot_start_while_one_is_running(tmp_path):
    """Starting an attempt while one runs raises already running, and finishing it allows the next start."""
    session = _session(tmp_path, "b")
    attempt = session.start_attempt({"schema": "test.request/v1"})

    with pytest.raises(RuntimeError, match="already running"):
        session.start_attempt({"schema": "test.request/v1"})

    attempt.finish(state="complete", detail={"exit_code": 0})
    session.start_attempt({"schema": "test.request/v1"})


def test_reopening_session_marks_running_attempt_interrupted(tmp_path):
    """Reopening after the lock holder exits marks the old attempt interrupted with finished_at set."""
    session = _session(tmp_path, "d")
    attempt = session.start_attempt({"schema": "test.request/v1"})
    _simulate_process_exit(attempt)

    reopened = _session(tmp_path, "d")
    next_attempt = reopened.start_attempt({"schema": "test.request/v1"})
    next_attempt.finish(state="complete", detail={"exit_code": 0})

    state = json.loads((attempt.path / "attempt.json").read_text())
    assert state["state"] == "interrupted"
    assert state["finished_at"] is not None
    assert json.loads((next_attempt.path / "attempt.json").read_text())["detail"] == {"exit_code": 0}


def test_terminal_attempt_cannot_finish_again(tmp_path):
    """Finishing a failed attempt again raises terminal state and leaves the stored state failed."""
    attempt = _session(tmp_path, "e").start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="failed", detail={}, error={"code": "c", "type": "t", "message": "m"})

    with pytest.raises(RuntimeError, match="terminal state"):
        attempt.finish(state="complete", detail={})
    assert attempt.read_state()["state"] == "failed"


def test_attempt_state_identity_must_match_its_directory(tmp_path):
    """An attempt.json whose attempt_id differs from its directory raises WorkspaceCorruptionError."""
    session = _session(tmp_path, "f")
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="complete", detail={})
    path = attempt.path / "attempt.json"
    value = json.loads(path.read_text())
    value["attempt_id"] = "attempt-" + "0" * 32
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
    value["session_id"] = "fetch-" + "d" * 32
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
        session_id="review-" + "4" * 32,
        kind="review",
    )

    assert stat.S_IMODE(root.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "reviews").stat().st_mode) == 0o700


def test_namespace_symlink_is_rejected(tmp_path):
    """A reviews namespace that is a symlink to another directory raises ValueError naming symlink."""
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "reviews").symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        SessionWorkspace.open_or_create(
            root,
            namespace="reviews",
            session_id="review-" + "5" * 32,
            kind="review",
        )


def test_session_rejects_traversal_and_symlink_roots(tmp_path):
    """A review-../escape session id and a state root that is a symlink each raise ValueError."""
    with pytest.raises(ValueError, match="session id"):
        SessionWorkspace.open_or_create(
            tmp_path,
            namespace="reviews",
            session_id="review-../escape",
            kind="review",
        )

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        SessionWorkspace.open_or_create(
            link,
            namespace="reviews",
            session_id="review-" + "f" * 32,
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


def _older_attempt_layout(session):
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="complete", detail={})
    (attempt.path / "attempt.json").unlink()
    (attempt.path / "status.json").write_text(json.dumps({"schema": "cyberjury.attempt-status/v1"}))


def _older_attempt_schema(session):
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="complete", detail={})
    path = attempt.path / "attempt.json"
    path.write_text(json.dumps(json.loads(path.read_text()) | {"schema": "cyberjury.attempt/v0"}))


def _older_session_schema(session):
    path = session.path / "session.json"
    path.write_text(json.dumps(json.loads(path.read_text()) | {"schema": "cyberjury.session/v0"}))


@pytest.mark.parametrize("age", [_older_attempt_layout, _older_attempt_schema, _older_session_schema])
def test_an_older_session_format_is_reported_as_unsupported(tmp_path, age):
    """A legacy status.json layout or v0 attempt or session schema raises an error suggesting --fresh."""
    session = _session(tmp_path, "7")
    age(session)

    with pytest.raises(UnsupportedSessionFormatError, match=r"unsupported session format.*--fresh"):
        _session(tmp_path, "7").start_attempt({"schema": "test.request/v1"})
