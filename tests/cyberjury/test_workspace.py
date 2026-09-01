"""Generic session storage tests cover recovery, integrity, and concurrency."""

import fcntl
import json
import stat
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

from cyberjury.workspace import AttemptWorkspace, SessionLocator, SessionWorkspace, WorkspaceCorruptionError


def _process_record(values: tuple[str, str, str, int]) -> None:
    path, session_id, _attempt_id, index = values
    attempt = AttemptWorkspace.open(path, session_id=session_id)
    attempt.record(
        operation="worker.completed",
        status="complete",
        payload_schema="test.worker/v1",
        payload={"index": index},
    )


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]


def _simulate_process_exit(attempt: AttemptWorkspace) -> None:
    assert attempt._session_lock is not None
    fcntl.flock(attempt._session_lock.fileno(), fcntl.LOCK_UN)
    attempt._session_lock.close()
    attempt._session_lock = None


def test_session_and_attempt_use_json_and_jsonl_only(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "a" * 32,
        kind="review",
    )
    session.write_json_once("review.json", {"schema": "test.review/v1"})
    attempt = session.start_attempt({"schema": "test.request/v1"})

    assert session.path == tmp_path / "reviews" / ("review-" + "a" * 32)
    assert {path.name for path in session.path.iterdir()} == {"session.json", "review.json", "attempts"}
    assert {path.name for path in attempt.path.iterdir()} == {
        "request.json",
        "events.jsonl",
        "status.json",
    }
    assert stat.S_IMODE(session.path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in attempt.path.iterdir())


def test_attempt_journal_is_gapless_under_threads(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "b" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: attempt.record(
                    operation="worker.completed",
                    status="complete",
                    payload_schema="test.worker/v1",
                    payload={"index": index},
                ),
                range(32),
            )
        )

    events = _events(attempt.path)
    assert [event["sequence"] for event in events] == list(range(1, 34))
    AttemptWorkspace.open(attempt.path, session_id=session.session_id)


def test_attempt_journal_is_gapless_across_processes(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "c" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    values = [(str(attempt.path), session.session_id, attempt.attempt_id, index) for index in range(12)]

    with ProcessPoolExecutor(max_workers=4) as pool:
        list(pool.map(_process_record, values))

    events = _events(attempt.path)
    assert [event["sequence"] for event in events] == list(range(1, 14))
    AttemptWorkspace.open(attempt.path, session_id=session.session_id)


def test_reopening_session_marks_running_attempt_interrupted(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "d" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    _simulate_process_exit(attempt)

    reopened = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id=session.session_id,
        kind="review",
    )
    next_attempt = reopened.start_attempt({"schema": "test.request/v1"})
    next_attempt.finish(
        state="complete",
        payload_schema="test.complete/v1",
        payload={"exit_code": 0},
    )

    status = json.loads((attempt.path / "status.json").read_text())
    assert status["state"] == "interrupted"
    assert _events(attempt.path)[-1]["operation"] == "attempt.interrupted"


def test_tampered_event_fails_loud(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "e" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    events = attempt.path / "events.jsonl"
    events.write_text(events.read_text().replace("attempt.started", "attempt.changed"))

    with pytest.raises(WorkspaceCorruptionError, match="invalid hash"):
        AttemptWorkspace.open(attempt.path, session_id=session.session_id)


def test_tampered_journal_cannot_be_marked_complete(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "e" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    events = attempt.path / "events.jsonl"
    events.write_text(events.read_text().replace("attempt.started", "attempt.changed"))

    with pytest.raises(WorkspaceCorruptionError, match="invalid hash"):
        attempt.finish(state="complete", payload_schema="test.complete/v1", payload={})

    assert json.loads((attempt.path / "status.json").read_text())["state"] == "running"


def test_status_state_must_match_the_terminal_journal_event(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "1" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="complete", payload_schema="test.complete/v1", payload={})
    status_path = attempt.path / "status.json"
    status = json.loads(status_path.read_text())
    status["state"] = "running"
    status_path.write_text(json.dumps(status))

    with pytest.raises(WorkspaceCorruptionError, match="status state"):
        AttemptWorkspace.open(attempt.path, session_id=session.session_id)


def test_terminal_attempt_rejects_later_events(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "2" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    attempt.finish(state="complete", payload_schema="test.complete/v1", payload={})

    with pytest.raises(RuntimeError, match="terminal attempt"):
        attempt.record(
            operation="worker.completed",
            status="complete",
            payload_schema="test.worker/v1",
            payload={},
        )


def test_locator_reuses_active_session_and_can_publish_a_new_one(tmp_path):
    locator = SessionLocator.open(tmp_path, namespace="reviews")
    key = "3" * 64

    first = locator.select(key, kind="review", reuse=True)
    reused = locator.select(key, kind="review", reuse=True)
    second = locator.select(key, kind="review", reuse=False)

    assert reused == first
    assert second != first
    assert locator.select(key, kind="review", reuse=True) == second


def test_locator_session_id_must_match_requested_kind(tmp_path):
    locator = SessionLocator.open(tmp_path, namespace="reviews")
    key = "c" * 64
    locator.select(key, kind="review", reuse=True)
    path = locator.path / f"{key}.json"
    value = json.loads(path.read_text())
    value["session_id"] = "fetch-" + "d" * 32
    path.write_text(json.dumps(value))

    with pytest.raises(WorkspaceCorruptionError, match="identity"):
        locator.select(key, kind="review", reuse=True)


def test_existing_state_root_permissions_are_not_changed(tmp_path):
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


def test_stale_running_projection_is_rebuilt_before_interruption(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "6" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    stale_status = json.loads((attempt.path / "status.json").read_text())
    attempt.record(
        operation="worker.completed",
        status="complete",
        payload_schema="test.worker/v1",
        payload={},
    )
    (attempt.path / "status.json").write_text(json.dumps(stale_status))
    _simulate_process_exit(attempt)

    next_attempt = session.start_attempt({"schema": "test.request/v1"})
    next_attempt.finish(state="complete", payload_schema="test.complete/v1", payload={})

    assert _events(attempt.path)[-1]["operation"] == "attempt.interrupted"
    assert json.loads((attempt.path / "status.json").read_text())["last_sequence"] == 3


def test_uncommitted_partial_tail_is_discarded_from_valid_projection(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "7" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    with (attempt.path / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write('{"partial":')
    _simulate_process_exit(attempt)

    next_attempt = session.start_attempt({"schema": "test.request/v1"})
    next_attempt.finish(state="complete", payload_schema="test.complete/v1", payload={})

    assert _events(attempt.path)[-1]["operation"] == "attempt.interrupted"


def test_request_file_is_bound_to_the_start_event(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "8" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    (attempt.path / "request.json").write_text('{"schema":"changed/v1"}\n')

    with pytest.raises(WorkspaceCorruptionError, match="journal receipt"):
        AttemptWorkspace.open(attempt.path, session_id=session.session_id)


def test_append_does_not_replay_the_whole_journal(monkeypatch, tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "9" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    monkeypatch.setattr(attempt, "_read_events", lambda _stream: pytest.fail("journal replayed during append"))

    attempt.record(
        operation="worker.completed",
        status="complete",
        payload_schema="test.worker/v1",
        payload={},
    )


def test_status_write_failure_cannot_append_from_a_stale_tail(monkeypatch, tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "a" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})
    original = attempt._write_status

    def fail_status(**_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(attempt, "_write_status", fail_status)

    with pytest.raises(OSError, match="disk full"):
        attempt.record(
            operation="worker.completed",
            status="complete",
            payload_schema="test.worker/v1",
            payload={},
        )
    with pytest.raises(WorkspaceCorruptionError, match="event journal"):
        attempt.finish(state="failed", payload_schema="test.failed/v1", payload={})

    monkeypatch.setattr(attempt, "_write_status", original)
    recovered = AttemptWorkspace.open(attempt.path, session_id=session.session_id, repair_projection=True)
    assert [event["sequence"] for event in recovered.read_events()] == [1, 2]


def test_event_payload_rejects_nonfinite_json_number(tmp_path):
    session = SessionWorkspace.open_or_create(
        tmp_path,
        namespace="reviews",
        session_id="review-" + "b" * 32,
        kind="review",
    )
    attempt = session.start_attempt({"schema": "test.request/v1"})

    with pytest.raises(ValueError, match="Out of range float values"):
        attempt.record(
            operation="worker.completed",
            status="complete",
            payload_schema="test.worker/v1",
            payload={"duration_seconds": float("nan")},
        )

    assert json.loads((attempt.path / "status.json").read_text())["last_sequence"] == 1


def test_session_rejects_traversal_and_symlink_roots(tmp_path):
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
