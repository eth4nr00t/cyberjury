"""Review session tests cover logical identity, attempts, and error redaction."""

import json
from dataclasses import replace

import pytest

from cyberjury.review.engine import ReviewSchedule
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    ScheduleRecord,
    TargetInput,
    VerificationRecord,
    seat_identity,
)
from cyberjury.review.session import ReviewSession, safe_error
from cyberjury.review.target import GitTarget, PatchArtifact, ResolvedTarget
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import WorkspaceCorruptionError


def _request(action: str = "run") -> ReviewAttemptRequest:
    schedule = ScheduleRecord.from_schedule(ReviewSchedule(mode="standard", max_rounds=1)) if action == "run" else None
    seat_id = seat_identity("mock", "mock", "default", None)
    seats = (
        (
            ProviderSeatRecord(
                seat_id=seat_id,
                provider="mock",
                model="mock",
                endpoint_identity="default",
                wire_api=None,
            ),
        )
        if action == "run"
        else ()
    )
    return ReviewAttemptRequest(
        action=action,
        engine_version="test",
        schedule=schedule,
        concurrency=ConcurrencyRecord(review=1, verification=None) if action == "run" else None,
        dry_run=True if action == "run" else None,
        fresh=False if action in {"run", "scaffold"} else None,
        providers=(
            ProviderPlanRecord(
                retries=None,
                timeout_seconds=None,
                seats=seats,
                base_seat_id=seat_id,
                finder_seat_id=seat_id,
                challenger_seat_id=None,
                judge_seat_id=None,
            )
            if action == "run"
            else None
        ),
        verification=(
            VerificationRecord(
                enabled=False,
                votes_required=None,
                skeptic_seat_id=None,
                confirmer_seat_ids=(),
            )
            if action == "run"
            else None
        ),
    )


def _record_route(attempt) -> None:
    request = attempt.request
    assert request.providers is not None
    expected = {
        request.providers.base_seat_id,
        request.providers.finder_seat_id,
        request.providers.challenger_seat_id,
        request.providers.judge_seat_id,
    } - {None}
    if request.verification is not None:
        expected.update({request.verification.skeptic_seat_id, *request.verification.confirmer_seat_ids} - {None})
    attempt.record_provider_route(seat_ids=tuple(sorted(expected)))


def _bind_source(attempt, root) -> None:
    target = ResolvedTarget(kind="repository", repository_root=str(root.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(root, ()))


def test_same_review_intent_reuses_session_with_distinct_attempts(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    first_session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = first_session.start_attempt(_request("scaffold"))
    _bind_source(first, tmp_path)
    first.complete(exit_code=0)
    second_session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    second = second_session.start_attempt(_request("run"))

    assert first_session.workspace.path == second_session.workspace.path
    assert first.workspace.attempt_id != second.workspace.attempt_id
    assert len(list((first_session.workspace.path / "attempts").iterdir())) == 2


def test_review_attempt_request_is_the_persisted_request(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"),
        requested_profile="auto",
    )
    request = replace(_request(), fresh=None)
    attempt = ReviewSession.create(tmp_path, intent).start_attempt(request)

    assert ReviewAttemptRequest.from_dict(json.loads((attempt.workspace.path / "request.json").read_text())) == request


def test_safe_error_redacts_and_bounds_sensitive_values():
    secret = (
        "Authorization: Bearer super-secret "
        "headers={'Authorization': 'Bearer dict-secret'} "
        "api key loose-secret token token-secret"
    )
    error = safe_error(RuntimeError(secret))

    assert "secret" not in error["message"]
    assert len(error["message"]) <= 2000


def test_independent_reviews_of_the_same_intent_have_unique_ids(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"),
        requested_profile="web",
    )

    first = ReviewSession.create(tmp_path, intent)
    second = ReviewSession.create(tmp_path, intent)

    assert first.workspace.session_id != second.workspace.session_id


def test_repository_judgment_change_requires_a_fresh_session(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _record_route(first)
    first.complete(exit_code=0)
    changed = replace(_request(), engine_version="different-build")

    with pytest.raises(ValueError, match="--fresh"):
        session.start_attempt(changed)

    fresh = ReviewSession.select_active(tmp_path, intent, reuse=False)
    assert fresh.workspace.session_id != session.workspace.session_id
    fresh_attempt = fresh.start_attempt(changed)
    _bind_source(fresh_attempt, tmp_path)
    _record_route(fresh_attempt)
    fresh_attempt.complete(exit_code=0)


def test_repository_concurrency_change_can_resume_same_judgment(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _record_route(first)
    first.complete(exit_code=0)
    changed = replace(_request(), concurrency=ConcurrencyRecord(review=4, verification=None))

    second = session.start_attempt(changed)
    _bind_source(second, tmp_path)
    _record_route(second)
    second.complete(exit_code=0)


def test_diff_session_rejects_repository_lifecycle_action(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"),
        requested_profile="web",
    )
    session = ReviewSession.create(tmp_path, intent)

    with pytest.raises(ValueError, match="diff review supports run"):
        session.start_attempt(_request("scaffold"))


def test_review_session_rejects_wrong_operation_payload_schema(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    attempt = session.start_attempt(_request())
    _bind_source(attempt, tmp_path)
    attempt.workspace.record(
        operation="provider.route.resolved",
        status="complete",
        payload_schema="wrong/v999",
        payload={"secret": "value"},
    )

    with pytest.raises(WorkspaceCorruptionError, match="provider route receipt"):
        attempt.complete(exit_code=0)

    with pytest.raises(WorkspaceCorruptionError, match="provider route receipt"):
        ReviewSession.open(tmp_path, intent, review_id=session.workspace.session_id)


def test_completed_model_action_requires_exact_provider_route(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    attempt = session.start_attempt(_request())
    _bind_source(attempt, tmp_path)

    with pytest.raises(WorkspaceCorruptionError, match="no provider route"):
        attempt.complete(exit_code=0)
    assert json.loads((attempt.workspace.path / "status.json").read_text())["state"] == "running"


def test_provider_route_must_exactly_match_request(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    attempt = session.start_attempt(_request())
    _bind_source(attempt, tmp_path)

    with pytest.raises(ValueError, match="does not match"):
        attempt.record_provider_route(seat_ids=())
    assert json.loads((attempt.workspace.path / "status.json").read_text())["state"] == "running"


def test_source_binding_persists_target_snapshot_and_ordered_receipts(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    session = ReviewSession.select_active(state, intent, reuse=True)
    attempt = session.start_attempt(_request("scaffold"))
    _bind_source(attempt, tmp_path)
    attempt.complete(exit_code=0)

    assert (session.workspace.path / "target.json").is_file()
    assert (session.workspace.path / "snapshot.json").is_file()
    operations = [event["operation"] for event in attempt.workspace.read_events()]
    assert operations == [
        "attempt.started",
        "configuration.normalized",
        "target.resolved",
        "source.snapshot.captured",
        "attempt.complete",
    ]


def test_successful_attempt_requires_source_binding_before_terminal(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    session = ReviewSession.select_active(state, intent, reuse=True)
    attempt = session.start_attempt(_request("scaffold"))

    with pytest.raises(WorkspaceCorruptionError, match="source binding"):
        attempt.complete(exit_code=0)

    assert json.loads((attempt.workspace.path / "status.json").read_text())["state"] == "running"


def test_repository_target_rejects_a_snapshot_from_another_root(tmp_path):
    repository = tmp_path / "repository"
    other = tmp_path / "other"
    repository.mkdir()
    other.mkdir()
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(repository)),
        requested_profile="web",
    )
    attempt = ReviewSession.create(tmp_path / "state", intent).start_attempt(_request("scaffold"))
    attempt.bind_target(ResolvedTarget(kind="repository", repository_root=str(repository.resolve())))

    with pytest.raises(ValueError, match="snapshot root"):
        attempt.bind_snapshot(SourceSnapshot.capture(other, ()))


def test_diff_target_rejects_a_range_other_than_the_review_intent(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    intent = ReviewIntent(
        target=TargetInput(kind="diff", repository=str(repository), git_range="base..head"),
        requested_profile="web",
    )
    attempt = ReviewSession.create(tmp_path / "state", intent).start_attempt(replace(_request(), fresh=None))
    revision = "0" * 40
    target = ResolvedTarget(
        kind="diff",
        repository_root=str(repository.resolve()),
        git=GitTarget(
            object_format="sha1",
            requested_range="other..head",
            range_kind="two-dot",
            left_revision=revision,
            right_revision=revision,
            patch_base_revision=revision,
        ),
        patch=PatchArtifact.from_text(""),
    )

    with pytest.raises(ValueError, match="Git range"):
        attempt.bind_target(target)
