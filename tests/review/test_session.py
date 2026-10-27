"""Review session tests cover logical identity, attempts, and where each stage writes its artifacts."""

import json
from dataclasses import replace

import pytest

from cyberjury.record import Record
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    seat_identity,
)
from cyberjury.review.result import FindingsArtifact, SkippedFiles
from cyberjury.review.session import ReviewSession
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import SessionConflictError

_FACTS = FactsReceipt.create(backend_id="test", facts=Facts())


def _request() -> ReviewAttemptRequest:
    seat = ProviderSeatRecord(
        seat_id=seat_identity("mock", "mock", "default"),
        provider="mock",
        model="mock",
        endpoint_identity="default",
    )
    return ReviewAttemptRequest(
        engine_version="test",
        concurrency=ConcurrencyRecord(review=1),
        dry_run=True,
        fresh=False,
        providers=ProviderPlanRecord(retries=None, timeout_seconds=None, seat=seat),
    )


def _finish(attempt) -> None:
    attempt.bind(FindingsArtifact.create((), ()))
    attempt.finish(
        Record(
            id=attempt.workspace.attempt_id, status="ok", started_at=attempt.workspace.started_at, duration_seconds=1.0
        )
    )


def _bind_source(attempt, root) -> None:
    target = ResolvedTarget(kind="repository", repository_root=str(root.resolve()))
    unit_plan = UnitPlanReceipt.create(facts=_FACTS, units=())
    for value in (
        target,
        SourceSnapshot.capture(root, ()),
        ContractReceipt.capture(),
        _FACTS,
        unit_plan,
        GroundingReceipt.create(unit_plan=unit_plan, contexts=()),
    ):
        attempt.bind(value)


def test_same_review_intent_reuses_session_with_distinct_attempts(tmp_path):
    """Two attempts for one repository intent share a session directory and leave two attempt folders."""
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    first_session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = first_session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _finish(first)
    second_session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    second = second_session.start_attempt(_request())

    assert first_session.workspace.path == second_session.workspace.path
    assert first.workspace.attempt_id != second.workspace.attempt_id
    assert len(list((first_session.workspace.path / "attempts").iterdir())) == 2


def test_review_attempt_request_is_the_persisted_request(tmp_path):
    """The request.json of a base..HEAD diff attempt equals the request's to_dict(), including fresh=None."""
    intent = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"))
    request = replace(_request(), fresh=None)
    attempt = ReviewSession.create(tmp_path, intent).start_attempt(request)

    assert json.loads((attempt.workspace.path / "request.json").read_text()) == request.to_dict()


def test_independent_reviews_of_the_same_intent_have_unique_ids(tmp_path):
    """Two ReviewSession.create calls for one base..HEAD diff intent get different session ids."""
    intent = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"))

    first = ReviewSession.create(tmp_path, intent)
    second = ReviewSession.create(tmp_path, intent)

    assert first.workspace.session_id != second.workspace.session_id


def test_repository_judgment_change_requires_a_fresh_session(tmp_path):
    """A different engine_version on a used session raises a --fresh hint, and a new session accepts it."""
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _finish(first)
    changed = replace(_request(), engine_version="different-build")

    with pytest.raises(SessionConflictError, match="--fresh"):
        session.start_attempt(changed)

    fresh = ReviewSession.select_active(tmp_path, intent, reuse=False)
    assert fresh.workspace.session_id != session.workspace.session_id
    fresh_attempt = fresh.start_attempt(changed)
    _bind_source(fresh_attempt, tmp_path)
    _finish(fresh_attempt)


def test_repository_concurrency_change_can_resume_same_judgment(tmp_path):
    """Raising review concurrency to 4 reuses the session and judgment-configuration.json in a new attempt."""
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _finish(first)
    bound = session.workspace.read_json("session/judgment-configuration.json")
    changed = replace(_request(), concurrency=ConcurrencyRecord(review=4))

    second = session.start_attempt(changed)
    _bind_source(second, tmp_path)
    _finish(second)

    assert second.session_workspace.path == first.session_workspace.path == session.workspace.path
    assert second.workspace.path != first.workspace.path
    assert session.workspace.read_json("session/judgment-configuration.json") == bound
    assert second.workspace.read_record().status == "ok"


def test_each_stage_writes_its_artifacts_under_its_own_directory(tmp_path):
    """Target, source, facts, plan, and grounding artifacts land in their stage directories of the review."""
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    attempt.bind(SkippedFiles(()))

    for name in (
        "target/target.json",
        "source/snapshot.json",
        "source/contract.json",
        "facts/facts.json",
        "plan/plan.json",
        "plan/skipped-files.json",
        "grounding/grounding.json",
    ):
        assert (attempt.session_workspace.path / name).is_file()


def test_an_attempt_runs_until_its_terminal_record_is_written(tmp_path):
    """record.json reads running after start and ok after finish."""
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    assert attempt.workspace.read_record().status == "running"

    _finish(attempt)

    assert attempt.workspace.read_record().status == "ok"
