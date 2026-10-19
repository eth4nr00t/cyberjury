"""Review session tests cover logical identity, attempts, and error redaction."""

import json
from dataclasses import replace

import pytest

from cyberjury.providers.metering import UsageMeter
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.engine import ReviewOutcome
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
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.session import ReviewSession, safe_error
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import SourceSnapshot


def _request(action: str = "run") -> ReviewAttemptRequest:
    seat = ProviderSeatRecord(
        seat_id=seat_identity("mock", "mock", "default", None),
        provider="mock",
        model="mock",
        endpoint_identity="default",
        wire_api=None,
    )
    return ReviewAttemptRequest(
        action=action,
        engine_version="test",
        concurrency=ConcurrencyRecord(review=1) if action == "run" else None,
        dry_run=True if action == "run" else None,
        fresh=False if action in {"run", "scaffold"} else None,
        providers=(ProviderPlanRecord(retries=None, timeout_seconds=None, seat=seat) if action == "run" else None),
    )


def _record_run_artifacts(attempt) -> None:
    findings = FindingsArtifact.create((), ())
    outcome = OutcomeArtifact.create(
        target=attempt.intent.target.kind,
        source_revision=_snapshot_id(attempt),
        findings=findings,
        outcome=ReviewOutcome(findings=()),
    )
    attempt.bind_result(findings, outcome)
    attempt.record_model_calls(UsageMeter().document())


def _snapshot_id(attempt) -> str:
    return attempt.session_workspace.read_json("snapshot.json")["snapshot_id"]


def _bind_source(attempt, root) -> None:
    target = ResolvedTarget(kind="repository", repository_root=str(root.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(root, ()))
    attempt.bind_contract(ContractReceipt.capture())
    attempt.bind_facts(_FACTS)
    unit_plan = UnitPlanReceipt.create(facts=_FACTS, units=())
    attempt.bind_unit_plan(unit_plan)
    grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=())
    attempt.bind_grounding(grounding)


_FACTS = FactsReceipt.create(backend_id="test", facts=Facts())


def test_same_review_intent_reuses_session_with_distinct_attempts(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
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
    intent = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"))
    request = replace(_request(), fresh=None)
    attempt = ReviewSession.create(tmp_path, intent).start_attempt(request)

    assert json.loads((attempt.workspace.path / "request.json").read_text()) == request.to_dict()


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
    intent = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"))

    first = ReviewSession.create(tmp_path, intent)
    second = ReviewSession.create(tmp_path, intent)

    assert first.workspace.session_id != second.workspace.session_id


def test_repository_judgment_change_requires_a_fresh_session(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _record_run_artifacts(first)
    first.complete(exit_code=0)
    changed = replace(_request(), engine_version="different-build")

    with pytest.raises(ValueError, match="--fresh"):
        session.start_attempt(changed)

    fresh = ReviewSession.select_active(tmp_path, intent, reuse=False)
    assert fresh.workspace.session_id != session.workspace.session_id
    fresh_attempt = fresh.start_attempt(changed)
    _bind_source(fresh_attempt, tmp_path)
    _record_run_artifacts(fresh_attempt)
    fresh_attempt.complete(exit_code=0)


def test_repository_concurrency_change_can_resume_same_judgment(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _record_run_artifacts(first)
    first.complete(exit_code=0)
    bound = session.workspace.read_json("judgment-configuration.json")
    changed = replace(_request(), concurrency=ConcurrencyRecord(review=4))

    second = session.start_attempt(changed)
    _bind_source(second, tmp_path)
    _record_run_artifacts(second)
    second.complete(exit_code=0)

    assert second.session_workspace.path == first.session_workspace.path == session.workspace.path
    assert second.workspace.path != first.workspace.path
    assert session.workspace.read_json("judgment-configuration.json") == bound
    assert json.loads((second.workspace.path / "attempt.json").read_text())["state"] == "complete"


def test_attempt_state_records_the_terminal_state_and_exit_code(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    assert json.loads((attempt.workspace.path / "attempt.json").read_text())["state"] == "running"
    _bind_source(attempt, tmp_path)
    attempt.complete(exit_code=0)

    recorded = json.loads((attempt.workspace.path / "attempt.json").read_text())
    assert recorded["state"] == "complete"
    assert recorded["detail"]["exit_code"] == 0
    for name in ("target", "snapshot", "contract", "facts", "units", "grounding"):
        assert (attempt.session_workspace.path / f"{name}.json").is_file()


def test_a_receipt_cannot_bind_before_the_receipt_it_extends(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    attempt.bind_target(ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve())))
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))
    attempt.bind_contract(ContractReceipt.capture())

    with pytest.raises(ValueError, match="no bound facts"):
        attempt.bind_unit_plan(UnitPlanReceipt.create(facts=_FACTS, units=()))


def test_terminal_state_must_match_the_review_outcome(tmp_path):
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(tmp_path)))
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    findings = FindingsArtifact.create((), ())
    outcome = OutcomeArtifact.create(
        target="repository",
        source_revision=_snapshot_id(attempt),
        findings=findings,
        outcome=ReviewOutcome(findings=(), errors=1),
    )
    attempt.bind_result(findings, outcome)
    attempt.record_model_calls(UsageMeter().document())

    with pytest.raises(ValueError, match="terminal state"):
        attempt.complete(exit_code=0)
