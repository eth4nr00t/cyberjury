"""Review session tests cover logical identity, attempts, and error redaction."""

import json
from dataclasses import replace

import pytest

from cyberjury.profiles.base import profile_binding
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    VerificationRecord,
    seat_identity,
)
from cyberjury.review.result import FindingRecord, FindingsArtifact, OutcomeArtifact
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.session import ReviewSession, safe_error
from cyberjury.review.target import GitTarget, PatchArtifact, ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.review.verification import VerificationCandidate, VerificationReceipt, VerificationVote
from cyberjury.review.verification import VerificationRecord as CandidateVerificationRecord
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import WorkspaceCorruptionError


def _request(action: str = "run") -> ReviewAttemptRequest:
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
            )
            if action == "run"
            else None
        ),
        verification=(
            VerificationRecord(
                enabled=False,
                skeptic_seat_id=None,
                confirmer_seat_ids=(),
            )
            if action == "run"
            else None
        ),
        poc=False if action == "run" else None,
    )


def _record_route(attempt) -> None:
    request = attempt.request
    assert request.providers is not None
    expected = {request.providers.base_seat_id, request.providers.finder_seat_id} - {None}
    if request.verification is not None:
        expected.update({request.verification.skeptic_seat_id, *request.verification.confirmer_seat_ids} - {None})
    attempt.record_provider_route(seat_ids=tuple(sorted(expected)))


def _record_scheduling(attempt) -> None:
    attempt.bind_scheduling(SchedulingReceipt.empty(stop_reason="no_reviewable_units"))


def _record_run_artifacts(attempt, *, model_calls: bool = True) -> None:
    _record_scheduling(attempt)
    verification = attempt.request.verification
    assert verification is not None
    attempt.bind_verification(
        VerificationReceipt.create(
            request_sha256=attempt.request.request_sha256,
            enabled=verification.enabled,
            candidate_ids=(),
        )
    )
    target = ResolvedTarget.from_dict(attempt.session_workspace.read_json("target.json"))
    snapshot = SourceSnapshot.from_dict(
        attempt.session_workspace.read_json("snapshot.json"),
        root=target.repository_root,
    )
    findings = FindingsArtifact.create(())
    outcome = OutcomeArtifact.create(
        target=attempt.intent_target.kind,
        source_revision=snapshot.snapshot_id,
        findings=findings,
        outcome=ReviewOutcome(findings=()),
    )
    attempt.bind_result(findings, outcome)
    if model_calls:
        attempt.record_model_calls(UsageMeter().document())


def _bind_source(attempt, root) -> None:
    target = ResolvedTarget(kind="repository", repository_root=str(root.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(root, ()))
    binding = profile_binding(WEB_PROFILE)
    attempt.bind_profile(binding)
    native_analysis = _native_analysis()
    attempt.bind_native_analysis(native_analysis)
    facts_resolution = _facts_resolution(native_analysis)
    attempt.bind_facts_resolution(facts_resolution)
    unit_plan = _unit_plan(facts_resolution)
    attempt.bind_unit_plan(unit_plan)
    grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=())
    attempt.bind_grounding(grounding, duration_seconds=0)


def _native_analysis() -> NativeAnalysisReceipt:
    return NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )


def _facts_resolution(native_analysis: NativeAnalysisReceipt) -> FactsResolutionReceipt:
    return FactsResolutionReceipt.create(
        native_analysis=native_analysis,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def _unit_plan(facts_resolution: FactsResolutionReceipt) -> UnitPlanReceipt:
    return UnitPlanReceipt.create(facts_resolution=facts_resolution, units=())


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
    _record_run_artifacts(first)
    first.complete(exit_code=0)
    changed = replace(_request(), engine_version="different-build")

    with pytest.raises(ValueError, match="--fresh"):
        session.start_attempt(changed)

    fresh = ReviewSession.select_active(tmp_path, intent, reuse=False)
    assert fresh.workspace.session_id != session.workspace.session_id
    fresh_attempt = fresh.start_attempt(changed)
    _bind_source(fresh_attempt, tmp_path)
    _record_route(fresh_attempt)
    _record_run_artifacts(fresh_attempt)
    fresh_attempt.complete(exit_code=0)


def test_result_cannot_restore_an_unlocatable_verification_candidate(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    base = _request()
    assert base.providers is not None
    request = replace(
        base,
        dry_run=False,
        concurrency=ConcurrencyRecord(review=1, verification=1),
        verification=VerificationRecord(
            enabled=True,
            skeptic_seat_id=base.providers.base_seat_id,
            confirmer_seat_ids=(),
        ),
    )
    candidate = FindingRecord(
        id="candidate-" + "a" * 20,
        category="missing-authorization",
        severity="HIGH",
        file="app.py",
        line=1,
        entrypoint="POST /records",
        summary="unprotected record write",
        evidence="",
        attack_path="",
        recommendation="",
        status="confirmed",
        evidence_refs=(),
        supporting_reviewers=(),
    )
    findings = FindingsArtifact.create((candidate,))

    def bind(state, *, unlocatable):
        attempt = ReviewSession.create(state, intent).start_attempt(request)
        _bind_source(attempt, tmp_path)
        receipt = VerificationReceipt.create(
            request_sha256=request.request_sha256,
            enabled=True,
            candidate_ids=(candidate.id,),
            records=(
                CandidateVerificationRecord(
                    candidate=VerificationCandidate(
                        title=candidate.summary,
                        finding_id=candidate.id,
                        file=candidate.file,
                        line=candidate.line,
                    ),
                    outcome="retained",
                    votes=(),
                    reason="no independent confirmer",
                ),
            )
            if not unlocatable
            else (),
            unlocatable_ids=(candidate.id,) if unlocatable else (),
        )
        attempt.bind_verification(receipt)
        target = ResolvedTarget.from_dict(attempt.session_workspace.read_json("target.json"))
        snapshot = SourceSnapshot.from_dict(
            attempt.session_workspace.read_json("snapshot.json"),
            root=target.repository_root,
        )
        outcome = OutcomeArtifact.create(
            target="repository",
            source_revision=snapshot.snapshot_id,
            findings=findings,
            outcome=ReviewOutcome(findings=(candidate,)),
        )
        return attempt, outcome

    rejected, rejected_outcome = bind(tmp_path.parent / f"{tmp_path.name}-rejected", unlocatable=True)
    with pytest.raises(ValueError, match="refuted or unlocatable"):
        rejected.bind_result(findings, rejected_outcome)

    retained, retained_outcome = bind(tmp_path.parent / f"{tmp_path.name}-retained", unlocatable=False)
    retained.bind_result(findings, retained_outcome)
    assert FindingsArtifact.from_dict(retained.workspace.read_json("findings.json")) == findings


def test_verification_binding_rejects_an_unconfigured_skeptic_seat(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    base = _request()
    assert base.providers is not None
    request = replace(
        base,
        dry_run=False,
        concurrency=ConcurrencyRecord(review=1, verification=1),
        verification=VerificationRecord(
            enabled=True,
            skeptic_seat_id=base.providers.base_seat_id,
            confirmer_seat_ids=(),
        ),
    )
    attempt = ReviewSession.create(tmp_path.parent / f"{tmp_path.name}-state", intent).start_attempt(request)
    candidate = VerificationCandidate(title="candidate", finding_id="candidate-" + "b" * 20, file="app.py", line=1)
    receipt = VerificationReceipt.create(
        request_sha256=request.request_sha256,
        enabled=True,
        candidate_ids=(candidate.finding_id,),
        records=(
            CandidateVerificationRecord(
                candidate=candidate,
                outcome="incomplete",
                votes=(
                    VerificationVote(
                        role="skeptic",
                        actor_id="actor-other",
                        seat_id="seat-other",
                        verdict="error",
                        reason="provider failed",
                    ),
                ),
                reason="provider failed",
            ),
        ),
    )

    with pytest.raises(ValueError, match="wrong skeptic seat"):
        attempt.bind_verification(receipt)


def test_repository_concurrency_change_can_resume_same_judgment(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    first = session.start_attempt(_request())
    _bind_source(first, tmp_path)
    _record_route(first)
    _record_run_artifacts(first)
    first.complete(exit_code=0)
    changed = replace(_request(), concurrency=ConcurrencyRecord(review=4, verification=None))

    second = session.start_attempt(changed)
    _bind_source(second, tmp_path)
    _record_route(second)
    _record_run_artifacts(second)
    second.complete(exit_code=0)


def test_diff_session_rejects_repository_lifecycle_action(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"),
        requested_profile="web",
    )
    session = ReviewSession.create(tmp_path, intent)

    with pytest.raises(ValueError, match="diff review supports run"):
        session.start_attempt(_request("scaffold"))


def test_review_session_rejects_a_duplicate_stage_receipt(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    attempt = session.start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_route(attempt)

    with pytest.raises(WorkspaceCorruptionError, match="duplicate provider route"):
        attempt.complete(exit_code=0)

    with pytest.raises(WorkspaceCorruptionError, match="duplicate provider route"):
        ReviewSession.open(tmp_path, intent, review_id=session.workspace.session_id)


def test_review_session_rejects_an_out_of_order_stage_receipt(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    session = ReviewSession.select_active(tmp_path, intent, reuse=True)
    attempt = session.start_attempt(_request())
    _record_route(attempt)
    _bind_source(attempt, tmp_path)

    with pytest.raises(WorkspaceCorruptionError, match="out of order"):
        attempt.complete(exit_code=0)


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
    assert (session.workspace.path / "profile.json").is_file()
    assert (session.workspace.path / "analysis.json").is_file()
    assert (session.workspace.path / "facts.json").is_file()
    assert (session.workspace.path / "units.json").is_file()
    assert (session.workspace.path / "grounding.json").is_file()
    operations = [event["operation"] for event in attempt.workspace.read_events()]
    assert operations == [
        "attempt.started",
        "configuration.normalized",
        "target.resolved",
        "source.snapshot.captured",
        "profile.resolved",
        "native.analysis.completed",
        "facts.resolved",
        "units.planned",
        "grounding.prepared",
        "attempt.complete",
    ]


def test_run_persists_receipts_in_stage_order(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())

    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_run_artifacts(attempt)
    attempt.complete(exit_code=0)

    operations = [event["operation"] for event in attempt.workspace.read_events()]
    assert operations.index("grounding.prepared") < operations.index("provider.route.resolved")
    assert operations.index("provider.route.resolved") < operations.index("scheduling.completed")
    assert operations.index("scheduling.completed") < operations.index("verification.completed")
    assert operations.index("verification.completed") < operations.index("model.calls.recorded")


def test_completed_model_action_requires_model_call_receipt(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_run_artifacts(attempt, model_calls=False)

    with pytest.raises(WorkspaceCorruptionError, match="no model calls receipt"):
        attempt.complete(exit_code=0)


def test_completed_review_run_requires_scheduling_receipt(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    attempt.record_model_calls(UsageMeter().document())

    with pytest.raises(WorkspaceCorruptionError, match="no scheduling receipt"):
        attempt.complete(exit_code=0)


def test_completed_review_run_requires_verification_receipt(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_scheduling(attempt)
    attempt.record_model_calls(UsageMeter().document())

    with pytest.raises(WorkspaceCorruptionError, match="no verification receipt"):
        attempt.complete(exit_code=0)


def test_scheduling_binding_rejects_a_unit_outside_the_unit_plan(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    receipt = SchedulingReceipt.create(
        unit_ids=("unit-unknown",),
        new_finding_ids=(),
        union_finding_ids=(),
        errors=0,
        failures=0,
        incomplete=0,
        clean=True,
        duration_seconds=0,
    )

    with pytest.raises(ValueError, match="ordered subset"):
        attempt.bind_scheduling(receipt)


def test_successful_attempt_requires_source_binding_before_terminal(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    session = ReviewSession.select_active(state, intent, reuse=True)
    attempt = session.start_attempt(_request("scaffold"))

    with pytest.raises(WorkspaceCorruptionError, match="no target receipt"):
        attempt.complete(exit_code=0)

    assert json.loads((attempt.workspace.path / "status.json").read_text())["state"] == "running"


def test_successful_attempt_requires_profile_binding_after_source_snapshot(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))

    with pytest.raises(WorkspaceCorruptionError, match="no profile receipt"):
        attempt.complete(exit_code=0)


def test_explicit_profile_intent_rejects_a_different_profile_binding(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="other",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))

    with pytest.raises(ValueError, match="explicit review intent"):
        attempt.bind_profile(profile_binding(WEB_PROFILE))


def test_successful_review_action_requires_native_analysis_after_profile_binding(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))
    attempt.bind_profile(profile_binding(WEB_PROFILE))

    with pytest.raises(WorkspaceCorruptionError, match="native analysis"):
        attempt.complete(exit_code=0)


def test_successful_review_action_requires_facts_resolution_after_native_analysis(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))
    attempt.bind_profile(profile_binding(WEB_PROFILE))
    attempt.bind_native_analysis(_native_analysis())

    with pytest.raises(WorkspaceCorruptionError, match="facts resolution"):
        attempt.complete(exit_code=0)


def test_successful_review_action_requires_unit_plan_after_facts_resolution(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))
    attempt.bind_profile(profile_binding(WEB_PROFILE))
    native = _native_analysis()
    attempt.bind_native_analysis(native)
    attempt.bind_facts_resolution(_facts_resolution(native))

    with pytest.raises(WorkspaceCorruptionError, match="unit plan"):
        attempt.complete(exit_code=0)


def test_successful_review_action_requires_grounding_after_unit_planning(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request("scaffold"))
    target = ResolvedTarget(kind="repository", repository_root=str(tmp_path.resolve()))
    attempt.bind_target(target)
    attempt.bind_snapshot(SourceSnapshot.capture(tmp_path, ()))
    attempt.bind_profile(profile_binding(WEB_PROFILE))
    native = _native_analysis()
    attempt.bind_native_analysis(native)
    facts = _facts_resolution(native)
    attempt.bind_facts_resolution(facts)
    attempt.bind_unit_plan(_unit_plan(facts))

    with pytest.raises(WorkspaceCorruptionError, match="grounding receipt"):
        attempt.complete(exit_code=0)


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


def test_completed_run_requires_hash_bound_result_artifacts(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_scheduling(attempt)
    verification = attempt.request.verification
    assert verification is not None
    attempt.bind_verification(
        VerificationReceipt.create(
            request_sha256=attempt.request.request_sha256,
            enabled=verification.enabled,
            candidate_ids=(),
        )
    )
    attempt.record_model_calls(UsageMeter().document())

    with pytest.raises(WorkspaceCorruptionError, match="result receipt"):
        attempt.complete(exit_code=0)


def test_terminal_state_must_match_the_review_outcome(tmp_path):
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(tmp_path)),
        requested_profile="web",
    )
    state = tmp_path.parent / f"{tmp_path.name}-state"
    attempt = ReviewSession.select_active(state, intent, reuse=True).start_attempt(_request())
    _bind_source(attempt, tmp_path)
    _record_route(attempt)
    _record_scheduling(attempt)
    verification = attempt.request.verification
    assert verification is not None
    attempt.bind_verification(
        VerificationReceipt.create(
            request_sha256=attempt.request.request_sha256,
            enabled=verification.enabled,
            candidate_ids=(),
        )
    )
    target = ResolvedTarget.from_dict(attempt.session_workspace.read_json("target.json"))
    snapshot = SourceSnapshot.from_dict(
        attempt.session_workspace.read_json("snapshot.json"),
        root=target.repository_root,
    )
    findings = FindingsArtifact.create(())
    outcome = OutcomeArtifact.create(
        target="repository",
        source_revision=snapshot.snapshot_id,
        findings=findings,
        outcome=ReviewOutcome(findings=(), errors=1),
    )
    attempt.bind_result(findings, outcome)
    attempt.record_model_calls(UsageMeter().document())

    with pytest.raises(WorkspaceCorruptionError, match="terminal state"):
        attempt.complete(exit_code=0)
