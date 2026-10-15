"""Review domain composition over generic session and attempt storage."""

from __future__ import annotations

import contextlib
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.profiles.base import ProfileBinding
from cyberjury.providers.metering import validate_model_calls_document
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import ReviewAttemptRequest, ReviewIntent, TargetInput
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.review.verification import VerificationReceipt
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError
from cyberjury.workspace import (
    AttemptWorkspace,
    SessionLocator,
    SessionWorkspace,
    WorkspaceCorruptionError,
    new_session_id,
)


def safe_error(exc: BaseException) -> dict[str, str]:
    """Return failure identity without persisting uncontrolled exception text."""
    return {"code": "command_failed", "type": type(exc).__name__, "message": "command failed"}


def _configured_seat_ids(request: ReviewAttemptRequest) -> tuple[str, ...]:
    if request.providers is None:
        return ()
    expected = {request.providers.base_seat_id, request.providers.finder_seat_id} - {None}
    if request.verification is not None:
        expected.update(
            {
                request.verification.skeptic_seat_id,
                *request.verification.confirmer_seat_ids,
            }
            - {None}
        )
    return tuple(sorted(expected))


_STAGE_OPERATIONS = (
    ("target", frozenset({"target.resolved", "target.bound"})),
    ("snapshot", frozenset({"source.snapshot.captured", "source.snapshot.validated"})),
    ("profile", frozenset({"profile.resolved", "profile.bound"})),
    ("native analysis", frozenset({"native.analysis.completed", "native.analysis.bound"})),
    ("facts resolution", frozenset({"facts.resolved", "facts.bound"})),
    ("unit plan", frozenset({"units.planned", "units.bound"})),
    ("grounding", frozenset({"grounding.prepared", "grounding.bound"})),
    ("provider route", frozenset({"provider.route.resolved"})),
    ("scheduling", frozenset({"scheduling.completed"})),
    ("verification", frozenset({"verification.completed"})),
    ("result", frozenset({"result.persisted"})),
    ("model calls", frozenset({"model.calls.recorded"})),
)


def _validate_journal(
    request: ReviewAttemptRequest,
    events: tuple[dict[str, object], ...],
    *,
    required: frozenset[str],
) -> None:
    """Require one normalized configuration, then each bound stage once and in stage order.

    Every stage receipt is validated when it is bound, and the attempt journal hash chain
    protects the receipts afterward, so reopening checks only presence and order.
    """
    normalized = [index for index, event in enumerate(events) if event["operation"] == "configuration.normalized"]
    if len(normalized) != 1:
        raise WorkspaceCorruptionError("attempt must contain exactly one normalized configuration")
    payload = events[normalized[0]]["payload"]
    if payload["schema"] != "cyberjury.configuration-normalized/v1" or payload["data"] != {
        "configuration_sha256": request.request_sha256
    }:
        raise WorkspaceCorruptionError("attempt normalized configuration does not match its request")
    previous = normalized[0]
    for stage, operations in _STAGE_OPERATIONS:
        indexes = [index for index, event in enumerate(events) if event["operation"] in operations]
        if len(indexes) > 1:
            raise WorkspaceCorruptionError(f"attempt has duplicate {stage} receipts")
        if not indexes:
            if stage in required:
                raise WorkspaceCorruptionError(f"attempt has no {stage} receipt")
            continue
        if indexes[0] <= previous:
            raise WorkspaceCorruptionError(f"attempt {stage} receipt is out of order")
        previous = indexes[0]


def _required_stages(request: ReviewAttemptRequest, *, completing: bool) -> frozenset[str]:
    """Name the stage receipts a successful attempt of this action must have bound."""
    stages = {"target", "snapshot", "profile"}
    if request.action in {"run", "scaffold"}:
        stages.update({"native analysis", "facts resolution", "unit plan", "grounding"})
    if request.providers is not None:
        stages.add("provider route")
    if request.action == "run":
        stages.add("result")
        if completing:
            stages.add("verification")
            if request.providers is not None:
                stages.add("model calls")
    if completing and request.action == "run":
        stages.add("scheduling")
    return frozenset(stages)


@dataclass(frozen=True, kw_only=True)
class ReviewSession:
    """One logical target review shared by multiple command attempts."""

    workspace: SessionWorkspace
    intent: ReviewIntent

    @classmethod
    def open(cls, root: str | Path, intent: ReviewIntent, *, review_id: str) -> ReviewSession:
        """Open one unique review session and verify its immutable intent."""
        workspace = SessionWorkspace.open_or_create(
            root,
            namespace="reviews",
            session_id=review_id,
            kind="review",
        )
        workspace.write_json_once("review.json", intent.to_dict())
        session = cls(workspace=workspace, intent=intent)
        session._validate_attempts()
        return session

    @classmethod
    def create(cls, root: str | Path, intent: ReviewIntent) -> ReviewSession:
        """Create one independent review session."""
        return cls.open(root, intent, review_id=new_session_id("review"))

    @classmethod
    def open_existing(cls, root: str | Path, intent: ReviewIntent, *, review_id: str) -> ReviewSession:
        """Open an existing review id without creating a session for a typo."""
        if not re.fullmatch(r"review-[0-9a-f]{32}", review_id):
            raise ValueError("review id is invalid")
        path = Path(root).expanduser() / "reviews" / review_id
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"review session does not exist: {review_id}")
        return cls.open(root, intent, review_id=review_id)

    @classmethod
    def select_active(
        cls,
        root: str | Path,
        intent: ReviewIntent,
        *,
        reuse: bool,
        create_if_missing: bool = True,
    ) -> ReviewSession:
        """Select the active repository review or publish a new one."""
        locator = SessionLocator.open(root, namespace="reviews")
        review_id, created = locator.select_with_state(
            intent.intent_sha256,
            kind="review",
            reuse=reuse,
            create_if_missing=create_if_missing,
        )
        if created:
            return cls.open(root, intent, review_id=review_id)
        return cls.open_existing(root, intent, review_id=review_id)

    def start_attempt(self, request: ReviewAttemptRequest) -> ReviewAttempt:
        """Create one invocation whose wire request and runtime request are identical."""
        self._validate_attempts()
        workspace = self.workspace.start_attempt(request.to_dict())
        attempt = ReviewAttempt(workspace=workspace, session_workspace=self.workspace, request=request)
        try:
            workspace.record(
                operation="configuration.normalized",
                status="complete",
                payload_schema="cyberjury.configuration-normalized/v1",
                payload={"configuration_sha256": request.request_sha256},
            )
            self._validate_execution(request)
            self._bind_repository_judgment(attempt)
        except BaseException as exc:
            with contextlib.suppress(BaseException):
                attempt.fail(exc)
            raise
        return attempt

    def _validate_attempts(self) -> None:
        """Validate every persisted request and the presence and order of its stage receipts."""
        for path in sorted((self.workspace.path / "attempts").glob("attempt-*")):
            attempt = AttemptWorkspace.open(
                path,
                session_id=self.workspace.session_id,
                repair_projection=True,
            )
            try:
                request = ReviewAttemptRequest.from_dict(attempt.read_request())
            except ValueError as exc:
                raise WorkspaceCorruptionError("attempt request schema is invalid") from exc
            events = attempt.read_events()
            terminal_success = bool(events) and events[-1]["operation"] in {"attempt.complete", "attempt.incomplete"}
            if not any(event["operation"] == "configuration.normalized" for event in events) and not terminal_success:
                continue
            _validate_journal(
                request,
                events,
                required=_required_stages(request, completing=False) if terminal_success else frozenset(),
            )

    def _validate_execution(self, request: ReviewAttemptRequest) -> None:
        """Reject target and execution policy combinations at the domain boundary."""
        if self.intent.target.kind == "diff" and (request.action != "run" or request.fresh is not None):
            raise ValueError("diff review supports run without repository fresh state")
        if (
            self.intent.target.kind == "repository"
            and request.action in {"run", "scaffold"}
            and not isinstance(request.fresh, bool)
        ):
            raise ValueError("repository run and scaffold require an explicit fresh policy")

    def _bind_repository_judgment(self, attempt: ReviewAttempt) -> None:
        """Prevent resumable repository work from changing its judgment provenance."""
        request = attempt.request
        if self.intent.target.kind != "repository" or request.action != "run":
            return
        name = "judgment-configuration.json"
        path = self.workspace.path / name
        expected_hash = request.judgment_configuration_sha256
        if path.exists():
            bound = self.workspace.read_json(name)
            fields = {"schema", "judgment_configuration_sha256"}
            if set(bound) != fields or bound["schema"] != "cyberjury.judgment-configuration/v1":
                raise WorkspaceCorruptionError("repository judgment configuration has an invalid schema")
            if bound["judgment_configuration_sha256"] != expected_hash:
                raise ValueError("repository judgment configuration changed, start again with --fresh")
            return
        self.workspace.write_json_once(
            name,
            {
                "schema": "cyberjury.judgment-configuration/v1",
                "judgment_configuration_sha256": expected_hash,
            },
        )


@dataclass(frozen=True, kw_only=True)
class ReviewAttempt:
    """One command invocation and its authoritative effective configuration."""

    workspace: AttemptWorkspace
    session_workspace: SessionWorkspace
    request: ReviewAttemptRequest
    _started_at: float = field(default_factory=time.monotonic, repr=False)

    def _duration(self) -> float:
        return round(time.monotonic() - self._started_at, 3)

    def record_provider_route(self, *, seat_ids: tuple[str, ...]) -> None:
        """Record configured provider routing without claiming calls have succeeded."""
        if seat_ids != _configured_seat_ids(self.request):
            raise ValueError("provider route does not match the review request")
        self.workspace.record(
            operation="provider.route.resolved",
            status="complete",
            payload_schema="cyberjury.provider-route/v1",
            payload={"configured_seat_ids": list(seat_ids)},
        )

    def record_model_calls(self, document: dict[str, object]) -> None:
        """Persist the exact call, prompt identity, and usage record."""
        validate_model_calls_document(document)
        calls = document["calls"]
        if not isinstance(calls, list):
            raise AssertionError("validated model calls artifact lost its call list")
        if any(not call["role"] for call in calls):
            raise ValueError("model call has no role identity")
        verification_candidate_ids = {
            call["candidate_id"] for call in calls if call["trigger"] in {"verification", "refutation_confirmation"}
        }
        if verification_candidate_ids and (self.workspace.path / "verification.json").is_file():
            receipt = VerificationReceipt.from_dict(self.workspace.read_json("verification.json"))
            if not verification_candidate_ids.issubset(receipt.candidate_ids):
                raise ValueError("verification model call references an unknown candidate")
        self.workspace.write_json_once("model-calls.json", document)
        self.workspace.record(
            operation="model.calls.recorded",
            status="complete",
            payload_schema="cyberjury.model-calls-receipt/v1",
            payload={
                "artifact": "model-calls.json",
                "call_count": len(calls),
                "content_sha256": document["content_sha256"],
            },
        )

    def bind_scheduling(self, receipt: SchedulingReceipt) -> None:
        """Persist the exact unit fan-out and completion receipt."""
        if self.request.action != "run":
            raise ValueError("only review run attempts have scheduling state")
        try:
            unit_plan = UnitPlanReceipt.from_dict(self.session_workspace.read_json("units.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("scheduling cannot bind without a valid unit plan") from exc
        planned_ids = tuple(unit.id for unit in unit_plan.units)
        scheduled = iter(receipt.unit_ids)
        expected = next(scheduled, None)
        for unit_id in planned_ids:
            if unit_id == expected:
                expected = next(scheduled, None)
        if expected is not None:
            raise ValueError("scheduling units are not an ordered subset of the unit plan")
        target_kind = self.intent_target.kind
        if receipt.stop_reason == "no_reviewable_units" and planned_ids:
            raise ValueError("scheduling skipped a nonempty unit plan")
        if receipt.stop_reason == "no_open_units" and target_kind != "repository":
            raise ValueError("only repository review can have no open units")
        if target_kind == "diff" and receipt.unit_ids != planned_ids:
            raise ValueError("diff scheduling does not cover its complete unit plan")
        self.workspace.write_json_once("scheduling.json", receipt.to_dict())
        self.workspace.record(
            operation="scheduling.completed",
            status="complete",
            payload_schema="cyberjury.scheduling-receipt/v2",
            payload={"artifact": "scheduling.json", "content_sha256": receipt.content_sha256},
        )

    def bind_verification(self, receipt: VerificationReceipt) -> None:
        """Persist every candidate deletion decision under the immutable request."""
        policy = self.request.verification
        if policy is None:
            raise ValueError("only review model actions have verification state")
        if receipt.request_sha256 != self.request.request_sha256:
            raise ValueError("verification receipt does not match the review request")
        if receipt.enabled != policy.enabled:
            raise ValueError("verification receipt enabled state does not match the review request")
        confirmers = set(policy.confirmer_seat_ids)
        for decision in receipt.decisions:
            if not set(decision.required_confirmer_seat_ids).issubset(confirmers):
                raise ValueError("verification decision requires an unconfigured confirmer")
            for vote in decision.votes:
                if vote.role == "skeptic" and vote.seat_id != policy.skeptic_seat_id:
                    raise ValueError("verification decision uses the wrong skeptic seat")
                if vote.role == "confirmer" and vote.seat_id not in confirmers:
                    raise ValueError("verification decision uses an unconfigured confirmer seat")
        self.workspace.write_json_once("verification.json", receipt.to_dict())
        self.workspace.record(
            operation="verification.completed",
            status="complete",
            payload_schema="cyberjury.verification-receipt/v1",
            payload={
                "artifact": "verification.json",
                "candidate_count": len(receipt.candidate_ids),
                "content_sha256": receipt.content_sha256,
            },
        )

    def bind_result(self, findings: FindingsArtifact, outcome: OutcomeArtifact) -> None:
        """Persist and journal one source bound final result."""
        try:
            target = ResolvedTarget.from_dict(self.session_workspace.read_json("target.json"))
            snapshot = SourceSnapshot.from_dict(
                self.session_workspace.read_json("snapshot.json"),
                root=target.repository_root,
            )
        except (ValueError, SourceSnapshotError) as exc:
            raise WorkspaceCorruptionError("result cannot bind without a valid source snapshot") from exc
        if outcome.target != self.intent_target.kind or outcome.source_revision != snapshot.snapshot_id:
            raise ValueError("review result does not match the attempt target snapshot")
        if outcome.findings_sha256 != findings.content_sha256:
            raise ValueError("review outcome does not identify its findings")
        if self.request.verification is not None and self.request.verification.enabled:
            verification_receipt = VerificationReceipt.from_dict(self.workspace.read_json("verification.json"))
            allowed = {
                decision.candidate_id
                for decision in verification_receipt.decisions
                if decision.outcome in {"retained", "incomplete"}
            }
            if not {finding.id for finding in findings.findings}.issubset(allowed):
                raise ValueError("review result restores a refuted or unlocatable candidate")
        self.workspace.write_json_once("findings.json", findings.to_dict())
        self.workspace.write_json_once("outcome.json", outcome.to_dict())
        self.workspace.record(
            operation="result.persisted",
            status="complete",
            payload_schema="cyberjury.review-result-receipt/v1",
            payload={
                "findings_artifact": "findings.json",
                "findings_sha256": findings.content_sha256,
                "outcome_artifact": "outcome.json",
                "outcome_sha256": outcome.content_sha256,
            },
        )

    def bind_target(self, target: ResolvedTarget) -> None:
        """Bind one resolved target artifact to this review and attempt."""
        intent_target = self.intent_target
        requested_root = Path(intent_target.repository).resolve()
        resolved_root = Path(target.repository_root)
        if target.kind != intent_target.kind:
            raise ValueError("resolved target kind does not match review intent")
        if target.kind == "repository" and requested_root != resolved_root:
            raise ValueError("repository target root does not match review intent")
        if target.kind == "diff":
            if requested_root != resolved_root and not requested_root.is_relative_to(resolved_root):
                raise ValueError("diff Git root does not contain the requested repository path")
            if target.git is None or target.git.requested_range != intent_target.git_range:
                raise ValueError("resolved Git range does not match review intent")
        path = self.session_workspace.path / "target.json"
        operation = "target.bound" if path.exists() else "target.resolved"
        self.session_workspace.write_json_once("target.json", target.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.target-binding/v1",
            payload={"artifact": "target.json", "target_sha256": target.target_sha256},
        )

    def bind_snapshot(self, snapshot: SourceSnapshot) -> None:
        """Bind or revalidate the source-only manifest for this review."""
        try:
            target = ResolvedTarget.from_dict(self.session_workspace.read_json("target.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("snapshot cannot bind without a valid target") from exc
        if target.kind == "repository" and snapshot.root != Path(target.repository_root):
            raise ValueError("repository snapshot root does not match its resolved target")
        path = self.session_workspace.path / "snapshot.json"
        operation = "source.snapshot.validated" if path.exists() else "source.snapshot.captured"
        self.session_workspace.write_json_once("snapshot.json", snapshot.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.source-snapshot-binding/v1",
            payload={
                "artifact": "snapshot.json",
                "target_sha256": target.target_sha256,
                "snapshot_id": snapshot.snapshot_id,
                "file_count": len(snapshot.entries),
                "total_bytes": snapshot.total_bytes,
            },
        )

    def bind_profile(self, binding: ProfileBinding) -> None:
        """Bind one validated profile behavior receipt to the source snapshot."""
        try:
            target = ResolvedTarget.from_dict(self.session_workspace.read_json("target.json"))
            snapshot = SourceSnapshot.from_dict(
                self.session_workspace.read_json("snapshot.json"),
                root=target.repository_root,
            )
            intent = ReviewIntent.from_dict(self.session_workspace.read_json("review.json"))
        except (ValueError, SourceSnapshotError) as exc:
            raise WorkspaceCorruptionError("profile cannot bind without a valid source snapshot") from exc
        if intent.requested_profile != "auto" and binding.name != intent.requested_profile:
            raise ValueError("resolved profile does not match the explicit review intent")
        path = self.session_workspace.path / "profile.json"
        operation = "profile.bound" if path.exists() else "profile.resolved"
        self.session_workspace.write_json_once("profile.json", binding.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.profile-binding-receipt/v1",
            payload={
                "artifact": "profile.json",
                "snapshot_id": snapshot.snapshot_id,
                "profile_sha256": binding.profile_sha256,
            },
        )

    def bind_native_analysis(self, receipt: NativeAnalysisReceipt) -> None:
        """Bind one native analyzer receipt to source and profile identities."""
        try:
            target = ResolvedTarget.from_dict(self.session_workspace.read_json("target.json"))
            snapshot = SourceSnapshot.from_dict(
                self.session_workspace.read_json("snapshot.json"),
                root=target.repository_root,
            )
            binding = ProfileBinding.from_dict(self.session_workspace.read_json("profile.json"))
        except (ValueError, SourceSnapshotError) as exc:
            raise WorkspaceCorruptionError("native analysis cannot bind without source and profile") from exc
        path = self.session_workspace.path / "analysis.json"
        operation = "native.analysis.bound" if path.exists() else "native.analysis.completed"
        self.session_workspace.write_json_once("analysis.json", receipt.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.native-analysis-receipt/v1",
            payload={
                "artifact": "analysis.json",
                "snapshot_id": snapshot.snapshot_id,
                "profile_sha256": binding.profile_sha256,
                "receipt_sha256": receipt.receipt_sha256,
            },
        )

    def bind_facts_resolution(self, receipt: FactsResolutionReceipt) -> None:
        """Bind one shared facts receipt to its native analyzer identity."""
        try:
            native = NativeAnalysisReceipt.from_dict(self.session_workspace.read_json("analysis.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("facts resolution cannot bind without native analysis") from exc
        if receipt.native_analysis_receipt_sha256 != native.receipt_sha256:
            raise WorkspaceCorruptionError("facts resolution does not match the bound native analysis")
        path = self.session_workspace.path / "facts.json"
        operation = "facts.bound" if path.exists() else "facts.resolved"
        self.session_workspace.write_json_once("facts.json", receipt.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.facts-resolution-receipt/v1",
            payload={
                "artifact": "facts.json",
                "native_analysis_receipt_sha256": native.receipt_sha256,
                "receipt_sha256": receipt.receipt_sha256,
            },
        )

    def bind_unit_plan(self, receipt: UnitPlanReceipt) -> None:
        """Bind one deterministic unit worklist to its facts resolution identity."""
        try:
            facts = FactsResolutionReceipt.from_dict(self.session_workspace.read_json("facts.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("unit plan cannot bind without facts resolution") from exc
        if receipt.facts_resolution_receipt_sha256 != facts.receipt_sha256:
            raise WorkspaceCorruptionError("unit plan does not match the bound facts resolution")
        path = self.session_workspace.path / "units.json"
        operation = "units.bound" if path.exists() else "units.planned"
        self.session_workspace.write_json_once("units.json", receipt.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.unit-plan-receipt/v1",
            payload={
                "artifact": "units.json",
                "facts_resolution_receipt_sha256": facts.receipt_sha256,
                "receipt_sha256": receipt.receipt_sha256,
            },
        )

    def bind_grounding(self, receipt: GroundingReceipt, *, duration_seconds: float) -> None:
        """Bind every initial evidence envelope to the current unit plan."""
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int | float)
            or not math.isfinite(duration_seconds)
            or duration_seconds < 0
        ):
            raise ValueError("grounding duration must be a finite nonnegative number")
        try:
            unit_plan = UnitPlanReceipt.from_dict(self.session_workspace.read_json("units.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("grounding cannot bind without a unit plan") from exc
        if receipt.unit_plan_receipt_sha256 != unit_plan.receipt_sha256:
            raise WorkspaceCorruptionError("grounding does not match the bound unit plan")
        if tuple(context.unit_id for context in receipt.contexts) != tuple(unit.id for unit in unit_plan.units):
            raise WorkspaceCorruptionError("grounding contexts do not match the bound unit order")
        if any(
            context.source != ("diff" if unit.kind == "diff" else "repository")
            for unit, context in zip(unit_plan.units, receipt.contexts, strict=True)
        ):
            raise WorkspaceCorruptionError("grounding context sources do not match the bound unit kinds")
        path = self.session_workspace.path / "grounding.json"
        operation = "grounding.bound" if path.exists() else "grounding.prepared"
        self.session_workspace.write_json_once("grounding.json", receipt.to_dict())
        self.workspace.record(
            operation=operation,
            status="complete",
            payload_schema="cyberjury.grounding-receipt/v1",
            payload={
                "artifact": "grounding.json",
                "unit_plan_receipt_sha256": unit_plan.receipt_sha256,
                "receipt_sha256": receipt.receipt_sha256,
                "duration_seconds": duration_seconds,
            },
        )

    @property
    def intent_target(self) -> TargetInput:
        """Return the immutable target intent owned by the parent review session."""
        try:
            return ReviewIntent.from_dict(self.session_workspace.read_json("review.json")).target
        except ValueError as exc:
            raise WorkspaceCorruptionError("review intent artifact is invalid") from exc

    def complete(self, *, exit_code: int) -> None:
        """Close a normally returned command without interpreting its domain verdict."""
        self._validate_completion_ready()
        self._validate_terminal_outcome(complete=True)
        self.workspace.finish(
            state="complete",
            payload_schema="cyberjury.attempt-completed/v1",
            payload={"exit_code": exit_code, "duration_seconds": self._duration()},
        )

    def incomplete(self, *, exit_code: int) -> None:
        """Close a command whose review work returned an incomplete outcome."""
        self._validate_completion_ready()
        self._validate_terminal_outcome(complete=False)
        self.workspace.finish(
            state="incomplete",
            payload_schema="cyberjury.attempt-incomplete/v1",
            payload={"exit_code": exit_code, "duration_seconds": self._duration()},
        )

    def interrupt(self) -> None:
        """Close an attempt stopped by the operator before completion."""
        self.workspace.finish(
            state="interrupted",
            payload_schema="cyberjury.attempt-interrupted/v1",
            payload={"reason": "operator interrupted the command", "duration_seconds": self._duration()},
        )

    def fail(self, exc: BaseException) -> None:
        """Close a command that raised before returning an exit code."""
        self.workspace.finish(
            state="failed",
            payload_schema="cyberjury.attempt-failed/v1",
            payload={"duration_seconds": self._duration()},
            error=safe_error(exc),
        )

    def _validate_completion_ready(self) -> None:
        """Prevent a successful terminal state before every required receipt is bound."""
        _validate_journal(
            self.request,
            self.workspace.read_events(),
            required=_required_stages(self.request, completing=True),
        )

    def _validate_terminal_outcome(self, *, complete: bool) -> None:
        """Prevent the attempt terminal label from contradicting its domain result."""
        if self.request.action != "run":
            return
        try:
            outcome = OutcomeArtifact.from_dict(self.workspace.read_json("outcome.json"))
        except ValueError as exc:
            raise WorkspaceCorruptionError("review outcome artifact is invalid") from exc
        if outcome.complete is not complete:
            raise WorkspaceCorruptionError("attempt terminal state contradicts its review outcome")
