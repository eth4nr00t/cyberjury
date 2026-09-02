"""Review domain composition over generic session and attempt storage."""

from __future__ import annotations

import contextlib
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.profiles.base import ProfileBinding
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import ReviewAttemptRequest, ReviewIntent, TargetInput
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
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
    expected = {
        request.providers.base_seat_id,
        request.providers.finder_seat_id,
        request.providers.challenger_seat_id,
        request.providers.judge_seat_id,
    } - {None}
    if request.verification is not None:
        expected.update(
            {
                request.verification.skeptic_seat_id,
                *request.verification.confirmer_seat_ids,
            }
            - {None}
        )
    return tuple(sorted(expected))


def _validate_source_binding(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 02 target and snapshot receipts against session artifacts."""
    targets = [event for event in events if event["operation"] in {"target.resolved", "target.bound"}]
    snapshots = [
        event for event in events if event["operation"] in {"source.snapshot.captured", "source.snapshot.validated"}
    ]
    if len(targets) > 1 or len(snapshots) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate source binding receipts")
    if not targets:
        if snapshots:
            raise WorkspaceCorruptionError("attempt source snapshot has no resolved target")
        if required:
            raise WorkspaceCorruptionError("completed attempt has no source binding")
        return
    try:
        target = ResolvedTarget.from_dict(workspace.read_json("target.json"))
        intent = ReviewIntent.from_dict(workspace.read_json("review.json"))
    except (ValueError, SourceSnapshotError) as exc:
        raise WorkspaceCorruptionError("resolved target artifact is invalid") from exc
    requested_root = Path(intent.target.repository).resolve()
    resolved_root = Path(target.repository_root)
    if target.kind != intent.target.kind:
        raise WorkspaceCorruptionError("resolved target kind does not match review intent")
    if target.kind == "repository" and requested_root != resolved_root:
        raise WorkspaceCorruptionError("repository target root does not match review intent")
    if target.kind == "diff" and requested_root != resolved_root and not requested_root.is_relative_to(resolved_root):
        raise WorkspaceCorruptionError("diff Git root does not contain the requested repository path")
    if target.kind == "diff" and (target.git is None or target.git.requested_range != intent.target.git_range):
        raise WorkspaceCorruptionError("resolved Git range does not match review intent")
    target_payload = targets[0]["payload"]
    if (
        targets[0]["status"] != "complete"
        or target_payload["schema"] != "cyberjury.target-binding/v1"
        or set(target_payload["data"]) != {"artifact", "target_sha256"}
        or target_payload["data"]["artifact"] != "target.json"
        or target_payload["data"]["target_sha256"] != target.target_sha256
    ):
        raise WorkspaceCorruptionError("attempt target receipt is invalid")
    if not snapshots:
        if required:
            raise WorkspaceCorruptionError("completed attempt has no source snapshot binding")
        return
    try:
        snapshot = SourceSnapshot.from_dict(workspace.read_json("snapshot.json"), root=target.repository_root)
    except (ValueError, SourceSnapshotError) as exc:
        raise WorkspaceCorruptionError("source snapshot artifact is invalid") from exc
    snapshot_payload = snapshots[0]["payload"]
    if (
        snapshots[0]["status"] != "complete"
        or snapshot_payload["schema"] != "cyberjury.source-snapshot-binding/v1"
        or set(snapshot_payload["data"]) != {"artifact", "target_sha256", "snapshot_id", "file_count", "total_bytes"}
        or snapshot_payload["data"]["artifact"] != "snapshot.json"
        or snapshot_payload["data"]["target_sha256"] != target.target_sha256
        or snapshot_payload["data"]["snapshot_id"] != snapshot.snapshot_id
        or snapshot_payload["data"]["file_count"] != len(snapshot.entries)
        or snapshot_payload["data"]["total_bytes"] != snapshot.total_bytes
    ):
        raise WorkspaceCorruptionError("attempt source snapshot receipt is invalid")
    normalized_index = next(
        index for index, event in enumerate(events) if event["operation"] == "configuration.normalized"
    )
    target_index = events.index(targets[0])
    snapshot_index = events.index(snapshots[0])
    if not normalized_index < target_index < snapshot_index:
        raise WorkspaceCorruptionError("attempt source binding order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= snapshot_index:
        raise WorkspaceCorruptionError("attempt provider route precedes source snapshot")


def _validate_profile_binding(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 03 profile selection against its source snapshot."""
    profiles = [event for event in events if event["operation"] in {"profile.resolved", "profile.bound"}]
    snapshots = [
        event for event in events if event["operation"] in {"source.snapshot.captured", "source.snapshot.validated"}
    ]
    if len(profiles) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate profile binding receipts")
    if not profiles:
        if required:
            raise WorkspaceCorruptionError("completed attempt has no profile binding")
        return
    if len(snapshots) != 1:
        raise WorkspaceCorruptionError("attempt profile binding has no source snapshot")
    try:
        binding = ProfileBinding.from_dict(workspace.read_json("profile.json"))
        target = ResolvedTarget.from_dict(workspace.read_json("target.json"))
        snapshot = SourceSnapshot.from_dict(workspace.read_json("snapshot.json"), root=target.repository_root)
        intent = ReviewIntent.from_dict(workspace.read_json("review.json"))
    except (ValueError, SourceSnapshotError) as exc:
        raise WorkspaceCorruptionError("resolved profile artifact is invalid") from exc
    if intent.requested_profile != "auto" and binding.name != intent.requested_profile:
        raise WorkspaceCorruptionError("resolved profile does not match the explicit review intent")
    payload = profiles[0]["payload"]
    if (
        profiles[0]["status"] != "complete"
        or payload["schema"] != "cyberjury.profile-binding-receipt/v1"
        or set(payload["data"]) != {"artifact", "snapshot_id", "profile_sha256"}
        or payload["data"]["artifact"] != "profile.json"
        or payload["data"]["snapshot_id"] != snapshot.snapshot_id
        or payload["data"]["profile_sha256"] != binding.profile_sha256
    ):
        raise WorkspaceCorruptionError("attempt profile binding receipt is invalid")
    profile_index = events.index(profiles[0])
    snapshot_index = events.index(snapshots[0])
    if profile_index <= snapshot_index:
        raise WorkspaceCorruptionError("attempt profile binding order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= profile_index:
        raise WorkspaceCorruptionError("attempt provider route precedes profile binding")


def _validate_native_analysis(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 04 native analyzer identity against source and profile artifacts."""
    analyses = [
        event for event in events if event["operation"] in {"native.analysis.completed", "native.analysis.bound"}
    ]
    if len(analyses) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate native analysis receipts")
    if not analyses:
        if required:
            raise WorkspaceCorruptionError("completed review action has no native analysis receipt")
        return
    profiles = [event for event in events if event["operation"] in {"profile.resolved", "profile.bound"}]
    if len(profiles) != 1:
        raise WorkspaceCorruptionError("attempt native analysis has no profile binding")
    try:
        receipt = NativeAnalysisReceipt.from_dict(workspace.read_json("analysis.json"))
        binding = ProfileBinding.from_dict(workspace.read_json("profile.json"))
        target = ResolvedTarget.from_dict(workspace.read_json("target.json"))
        snapshot = SourceSnapshot.from_dict(workspace.read_json("snapshot.json"), root=target.repository_root)
    except (ValueError, SourceSnapshotError) as exc:
        raise WorkspaceCorruptionError("native analysis artifact is invalid") from exc
    payload = analyses[0]["payload"]
    if (
        analyses[0]["status"] != "complete"
        or payload["schema"] != "cyberjury.native-analysis-receipt/v1"
        or set(payload["data"]) != {"artifact", "snapshot_id", "profile_sha256", "receipt_sha256"}
        or payload["data"]["artifact"] != "analysis.json"
        or payload["data"]["snapshot_id"] != snapshot.snapshot_id
        or payload["data"]["profile_sha256"] != binding.profile_sha256
        or payload["data"]["receipt_sha256"] != receipt.receipt_sha256
    ):
        raise WorkspaceCorruptionError("attempt native analysis receipt is invalid")
    if events.index(analyses[0]) <= events.index(profiles[0]):
        raise WorkspaceCorruptionError("attempt native analysis order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= events.index(analyses[0]):
        raise WorkspaceCorruptionError("attempt provider route precedes native analysis")


def _validate_facts_resolution(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 05 shared facts identity against the native analysis artifact."""
    resolutions = [event for event in events if event["operation"] in {"facts.resolved", "facts.bound"}]
    if len(resolutions) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate facts resolution receipts")
    if not resolutions:
        if required:
            raise WorkspaceCorruptionError("completed review action has no facts resolution receipt")
        return
    analyses = [
        event for event in events if event["operation"] in {"native.analysis.completed", "native.analysis.bound"}
    ]
    if len(analyses) != 1:
        raise WorkspaceCorruptionError("attempt facts resolution has no native analysis binding")
    try:
        receipt = FactsResolutionReceipt.from_dict(workspace.read_json("facts.json"))
        native = NativeAnalysisReceipt.from_dict(workspace.read_json("analysis.json"))
    except ValueError as exc:
        raise WorkspaceCorruptionError("facts resolution artifact is invalid") from exc
    payload = resolutions[0]["payload"]
    if (
        resolutions[0]["status"] != "complete"
        or payload["schema"] != "cyberjury.facts-resolution-receipt/v1"
        or set(payload["data"]) != {"artifact", "native_analysis_receipt_sha256", "receipt_sha256"}
        or payload["data"]["artifact"] != "facts.json"
        or payload["data"]["native_analysis_receipt_sha256"] != native.receipt_sha256
        or payload["data"]["native_analysis_receipt_sha256"] != receipt.native_analysis_receipt_sha256
        or payload["data"]["receipt_sha256"] != receipt.receipt_sha256
    ):
        raise WorkspaceCorruptionError("attempt facts resolution receipt is invalid")
    if events.index(resolutions[0]) <= events.index(analyses[0]):
        raise WorkspaceCorruptionError("attempt facts resolution order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= events.index(resolutions[0]):
        raise WorkspaceCorruptionError("attempt provider route precedes facts resolution")


def _validate_unit_plan(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 06 unit ownership against the shared facts artifact."""
    plans = [event for event in events if event["operation"] in {"units.planned", "units.bound"}]
    if len(plans) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate unit plan receipts")
    if not plans:
        if required:
            raise WorkspaceCorruptionError("completed review action has no unit plan receipt")
        return
    resolutions = [event for event in events if event["operation"] in {"facts.resolved", "facts.bound"}]
    if len(resolutions) != 1:
        raise WorkspaceCorruptionError("attempt unit plan has no facts resolution binding")
    try:
        receipt = UnitPlanReceipt.from_dict(workspace.read_json("units.json"))
        facts = FactsResolutionReceipt.from_dict(workspace.read_json("facts.json"))
    except ValueError as exc:
        raise WorkspaceCorruptionError("unit plan artifact is invalid") from exc
    payload = plans[0]["payload"]
    if (
        plans[0]["status"] != "complete"
        or payload["schema"] != "cyberjury.unit-plan-receipt/v1"
        or set(payload["data"]) != {"artifact", "facts_resolution_receipt_sha256", "receipt_sha256"}
        or payload["data"]["artifact"] != "units.json"
        or payload["data"]["facts_resolution_receipt_sha256"] != facts.receipt_sha256
        or payload["data"]["facts_resolution_receipt_sha256"] != receipt.facts_resolution_receipt_sha256
        or payload["data"]["receipt_sha256"] != receipt.receipt_sha256
    ):
        raise WorkspaceCorruptionError("attempt unit plan receipt is invalid")
    if events.index(plans[0]) <= events.index(resolutions[0]):
        raise WorkspaceCorruptionError("attempt unit plan order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= events.index(plans[0]):
        raise WorkspaceCorruptionError("attempt provider route precedes unit planning")


def _validate_grounding(
    workspace: SessionWorkspace,
    events: tuple[dict[str, object], ...],
    *,
    required: bool,
) -> None:
    """Validate Stage 07 evidence envelopes against the Stage 06 worklist."""
    groundings = [event for event in events if event["operation"] in {"grounding.prepared", "grounding.bound"}]
    if len(groundings) > 1:
        raise WorkspaceCorruptionError("attempt has duplicate grounding receipts")
    if not groundings:
        if required:
            raise WorkspaceCorruptionError("completed review action has no grounding receipt")
        return
    plans = [event for event in events if event["operation"] in {"units.planned", "units.bound"}]
    if len(plans) != 1:
        raise WorkspaceCorruptionError("attempt grounding has no unit plan binding")
    try:
        receipt = GroundingReceipt.from_dict(workspace.read_json("grounding.json"))
        unit_plan = UnitPlanReceipt.from_dict(workspace.read_json("units.json"))
    except ValueError as exc:
        raise WorkspaceCorruptionError("grounding artifact is invalid") from exc
    if receipt.unit_plan_receipt_sha256 != unit_plan.receipt_sha256:
        raise WorkspaceCorruptionError("grounding receipt does not match the unit plan")
    if tuple(context.unit_id for context in receipt.contexts) != tuple(unit.id for unit in unit_plan.units):
        raise WorkspaceCorruptionError("grounding contexts do not match unit plan order")
    if any(
        context.source != ("diff" if unit.kind == "diff" else "repository")
        for unit, context in zip(unit_plan.units, receipt.contexts, strict=True)
    ):
        raise WorkspaceCorruptionError("grounding context sources do not match unit kinds")
    payload = groundings[0]["payload"]
    if (
        groundings[0]["status"] != "complete"
        or payload["schema"] != "cyberjury.grounding-receipt/v1"
        or set(payload["data"]) != {"artifact", "unit_plan_receipt_sha256", "receipt_sha256", "duration_seconds"}
        or payload["data"]["artifact"] != "grounding.json"
        or payload["data"]["unit_plan_receipt_sha256"] != unit_plan.receipt_sha256
        or payload["data"]["receipt_sha256"] != receipt.receipt_sha256
        or isinstance(payload["data"]["duration_seconds"], bool)
        or not isinstance(payload["data"]["duration_seconds"], (int, float))
        or not math.isfinite(payload["data"]["duration_seconds"])
        or payload["data"]["duration_seconds"] < 0
    ):
        raise WorkspaceCorruptionError("attempt grounding receipt is invalid")
    if events.index(groundings[0]) <= events.index(plans[0]):
        raise WorkspaceCorruptionError("attempt grounding order is invalid")
    route_indexes = [index for index, event in enumerate(events) if event["operation"] == "provider.route.resolved"]
    if route_indexes and route_indexes[0] <= events.index(groundings[0]):
        raise WorkspaceCorruptionError("attempt provider route precedes grounding")


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
        """Validate every persisted request and its Stage 01 journal receipts."""
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
            normalized = [event for event in events if event["operation"] == "configuration.normalized"]
            if not normalized:
                if events and events[-1]["operation"] in {"attempt.complete", "attempt.incomplete"}:
                    raise WorkspaceCorruptionError("completed attempt has no normalized configuration")
                self._validate_terminal_event(events)
                continue
            if len(normalized) != 1:
                raise WorkspaceCorruptionError("attempt has duplicate normalized configuration events")
            payload = normalized[0]["payload"]
            if (
                normalized[0]["status"] != "complete"
                or payload["schema"] != "cyberjury.configuration-normalized/v1"
                or set(payload["data"]) != {"configuration_sha256"}
                or payload["data"]["configuration_sha256"] != request.request_sha256
            ):
                raise WorkspaceCorruptionError("attempt normalized configuration receipt is invalid")
            self._validate_provider_route(request, events)
            terminal_success = events and events[-1]["operation"] in {"attempt.complete", "attempt.incomplete"}
            _validate_source_binding(self.workspace, events, required=bool(terminal_success))
            _validate_profile_binding(self.workspace, events, required=bool(terminal_success))
            _validate_native_analysis(
                self.workspace,
                events,
                required=bool(terminal_success and request.action in {"run", "scaffold"}),
            )
            _validate_facts_resolution(
                self.workspace,
                events,
                required=bool(terminal_success and request.action in {"run", "scaffold"}),
            )
            _validate_unit_plan(
                self.workspace,
                events,
                required=bool(terminal_success and request.action in {"run", "scaffold"}),
            )
            _validate_grounding(
                self.workspace,
                events,
                required=bool(terminal_success and request.action in {"run", "scaffold"}),
            )
            self._validate_terminal_event(events)

    @staticmethod
    def _validate_provider_route(
        request: ReviewAttemptRequest,
        events: tuple[dict[str, object], ...],
        *,
        required: bool = False,
    ) -> None:
        routes = [event for event in events if event["operation"] == "provider.route.resolved"]
        if len(routes) > 1:
            raise WorkspaceCorruptionError("attempt has duplicate provider route events")
        if not routes:
            terminal_requires_route = events and events[-1]["operation"] in {
                "attempt.complete",
                "attempt.incomplete",
            }
            if request.providers is not None and (required or terminal_requires_route):
                raise WorkspaceCorruptionError("completed model action has no provider route receipt")
            return
        if request.providers is None:
            raise WorkspaceCorruptionError("attempt provider route has no provider plan")
        payload = routes[0]["payload"]
        if (
            routes[0]["status"] != "complete"
            or payload["schema"] != "cyberjury.provider-route/v1"
            or set(payload["data"]) != {"configured_seat_ids"}
            or not isinstance(payload["data"]["configured_seat_ids"], list)
        ):
            raise WorkspaceCorruptionError("attempt provider route receipt is invalid")
        configured = payload["data"]["configured_seat_ids"]
        if configured != list(_configured_seat_ids(request)):
            raise WorkspaceCorruptionError("attempt provider route does not match its request")
        normalized_index = next(
            index for index, event in enumerate(events) if event["operation"] == "configuration.normalized"
        )
        route_index = events.index(routes[0])
        if route_index <= normalized_index:
            raise WorkspaceCorruptionError("attempt provider route precedes normalized configuration")

    @staticmethod
    def _validate_terminal_event(events: tuple[dict[str, object], ...]) -> None:
        """Validate the operation-specific terminal payload owned by Stage 01."""
        if not events or not events[-1]["operation"].startswith("attempt."):
            return
        event = events[-1]
        payload = event["payload"]
        operation = event["operation"]
        schemas = {
            "attempt.complete": "cyberjury.attempt-completed/v1",
            "attempt.incomplete": "cyberjury.attempt-incomplete/v1",
            "attempt.failed": "cyberjury.attempt-failed/v1",
            "attempt.interrupted": "cyberjury.attempt-interrupted/v1",
        }
        if payload["schema"] != schemas.get(operation):
            raise WorkspaceCorruptionError("attempt terminal payload schema is invalid")
        if operation != "attempt.failed" and event["error"] is not None:
            raise WorkspaceCorruptionError("nonfailed attempt terminal event cannot have an error")
        data = payload["data"]
        if operation in {"attempt.complete", "attempt.incomplete"}:
            if (
                set(data) != {"exit_code", "duration_seconds"}
                or isinstance(data["exit_code"], bool)
                or not isinstance(data["exit_code"], int)
            ):
                raise WorkspaceCorruptionError("attempt terminal exit code is invalid")
        elif operation == "attempt.failed":
            if set(data) != {"duration_seconds"} or event["error"] is None:
                raise WorkspaceCorruptionError("failed attempt terminal payload is invalid")
        elif set(data) != {"reason", "duration_seconds"} or not isinstance(data["reason"], str):
            raise WorkspaceCorruptionError("interrupted attempt terminal payload is invalid")
        duration = data["duration_seconds"]
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration < 0:
            raise WorkspaceCorruptionError("attempt terminal duration is invalid")

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
        self.workspace.finish(
            state="complete",
            payload_schema="cyberjury.attempt-completed/v1",
            payload={"exit_code": exit_code, "duration_seconds": self._duration()},
        )

    def incomplete(self, *, exit_code: int) -> None:
        """Close a command whose review work returned an incomplete outcome."""
        self._validate_completion_ready()
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
        """Prevent a successful terminal state before required receipts are valid."""
        events = self.workspace.read_events()
        normalized = [event for event in events if event["operation"] == "configuration.normalized"]
        if len(normalized) != 1:
            raise WorkspaceCorruptionError("attempt cannot complete without normalized configuration")
        payload = normalized[0]["payload"]
        if (
            normalized[0]["status"] != "complete"
            or payload["schema"] != "cyberjury.configuration-normalized/v1"
            or set(payload["data"]) != {"configuration_sha256"}
            or payload["data"]["configuration_sha256"] != self.request.request_sha256
        ):
            raise WorkspaceCorruptionError("attempt normalized configuration receipt is invalid")
        ReviewSession._validate_provider_route(
            self.request,
            events,
            required=self.request.providers is not None,
        )
        _validate_source_binding(self.session_workspace, events, required=True)
        _validate_profile_binding(self.session_workspace, events, required=True)
        _validate_native_analysis(
            self.session_workspace,
            events,
            required=self.request.action in {"run", "scaffold"},
        )
        _validate_facts_resolution(
            self.session_workspace,
            events,
            required=self.request.action in {"run", "scaffold"},
        )
        _validate_unit_plan(
            self.session_workspace,
            events,
            required=self.request.action in {"run", "scaffold"},
        )
        _validate_grounding(
            self.session_workspace,
            events,
            required=self.request.action in {"run", "scaffold"},
        )
