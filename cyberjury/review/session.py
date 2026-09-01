"""Review domain composition over generic session and attempt storage."""

from __future__ import annotations

import contextlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.review.request import ReviewAttemptRequest, ReviewIntent
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
        attempt = ReviewAttempt(workspace=workspace, request=request)
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
