"""Review domain composition over generic session and attempt storage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cyberjury.record import Record
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.facts import FactsReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import ReviewAttemptRequest, ReviewIntent
from cyberjury.review.result import FindingsArtifact, SkippedFiles
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import (
    AttemptWorkspace,
    SessionConflictError,
    SessionLocator,
    SessionWorkspace,
    WorkspaceCorruptionError,
    new_session_id,
)

JUDGMENT_CONFIGURATION_SCHEMA = "cyberjury.judgment-configuration/v1"
_SESSION_ARTIFACTS: dict[type, str] = {
    ResolvedTarget: "target/target.json",
    SourceSnapshot: "source/snapshot.json",
    ContractReceipt: "source/contract.json",
    FactsReceipt: "facts/facts.json",
    UnitPlanReceipt: "plan/plan.json",
    SkippedFiles: "plan/skipped-files.json",
    GroundingReceipt: "grounding/grounding.json",
}


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
        workspace.write_json_once("session/intent.json", intent.to_dict())
        return cls(workspace=workspace, intent=intent)

    @classmethod
    def create(cls, root: str | Path, intent: ReviewIntent) -> ReviewSession:
        """Create one independent review session."""
        return cls.open(root, intent, review_id=new_session_id("review"))

    @classmethod
    def open_existing(cls, root: str | Path, intent: ReviewIntent, *, review_id: str) -> ReviewSession:
        """Open an existing review id without creating a session for a typo."""
        if not re.fullmatch(r"review-\d{8}-\d{6}-[0-9a-f]{8}", review_id):
            raise ValueError("review id is invalid")
        path = Path(root).expanduser() / "reviews" / review_id
        if not path.is_dir() or path.is_symlink():
            raise SessionConflictError(f"review session {review_id} no longer exists, start again with --fresh")
        return cls.open(root, intent, review_id=review_id)

    @classmethod
    def select_active(
        cls,
        root: str | Path,
        intent: ReviewIntent,
        *,
        reuse: bool,
    ) -> ReviewSession:
        """Select the active repository review or publish a new one."""
        locator = SessionLocator.open(root, namespace="reviews")
        review_id, created = locator.select_with_state(
            intent.intent_sha256,
            kind="review",
            reuse=reuse,
        )
        if created:
            return cls.open(root, intent, review_id=review_id)
        return cls.open_existing(root, intent, review_id=review_id)

    def start_attempt(
        self, request: ReviewAttemptRequest, *, attempt_id: str | None = None, started_at: str | None = None
    ) -> ReviewAttempt:
        """Create one invocation whose wire request and runtime request are identical."""
        self._bind_repository_judgment(request)
        workspace = self.workspace.start_attempt(
            request.to_dict(), attempt_id=attempt_id, started_at=started_at, attributes={"source_changed": None}
        )
        return ReviewAttempt(workspace=workspace, session_workspace=self.workspace)

    def _bind_repository_judgment(self, request: ReviewAttemptRequest) -> None:
        if self.intent.target.kind != "repository":
            return
        name = "session/judgment-configuration.json"
        expected_hash = request.judgment_configuration_sha256
        if (self.workspace.path / name).exists():
            bound = self.workspace.read_json(name)
            fields = {"schema", "judgment_configuration_sha256"}
            if set(bound) != fields or bound["schema"] != JUDGMENT_CONFIGURATION_SCHEMA:
                raise WorkspaceCorruptionError("repository judgment configuration has an invalid schema")
            if bound["judgment_configuration_sha256"] != expected_hash:
                raise SessionConflictError("repository judgment configuration changed, start again with --fresh")
            return
        self.workspace.write_json_once(
            name,
            {
                "schema": JUDGMENT_CONFIGURATION_SCHEMA,
                "judgment_configuration_sha256": expected_hash,
            },
        )


@dataclass(frozen=True, kw_only=True)
class ReviewAttempt:
    """One command invocation and the artifacts it wrote, each under the stage that produced it."""

    workspace: AttemptWorkspace
    session_workspace: SessionWorkspace

    @property
    def attempt_path(self) -> str:
        """Return this attempt directory relative to its review."""
        return f"attempts/{self.workspace.attempt_id}"

    def bind(self, value: object) -> str:
        """Write one stage artifact under the review or this attempt and return its artifact path."""
        if isinstance(value, FindingsArtifact):
            return self._write_own("findings.json", value.to_dict())
        name = _SESSION_ARTIFACTS.get(type(value))
        if name is None:
            raise TypeError(f"no artifact path for {type(value).__name__}")
        self.session_workspace.write_json_once(name, value.to_dict())
        return name

    def _write_own(self, name: str, value: dict[str, object]) -> str:
        self.workspace.write_json_once(name, value)
        return f"{self.attempt_path}/{name}"

    def write_model_calls(self, document: dict[str, object]) -> str:
        """Write this attempt's model call record and return the artifact path."""
        return self._write_own("model-calls.json", document)

    def write_stage(self, record: Record) -> None:
        """Write one stage record of this attempt."""
        self.workspace.write_stage(record)

    def finish(self, record: Record) -> None:
        """Write the terminal attempt record."""
        self.workspace.finish(record)
