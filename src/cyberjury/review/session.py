"""Review domain composition over generic session and attempt storage."""

from __future__ import annotations

import contextlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberjury.review.contract import ContractReceipt
from cyberjury.review.facts import FactsReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import ReviewAttemptRequest, ReviewIntent
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.target import ResolvedTarget
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import SourceSnapshot
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
        return cls(workspace=workspace, intent=intent)

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

    def start_attempt(self, request: ReviewAttemptRequest) -> ReviewAttempt:
        """Create one invocation whose wire request and runtime request are identical."""
        workspace = self.workspace.start_attempt(request.to_dict())
        attempt = ReviewAttempt(
            workspace=workspace,
            session_workspace=self.workspace,
            intent=self.intent,
            request=request,
        )
        try:
            self._bind_repository_judgment(request)
        except BaseException as exc:
            with contextlib.suppress(BaseException):
                attempt.fail(exc)
            raise
        return attempt

    def _bind_repository_judgment(self, request: ReviewAttemptRequest) -> None:
        """Prevent resumable repository work from changing its judgment provenance."""
        if self.intent.target.kind != "repository" or request.action != "run":
            return
        name = "judgment-configuration.json"
        expected_hash = request.judgment_configuration_sha256
        if (self.workspace.path / name).exists():
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
    """One command invocation and the receipts it bound, in binding order."""

    workspace: AttemptWorkspace
    session_workspace: SessionWorkspace
    intent: ReviewIntent
    request: ReviewAttemptRequest
    _bound: dict[str, object] = field(default_factory=dict, repr=False)
    _started_at: float = field(default_factory=time.monotonic, repr=False)

    def _duration(self) -> float:
        return round(time.monotonic() - self._started_at, 3)

    def _require(self, stage: str) -> Any:
        if stage not in self._bound:
            raise ValueError(f"attempt has no bound {stage}")
        return self._bound[stage]

    def record_model_calls(self, document: dict[str, object]) -> None:
        """Persist the call and usage record built by this command's meter."""
        self.workspace.write_json_once("model-calls.json", document)

    def bind_target(self, target: ResolvedTarget) -> None:
        """Bind one resolved target artifact to this review and attempt."""
        self.session_workspace.write_json_once("target.json", target.to_dict())
        self._bound["target"] = target

    def bind_snapshot(self, snapshot: SourceSnapshot) -> None:
        """Bind or revalidate the source-only manifest for this review."""
        self._require("target")
        self.session_workspace.write_json_once("snapshot.json", snapshot.to_dict())
        self._bound["snapshot"] = snapshot

    def bind_contract(self, receipt: ContractReceipt) -> None:
        """Bind or revalidate the exact review contract content for this review."""
        self._require("snapshot")
        self.session_workspace.write_json_once("contract.json", receipt.to_dict())
        self._bound["contract"] = receipt

    def bind_facts(self, receipt: FactsReceipt) -> None:
        """Bind one facts extraction receipt to source and contract identities."""
        self._require("contract")
        self.session_workspace.write_json_once("facts.json", receipt.to_dict())
        self._bound["facts"] = receipt

    def bind_unit_plan(self, receipt: UnitPlanReceipt) -> None:
        """Bind one deterministic unit worklist to its facts identity."""
        self._require("facts")
        self.session_workspace.write_json_once("units.json", receipt.to_dict())
        self._bound["unit plan"] = receipt

    def bind_grounding(self, receipt: GroundingReceipt) -> None:
        """Bind every initial evidence envelope to the current unit plan."""
        self._require("unit plan")
        self.session_workspace.write_json_once("grounding.json", receipt.to_dict())
        self._bound["grounding"] = receipt

    def bind_result(self, findings: FindingsArtifact, outcome: OutcomeArtifact) -> None:
        """Persist one source bound final result."""
        snapshot = self._require("snapshot")
        if outcome.target != self.intent.target.kind or outcome.source_revision != snapshot.snapshot_id:
            raise ValueError("review result does not match the attempt target snapshot")
        if outcome.findings_sha256 != findings.content_sha256:
            raise ValueError("review outcome does not identify its findings")
        self.workspace.write_json_once("findings.json", findings.to_dict())
        self.workspace.write_json_once("outcome.json", outcome.to_dict())
        self._bound["outcome"] = outcome

    def complete(self, *, exit_code: int) -> None:
        """Close a normally returned command without interpreting its domain verdict."""
        self._validate_terminal_outcome(complete=True)
        self.workspace.finish(
            state="complete",
            detail={"exit_code": exit_code, "duration_seconds": self._duration()},
        )

    def incomplete(self, *, exit_code: int) -> None:
        """Close a command whose review work returned an incomplete outcome."""
        self._validate_terminal_outcome(complete=False)
        self.workspace.finish(
            state="incomplete",
            detail={"exit_code": exit_code, "duration_seconds": self._duration()},
        )

    def interrupt(self) -> None:
        """Close an attempt stopped by the operator before completion."""
        self.workspace.finish(
            state="interrupted",
            detail={"reason": "operator interrupted the command", "duration_seconds": self._duration()},
        )

    def fail(self, exc: BaseException) -> None:
        """Close a command that raised before returning an exit code."""
        self.workspace.finish(
            state="failed",
            detail={"duration_seconds": self._duration()},
            error=safe_error(exc),
        )

    def _validate_terminal_outcome(self, *, complete: bool) -> None:
        """Prevent the attempt terminal label from contradicting its domain result."""
        if self.request.action != "run":
            return
        if self._require("outcome").complete is not complete:
            raise ValueError("attempt terminal state contradicts its review outcome")
