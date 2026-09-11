"""Strict shared findings and outcome artifacts for every review target."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from cyberjury.review.engine import ReviewOutcome
from cyberjury.severity import SEVERITIES, index
from cyberjury.sources.metadata import SourceError, SourceMeta, source_meta_from_dict

FINDINGS_SCHEMA = "cyberjury.findings/v1"
OUTCOME_SCHEMA = "cyberjury.review-outcome/v1"
RESULT_SCHEMA = "cyberjury.review-result/v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: object, label: str) -> str:
    invalid = (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    )
    if invalid:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


def _source_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("finding file must be a nonempty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or ".." in path.parts or "." in path.parts:
        raise ValueError("finding file must be a safe relative POSIX path")
    return value


def _source_meta(value: object) -> SourceMeta:
    if not isinstance(value, dict) or set(value) != set(SourceMeta().to_dict()):
        raise SourceError("source metadata has an unsupported or nonexact schema")
    if value.get("schema") != SourceMeta().to_dict()["schema"]:
        raise SourceError("source metadata schema is unsupported")
    metadata = source_meta_from_dict(value)
    if metadata.to_dict() != value:
        raise SourceError("source metadata fields have invalid persisted types")
    return metadata


@dataclass(frozen=True, slots=True, kw_only=True)
class ChangeLocation:
    """One exact changed line that caused or exposed a diff finding."""

    file: str
    line: int
    side: Literal["old", "new"]

    def __post_init__(self) -> None:
        """Reject locations that cannot name one immutable source line."""
        _source_path(self.file)
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("finding change line must be positive")
        if self.side not in {"old", "new"}:
            raise ValueError("finding change side must be old or new")

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"file": self.file, "line": self.line, "side": self.side}

    @classmethod
    def from_dict(cls, value: object) -> ChangeLocation:
        """Parse one strict change location."""
        if not isinstance(value, dict) or set(value) != {"file", "line", "side"}:
            raise ValueError("finding change location has an invalid shape")
        return cls(file=value["file"], line=value["line"], side=value["side"])


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingRecord:
    """One target neutral logical finding ready for output."""

    id: str
    category: str
    decision_rule_id: str
    severity: str
    file: str
    line: int
    entrypoint: str
    summary: str
    evidence: str
    attack_path: str
    recommendation: str
    status: Literal["confirmed", "blocked"]
    evidence_refs: tuple[str, ...]
    supporting_reviewers: tuple[str, ...]
    change_anchor: ChangeLocation | None = None

    def __post_init__(self) -> None:
        """Reject findings that cannot be reported or identified."""
        if not isinstance(self.id, str) or re.fullmatch(r"candidate-[0-9a-f]{20}", self.id) is None:
            raise ValueError("finding id must use the candidate namespace")
        for name in (
            "category",
            "decision_rule_id",
            "entrypoint",
            "summary",
            "evidence",
            "attack_path",
            "recommendation",
        ):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"finding {name} must be a string")
        if not self.category or not self.summary:
            raise ValueError("finding category and summary must be nonempty")
        if self.severity not in SEVERITIES:
            raise ValueError("finding severity is invalid")
        _source_path(self.file)
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("finding line must be positive")
        if self.change_anchor is not None and not isinstance(self.change_anchor, ChangeLocation):
            raise ValueError("finding change anchor is invalid")
        if self.status not in {"confirmed", "blocked"}:
            raise ValueError("finding status is invalid")
        for name in ("evidence_refs", "supporting_reviewers"):
            values = getattr(self, name)
            if (
                not isinstance(values, tuple)
                or not all(isinstance(value, str) and value for value in values)
                or len(set(values)) != len(values)
            ):
                raise ValueError(f"finding {name} must be a unique string tuple")
        if self.supporting_reviewers != tuple(sorted(self.supporting_reviewers)):
            raise ValueError("finding supporting reviewers must use canonical order")

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {
            "id": self.id,
            "category": self.category,
            "decision_rule_id": self.decision_rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "entrypoint": self.entrypoint,
            "summary": self.summary,
            "evidence": self.evidence,
            "attack_path": self.attack_path,
            "recommendation": self.recommendation,
            "status": self.status,
            "evidence_refs": list(self.evidence_refs),
            "supporting_reviewers": list(self.supporting_reviewers),
            "change_anchor": self.change_anchor.to_dict() if self.change_anchor is not None else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> FindingRecord:
        """Parse one strict logical finding."""
        fields = {
            "id",
            "category",
            "decision_rule_id",
            "severity",
            "file",
            "line",
            "entrypoint",
            "summary",
            "evidence",
            "attack_path",
            "recommendation",
            "status",
            "evidence_refs",
            "supporting_reviewers",
            "change_anchor",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("finding record has an invalid shape")
        anchor = value["change_anchor"]
        if not isinstance(value["evidence_refs"], list) or not isinstance(value["supporting_reviewers"], list):
            raise ValueError("finding provenance collections are invalid")
        return cls(
            **{
                key: tuple(item) if key in {"evidence_refs", "supporting_reviewers"} else item
                for key, item in value.items()
                if key != "change_anchor"
            },
            change_anchor=ChangeLocation.from_dict(anchor) if anchor is not None else None,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingsArtifact:
    """The ordered logical finding set shared by Diff and Repository Review."""

    findings: tuple[FindingRecord, ...]
    summary: tuple[tuple[str, int], ...]
    target: SourceMeta | None
    content_sha256: str
    schema: str = FINDINGS_SCHEMA

    def __post_init__(self) -> None:
        """Verify the finding set, summary, and content identity."""
        if self.schema != FINDINGS_SCHEMA:
            raise ValueError("findings artifact schema is unsupported")
        if not isinstance(self.findings, tuple) or not all(isinstance(item, FindingRecord) for item in self.findings):
            raise ValueError("findings artifact findings must be a finding tuple")
        if len({item.id for item in self.findings}) != len(self.findings):
            raise ValueError("findings artifact candidate ids must be unique")
        expected_order = tuple(
            sorted(self.findings, key=lambda item: (index(item.severity), item.file, item.line, item.id))
        )
        if self.findings != expected_order:
            raise ValueError("findings artifact findings must use canonical order")
        if self.target is not None and not isinstance(self.target, SourceMeta):
            raise ValueError("findings artifact target must be source metadata or null")
        expected_summary = tuple(
            (severity, sum(item.severity == severity for item in self.findings)) for severity in SEVERITIES
        )
        if self.summary != expected_summary:
            raise ValueError("findings summary does not match its finding set")
        if any(isinstance(count, bool) or not isinstance(count, int) for _severity, count in self.summary):
            raise ValueError("findings summary counts must be integers")
        if self.content_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("findings content hash does not match its artifact")

    @classmethod
    def create(
        cls,
        findings: tuple[FindingRecord, ...],
        *,
        target: SourceMeta | None = None,
    ) -> FindingsArtifact:
        """Create a canonical finding set and bind its content hash."""
        ordered = tuple(sorted(findings, key=lambda item: (index(item.severity), item.file, item.line, item.id)))
        summary = tuple((severity, sum(item.severity == severity for item in ordered)) for severity in SEVERITIES)
        semantic = {
            "findings": [item.to_dict() for item in ordered],
            "summary": dict(summary),
            "target": target.to_dict() if target is not None else None,
        }
        return cls(findings=ordered, summary=summary, target=target, content_sha256=_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return the content covered by the artifact hash."""
        return {
            "findings": [item.to_dict() for item in self.findings],
            "summary": dict(self.summary),
            "target": self.target.to_dict() if self.target is not None else None,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"schema": self.schema, **self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object) -> FindingsArtifact:
        """Parse and verify one findings artifact."""
        fields = {"schema", "findings", "summary", "target", "content_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("findings artifact has an invalid shape")
        if not isinstance(value["findings"], list) or not isinstance(value["summary"], dict):
            raise ValueError("findings artifact collections are invalid")
        if set(value["summary"]) != set(SEVERITIES):
            raise ValueError("findings artifact summary severities are invalid")
        try:
            target = _source_meta(value["target"]) if value["target"] is not None else None
            return cls(
                schema=value["schema"],
                findings=tuple(FindingRecord.from_dict(item) for item in value["findings"]),
                summary=tuple((severity, value["summary"][severity]) for severity in SEVERITIES),
                target=target,
                content_sha256=value["content_sha256"],
            )
        except SourceError as exc:
            raise ValueError("findings artifact target metadata is invalid") from exc


@dataclass(frozen=True, slots=True, kw_only=True)
class OutcomeArtifact:
    """The strict target neutral completion state for one review result."""

    target: Literal["diff", "repository"]
    source_revision: str
    findings_sha256: str
    status: Literal["complete", "incomplete"]
    complete: bool
    errors: int
    failures: int
    incomplete: int
    pending: int
    grounding_missing: int
    grounding_unresolved: int
    limitations: int
    requires_convergence: bool
    converged: bool
    rounds: int
    failure_reason: str
    content_sha256: str
    schema: str = OUTCOME_SCHEMA

    def __post_init__(self) -> None:
        """Verify completion from its controlling facts and content hash."""
        if self.schema != OUTCOME_SCHEMA or self.target not in {"diff", "repository"}:
            raise ValueError("review outcome schema or target is invalid")
        _digest(self.source_revision, "review outcome source revision")
        _digest(self.findings_sha256, "review outcome findings hash")
        if self.status not in {"complete", "incomplete"} or not isinstance(self.complete, bool):
            raise ValueError("review outcome status is invalid")
        for name in (
            "errors",
            "failures",
            "incomplete",
            "pending",
            "grounding_missing",
            "grounding_unresolved",
            "limitations",
            "rounds",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"review outcome {name} must be a nonnegative integer")
        if not isinstance(self.requires_convergence, bool) or not isinstance(self.converged, bool):
            raise ValueError("review outcome convergence state is invalid")
        if not isinstance(self.failure_reason, str):
            raise ValueError("review outcome failure reason must be a string")
        expected_complete = (not self.requires_convergence or self.converged) and not any(
            (
                self.errors,
                self.failures,
                self.incomplete,
                self.pending,
                self.grounding_missing,
                self.grounding_unresolved,
                self.limitations,
                self.failure_reason,
            )
        )
        if self.complete != expected_complete or self.status != ("complete" if self.complete else "incomplete"):
            raise ValueError("review outcome completion contradicts its counters")
        if self.content_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("review outcome content hash does not match its artifact")

    @classmethod
    def create[T](
        cls,
        *,
        target: Literal["diff", "repository"],
        source_revision: str,
        findings: FindingsArtifact,
        outcome: ReviewOutcome[T],
    ) -> OutcomeArtifact:
        """Create the target neutral terminal state from a review outcome."""
        semantic = {
            "target": target,
            "source_revision": source_revision,
            "findings_sha256": findings.content_sha256,
            "status": "complete" if outcome.complete else "incomplete",
            "complete": outcome.complete,
            "errors": outcome.errors,
            "failures": len(outcome.failures),
            "incomplete": len(outcome.incomplete),
            "pending": len(outcome.pending),
            "grounding_missing": len(outcome.grounding.missing),
            "grounding_unresolved": len(outcome.grounding.unresolved),
            "limitations": len(outcome.grounding.limitations),
            "requires_convergence": outcome.requires_convergence,
            "converged": outcome.converged,
            "rounds": outcome.rounds,
            "failure_reason": outcome.failure_reason,
        }
        return cls(**semantic, content_sha256=_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return the content covered by the artifact hash."""
        return {
            "target": self.target,
            "source_revision": self.source_revision,
            "findings_sha256": self.findings_sha256,
            "status": self.status,
            "complete": self.complete,
            "errors": self.errors,
            "failures": self.failures,
            "incomplete": self.incomplete,
            "pending": self.pending,
            "grounding_missing": self.grounding_missing,
            "grounding_unresolved": self.grounding_unresolved,
            "limitations": self.limitations,
            "requires_convergence": self.requires_convergence,
            "converged": self.converged,
            "rounds": self.rounds,
            "failure_reason": self.failure_reason,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"schema": self.schema, **self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object) -> OutcomeArtifact:
        """Parse and verify one outcome artifact."""
        fields = {
            "schema",
            "target",
            "source_revision",
            "findings_sha256",
            "status",
            "complete",
            "errors",
            "failures",
            "incomplete",
            "pending",
            "grounding_missing",
            "grounding_unresolved",
            "limitations",
            "requires_convergence",
            "converged",
            "rounds",
            "failure_reason",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("review outcome artifact has an invalid shape")
        return cls(**{key: item for key, item in value.items() if key != "schema"}, schema=value["schema"])


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewResultArtifact:
    """One self contained machine result for CLI consumers."""

    review_id: str
    attempt_id: str
    findings: FindingsArtifact
    outcome: OutcomeArtifact
    schema: str = RESULT_SCHEMA

    def __post_init__(self) -> None:
        """Require the outcome to identify the embedded finding set."""
        if self.schema != RESULT_SCHEMA:
            raise ValueError("review result schema is unsupported")
        if re.fullmatch(r"review-[0-9a-f]{32}", self.review_id) is None:
            raise ValueError("review result review id is invalid")
        if re.fullmatch(r"attempt-[0-9a-f]{32}", self.attempt_id) is None:
            raise ValueError("review result attempt id is invalid")
        if not isinstance(self.findings, FindingsArtifact) or not isinstance(self.outcome, OutcomeArtifact):
            raise ValueError("review result artifacts are invalid")
        if self.outcome.findings_sha256 != self.findings.content_sha256:
            raise ValueError("review result outcome does not identify its findings")

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {
            "schema": self.schema,
            "review_id": self.review_id,
            "attempt_id": self.attempt_id,
            "findings": self.findings.to_dict(),
            "outcome": self.outcome.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> ReviewResultArtifact:
        """Parse and verify one CLI result envelope."""
        fields = {"schema", "review_id", "attempt_id", "findings", "outcome"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("review result has an invalid shape")
        return cls(
            schema=value["schema"],
            review_id=value["review_id"],
            attempt_id=value["attempt_id"],
            findings=FindingsArtifact.from_dict(value["findings"]),
            outcome=OutcomeArtifact.from_dict(value["outcome"]),
        )
