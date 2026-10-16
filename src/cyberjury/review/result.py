"""Strict shared findings and outcome artifacts for every review target."""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from cyberjury.canonical import canonical_sha256
from cyberjury.finding import Finding
from cyberjury.review.engine import ReviewOutcome
from cyberjury.severity import SEVERITIES, index

FINDINGS_SCHEMA = "cyberjury.findings/v5"
OUTCOME_SCHEMA = "cyberjury.review-outcome/v4"
RESULT_SCHEMA = "cyberjury.review-result/v2"
SKIP_REASONS = {
    "noise": "excluded by the noise rules",
    "binary": "binary file",
    "not_utf8": "not UTF-8 text",
    "empty_file": "empty file",
    "rename_only": "rename only",
    "copy_only": "copy only",
    "mode_only": "mode change only",
    "empty_new_file": "empty new file",
    "empty_deleted_file": "empty deleted file",
    "no_hunk": "file section without a hunk",
}


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


@dataclass(frozen=True, slots=True, kw_only=True)
class SkippedFile:
    """One target file a review did not send to model review, and why."""

    path: str
    reason: str

    def __post_init__(self) -> None:
        """Require a named path and a known skip reason."""
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("skipped file path must be a nonempty string")
        if self.reason not in SKIP_REASONS:
            raise ValueError("skipped file reason is invalid")

    @property
    def description(self) -> str:
        """Return the operator wording of the skip reason."""
        return SKIP_REASONS[self.reason]

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"path": self.path, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: object) -> SkippedFile:
        """Parse one strict skipped file record."""
        if not isinstance(value, dict) or set(value) != {"path", "reason"}:
            raise ValueError("skipped file record has an invalid shape")
        return cls(path=value["path"], reason=value["reason"])


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
    title: str
    category: str
    severity: str
    file: str
    line: int
    entrypoint: str
    evidence: str
    attack_path: str
    status: Literal["candidate", "confirmed"]
    evidence_refs: tuple[str, ...]
    supporting_reviewers: tuple[str, ...]
    change_anchor: ChangeLocation | None = None

    def __post_init__(self) -> None:
        """Reject findings that cannot be reported or identified."""
        if not isinstance(self.id, str) or re.fullmatch(r"candidate-[0-9a-f]{20}", self.id) is None:
            raise ValueError("finding id must use the candidate namespace")
        for name in ("title", "category", "entrypoint", "evidence", "attack_path"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"finding {name} must be a string")
        if not self.title or not self.category:
            raise ValueError("finding title and category must be nonempty")
        if self.severity not in SEVERITIES:
            raise ValueError("finding severity is invalid")
        _source_path(self.file)
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("finding line must be positive")
        if self.change_anchor is not None and not isinstance(self.change_anchor, ChangeLocation):
            raise ValueError("finding change anchor is invalid")
        if self.status not in {"candidate", "confirmed"}:
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
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "entrypoint": self.entrypoint,
            "evidence": self.evidence,
            "attack_path": self.attack_path,
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
            "title",
            "category",
            "severity",
            "file",
            "line",
            "entrypoint",
            "evidence",
            "attack_path",
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
        expected_summary = tuple(
            (severity, sum(item.severity == severity for item in self.findings)) for severity in SEVERITIES
        )
        if self.summary != expected_summary:
            raise ValueError("findings summary does not match its finding set")
        if any(isinstance(count, bool) or not isinstance(count, int) for _severity, count in self.summary):
            raise ValueError("findings summary counts must be integers")
        if self.content_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("findings content hash does not match its artifact")

    @classmethod
    def create(
        cls,
        findings: tuple[FindingRecord, ...],
    ) -> FindingsArtifact:
        """Create a canonical finding set and bind its content hash."""
        ordered = tuple(sorted(findings, key=lambda item: (index(item.severity), item.file, item.line, item.id)))
        summary = tuple((severity, sum(item.severity == severity for item in ordered)) for severity in SEVERITIES)
        semantic = {
            "findings": [item.to_dict() for item in ordered],
            "summary": dict(summary),
        }
        return cls(findings=ordered, summary=summary, content_sha256=canonical_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return the content covered by the artifact hash."""
        return {
            "findings": [item.to_dict() for item in self.findings],
            "summary": dict(self.summary),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"schema": self.schema, **self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object) -> FindingsArtifact:
        """Parse and verify one findings artifact."""
        fields = {"schema", "findings", "summary", "content_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("findings artifact has an invalid shape")
        if not isinstance(value["findings"], list) or not isinstance(value["summary"], dict):
            raise ValueError("findings artifact collections are invalid")
        if set(value["summary"]) != set(SEVERITIES):
            raise ValueError("findings artifact summary severities are invalid")
        return cls(
            schema=value["schema"],
            findings=tuple(FindingRecord.from_dict(item) for item in value["findings"]),
            summary=tuple((severity, value["summary"][severity]) for severity in SEVERITIES),
            content_sha256=value["content_sha256"],
        )


def findings_artifact(findings: Iterable[Finding], verified_ids: Collection[str]) -> FindingsArtifact:
    """Map review findings into the shared machine output contract."""
    return FindingsArtifact.create(
        tuple(
            FindingRecord(
                id=finding.candidate_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                file=finding.file,
                line=finding.line,
                entrypoint=finding.entrypoint,
                evidence=finding.evidence,
                attack_path=finding.attack_path,
                status="confirmed" if finding.candidate_id in verified_ids else "candidate",
                evidence_refs=tuple(dict.fromkeys(finding.evidence_refs)),
                supporting_reviewers=tuple(sorted(set(finding.found_by))),
                change_anchor=(
                    ChangeLocation(
                        file=finding.change_anchor.file,
                        line=finding.change_anchor.line,
                        side=finding.change_anchor.side,
                    )
                    if finding.change_anchor is not None
                    else None
                ),
            )
            for finding in findings
        )
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class OutcomeArtifact:
    """The strict target neutral completion state for one review result."""

    target: Literal["diff", "repository"]
    source_revision: str
    findings_sha256: str
    complete: bool
    errors: int
    failures: int
    incomplete: int
    grounding_missing: int
    grounding_unresolved: int
    limitations: int
    failure_reason: str
    skipped_files: tuple[SkippedFile, ...]
    content_sha256: str
    schema: str = OUTCOME_SCHEMA

    def __post_init__(self) -> None:
        """Verify completion from its controlling facts and content hash."""
        if self.schema != OUTCOME_SCHEMA or self.target not in {"diff", "repository"}:
            raise ValueError("review outcome schema or target is invalid")
        _digest(self.source_revision, "review outcome source revision")
        _digest(self.findings_sha256, "review outcome findings hash")
        if not isinstance(self.complete, bool):
            raise ValueError("review outcome completion is invalid")
        for name in (
            "errors",
            "failures",
            "incomplete",
            "grounding_missing",
            "grounding_unresolved",
            "limitations",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"review outcome {name} must be a nonnegative integer")
        if not isinstance(self.failure_reason, str):
            raise ValueError("review outcome failure reason must be a string")
        if not isinstance(self.skipped_files, tuple) or not all(
            isinstance(item, SkippedFile) for item in self.skipped_files
        ):
            raise ValueError("review outcome skipped files are invalid")
        expected_complete = not any(
            (
                self.errors,
                self.failures,
                self.incomplete,
                self.grounding_missing,
                self.grounding_unresolved,
                self.limitations,
                self.failure_reason,
            )
        )
        if self.complete != expected_complete:
            raise ValueError("review outcome completion contradicts its counters")
        if self.content_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("review outcome content hash does not match its artifact")

    @classmethod
    def create[T](
        cls,
        *,
        target: Literal["diff", "repository"],
        source_revision: str,
        findings: FindingsArtifact,
        outcome: ReviewOutcome[T],
        skipped_files: tuple[SkippedFile, ...] = (),
    ) -> OutcomeArtifact:
        """Create the target neutral terminal state from a review outcome."""
        fields = {
            "target": target,
            "source_revision": source_revision,
            "findings_sha256": findings.content_sha256,
            "complete": outcome.complete,
            "errors": outcome.errors,
            "failures": len(outcome.failures),
            "incomplete": len(outcome.incomplete),
            "grounding_missing": len(outcome.grounding.missing),
            "grounding_unresolved": len(outcome.grounding.unresolved),
            "limitations": len(outcome.grounding.limitations),
            "failure_reason": outcome.failure_reason,
        }
        semantic = fields | {"skipped_files": [item.to_dict() for item in skipped_files]}
        return cls(**fields, skipped_files=tuple(skipped_files), content_sha256=canonical_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return the content covered by the artifact hash."""
        return {
            "target": self.target,
            "source_revision": self.source_revision,
            "findings_sha256": self.findings_sha256,
            "complete": self.complete,
            "errors": self.errors,
            "failures": self.failures,
            "incomplete": self.incomplete,
            "grounding_missing": self.grounding_missing,
            "grounding_unresolved": self.grounding_unresolved,
            "limitations": self.limitations,
            "failure_reason": self.failure_reason,
            "skipped_files": [item.to_dict() for item in self.skipped_files],
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
            "complete",
            "errors",
            "failures",
            "incomplete",
            "grounding_missing",
            "grounding_unresolved",
            "limitations",
            "failure_reason",
            "skipped_files",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or not isinstance(value["skipped_files"], list):
            raise ValueError("review outcome artifact has an invalid shape")
        return cls(
            **{key: item for key, item in value.items() if key not in {"schema", "skipped_files"}},
            skipped_files=tuple(SkippedFile.from_dict(item) for item in value["skipped_files"]),
            schema=value["schema"],
        )


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
