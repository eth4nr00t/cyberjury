"""Strict shared findings and skipped file artifacts for every review target."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from cyberjury.canonical import canonical_sha256, normalized_repository_path
from cyberjury.review.finding import Finding
from cyberjury.review.issues import Issue, issue_id
from cyberjury.severity import SEVERITIES, index

FINDINGS_SCHEMA = "cyberjury.findings/v1"
SKIPPED_FILES_SCHEMA = "cyberjury.skipped-files/v1"
SKIP_REASONS = (
    "noise",
    "binary",
    "not_utf8",
    "empty_file",
    "too_large",
    "rename_only",
    "copy_only",
    "mode_only",
    "empty_new_file",
    "empty_deleted_file",
    "no_hunk",
    "submodule",
)


def _digest(value: object, label: str) -> str:
    invalid = (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    )
    if invalid:
        raise ValueError(f"{label} must be a SHA-256 digest")
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

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"path": self.path, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: object) -> SkippedFile:
        """Parse one strict skipped file record."""
        if not isinstance(value, dict) or set(value) != {"path", "reason"}:
            raise ValueError("skipped file record has an invalid shape")
        return cls(path=value["path"], reason=value["reason"])


@dataclass(frozen=True, slots=True)
class SkippedFiles:
    """The target files one review kept out of model review."""

    files: tuple[SkippedFile, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"schema": SKIPPED_FILES_SCHEMA, "files": [item.to_dict() for item in self.files]}


@dataclass(frozen=True, slots=True, kw_only=True)
class ChangeAnchorRecord:
    """One exact changed line that caused or exposed a diff finding."""

    file: str
    line: int
    side: Literal["old", "new"]

    def __post_init__(self) -> None:
        """Reject locations that cannot name one immutable source line."""
        normalized_repository_path(self.file, "finding file")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("finding change line must be positive")
        if self.side not in {"old", "new"}:
            raise ValueError("finding change side must be old or new")

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"file": self.file, "line": self.line, "side": self.side}

    @classmethod
    def from_dict(cls, value: object) -> ChangeAnchorRecord:
        """Parse one strict change anchor."""
        if not isinstance(value, dict) or set(value) != {"file", "line", "side"}:
            raise ValueError("finding change anchor has an invalid shape")
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
    evidence_refs: tuple[str, ...]
    supporting_reviewers: tuple[str, ...]
    issue_id: str
    change_anchor: ChangeAnchorRecord | None = None

    def __post_init__(self) -> None:
        """Reject findings that cannot be reported or identified."""
        if not isinstance(self.id, str) or re.fullmatch(r"candidate-[0-9a-f]{20}", self.id) is None:
            raise ValueError("finding id must use the candidate namespace")
        if not isinstance(self.issue_id, str) or re.fullmatch(r"issue-[0-9a-f]{20}", self.issue_id) is None:
            raise ValueError("finding issue id must use the issue namespace")
        for name in ("title", "category", "entrypoint", "evidence", "attack_path"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"finding {name} must be a string")
        if not self.title or not self.category:
            raise ValueError("finding title and category must be nonempty")
        if self.severity not in SEVERITIES:
            raise ValueError("finding severity is invalid")
        normalized_repository_path(self.file, "finding file")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("finding line must be positive")
        if self.change_anchor is not None and not isinstance(self.change_anchor, ChangeAnchorRecord):
            raise ValueError("finding change anchor is invalid")
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
            "evidence_refs": list(self.evidence_refs),
            "supporting_reviewers": list(self.supporting_reviewers),
            "issue_id": self.issue_id,
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
            "evidence_refs",
            "supporting_reviewers",
            "issue_id",
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
            change_anchor=ChangeAnchorRecord.from_dict(anchor) if anchor is not None else None,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class IssueRecord:
    """Findings one code change fixes. Every member stays a reported finding."""

    id: str
    representative: str
    members: tuple[str, ...]
    linked_by: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require a representative first member, a member bound id, and canonical link kinds."""
        if (
            not isinstance(self.members, tuple)
            or not self.members
            or len(set(self.members)) != len(self.members)
            or not all(isinstance(member, str) for member in self.members)
        ):
            raise ValueError("issue members must be a nonempty unique candidate tuple")
        if self.representative != self.members[0]:
            raise ValueError("issue representative must be its first member")
        if self.id != issue_id(self.members):
            raise ValueError("issue id does not match its members")
        kinds = self.linked_by
        if (
            not isinstance(kinds, tuple)
            or not set(kinds) <= {"location", "judgment"}
            or kinds != tuple(sorted(set(kinds)))
            or bool(kinds) != (len(self.members) > 1)
        ):
            raise ValueError("issue link kinds must be canonical and present exactly for a grouped issue")

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {
            "id": self.id,
            "representative": self.representative,
            "members": list(self.members),
            "linked_by": list(self.linked_by),
        }

    @classmethod
    def from_dict(cls, value: object) -> IssueRecord:
        """Parse one strict issue record."""
        if not isinstance(value, dict) or set(value) != {"id", "representative", "members", "linked_by"}:
            raise ValueError("issue record has an invalid shape")
        if not isinstance(value["members"], list) or not isinstance(value["linked_by"], list):
            raise ValueError("issue record collections are invalid")
        return cls(
            id=value["id"],
            representative=value["representative"],
            members=tuple(value["members"]),
            linked_by=tuple(value["linked_by"]),
        )


def _finding_order(item: FindingRecord) -> tuple[int, str, int, str]:
    return (index(item.severity), item.file, item.line, item.id)


def _findings_semantic(
    findings: tuple[FindingRecord, ...],
    issues: tuple[IssueRecord, ...],
    summary: tuple[tuple[str, int], ...],
) -> dict[str, object]:
    return {
        "findings": [item.to_dict() for item in findings],
        "issues": [item.to_dict() for item in issues],
        "summary": dict(summary),
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingsArtifact:
    """The ordered logical finding set and its issues, shared by Diff and Repository Review."""

    findings: tuple[FindingRecord, ...]
    issues: tuple[IssueRecord, ...]
    summary: tuple[tuple[str, int], ...]
    content_sha256: str
    schema: str = FINDINGS_SCHEMA

    def __post_init__(self) -> None:
        """Verify the finding set, its issue partition, summary, and content identity."""
        if self.schema != FINDINGS_SCHEMA:
            raise ValueError("findings artifact schema is unsupported")
        if not isinstance(self.findings, tuple) or not all(isinstance(item, FindingRecord) for item in self.findings):
            raise ValueError("findings artifact findings must be a finding tuple")
        if len({item.id for item in self.findings}) != len(self.findings):
            raise ValueError("findings artifact candidate ids must be unique")
        if self.findings != tuple(sorted(self.findings, key=_finding_order)):
            raise ValueError("findings artifact findings must use canonical order")
        if not isinstance(self.issues, tuple) or not all(isinstance(item, IssueRecord) for item in self.issues):
            raise ValueError("findings artifact issues must be an issue tuple")
        issue_of = {member: issue.id for issue in self.issues for member in issue.members}
        if len(issue_of) != sum(len(issue.members) for issue in self.issues) or issue_of != {
            item.id: item.issue_id for item in self.findings
        }:
            raise ValueError("findings artifact issues must partition its findings and match their issue ids")
        position = {item.id: number for number, item in enumerate(self.findings)}
        if [position[issue.representative] for issue in self.issues] != sorted(
            position[issue.representative] for issue in self.issues
        ):
            raise ValueError("findings artifact issues must follow their representatives' finding order")
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
        issues: tuple[IssueRecord, ...],
    ) -> FindingsArtifact:
        """Create a canonical finding set with its issues and bind its content hash."""
        ordered = tuple(sorted(findings, key=_finding_order))
        position = {item.id: number for number, item in enumerate(ordered)}
        ordered_issues = tuple(sorted(issues, key=lambda issue: position.get(issue.representative, -1)))
        summary = tuple((severity, sum(item.severity == severity for item in ordered)) for severity in SEVERITIES)
        return cls(
            findings=ordered,
            issues=ordered_issues,
            summary=summary,
            content_sha256=canonical_sha256(_findings_semantic(ordered, ordered_issues, summary)),
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return the content covered by the artifact hash."""
        return _findings_semantic(self.findings, self.issues, self.summary)

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON representation."""
        return {"schema": self.schema, **self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object) -> FindingsArtifact:
        """Parse and verify one findings artifact."""
        fields = {"schema", "findings", "issues", "summary", "content_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("findings artifact has an invalid shape")
        if (
            not isinstance(value["findings"], list)
            or not isinstance(value["issues"], list)
            or not isinstance(value["summary"], dict)
        ):
            raise ValueError("findings artifact collections are invalid")
        if set(value["summary"]) != set(SEVERITIES):
            raise ValueError("findings artifact summary severities are invalid")
        return cls(
            schema=value["schema"],
            findings=tuple(FindingRecord.from_dict(item) for item in value["findings"]),
            issues=tuple(IssueRecord.from_dict(item) for item in value["issues"]),
            summary=tuple((severity, value["summary"][severity]) for severity in SEVERITIES),
            content_sha256=value["content_sha256"],
        )


def findings_artifact(findings: Iterable[Finding], issues: Sequence[Issue]) -> FindingsArtifact:
    """Map review findings and their issues into the shared machine output contract."""
    issue_of = {member.candidate_id: issue.id for issue in issues for member in issue.members}
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
                evidence_refs=tuple(dict.fromkeys(finding.evidence_refs)),
                supporting_reviewers=tuple(sorted(set(finding.found_by))),
                issue_id=issue_of[finding.candidate_id],
                change_anchor=(
                    ChangeAnchorRecord(
                        file=finding.change_anchor.file,
                        line=finding.change_anchor.line,
                        side=finding.change_anchor.side,
                    )
                    if finding.change_anchor is not None
                    else None
                ),
            )
            for finding in findings
        ),
        tuple(
            IssueRecord(
                id=issue.id,
                representative=issue.representative.candidate_id,
                members=tuple(member.candidate_id for member in issue.members),
                linked_by=issue.linked_by,
            )
            for issue in issues
        ),
    )
