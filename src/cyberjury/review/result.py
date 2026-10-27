"""The findings and skipped file artifacts every review target writes."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cyberjury.canonical import canonical_sha256
from cyberjury.review.finding import Finding, report_order
from cyberjury.review.issues import Issue
from cyberjury.severity import SEVERITIES

FINDINGS_SCHEMA = "cyberjury.findings/v1"
SKIPPED_FILES_SCHEMA = "cyberjury.skipped-files/v1"


@dataclass(frozen=True, slots=True, kw_only=True)
class SkippedFile:
    """One target file a review did not send to model review, and why."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Return the JSON representation."""
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class SkippedFiles:
    """The target files one review kept out of model review."""

    files: tuple[SkippedFile, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON representation."""
        return {"schema": SKIPPED_FILES_SCHEMA, "files": [item.to_dict() for item in self.files]}


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingsArtifact:
    """The findings of one review in severity order, their issues, and the count per severity."""

    findings: tuple[dict[str, object], ...]
    issues: tuple[dict[str, object], ...]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON representation with the hash of its content."""
        semantic = {"findings": list(self.findings), "issues": list(self.issues), "summary": dict(self.summary)}
        return {"schema": FINDINGS_SCHEMA, **semantic, "content_sha256": canonical_sha256(semantic)}


def findings_artifact(
    findings: Iterable[Finding], issues: Sequence[Issue], *, unfinished: frozenset[str]
) -> FindingsArtifact:
    """Order the findings by severity and location, mark those only failed units reported, and list each issue."""
    issue_of = {member.candidate_id: issue.id for issue in issues for member in issue.members}
    ordered = sorted(findings, key=report_order)
    position = {finding.candidate_id: number for number, finding in enumerate(ordered)}
    return FindingsArtifact(
        findings=tuple(
            {
                "id": finding.candidate_id,
                "fingerprint": finding.fingerprint,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "entrypoint": finding.entrypoint,
                "evidence": finding.evidence,
                "attack_path": finding.attack_path,
                "evidence_refs": list(dict.fromkeys(finding.evidence_refs)),
                "issue_id": issue_of[finding.candidate_id],
                "change_anchor": finding.change_anchor.to_dict() if finding.change_anchor is not None else None,
                "unit_complete": finding.candidate_id not in unfinished,
            }
            for finding in ordered
        ),
        issues=tuple(
            {
                "id": issue.id,
                "representative": issue.representative.candidate_id,
                "members": [member.candidate_id for member in issue.members],
                "linked_by": list(issue.linked_by),
            }
            for issue in sorted(issues, key=lambda issue: position[issue.representative.candidate_id])
        ),
        summary={severity: sum(finding.severity == severity for finding in ordered) for severity in SEVERITIES},
    )
