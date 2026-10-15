"""Map Diff Review findings into the shared machine findings artifact."""

from __future__ import annotations

from collections.abc import Collection

from cyberjury.finding import Finding
from cyberjury.review.result import ChangeLocation, FindingRecord, FindingsArtifact


def findings_artifact(
    findings: list[Finding] | tuple[Finding, ...],
    *,
    verified_ids: Collection[str] = (),
) -> FindingsArtifact:
    """Map Diff Review findings into the shared machine output contract."""
    unlocated = [finding.candidate_id for finding in findings if finding.line is None]
    if unlocated:
        raise ValueError(f"diff output findings require source lines: {', '.join(unlocated)}")
    return FindingsArtifact.create(
        tuple(
            FindingRecord(
                id=finding.candidate_id,
                category=finding.category,
                severity=finding.severity,
                file=finding.file,
                line=finding.line,
                entrypoint=finding.entrypoint,
                summary=finding.description,
                evidence="",
                attack_path=finding.exploit_scenario,
                recommendation=finding.recommendation,
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
        ),
    )
