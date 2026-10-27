"""Repository review target: the finder contract over one repository unit and its location rule."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.review.context import SourceEvidence, SourceSpan, cited_location_file
from cyberjury.review.finder import ReviewTarget, findings_from_reply
from cyberjury.review.finding import Finding
from cyberjury.review.replies import RoleReply
from cyberjury.review.repository.model import RepositoryUnit
from cyberjury.review.repository.prompts import FINDER_RESPONSE_SCHEMA, repository_finder_system


def locate(
    _unit: RepositoryUnit,
    finding: Finding,
    source_evidence: tuple[SourceEvidence, ...],
    seed_spans: tuple[SourceSpan, ...],
) -> Finding | None:
    """Require a cited source receipt covering the primary location, and use its canonical path."""
    cited = cited_location_file(
        file=finding.file,
        line=finding.line,
        evidence_refs=finding.evidence_refs,
        seed_spans=seed_spans,
        source_evidence=source_evidence,
    )
    return replace(finding, file=cited) if cited is not None else None


def _findings_from_reply(_unit: RepositoryUnit, reply: RoleReply) -> list[Finding]:
    return findings_from_reply(reply)


REPOSITORY_TARGET = ReviewTarget[RepositoryUnit](
    role="repository finder",
    response_schema=FINDER_RESPONSE_SCHEMA,
    system=repository_finder_system,
    findings_from_reply=_findings_from_reply,
    locate=locate,
    location_failure="one or more findings lack a cited source receipt for their primary location",
    covers_all_files=True,
)
