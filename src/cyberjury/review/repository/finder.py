"""Repository Review target: the Finder contract over one repository unit and its location rule."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.review.context import SourceEvidence, SourceSpan, source_location_receipt
from cyberjury.review.engine import RoleReply
from cyberjury.review.finder import ReviewTarget, findings_from_reply
from cyberjury.review.finding import Finding
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.prompts import FINDER_RESPONSE_SCHEMA, repository_finder_system


def locate(
    _unit: Unit,
    finding: Finding,
    source_evidence: tuple[SourceEvidence, ...],
    seed_spans: tuple[SourceSpan, ...],
) -> Finding | None:
    """Require a cited source receipt covering the primary location, and use its canonical path."""
    receipt = source_location_receipt(
        file=finding.file,
        line=finding.line,
        evidence_refs=finding.evidence_refs,
        seed_spans=seed_spans,
        source_evidence=source_evidence,
    )
    return replace(finding, file=receipt.file) if receipt is not None else None


def _findings_from_reply(_unit: Unit, reply: RoleReply) -> list[Finding]:
    return findings_from_reply(reply)


REPOSITORY_TARGET = ReviewTarget[Unit](
    kind="repository",
    role="unit finder",
    response_schema=FINDER_RESPONSE_SCHEMA,
    system=repository_finder_system,
    findings_from_reply=_findings_from_reply,
    locate=locate,
    location_failure="one or more findings lack a cited source receipt for their primary location",
    covers_all_files=True,
)
