"""Diff Review target: the Finder contract over one diff unit and its change location rules."""

from __future__ import annotations

import dataclasses

from cyberjury.review.context import SourceEvidence, SourceSpan, cited_location_file
from cyberjury.review.diff.model import DiffLineRanges, DiffUnit, canonical_diff_path
from cyberjury.review.diff.prompts import FINDER_RESPONSE_SCHEMA, diff_finder_system
from cyberjury.review.finder import ReviewTarget, finding_from_item, finding_violations
from cyberjury.review.finding import Finding
from cyberjury.review.replies import CorrectableRoleResponseError, RoleReply


def findings_from_reply(unit: DiffUnit, reply: RoleReply) -> list[Finding]:
    """Map the shared finding fields and request a correction for a change anchor outside the unit's changes."""
    findings = []
    valid_findings = []
    corrections = []
    for index, item in enumerate(reply["findings"]):
        violations = finding_violations(item, index)
        if violations:
            corrections.extend(violations)
            continue
        finding = finding_from_item(item)
        findings.append(finding)
        correction = _change_anchor_correction(item["change_anchor"], index, unit.line_ranges)
        if correction:
            corrections.append(correction)
        else:
            valid_findings.append(finding)
    if corrections:
        raise CorrectableRoleResponseError(" ".join(corrections), tuple(valid_findings), tuple(findings))
    return findings


def _change_anchor_correction(anchor: dict[str, object], index: int, ranges: DiffLineRanges) -> str:
    line = anchor["line"]
    side = anchor["side"]
    available_paths = {*ranges.old, *ranges.new}
    normalized = canonical_diff_path(str(anchor["file"]), available_paths)
    selected = ranges.old if side == "old" else ranges.new
    if _line_in_ranges(line, selected.get(normalized, ())):
        return ""
    if normalized in available_paths:
        candidates = []
        for candidate_side, by_path in (("old", ranges.old), ("new", ranges.new)):
            spans = by_path.get(normalized, ())
            if spans:
                rendered = ", ".join(str(start) if start == end else f"{start}-{end}" for start, end in spans)
                candidates.append(f"{candidate_side} lines {rendered}")
        choices = "; ".join(candidates)
        detail = f"Exact changed ranges for `{normalized}` are: {choices}."
    else:
        files = ", ".join(f"`{path}`" for path in sorted(available_paths))
        detail = f"The files with exact changed lines in this unit are: {files}."
    return (
        f"Finding {index} has an invalid `change_anchor`. {detail} Select one exact changed line that is "
        "causally responsible for this vulnerability. If none is responsible, remove the finding."
    )


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def locate(
    unit: DiffUnit,
    finding: Finding,
    source_evidence: tuple[SourceEvidence, ...],
    seed_spans: tuple[SourceSpan, ...],
) -> Finding | None:
    """Require a post change patch line or a cited source receipt, and one exact change anchor."""
    ranges = unit.line_ranges
    current_path = canonical_diff_path(finding.file, ranges.current)
    primary_in_patch = _line_in_ranges(finding.line, ranges.current.get(current_path, ()))
    cited = cited_location_file(
        file=finding.file,
        line=finding.line,
        evidence_refs=finding.evidence_refs,
        seed_spans=seed_spans,
        source_evidence=source_evidence,
    )
    if not primary_in_patch and cited is None:
        return None
    anchor = finding.change_anchor
    anchor_ranges = ranges.new if anchor.side == "new" else ranges.old
    anchor_file = canonical_diff_path(anchor.file, anchor_ranges)
    if not _line_in_ranges(anchor.line, anchor_ranges.get(anchor_file, ())):
        return None
    return dataclasses.replace(
        finding,
        file=current_path if primary_in_patch else cited,
        change_anchor=dataclasses.replace(anchor, file=anchor_file),
    )


DIFF_TARGET = ReviewTarget[DiffUnit](
    role="diff finder",
    response_schema=FINDER_RESPONSE_SCHEMA,
    system=diff_finder_system,
    findings_from_reply=findings_from_reply,
    locate=locate,
    location_failure="one or more findings lack a current unit location receipt or exact change anchor",
    covers_all_files=False,
)
