"""Bind source assessment ledgers to recorded review attempts.

A ledger, `ledger-NN.json` beside its attempt, assesses every report exactly once at the case's
pinned source commit and is bound to the attempt bytes, the current case checks, the adjudication
round that produced it, and the rubric that round used. The attempt's issues are measured against
the supported and duplicate verdicts: an issue that holds reports of two root causes is mixed, and
a root cause spread over several issues leaves duplicate issues. An attempt recorded without
issues has one issue per report.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from evals.attempts import Attempt
from evals.benchmarks.cases import BenchmarkCase, checks_sha256
from evals.benchmarks.validate import validate_document

LEDGER_SCHEMA = "cyberjury.eval-ledger/v1"
VERDICTS = ("duplicate", "needs_review", "not_actionable", "supported")


@dataclass(frozen=True, kw_only=True)
class Adjudication:
    """Reviewed check credit and report verdicts of one attempt."""

    case: str
    attempt: int
    found: tuple[str, ...]
    missed: tuple[str, ...]
    pending: tuple[str, ...]
    counts: dict[str, int]
    issues: int = 0
    duplicate_issues: int = 0
    mixed_issues: int = 0
    round_id: str = ""
    rubric_sha256: str = ""


def adjudicate(case: BenchmarkCase, attempt: Attempt, ledger: object, source: Path | None) -> Adjudication:
    """Validate one ledger against its attempt and case, and count reviewed credit and verdicts.

    `source` is the root of a checkout at the pinned commit. When given, every
    evidence location must name an existing line there.
    """
    validate_document(ledger, "ledger-v1.schema.json", attempt.ledger_path)
    if (
        ledger["case"] != case.name
        or attempt.case != case.name
        or ledger["attempt"] != attempt.number
        or ledger["source_commit"] != case.target["commit"]
        or ledger["attempt_sha256"] != attempt.sha256
    ):
        raise ValueError(f"{attempt.ledger_path} does not identify this attempt and pinned source")
    if not attempt.complete:
        raise ValueError(f"{attempt.path} is not a complete review")
    if ledger["checks_sha256"] != checks_sha256(case):
        raise ValueError(f"{attempt.ledger_path} was adjudicated against other case checks, adjudicate it again")
    records = {record["candidate_id"]: record for record in ledger["records"]}
    if len(records) != len(ledger["records"]) or set(records) != set(attempt.findings):
        raise ValueError(f"{attempt.ledger_path} must assess every report of the attempt exactly once")
    checks = {check.id for check in case.checks}
    credited = [check_id for record in ledger["records"] for check_id in record["check_ids"]]
    if not set(credited) <= checks:
        raise ValueError(f"{attempt.ledger_path} credits checks outside the case: {sorted(set(credited) - checks)}")
    for identity, record in records.items():
        canonical = record["canonical_id"]
        if canonical is not None and (
            canonical == identity or canonical not in records or records[canonical]["verdict"] == "duplicate"
        ):
            raise ValueError(f"{identity} needs a distinct canonical report that is not itself a duplicate")
        if source is not None:
            for location in record["evidence"]:
                _source_line(source, location, identity)
    counts = Counter(record["verdict"] for record in ledger["records"])
    causes = [
        {
            records[member]["canonical_id"] or member
            for member in members
            if records[member]["verdict"] in ("supported", "duplicate")
        }
        for members in attempt.issues
    ]
    spread = Counter(cause for issue_causes in causes for cause in issue_causes)
    return Adjudication(
        case=case.name,
        attempt=attempt.number,
        found=tuple(sorted(set(credited))),
        missed=tuple(sorted(checks - set(credited))),
        pending=tuple(sorted(identity for identity, record in records.items() if record["verdict"] == "needs_review")),
        counts={verdict: counts[verdict] for verdict in VERDICTS},
        issues=len(attempt.issues),
        duplicate_issues=sum(count - 1 for count in spread.values()),
        mixed_issues=sum(len(issue_causes) > 1 for issue_causes in causes),
        round_id=ledger["round_id"],
        rubric_sha256=ledger["rubric_sha256"],
    )


def _source_line(root: Path, location: dict, identity: str) -> None:
    file, line = location["file"], location["line"]
    path = (root / file).resolve()
    if Path(file).is_absolute() or not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"{identity} evidence file does not exist in the pinned source: {file}")
    with path.open(encoding="utf-8", errors="replace") as lines:
        if line > sum(1 for _ in lines):
            raise ValueError(f"{identity} evidence line does not exist in the pinned source: {file}:{line}")
