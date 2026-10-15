"""Match every report against an answer key and tally the result.

This strict location match is a pre-assignment hint for source assessment ledgers. A
findings check is found when some report matches its changed line and source location.
Vulnerability class and severity wording never decide a match. A report on a clean check
is a false positive, and a report on neither is extra.
"""

from __future__ import annotations

from pathlib import Path

from cyberjury.review.trace import Trace, emit_trace
from evals.benchmarks.contract import AnswerKey, KeyCheck
from evals.score.assignment import maximum_weight_assignment
from evals.score.location import SymbolLocationError, symbol_line_spans
from evals.score.report import Report
from evals.score.result import Result


def _path_key(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def _location_hit(report: Report, check: KeyCheck, *, source_root: str | None) -> bool:
    for location in check.locations:
        lines = report.lines_for(location.file)
        if not lines:
            continue
        if location.line is not None and location.line in lines:
            return True
        if not location.symbol:
            continue
        if source_root is None:
            raise SymbolLocationError(f"cannot resolve {location.symbol!r} without benchmark source")
        spans = symbol_line_spans(source_root, location.file, location.symbol)
        if not spans:
            raise SymbolLocationError(f"cannot resolve {location.symbol!r} in {location.file}")
        if any(start <= line <= end for start, end in spans for line in lines):
            return True
    return False


def _change_hit(report: Report, check: KeyCheck, *, source_root: str | None) -> bool:
    if not check.changes:
        return True
    anchor = report.change_anchor
    if anchor is None:
        return False
    anchor_file = _path_key(anchor.file)
    if any(
        anchor_file == _path_key(expected.file) and anchor.line == expected.line and anchor.side == expected.side
        for expected in check.changes
    ):
        return True
    if source_root is None:
        return False
    if not any(anchor_file == _path_key(expected.file) and anchor.side == expected.side for expected in check.changes):
        return False
    return any(
        start <= anchor.line <= end
        for location in check.locations
        if location.symbol and anchor_file == _path_key(location.file)
        for start, end in symbol_line_spans(source_root, location.file, location.symbol)
    )


def _matches(report: Report, check: KeyCheck, *, source_root: str | None) -> bool:
    return _change_hit(report, check, source_root=source_root) and _location_hit(report, check, source_root=source_root)


def _maximum_finding_assignment(
    checks: tuple[KeyCheck, ...],
    reports: list[Report],
    *,
    source_root: str | None,
) -> dict[int, int]:
    """Match the most checks with a stable order over check and report identities."""
    check_order = sorted(range(len(checks)), key=lambda index: (checks[index].id, index))
    report_order = sorted(range(len(reports)), key=lambda index: (reports[index].name, index))
    weights = [
        [
            int(_matches(reports[report_index], checks[check_index], source_root=source_root))
            for report_index in report_order
        ]
        for check_index in check_order
    ]
    ranked_assignment = maximum_weight_assignment(weights)
    return {check_order[check_rank]: report_order[report_rank] for check_rank, report_rank in ranked_assignment.items()}


def score(
    key: AnswerKey,
    reports: list[Report],
    *,
    source_root: str | None = None,
    trace: Trace | None = None,
) -> Result:
    """Score reports against one task scoped answer key."""
    res = Result(target=key.benchmark_id, n_findings=len(key.findings), n_reports=len(reports))
    assignment = _maximum_finding_assignment(key.findings, reports, source_root=source_root)
    for check_index, check in enumerate(key.findings):
        report_index = assignment.get(check_index)
        if report_index is None:
            res.missed.append(check.id)
            emit_trace(trace, "score_match", kind="missed", key=check.id)
            continue
        res.found.append(check.id)
        emit_trace(trace, "score_match", report=reports[report_index].name, kind="findings", key=check.id)
    unavailable = set(assignment.values()) | {
        index
        for index, report in enumerate(reports)
        if any(_matches(report, check, source_root=source_root) for check in key.findings)
    }
    matched = set(assignment.values())
    for check in key.clean:
        for index, report in enumerate(reports):
            if index in unavailable or index in matched or not _matches(report, check, source_root=source_root):
                continue
            res.false_positives.append(check.id)
            matched.add(index)
            emit_trace(trace, "score_match", report=report.name, kind="clean", key=check.id)
    res.extra = [report.name for index, report in enumerate(reports) if index not in matched]
    for name in res.extra:
        emit_trace(trace, "score_match", report=name, kind="extra")
    return res
