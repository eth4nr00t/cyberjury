"""Match every report against an answer key and tally the result.

This is the shared end of both paths. A findings check is found when some report matches
it, a report on a clean check is a false positive, a report on neither is extra and
kept for a human since it may be a real bug the key misses.
"""

from __future__ import annotations

import re
from pathlib import Path

from cyberjury.review.trace import Trace, emit_trace
from evals.benchmarks.contract import AnswerKey, KeyCheck
from evals.score.assignment import maximum_weight_assignment
from evals.score.location import symbol_line_spans
from evals.score.match import category_match, endpoint_match
from evals.score.report import Report
from evals.score.result import Result


def _path_key(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def _symbol_present(hay: str, symbols) -> bool:
    """Match anchor symbols as whole tokens in the report body.

    Token boundaries prevent `approve` from matching `approved`. They also handle symbols
    that begin or end with a nonword character, such as `$queryRawUnsafe` or `_mint`.
    """
    return any(re.search(rf"(?<!\w){re.escape(s)}(?!\w)", hay) for s in symbols)


def _matching_check_files(report: Report, check: KeyCheck, *, exact: bool) -> tuple[str, ...]:
    report_files = {_path_key(file) for file in report.files}
    if exact:
        return tuple(file for file in check.files if _path_key(file) in report_files)
    return tuple(
        file
        for file in check.files
        if sum(Path(report_file).name == Path(file).name for report_file in report.files) == 1
    )


def _symbol_line_hit(
    report: Report,
    files: tuple[str, ...],
    symbols: tuple[str, ...],
    source_root: str,
    *,
    exact: bool,
) -> bool:
    return any(
        start <= line <= end
        for file in files
        for symbol in symbols
        for start, end in symbol_line_spans(source_root, file, symbol)
        for line in report.lines_for(file, exact=exact)
    )


def _file_symbol_hit(report: Report, check: KeyCheck, *, source_root: str | None = None, exact: bool = False) -> bool:
    files = _matching_check_files(report, check, exact=exact)
    if not files:
        return False
    if check.symbols:
        hay = f"{report.text} {report.endpoint}"
        if _symbol_present(hay, check.symbols):
            return True
        return bool(
            source_root and report.lines and _symbol_line_hit(report, files, check.symbols, source_root, exact=exact)
        )
    return category_match(report.category, check.category)


def _matches(
    report: Report,
    check: KeyCheck,
    *,
    clean: bool = False,
    source_root: str | None = None,
    endpoint_required: bool = True,
) -> bool:
    def _class_ok() -> bool:
        return not check.category or category_match(report.category, check.category)

    if check.endpoint:
        endpoint_hit = bool(report.endpoint) and endpoint_match(report.endpoint, check.endpoint)
        if clean:
            if endpoint_hit:
                return _class_ok()
            if endpoint_required:
                return False
        elif endpoint_hit:
            return True
        elif endpoint_required:
            return (
                bool(check.symbols and check.files)
                and _file_symbol_hit(report, check, source_root=source_root)
                and _class_ok()
            )
        if not check.files:
            return False
        anchor_hit = (
            _file_symbol_hit(report, check, source_root=source_root)
            if check.symbols
            else _file_localization_matches(report, check)
        )
        return anchor_hit and _class_ok()
    return _file_symbol_hit(report, check, source_root=source_root) and _class_ok()


def _finding_match_quality(
    report: Report,
    check: KeyCheck,
    *,
    source_root: str | None = None,
    endpoint_required: bool = True,
) -> int:
    if not _matches(report, check, source_root=source_root, endpoint_required=endpoint_required):
        return 0
    if _file_localization_matches(report, check):
        return 4
    if check.endpoint and report.endpoint and endpoint_match(report.endpoint, check.endpoint):
        return 3 if category_match(report.category, check.category) else 2
    if check.category and category_match(report.category, check.category):
        return 2
    return 1


def _file_localization_matches(report: Report, check: KeyCheck) -> bool:
    report_files = {_path_key(f) for f in report.files}
    return (
        bool(check.files)
        and any(_path_key(kf) in report_files for kf in check.files)
        and category_match(report.category, check.category)
    )


def _maximum_finding_assignment(
    checks: tuple[KeyCheck, ...],
    reports: list[Report],
    *,
    source_root: str | None,
    endpoint_required: bool,
) -> dict[int, int]:
    """Match the most checks, then maximize the total evidence quality."""
    check_order = sorted(range(len(checks)), key=lambda index: (checks[index].id, index))
    report_order = sorted(range(len(reports)), key=lambda index: (reports[index].name, index))
    weights = [
        [
            _finding_match_quality(
                reports[report_index],
                checks[check_index],
                source_root=source_root,
                endpoint_required=endpoint_required,
            )
            for report_index in report_order
        ]
        for check_index in check_order
    ]
    ranked_assignment = maximum_weight_assignment(weights)
    return {check_order[check_rank]: report_order[report_rank] for check_rank, report_rank in ranked_assignment.items()}


def _record_file_localization(res: Result, check: KeyCheck, reports: list[Report]) -> None:
    if not check.files:
        return
    destination = (
        res.file_found if any(_file_localization_matches(report, check) for report in reports) else res.file_missed
    )
    destination.append(check.id)


def _record_finding_results(
    res: Result,
    checks: tuple[KeyCheck, ...],
    reports: list[Report],
    assignment: dict[int, int],
    trace: Trace | None,
) -> None:
    for check_index, check in enumerate(checks):
        _record_file_localization(res, check, reports)
        report_index = assignment.get(check_index)
        if report_index is None:
            res.missed.append(check.id)
            emit_trace(trace, "score_match", kind="missed", key=check.id)
            continue
        report = reports[report_index]
        res.found.append(check.id)
        emit_trace(trace, "score_match", report=report.name, kind="findings", key=check.id)


def _record_clean_results(
    res: Result,
    checks: tuple[KeyCheck, ...],
    reports: list[Report],
    unavailable_reports: set[int],
    *,
    source_root: str | None,
    endpoint_required: bool,
    trace: Trace | None,
) -> set[int]:
    matched: set[int] = set()
    for check in checks:
        for report_index, report in enumerate(reports):
            if report_index in unavailable_reports or report_index in matched:
                continue
            if not _matches(
                report,
                check,
                clean=True,
                source_root=source_root,
                endpoint_required=endpoint_required,
            ):
                continue
            res.false_positives.append(check.id)
            matched.add(report_index)
            emit_trace(trace, "score_match", report=report.name, kind="clean", key=check.id)
    return matched


def score(
    key: AnswerKey,
    reports: list[Report],
    *,
    source_root: str | None = None,
    endpoint_required: bool = True,
    trace: Trace | None = None,
) -> Result:
    """Score reports, requiring keyed endpoint anchors unless the caller opts out."""
    res = Result(
        target=key.benchmark_id,
        n_findings=len(key.findings),
        n_file_findings=sum(1 for p in key.findings if p.files),
        n_reports=len(reports),
    )
    assignment = _maximum_finding_assignment(
        key.findings,
        reports,
        source_root=source_root,
        endpoint_required=endpoint_required,
    )
    matched_report_indexes = set(assignment.values())
    _record_finding_results(res, key.findings, reports, assignment, trace)
    finding_matches = {
        report_index
        for report_index, report in enumerate(reports)
        if any(_matches(report, p, source_root=source_root, endpoint_required=endpoint_required) for p in key.findings)
    }
    matched_report_indexes.update(
        _record_clean_results(
            res,
            key.clean,
            reports,
            matched_report_indexes | finding_matches,
            source_root=source_root,
            endpoint_required=endpoint_required,
            trace=trace,
        )
    )
    res.extra = [report.name for index, report in enumerate(reports) if index not in matched_report_indexes]
    for index, report in enumerate(reports):
        if index not in matched_report_indexes:
            emit_trace(trace, "score_match", report=report.name, kind="extra")
    return res
