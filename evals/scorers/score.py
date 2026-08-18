"""The score algorithm: match every report against an answer key and tally the result.

This is the shared end of both paths. A findings check is found when some report matches
it, a report on a clean check is a false positive, a report on neither is extra and
kept for a human since it may be a real bug the key misses.
"""

from __future__ import annotations

import re
from pathlib import Path

from cyberjury.review.trace import Trace, emit_trace
from evals.models import AnswerKey, KeyCheck, Report
from evals.results import Result
from evals.scorers.match import category_match, endpoint_match
from evals.scorers.parse import symbol_line_span


def _path_key(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def _symbol_present(hay: str, symbols) -> bool:
    """Whether any anchor symbol appears in the report body as a whole token, not a substring.

    so a symbol like `approve` does not match the word `approved` in an unrelated allowance
    finding. The token bound is a non-word character on each side, which also holds for a
    symbol that itself begins or ends with a non-word character such as `$queryRawUnsafe` or
    `_mint`.
    """
    return any(re.search(rf"(?<!\w){re.escape(s)}(?!\w)", hay) for s in symbols)


def _file_symbol_hit(report: Report, check: KeyCheck, *, source_root: str | None = None, exact: bool = False) -> bool:
    report_files = {_path_key(f) for f in report.files}
    if exact:
        if not any(_path_key(kf) in report_files for kf in check.files):
            return False
    else:
        report_names = {Path(f).name for f in report.files}
        if not any(Path(kf).name in report_names for kf in check.files):
            return False
    if check.symbols:
        hay = f"{report.text} {report.endpoint}"
        if _symbol_present(hay, check.symbols):
            return True
        if source_root and report.lines:
            for kf in check.files:
                if exact and _path_key(kf) not in report_files:
                    continue
                if not exact and Path(kf).name not in {Path(f).name for f in report.files}:
                    continue
                for s in check.symbols:
                    span = symbol_line_span(source_root, kf, s)
                    if span and any(span[0] <= ln <= span[1] for ln in report.lines):
                        return True
        return False
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
    matched_reports: set[str] = set()
    for p in key.findings:
        if p.files:
            if any(_file_localization_matches(r, p) for r in reports):
                res.file_found.append(p.id)
            else:
                res.file_missed.append(p.id)
        quality, hit = max(
            (
                (
                    _finding_match_quality(
                        report,
                        p,
                        source_root=source_root,
                        endpoint_required=endpoint_required,
                    ),
                    report,
                )
                for report in reports
                if report.name not in matched_reports
            ),
            key=lambda item: item[0],
            default=(0, None),
        )
        if quality == 0:
            hit = None
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
            emit_trace(trace, "score_match", report=hit.name, kind="findings", key=p.id)
        else:
            emit_trace(trace, "score_match", kind="missed", key=p.id)
            res.missed.append(p.id)
    finding_matches = {
        r.name
        for r in reports
        if any(_matches(r, p, source_root=source_root, endpoint_required=endpoint_required) for p in key.findings)
    }
    for s in key.clean:
        for r in reports:
            if r.name in matched_reports or r.name in finding_matches:
                continue
            if _matches(r, s, clean=True, source_root=source_root, endpoint_required=endpoint_required):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
                emit_trace(trace, "score_match", report=r.name, kind="clean", key=s.id)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    for report in reports:
        if report.name in res.extra:
            emit_trace(trace, "score_match", report=report.name, kind="extra")
    return res
