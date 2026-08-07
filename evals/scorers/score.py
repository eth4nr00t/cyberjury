"""The score algorithm: match every report against an answer key and tally the result.

This is the shared end of both paths. A planted issue is found when some report matches
it, a report on a safe lookalike is a false positive, a report on neither is extra and
kept for a human since it may be a real bug the key misses.
"""

from __future__ import annotations

import re
from pathlib import Path

from evals.results import Result
from evals.schema import AnswerKey, KeyEntry, Report
from evals.scorers.match import category_match, endpoint_match
from evals.scorers.parse import symbol_line_span


def _symbol_present(hay: str, symbols) -> bool:
    """Whether any anchor symbol appears in the report body as a whole token, not a substring.

    so a symbol like `approve` does not match the word `approved` in an unrelated allowance
    finding. The token bound is a non-word character on each side, which also holds for a
    symbol that itself begins or ends with a non-word character such as `$queryRawUnsafe` or
    `_mint`.
    """
    return any(re.search(rf"(?<!\w){re.escape(s)}(?!\w)", hay) for s in symbols)


def _matches(report: Report, entry: KeyEntry, *, safe: bool = False, source_root: str | None = None) -> bool:
    def _class_ok() -> bool:
        return not (safe and entry.category) or category_match(report.category, entry.category)

    def _file_symbol_hit() -> bool:
        report_names = {Path(f).name for f in report.files}
        if not any(Path(kf).name in report_names for kf in entry.files):
            return False
        if entry.symbols:
            hay = f"{report.text} {report.endpoint}"
            if _symbol_present(hay, entry.symbols):
                return True
            if source_root and report.lines:
                for kf in entry.files:
                    if Path(kf).name not in report_names:
                        continue
                    for s in entry.symbols:
                        span = symbol_line_span(source_root, kf, s)
                        if span and any(span[0] <= ln <= span[1] for ln in report.lines):
                            return True
            return False
        return category_match(report.category, entry.category)

    if entry.entry:
        endpoint_hit = bool(report.endpoint) and endpoint_match(report.endpoint, entry.entry)
        if safe:
            return endpoint_hit and _class_ok()
        return endpoint_hit or (bool(entry.symbols and entry.files) and _file_symbol_hit())
    return _file_symbol_hit() and _class_ok()


def score(key: AnswerKey, reports: list[Report], *, source_root: str | None = None) -> Result:
    """Score the result."""
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched_reports: set[str] = set()
    for p in key.planted:
        hit = next(
            (r for r in reports if r.name not in matched_reports and _matches(r, p, source_root=source_root)), None
        )
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
        else:
            res.missed.append(p.id)
    finds_planted = {r.name for r in reports if any(_matches(r, p, source_root=source_root) for p in key.planted)}
    for s in key.safe:
        for r in reports:
            if r.name in matched_reports or r.name in finds_planted:
                continue
            if _matches(r, s, safe=True, source_root=source_root):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    return res
