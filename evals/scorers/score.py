"""The score algorithm: match every report against an answer key and tally the result.

This is the shared end of both paths. A planted issue is found when some report matches it,
a report on a safe lookalike is a false positive, a report on neither is extra and kept for
a human since it may be a real bug the key misses.
"""

from __future__ import annotations

import re
from pathlib import Path

from evals.results import Result
from evals.schema import AnswerKey, KeyEntry, Report
from evals.scorers.match import category_match, endpoint_match
from evals.scorers.parse import symbol_line_span


def _symbol_present(hay: str, symbols) -> bool:
    """Whether any anchor symbol appears in the report body as a whole token, not a substring,
    so a symbol like `approve` does not match the word `approved` in an unrelated allowance
    finding. The token bound is a non-word character on each side, which also holds for a symbol
    that itself begins or ends with a non-word character such as `$queryRawUnsafe` or `_mint`."""
    return any(re.search(rf"(?<!\w){re.escape(s)}(?!\w)", hay) for s in symbols)


def _matches(report: Report, entry: KeyEntry, *, safe: bool = False, source_root: str | None = None) -> bool:
    # A safe anchor certifies one endpoint or function safe for one vulnerability class, so a
    # report of a different class on that same anchor is not the false positive the anchor
    # guards, it is an adjacent finding. Require the report's class to agree with a safe anchor's
    # class before crediting it a false positive. Planted matching stays class-blind on the
    # endpoint and symbol anchors, since the finder's own class label is noisy and the anchor
    # already pins the bug, tightening it there would drop real recall.
    def _class_ok() -> bool:
        return not (safe and entry.category) or category_match(report.category, entry.category)

    def _file_symbol_hit() -> bool:
        # the precise sink anchor: the report cites the entry's file, and when the entry pins a
        # symbol, that symbol appears in the report. This is the no-endpoint match, and for a
        # planted it is also an alternative to the endpoint match, since a report that traces the
        # exact sink file and function is the same defect even when it writes the endpoint string
        # a little differently, a version prefix or an extra path segment.
        report_names = {Path(f).name for f in report.files}
        if not any(Path(kf).name in report_names for kf in entry.files):
            return False
        # symbols narrow a file anchor to the bug's real framing, so a report of the same class on
        # a sibling function in the same file no longer credits it. The class label is then
        # redundant, a report that traces the same function at the same file is the same defect
        # even when it names the class idor where the key names it access-control.
        if entry.symbols:
            hay = f"{report.text} {report.endpoint}"
            if _symbol_present(hay, entry.symbols):
                return True
            # the report may have located the same function by line without naming it, so when the
            # source is available credit a report whose cited line falls in the symbol's real span
            if source_root and report.lines:
                for kf in entry.files:
                    if Path(kf).name not in report_names:
                        continue
                    for s in entry.symbols:
                        span = symbol_line_span(source_root, kf, s)
                        if span and any(span[0] <= ln <= span[1] for ln in report.lines):
                            return True
            return False
        # no symbols, so the class is the only thing that narrows a whole-file anchor to the bug
        return category_match(report.category, entry.category)

    # endpoint is the precise signal: when the key entry cites one, the report must match it, no
    # loose file fallback that would credit a report on a sibling endpoint. A safe anchor keeps
    # this strict plus the class gate. A planted that also pins a file and symbol may be credited
    # by that exact sink anchor instead, so a correct finding is not lost to an endpoint string
    # that differs by a version prefix or a path segment.
    if entry.entry:
        endpoint_hit = bool(report.endpoint) and endpoint_match(report.endpoint, entry.entry)
        if safe:
            return endpoint_hit and _class_ok()
        return endpoint_hit or (bool(entry.symbols and entry.files) and _file_symbol_hit())
    # the no-endpoint anchor keeps the same class gate, so a report of a different class that
    # only shares the file and a symbol line span is not scored a false positive on a safe anchor.
    # It does nothing for a planted entry, which stays class-blind
    return _file_symbol_hit() and _class_ok()


def score(key: AnswerKey, reports: list[Report], *, source_root: str | None = None) -> Result:
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched_reports: set[str] = set()
    for p in key.planted:
        # credit a report to one planted entry only, so a single report cannot satisfy two
        # planted entries that share a loose file and class anchor and inflate recall
        hit = next(
            (r for r in reports if r.name not in matched_reports and _matches(r, p, source_root=source_root)), None
        )
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
        else:
            res.missed.append(p.id)
    # a report that matches any planted entry found a real bug, so it is never a false positive on
    # a safe anchor, not even the duplicate the planted credit did not take. A bug spanning two
    # functions is often written as two findings, one credits the planted and the other must not be
    # scored a false positive because it also matches the safe sibling on a loose file and symbol.
    finds_planted = {r.name for r in reports if any(_matches(r, p, source_root=source_root) for p in key.planted)}
    for s in key.safe:
        for r in reports:
            # count a report once: skip one already credited to a planted finding or to an
            # earlier safe anchor, so a report matching several safe entries is one false
            # positive, not several, which would understate precision
            if r.name in matched_reports or r.name in finds_planted:
                continue
            if _matches(r, s, safe=True, source_root=source_root):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    return res
