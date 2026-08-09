"""Cross-pass accumulation and convergence for the multi-pass union engine.

A single review pass over a large repository is shallow and its misses land somewhere
different each time, so one pass is random and incomplete. Recall is a multi-pass
property: run independent role rounds, each covering every unit, and take the union.
This module is the deterministic core of that, the part that makes
the result converge and stop being random: - `merge` folds a pass's candidates into the
running union, deduped by location, so a finding several passes reach is counted once
and the union only grows. - `Accumulator` tracks the union and the per-pass new-finding
counts, and reports convergence: the union is complete enough to stop when the last K
passes each add nothing new. The orchestration keeps spawning passes until then. This
holds no model logic and makes no calls, so it is fully testable on its own. The per-
pass review that produces candidates is injected, see the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.provenance import found_by_tuple
from cyberjury.review.repository.severity import median


@dataclass(frozen=True, kw_only=True)
class Candidate:
    """One finding a pass proposed, before cross-pass dedup and verification."""

    title: str
    category: str = ""
    endpoint: str = ""
    symbol: str = ""
    file: str = ""
    line: int | None = None
    severity: str = "HIGH"
    evidence: str = ""
    status: str = "confirmed"
    source: str = ""
    found_by: tuple[str, ...] = ()

    def key(self, by_file: bool = False) -> tuple:
        """The dedup identity, a stable anchor plus the class.

        The anchor is the first of these a pass records: the function or method symbol, else the
        endpoint with path params normalized so /x/<id> and /x/{id} collapse, else the line,
        else the file alone. The category is always part of the key, so two distinct classes at
        one anchor, a missing binding and a race on the same token route, stay separate
        findings. With `by_file` the file joins the endpoint key, so the same endpoint name in
        two files stays separate. Two distinct functions of one contract, a reentrancy in
        `_cleanupLoan` and one in `transform`, are two findings, not one, so collapsing them
        drops a real finding.
        """
        cat = self.category.strip().lower()
        file = self.file.strip().lower()
        sym = re.sub(r"[^a-z0-9_]", "", self.symbol.strip().lower().rsplit(".", 1)[-1])
        if sym:
            return ("sym", file, cat, sym)
        if self.endpoint:
            ep = re.sub(r"\s+", " ", re.sub(r"[<{][^>}]*[>}]", "*", self.endpoint.strip().lower()))
            return ("fc", file, cat, ep) if by_file else ("ep", ep, cat)
        if self.line is not None:
            return ("fl", file, cat, self.line)
        return ("fc", file, cat)


def _fold(existing: Candidate, incoming: Candidate) -> Candidate:
    """Fold a re-report into the kept candidate, never dropping it.

    The second report may be a distinct defect that only shares the anchor, so its evidence
    is unioned rather than discarded, the recall red line. A confirmed status upgrades a
    blocked one, since a later pass that confirms what an earlier could only block is
    strictly more informative.
    """
    status = "confirmed" if "confirmed" in (existing.status, incoming.status) else existing.status
    evidence = existing.evidence
    if incoming.evidence and incoming.evidence not in existing.evidence:
        evidence = f"{evidence}; {incoming.evidence}" if evidence else incoming.evidence
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    if status == existing.status and evidence == existing.evidence and found_by == existing.found_by:
        return existing
    return replace(existing, status=status, evidence=evidence, found_by=found_by)


def merge(pool: dict[tuple, Candidate], incoming: list[Candidate], by_file: bool = False) -> int:
    """Fold `incoming` into `pool` keyed by location, return how many were new.

    A duplicate never overwrites and never drops: it folds into the kept candidate, unioning
    evidence and upgrading a blocked status to confirmed, so a distinct defect that shares
    the anchor cannot be silently lost.
    """
    new = 0
    for cand in incoming:
        k = cand.key(by_file)
        existing = pool.get(k)
        if existing is None:
            pool[k] = cand
            new += 1
        else:
            pool[k] = _fold(existing, cand)
    return new


def collapse_colocated(cands: list[Candidate]) -> list[Candidate]:
    """Merge candidates that cite the exact same file, line, and class, preserving order.

    The primary key dedups by endpoint, but two passes can label one defect with different
    endpoint prose, a controller method on one pass and the HTTP route on another, so they
    survive endpoint dedup. An identical file, line, and category is the same defect by its
    objective location, so collapse those too. Only applies when a line is present, so a
    finding with no parsed line is never merged on file alone, which keeps recall safe.
    """
    seen: set[tuple] = set()
    out: list[Candidate] = []
    for c in cands:
        if c.file and c.line is not None:
            lk = (c.file.strip().lower(), c.line, c.category.strip().lower())
            if lk in seen:
                continue
            seen.add(lk)
        out.append(c)
    return out


@dataclass
class Accumulator:
    """The running union plus the convergence signal across passes."""

    converge_after: int = 2
    pool: dict[tuple, Candidate] = field(default_factory=dict)
    new_per_pass: list[int] = field(default_factory=list)
    clean_per_pass: list[bool] = field(default_factory=list)
    errors: int = 0
    failed_units: set[str] = field(default_factory=set)
    unit_failures: list[ReviewUnitFailure] = field(default_factory=list)
    sev_votes: dict[tuple, list[str]] = field(default_factory=dict)
    dedup_by_file: bool = False

    def add_pass(self, candidates: list[Candidate], *, clean: bool = True) -> int:
        """Fold one completed review pass into the growing union."""
        for c in candidates:
            self.sev_votes.setdefault(c.key(self.dedup_by_file), []).append(c.severity)
        n = merge(self.pool, candidates, self.dedup_by_file)
        self.new_per_pass.append(n)
        self.clean_per_pass.append(clean)
        return n

    @property
    def converged(self) -> bool:
        """True once the last `converge_after` passes each added nothing new and were each.

        reviewed cleanly. A pass whose model calls failed adds nothing not because the union
        saturated but because it never ran, so counting its empty result toward convergence
        would report a run that hit a rate limit or errored as complete, invariant 4. A failed
        pass resets the streak, so the run keeps going to max_passes and reports converged
        False.
        """
        if len(self.new_per_pass) < self.converge_after:
            return False
        recent_new = self.new_per_pass[-self.converge_after :]
        recent_clean = self.clean_per_pass[-self.converge_after :]
        return all(n == 0 for n in recent_new) and all(recent_clean)

    @property
    def findings(self) -> list[Candidate]:
        """The union, each finding's severity the median of the grades it was given across passes.

        so a jittering grade converges instead of taking whichever was seen first.
        """
        out: list[Candidate] = []
        for k, c in self.pool.items():
            sev = median(self.sev_votes.get(k, [c.severity]))
            out.append(replace(c, severity=sev) if sev != c.severity else c)
        return out
