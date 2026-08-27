"""Define repository finding identity and shared accumulation adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from cyberjury.review.engine import ConvergenceState, FindingAccumulator, ReviewOutcome, merge_findings
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.provenance import found_by_tuple


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
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)
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
    return merge_findings(
        pool,
        incoming,
        key=lambda candidate: candidate.key(by_file),
        fold=_fold,
    )


def candidate_accumulator(
    *,
    by_file: bool = False,
    pool: dict[tuple, Candidate] | None = None,
    severity_votes: dict[tuple, list[str]] | None = None,
) -> FindingAccumulator[Candidate]:
    """Build the repository identity and evidence policy on the shared union."""
    return FindingAccumulator(
        key=lambda candidate: candidate.key(by_file),
        fold=_fold,
        grade=lambda candidate: candidate.severity,
        with_grade=lambda candidate, severity: replace(candidate, severity=severity),
        pool=pool if pool is not None else {},
        grade_votes=severity_votes if severity_votes is not None else {},
    )


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
    pending_per_pass: list[bool] = field(default_factory=list)
    errors: int = 0
    failed_units: set[str] = field(default_factory=set)
    unit_failures: list[ReviewUnitFailure] = field(default_factory=list)
    outcome: ReviewOutcome[Candidate] | None = None
    sev_votes: dict[tuple, list[str]] = field(default_factory=dict)
    dedup_by_file: bool = False
    _convergence: ConvergenceState = field(init=False, repr=False)
    _findings: FindingAccumulator[Candidate] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Bind persisted pass fields to the shared accumulation state."""
        self._convergence = ConvergenceState(
            converge_after=self.converge_after,
            new_per_round=self.new_per_pass,
            clean_per_round=self.clean_per_pass,
            pending_per_round=self.pending_per_pass,
        )
        self._findings = candidate_accumulator(
            by_file=self.dedup_by_file,
            pool=self.pool,
            severity_votes=self.sev_votes,
        )

    def add_pass(self, candidates: list[Candidate], *, clean: bool = True, pending: bool = False) -> int:
        """Fold one completed review pass into the growing union."""
        n = self._findings.add(candidates)
        self._convergence.record(n, clean=clean, pending=pending)
        return n

    @property
    def converged(self) -> bool:
        """Require consecutive clean passes that add no finding identity."""
        return self.outcome.converged if self.outcome is not None else self._convergence.converged

    @property
    def findings(self) -> list[Candidate]:
        """Return the union with repeated severity grades stabilized by their median."""
        return self._findings.findings

    @property
    def finding_accumulator(self) -> FindingAccumulator[Candidate]:
        """Expose the shared union to the shared cycle scheduler."""
        return self._findings

    @property
    def convergence(self) -> ConvergenceState:
        """Expose the shared convergence state to the shared cycle scheduler."""
        return self._convergence
