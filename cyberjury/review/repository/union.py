"""Define repository finding identity and shared accumulation adapters."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace

from cyberjury.review.claims import ClaimRecord, merge_claims
from cyberjury.review.engine import ConvergenceState, FindingAccumulator, ReviewOutcome, merge_findings
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.identity import attack_path_identity, candidate_identity
from cyberjury.review.navigation import SourceNavigationSession, SourceNavigator
from cyberjury.review.provenance import found_by_tuple


@dataclass(frozen=True, kw_only=True)
class Candidate:
    """One finding a pass proposed, before cross-pass dedup and verification."""

    title: str
    category: str = ""
    decision_rule_id: str = field(default="", repr=False, compare=False)
    source_operation_id: str = field(default="", repr=False, compare=False)
    endpoint: str = ""
    symbol: str = ""
    file: str = ""
    line: int | None = None
    repair_file: str = field(default="", repr=False, compare=False)
    repair_line: int | None = field(default=None, repr=False, compare=False)
    repair_complete: bool = field(default=False, repr=False, compare=False)
    severity: str = "HIGH"
    attack_path: str = ""
    evidence: str = ""
    status: str = "confirmed"
    source: str = ""
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)
    found_by: tuple[str, ...] = ()
    claims: tuple[ClaimRecord, ...] = field(default=(), repr=False, compare=False)

    @property
    def claim_records(self) -> tuple[ClaimRecord, ...]:
        """Expose the original report even when this identity has not folded."""
        if self.claims:
            return self.claims
        record = asdict(self)
        for field_name in ("claims", "found_by", "status", "source", "source_operation_id"):
            record.pop(field_name)
        return (ClaimRecord.create(self.candidate_id, record),)

    @property
    def attack_path_id(self) -> str:
        """Return the shared path identity independent from security category."""
        return attack_path_identity(
            target="repository",
            path_anchor=self.endpoint or self.symbol or f"{self.file}:{self.line or ''}",
        )

    @property
    def candidate_id(self) -> str:
        """Return one security violation identity on the shared attack path."""
        return candidate_identity(
            target="repository",
            file=self.file,
            line=self.line,
            category=self.category,
            path_anchor=self.endpoint or self.symbol or f"{self.file}:{self.line or ''}",
            decision_rule_id=self.decision_rule_id,
            source_operation_id=self.source_operation_id,
        )

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

        The repair site is deliberately not part of this key: the same identity reported across
        passes carries inconsistent repair annotations, so keying on it would split one finding
        into several. Root-cause folding by repair site runs as a second stage, `fold_by_repair`,
        over this anchor-deduped union, where each identity already appears once.
        """
        cat = self.category.strip().lower()
        rule = self.decision_rule_id.strip().lower()
        file = self.file.strip().lower()
        if self.source_operation_id and rule:
            return ("operation", self.source_operation_id, cat, rule)
        if self.line is not None:
            return ("fl", file, cat, rule, self.line)
        sym = re.sub(r"[^a-z0-9_]", "", self.symbol.strip().lower().rsplit(".", 1)[-1])
        if sym:
            return ("sym", file, cat, rule, sym)
        if self.endpoint:
            ep = re.sub(r"\s+", " ", re.sub(r"[<{][^>}]*[>}]", "*", self.endpoint.strip().lower()))
            return ("fc", file, cat, rule, ep) if by_file else ("ep", ep, cat, rule)
        return ("fc", file, cat, rule)


def bind_source_operation(
    candidate: Candidate,
    navigator: SourceNavigator | SourceNavigationSession | None,
) -> Candidate:
    """Bind one report line to an unambiguous shared callsite identity."""
    if navigator is None or candidate.source_operation_id:
        return candidate
    operation_id = navigator.source_operation_id(candidate.file, candidate.line)
    return replace(candidate, source_operation_id=operation_id) if operation_id else candidate


def _fold(existing: Candidate, incoming: Candidate) -> Candidate:
    """Fold a re-report into the kept candidate, never dropping it.

    The second report may be a distinct defect that only shares the anchor, so its evidence
    is unioned rather than discarded, the recall red line. A confirmed status upgrades a
    blocked one, since a later pass that confirms what an earlier could only block is
    strictly more informative.
    """
    status = "confirmed" if "confirmed" in (existing.status, incoming.status) else existing.status
    attack_path = existing.attack_path
    if incoming.attack_path and incoming.attack_path not in existing.attack_path:
        attack_path = f"{attack_path}; {incoming.attack_path}" if attack_path else incoming.attack_path
    evidence = existing.evidence
    if incoming.evidence and incoming.evidence not in existing.evidence:
        evidence = f"{evidence}; {incoming.evidence}" if evidence else incoming.evidence
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    claims = merge_claims(existing.claim_records, incoming.claim_records)
    if (
        status == existing.status
        and attack_path == existing.attack_path
        and evidence == existing.evidence
        and found_by == existing.found_by
        and evidence_refs == existing.evidence_refs
        and claims == existing.claims
    ):
        return existing
    return replace(
        existing,
        status=status,
        attack_path=attack_path,
        evidence=evidence,
        evidence_refs=evidence_refs,
        found_by=found_by,
        claims=claims,
    )


def merge(
    pool: dict[tuple, Candidate],
    incoming: list[Candidate],
    by_file: bool = False,
) -> int:
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


def _repair_key(candidate: Candidate) -> tuple:
    """Group by the single site that fully fixes a finding, else keep its own identity.

    A finding folds on its repair site only when it declares one receipt-resolved site fully
    resolves it, so consumers of one uncontained producer each fully fixed there fold together. A
    finding that also needs another fix, keeps a residual claim, or left the completeness unstated
    keeps its own candidate identity and stays separate, the recall red line. The caller passes an
    anchor-deduped union, so every candidate identity already appears once and no identity can split.
    """
    if candidate.repair_complete and candidate.repair_file and candidate.repair_line is not None:
        return (
            "repair",
            candidate.repair_file.strip().lower(),
            candidate.category.strip().lower(),
            candidate.repair_line,
        )
    return ("id", candidate.candidate_id)


def fold_by_repair(candidates: list[Candidate]) -> list[Candidate]:
    """Collapse same-root duplicates in an anchor-deduped union by their shared repair site.

    This is the second identity stage after anchor accumulation, run before verification. It only
    merges candidates with distinct anchors that fully fix at one site, never splits an identity,
    and preserves every original claim through the shared fold.
    """
    pool: dict[tuple, Candidate] = {}
    merge_findings(pool, candidates, key=_repair_key, fold=_fold)
    return list(pool.values())


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
