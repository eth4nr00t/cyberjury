"""Define repository finding identity and shared accumulation adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from cyberjury.review.engine import FindingAccumulator, ReviewOutcome
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.identity import attack_path_identity, candidate_identity
from cyberjury.review.provenance import found_by_tuple


@dataclass(frozen=True, kw_only=True)
class Candidate:
    """One finding a unit proposed, before cross-unit accumulation and verification."""

    title: str
    category: str = ""
    source_operation_id: str = field(default="", repr=False, compare=False)
    endpoint: str = ""
    symbol: str = ""
    file: str = ""
    line: int | None = None
    severity: str = "HIGH"
    attack_path: str = ""
    evidence: str = ""
    evidence_refs: tuple[str, ...] = field(default=(), repr=False, compare=False)
    found_by: tuple[str, ...] = ()

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
            root_cause=self.title,
            source_operation_id=self.source_operation_id,
        )

    def key(self) -> tuple:
        """Return the report site identity, independent from model wording.

        A bound source operation or an exact file line is one finding whatever its title or
        class label. Only a report without a line falls back to its symbol, endpoint, or file
        together with its class.
        """
        file = self.file.strip().lower()
        if self.source_operation_id:
            return ("operation", self.source_operation_id)
        if self.line is not None:
            return ("site", file, self.line)
        category = self.category.strip().lower()
        symbol = re.sub(r"[^a-z0-9_]", "", self.symbol.strip().lower().rsplit(".", 1)[-1])
        if symbol:
            return ("symbol", file, symbol, category)
        if self.endpoint:
            endpoint = re.sub(r"\s+", " ", re.sub(r"[<{][^>}]*[>}]", "*", self.endpoint.strip().lower()))
            return ("endpoint", endpoint, category)
        return ("file", file, category)


def _fold(existing: Candidate, incoming: Candidate) -> Candidate:
    """Fold a re-report into the kept candidate, unioning evidence and never dropping it."""
    attack_path = existing.attack_path
    if incoming.attack_path and incoming.attack_path not in existing.attack_path:
        attack_path = f"{attack_path}; {incoming.attack_path}" if attack_path else incoming.attack_path
    evidence = existing.evidence
    if incoming.evidence and incoming.evidence not in existing.evidence:
        evidence = f"{evidence}; {incoming.evidence}" if evidence else incoming.evidence
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    if (
        attack_path == existing.attack_path
        and evidence == existing.evidence
        and found_by == existing.found_by
        and evidence_refs == existing.evidence_refs
    ):
        return existing
    return replace(
        existing,
        attack_path=attack_path,
        evidence=evidence,
        evidence_refs=evidence_refs,
        found_by=found_by,
    )


def candidate_accumulator(
    *,
    pool: dict[tuple, Candidate] | None = None,
    severity_votes: dict[tuple, list[str]] | None = None,
) -> FindingAccumulator[Candidate]:
    """Build the repository identity and evidence policy on the shared union."""
    return FindingAccumulator(
        key=lambda candidate: candidate.key(),
        fold=_fold,
        grade=lambda candidate: candidate.severity,
        with_grade=lambda candidate, severity: replace(candidate, severity=severity),
        pool=pool if pool is not None else {},
        grade_votes=severity_votes if severity_votes is not None else {},
    )


@dataclass
class Accumulator:
    """The running repository union with its failure accounting."""

    pool: dict[tuple, Candidate] = field(default_factory=dict)
    errors: int = 0
    failed_units: set[str] = field(default_factory=set)
    unit_failures: list[ReviewUnitFailure] = field(default_factory=list)
    outcome: ReviewOutcome[Candidate] | None = None
    sev_votes: dict[tuple, list[str]] = field(default_factory=dict)
    _findings: FindingAccumulator[Candidate] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Bind persisted union fields to the shared accumulation state."""
        self._findings = candidate_accumulator(pool=self.pool, severity_votes=self.sev_votes)

    @property
    def findings(self) -> list[Candidate]:
        """Return the union with repeated severity grades stabilized by their median."""
        return self._findings.findings

    @property
    def finding_accumulator(self) -> FindingAccumulator[Candidate]:
        """Expose the shared union to the shared unit scheduler."""
        return self._findings
