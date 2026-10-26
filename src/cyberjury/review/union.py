"""The one finding union every review target folds its findings into."""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass, field, replace

from cyberjury.review.finding import Finding
from cyberjury.review.provenance import found_by_tuple

MERGE_RULE = (
    "A returned finding that repeats the `title`, `category`, `entrypoint`, `file`, `line`, and any `change_anchor` "
    "of an accepted finding is merged into it: its `attack_path` and `evidence_refs` are added, and its other fields "
    "are discarded."
)


@dataclass
class FindingAccumulator[T]:
    """A monotonic finding union configured by one target policy."""

    key: Callable[[T], Hashable]
    fold: Callable[[T, T], T]
    pool: dict[Hashable, T] = field(default_factory=dict)

    def add(self, findings: Iterable[T]) -> int:
        """Fold one set into the union and return its new identity count."""
        new = 0
        for finding in findings:
            identity = self.key(finding)
            existing = self.pool.get(identity)
            if existing is None:
                self.pool[identity] = finding
                new += 1
            else:
                self.pool[identity] = self.fold(existing, finding)
        return new

    @property
    def findings(self) -> list[T]:
        """Return the stable insertion ordered union."""
        return list(self.pool.values())


def _normalized(text: str) -> str:
    return " ".join(text.lower().split())


def _union_text(existing: str, incoming: str) -> str:
    if not incoming or _normalized(incoming) in _normalized(existing):
        return existing
    return f"{existing}\n\n{incoming}" if existing else incoming


def _fold(existing: Finding, incoming: Finding) -> Finding:
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    attack_path = _union_text(existing.attack_path, incoming.attack_path)
    evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    cited_spans = tuple(dict.fromkeys((*existing.cited_spans, *incoming.cited_spans)))
    if (
        found_by == existing.found_by
        and attack_path == existing.attack_path
        and evidence_refs == existing.evidence_refs
        and cited_spans == existing.cited_spans
    ):
        return existing
    return replace(
        existing,
        attack_path=attack_path,
        evidence_refs=evidence_refs,
        cited_spans=cited_spans,
        found_by=found_by,
    )


def finding_accumulator() -> FindingAccumulator[Finding]:
    """Merge only exact duplicate reports: findings that share one candidate identity."""
    return FindingAccumulator(
        key=lambda finding: finding.candidate_id,
        fold=_fold,
    )
