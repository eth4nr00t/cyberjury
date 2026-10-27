"""The one finding union every review target folds its findings into."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from cyberjury.review.finding import Finding

MERGE_RULE = (
    "A returned finding that repeats the `title`, `category`, `entrypoint`, `file`, `line`, and any `change_anchor` "
    "of an accepted finding is merged into it: its `attack_path` and `evidence_refs` are added, and its other fields "
    "are discarded."
)


class FindingAccumulator:
    """A monotonic finding union that merges only exact duplicate reports: findings sharing one candidate identity."""

    def __init__(self) -> None:
        """Start an empty union."""
        self._pool: dict[str, Finding] = {}

    def add(self, findings: Iterable[Finding]) -> None:
        """Fold findings into the union, merging each duplicate into the first report of its identity."""
        for finding in findings:
            identity = finding.candidate_id
            existing = self._pool.get(identity)
            self._pool[identity] = finding if existing is None else _fold(existing, finding)

    @property
    def findings(self) -> list[Finding]:
        """Return the stable insertion ordered union."""
        return list(self._pool.values())


def _normalized(text: str) -> str:
    return " ".join(text.lower().split())


def _union_text(existing: str, incoming: str) -> str:
    if not incoming or _normalized(incoming) in _normalized(existing):
        return existing
    return f"{existing}\n\n{incoming}" if existing else incoming


def _fold(existing: Finding, incoming: Finding) -> Finding:
    attack_path = _union_text(existing.attack_path, incoming.attack_path)
    evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    cited_spans = tuple(dict.fromkeys((*existing.cited_spans, *incoming.cited_spans)))
    return replace(existing, attack_path=attack_path, evidence_refs=evidence_refs, cited_spans=cited_spans)
