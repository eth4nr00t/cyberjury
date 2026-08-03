"""The score of a review against an answer key.

A Result is one benchmark scored once, JSON-serializable so compare can read two of them
and name what moved. Recall and precision are derived, never stored, so they cannot drift
from the lists they summarize. A SuiteResult folds N repeated runs of one benchmark by
frequency, the anti-noise verdict the review is not deterministic, so a single lucky or
unlucky run cannot move the score.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(kw_only=True)
class Result:
    target: str
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    n_planted: int = 0
    n_reports: int = 0
    errors: int = 0  # review or engine calls that failed, counted not hidden, invariant 4

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        """Real reports over reports that landed on a known entry, planted or safe. An
        extra report is excluded since the key cannot say whether it is a real bug."""
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recall"] = round(self.recall, 4)
        d["precision_known"] = round(self.precision_known, 4)
        return d

    def to_markdown(self) -> str:
        rows = [
            f"### {self.target}",
            f"- recall: {len(self.found)}/{self.n_planted} = {self.recall:.0%}",
            f"- precision: {self.precision_known:.0%}",
        ]
        if self.missed:
            rows.append(f"- missed: {', '.join(self.missed)}")
        if self.false_positives:
            rows.append(f"- false positive on safe: {', '.join(self.false_positives)}")
        if self.errors:
            rows.append(f"- errors: {self.errors}, a failed step is not a clean pass")
        return "\n".join(rows)


@dataclass(kw_only=True)
class SuiteResult:
    """N repeated runs of one benchmark folded by frequency. A planted issue counts as found
    when a strict majority of the runs found it, so noise across runs does not flip the
    verdict. The frequencies are kept, not just the verdict, so compare can read the spread.
    The read surface mirrors Result, found and missed and recall, so the same formatter and
    compare serve both."""

    target: str
    runs: int
    found_freq: dict[str, int]  # planted id to the count of runs that found it
    fp_freq: dict[str, int]  # safe id to the count of runs that flagged it
    n_planted: int = 0
    errors: int = 0  # failed case runs summed across all runs, invariant 4
    reports_total: int = 0

    @classmethod
    def from_runs(cls, target: str, runs: list[Result]) -> SuiteResult:
        """Fold a list of single-run Results for one target into frequency counts. Every
        planted id seen in any run is kept, so an id found in no run still reads as missed
        rather than vanishing."""
        if not runs:
            raise ValueError("no runs to aggregate")
        found_freq: dict[str, int] = {}
        fp_freq: dict[str, int] = {}
        for r in runs:
            for i in (*r.found, *r.missed):
                found_freq.setdefault(i, 0)
            for i in r.found:
                found_freq[i] += 1
            for i in r.false_positives:
                fp_freq[i] = fp_freq.get(i, 0) + 1
        return cls(
            target=target,
            runs=len(runs),
            found_freq=found_freq,
            fp_freq=fp_freq,
            n_planted=max(r.n_planted for r in runs),
            errors=sum(r.errors for r in runs),
            reports_total=sum(r.n_reports for r in runs),
        )

    def _majority(self, count: int) -> bool:
        return count * 2 > self.runs

    @property
    def found(self) -> list[str]:
        return sorted(i for i, c in self.found_freq.items() if self._majority(c))

    @property
    def missed(self) -> list[str]:
        caught = set(self.found)
        return sorted(i for i in self.found_freq if i not in caught)

    @property
    def false_positives(self) -> list[str]:
        return sorted(i for i, c in self.fp_freq.items() if self._majority(c))

    @property
    def extra(self) -> list[str]:
        # frequency folds per-id, an unkeyed extra has no stable id across runs, so the
        # suite verdict does not carry it, read a single run for the extras
        return []

    @property
    def n_reports(self) -> int:
        return self.reports_total

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "runs": self.runs,
            "found": self.found,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "found_freq": dict(sorted(self.found_freq.items())),
            "fp_freq": dict(sorted(self.fp_freq.items())),
            "n_planted": self.n_planted,
            "n_reports": self.n_reports,
            "errors": self.errors,
            "recall": round(self.recall, 4),
            "precision_known": round(self.precision_known, 4),
        }

    def to_markdown(self) -> str:
        rows = [
            f"### {self.target}",
            f"- runs: {self.runs}, found by strict majority",
            f"- recall: {len(self.found)}/{self.n_planted} = {self.recall:.0%}",
            f"- precision: {self.precision_known:.0%}",
        ]
        flaky = {i: c for i, c in self.found_freq.items() if 0 < c < self.runs}
        if flaky:
            rows.append("- flaky: " + ", ".join(f"{i} {c}/{self.runs}" for i, c in sorted(flaky.items())))
        if self.missed:
            rows.append(f"- missed: {', '.join(self.missed)}")
        if self.false_positives:
            rows.append(f"- false positive on safe: {', '.join(self.false_positives)}")
        if self.errors:
            rows.append(f"- errors: {self.errors}, a failed step is not a clean pass")
        return "\n".join(rows)
