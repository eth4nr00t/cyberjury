"""Strict score results and repeated run frequency summaries.

`Result` records one strictly scored benchmark. `RepeatedResult` retains check frequencies
across runs and derives a strict majority summary. Source-reviewed adjudication, not this
score, is the measure of record.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(kw_only=True)
class Result:
    """Aggregate score counters for one evaluation run."""

    target: str
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    n_findings: int = 0
    n_reports: int = 0
    errors: int = 0
    error_details: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        """Return recall for findings checks in the score."""
        return len(self.found) / self.n_findings if self.n_findings else 0.0

    @property
    def precision_known(self) -> float:
        """Real reports over reports that landed on a known check, findings or clean.

        An extra report is excluded since the key cannot say whether it is a real bug.
        """
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict[str, object]:
        """Return the stable wire form consumed by reports and persisted state."""
        d = asdict(self)
        if not self.error_details:
            d.pop("error_details", None)
        d["recall"] = round(self.recall, 4)
        d["precision_known"] = round(self.precision_known, 4)
        return d


@dataclass(kw_only=True)
class RepeatedResult:
    """Repeated runs summarized by check frequency and strict majority.

    A findings check counts as found when more than half of the runs find it. Frequencies
    remain available so callers can inspect the spread instead of relying only on the
    summary. The read surface mirrors `Result` for shared formatting and comparison.
    """

    target: str
    runs: int
    found_freq: dict[str, int]
    fp_freq: dict[str, int]
    extra_freq: dict[str, int] = field(default_factory=dict)
    n_findings: int = 0
    errors: int = 0
    error_details: list[str] = field(default_factory=list)
    reports_total: int = 0

    @classmethod
    def from_runs(cls, target: str, runs: list[Result]) -> RepeatedResult:
        """Fold a list of single-run Results for one target into frequency counts.

        Every findings-check id seen in any run is kept, so an id found in no run still reads as missed
        rather than vanishing. Complete runs must describe the same answer-key checks. Failed runs may
        carry a partial check list, but retain the same target and denominators.
        """
        if not runs:
            raise ValueError("no runs to aggregate")
        cls._validate_runs(target, runs)
        found_freq: dict[str, int] = {}
        fp_freq: dict[str, int] = {}
        extra_freq: dict[str, int] = {}
        for r in runs:
            for i in (*r.found, *r.missed):
                found_freq.setdefault(i, 0)
            for i in r.found:
                found_freq[i] += 1
            for i in r.false_positives:
                fp_freq[i] = fp_freq.get(i, 0) + 1
            for i in r.extra:
                extra_freq[i] = extra_freq.get(i, 0) + 1
        return cls(
            target=target,
            runs=len(runs),
            found_freq=found_freq,
            fp_freq=fp_freq,
            extra_freq=extra_freq,
            n_findings=runs[0].n_findings,
            errors=sum(r.errors for r in runs),
            error_details=[detail for r in runs for detail in r.error_details],
            reports_total=sum(r.n_reports for r in runs),
        )

    @staticmethod
    def _validate_runs(target: str, runs: list[Result]) -> None:
        reference = runs[0]
        for index, run in enumerate(runs, 1):
            if run.target != target:
                raise ValueError(f"run {index} target {run.target!r} does not match {target!r}")
            if run.n_findings != reference.n_findings:
                raise ValueError(
                    f"run {index} findings denominator {run.n_findings} does not match {reference.n_findings}"
                )

        complete = [(index, run) for index, run in enumerate(runs, 1) if not run.errors]
        if not complete:
            return
        reference_index, reference = complete[0]
        findings = set(reference.found) | set(reference.missed)
        for index, run in complete[1:]:
            if set(run.found) | set(run.missed) != findings:
                raise ValueError(f"run {index} findings check ids do not match run {reference_index}")

    def _majority(self, count: int) -> bool:
        return count * 2 > self.runs

    @property
    def found(self) -> list[str]:
        """Return findings-check ids that won a majority of runs."""
        return sorted(i for i, c in self.found_freq.items() if self._majority(c))

    @property
    def missed(self) -> list[str]:
        """Return findings checks not credited by a strict majority of runs."""
        caught = set(self.found)
        return sorted(i for i in self.found_freq if i not in caught)

    @property
    def false_positives(self) -> list[str]:
        """Return clean checks reported in a strict majority of runs."""
        return sorted(i for i, c in self.fp_freq.items() if self._majority(c))

    @property
    def extra(self) -> list[str]:
        """Return unkeyed reports that won a majority of runs."""
        return sorted(i for i, c in self.extra_freq.items() if self._majority(c))

    @property
    def n_reports(self) -> int:
        """Return the total number of scored reports."""
        return self.reports_total

    @property
    def recall(self) -> float:
        """Return recall for findings checks in the score."""
        return len(self.found) / self.n_findings if self.n_findings else 0.0

    @property
    def precision_known(self) -> float:
        """Return precision over answer-key-known reports."""
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict[str, object]:
        """Return the stable wire form consumed by reports and persisted state."""
        d = {
            "target": self.target,
            "runs": self.runs,
            "found": self.found,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "found_freq": dict(sorted(self.found_freq.items())),
            "fp_freq": dict(sorted(self.fp_freq.items())),
            "extra": self.extra,
            "extra_freq": dict(sorted(self.extra_freq.items())),
            "n_findings": self.n_findings,
            "n_reports": self.n_reports,
            "errors": self.errors,
            "error_details": self.error_details,
            "recall": round(self.recall, 4),
            "precision_known": round(self.precision_known, 4),
        }
        if not self.error_details:
            d.pop("error_details", None)
        return d
