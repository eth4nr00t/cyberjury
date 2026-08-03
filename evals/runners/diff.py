"""Diff-path eval runner: run synthetic diff cases through the audit engine and score.

A capability probe, not a golden set in the product sense: it runs a set of realistic
small diffs through audit_diff against a real provider and tallies which vulnerability
classes the current model, prompt, and rules catch, and which safe lookalikes they wrongly
flag. The cases ship as data under benchmarks/diff, grouped by the knowledge guides
taxonomy, see diff_cases.py for the loader, so adding one is a data change.
"""

from __future__ import annotations

from cyberjury.domains.registry import get_domain
from cyberjury.review.diff.engine import audit_diff
from evals.diff_cases import DiffCase, default_cases, load_cases
from evals.results import Result

__all__ = ["DiffCase", "default_cases", "load_cases", "run_diff_cases"]


def run_diff_cases(
    cases: list[DiffCase],
    *,
    provider,
    model: str,
    mode: str = "standard",
    rounds: int = 3,
    finder_provider=None,
    finder_model=None,
    challenger_provider=None,
    challenger_model=None,
    judge_provider=None,
    judge_model=None,
) -> Result:
    """Run every case through audit_diff and fold into a Result. A positive is found when
    the audit returns any finding, a safe case is a false positive when it does. Each case
    runs under its own domain, so a Solidity case scores against the evm knowledge and
    prompt rather than the web default. The seats and rounds come from the same wiring the
    `review diff` CLI builds, so the probe reviews a diff the way the product does. An unusable
    model reply is counted as an error, not silently a clean pass, invariant 4."""
    res = Result(target="diff", n_planted=sum(1 for c in cases if c.is_positive))
    for c in cases:
        try:
            kept, _dropped, degraded = audit_diff(
                c.diff,
                provider=provider,
                model=model,
                mode=mode,
                max_rounds=rounds,
                finder_provider=finder_provider,
                finder_model=finder_model,
                challenger_provider=challenger_provider,
                challenger_model=challenger_model,
                judge_provider=judge_provider,
                judge_model=judge_model,
                domain=get_domain(c.domain),
            )
        except Exception:
            # a failed or unparsable model call is a failed case, counted not hidden,
            # so a provider outage cannot read as a clean probe, invariant 4
            res.errors += 1
            continue
        if degraded:
            # a degraded audit, such as adversarial mode falling back on an unusable judge,
            # is a failed step too, not a clean zero-finding result, invariant 4
            res.errors += 1
            continue
        res.n_reports += len(kept)
        hit = len(kept) > 0
        if c.is_positive:
            (res.found if hit else res.missed).append(c.name)
        elif hit:
            res.false_positives.append(c.name)
    return res
