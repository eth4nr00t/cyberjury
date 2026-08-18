"""Decide whether a backtest result satisfies the acceptance policy.

This is the policy the eval ruler enforces in CI. It reads a result, optionally against
a baseline, and fails loud on a regression. The bar follows the invariants: a failed
review step is not a clean pass, a findings check that was caught at baseline must not
silently go missing, a clean check must not become a false positive, precision must
hold a floor, and the benchmark data itself must be sound, every knowledge reference
resolving and every answer check locatable. An extra unkeyed report alone is not a failure,
the key cannot say whether it is a real bug, so the gate does not punish it.
"""

from __future__ import annotations


def gate(
    after: dict, baseline: dict | None = None, *, precision_floor: float = 0.0, structural: bool = True
) -> list[str]:
    """The failures that should block landing, empty when the result passes.

    A baseline lets the gate judge a move, a findings check newly missed or a newly
    introduced false positive, rather than an absolute that a noisy run could trip.
    """
    fails: list[str] = []

    if after.get("errors", 0):
        fails.append(f"{after['errors']} failed review steps, a failed step is not a clean pass, invariant 4")

    if precision_floor and after.get("precision_known", 1.0) < precision_floor:
        fails.append(f"precision {after.get('precision_known', 0.0):.0%} is below the floor {precision_floor:.0%}")

    bfp = set(baseline.get("false_positives", [])) if baseline else set()
    new_fp = sorted(set(after.get("false_positives", [])) - bfp)
    if new_fp:
        fails.append(f"new false positive on a clean check: {', '.join(new_fp)}")

    if baseline:
        newly_missed = sorted(set(baseline.get("found", [])) - set(after.get("found", [])))
        if newly_missed:
            fails.append(f"findings check newly missed, it was caught at baseline: {', '.join(newly_missed)}")

    if structural:
        try:
            from evals.benchmarks.coverage import coverage_problems

            for p in coverage_problems():
                if p.kind == "unresolved-reference":
                    fails.append(f"unresolved knowledge reference: {p.detail}")
        except ValueError as e:
            fails.append(f"benchmark data did not load, an answer check is unlocatable: {e}")

    return fails


def format_gate(fails: list[str], target: str) -> str:
    """Keep gate status stable for terminal output and CI logs."""
    if not fails:
        return f"gate PASS: {target}"
    lines = [f"gate FAIL: {target}, {len(fails)} blocking"]
    lines += [f"  - {f}" for f in fails]
    return "\n".join(lines)
