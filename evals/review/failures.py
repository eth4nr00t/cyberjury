"""Describe failed benchmark review outcomes without implying clean results."""

from cyberjury.review.engine import ReviewOutcome


def failure_summary(outcome: ReviewOutcome[object]) -> str:
    """Preserve every known failure reason in evaluation output."""
    states = []
    if outcome.failures:
        first = outcome.failures[0]
        suffix = f", and {len(outcome.failures) - 1} more" if len(outcome.failures) > 1 else ""
        states.append(f"{first.reason}{suffix}")
    if outcome.failure_reason:
        states.append(outcome.failure_reason)
    if outcome.errors:
        states.append(f"{outcome.errors} review or verification errors")
    if outcome.incomplete:
        states.append(f"{len(outcome.incomplete)} incomplete findings")
    if outcome.pending:
        states.append(f"{len(outcome.pending)} pending investigations")
    if outcome.requires_convergence and not outcome.converged:
        states.append("review did not converge")
    return ", ".join(states) or "review degraded"
