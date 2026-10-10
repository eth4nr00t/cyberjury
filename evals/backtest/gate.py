"""Apply the regression policy to a detection quality result.

The gate blocks failed review steps, newly missed findings checks, new false positives,
precision below the configured floor, and invalid benchmark contracts. Extra unkeyed
reports remain for human review because the answer key cannot classify them.
"""

from __future__ import annotations


def gate(
    after: dict,
    baseline: dict | None = None,
    *,
    precision_floor: float = 0.0,
    structural: bool = True,
    adjudication: dict | None = None,
    baseline_adjudication: dict | None = None,
    require_introductions: bool = False,
) -> list[str]:
    """The failures that should block landing, empty when the result passes.

    A baseline lets the gate judge a move, a findings check newly missed or a newly
    introduced false positive, rather than an absolute that a noisy run could trip.
    """
    fails: list[str] = []

    if after.get("errors", 0):
        fails.append(f"{after['errors']} failed review steps, a failed step is not a clean pass, invariant 4")

    if precision_floor:
        precision = adjudication["report_precision"] if adjudication is not None else after.get("precision_known", 1.0)
        if precision is None:
            fails.append("overall report precision is unknown while source assessments are pending")
        elif precision < precision_floor:
            label = "unique report precision" if adjudication is not None else "known-check precision"
            fails.append(f"{label} {precision:.0%} is below the floor {precision_floor:.0%}")

    bfp = set(baseline.get("false_positives", [])) if baseline else set()
    new_fp = sorted(set(after.get("false_positives", [])) - bfp)
    if new_fp:
        fails.append(f"new false positive on a clean check: {', '.join(new_fp)}")

    if baseline:
        if baseline.get("target") != after.get("target") or not after.get("target"):
            fails.append("baseline and changed results identify different targets")
        if "n_findings" in baseline and "n_findings" in after and baseline["n_findings"] != after["n_findings"]:
            fails.append("baseline and changed results use different findings denominators")
        if (adjudication is None) != (baseline_adjudication is None):
            fails.append("both comparison arms require source assessments when either arm has one")
        before_found = (
            baseline_adjudication["known_found"] if baseline_adjudication is not None else baseline.get("found", [])
        )
        after_found = adjudication["known_found"] if adjudication is not None else after.get("found", [])
        newly_missed = sorted(set(before_found) - set(after_found))
        if newly_missed:
            fails.append(f"findings check newly missed, it was caught at baseline: {', '.join(newly_missed)}")
    elif baseline_adjudication is not None:
        fails.append("baseline source assessment requires a baseline result")

    for side, assessment, score in (("changed", adjudication, after), ("baseline", baseline_adjudication, baseline)):
        if assessment is None or score is None:
            continue
        if assessment["target"] != score.get("target"):
            fails.append(f"{side} adjudication target does not match the score")
        if sum(assessment["counts"].values()) != score.get("n_reports"):
            fails.append(f"{side} adjudication candidate count does not match scored reports")
        if pending := assessment["pending"]:
            fails.append(f"{side} arm has {len(pending)} reports still needing source assessment")
        if assessment["machine_status_mismatch"]:
            fails.append(f"{side} machine confirmed labels disagree with independent verification count")
        if require_introductions:
            missing = assessment["missing_introductions"]
            invalid = assessment["introduction_not_ancestor"]
            unpaired = assessment["new_supported"]
            if missing:
                fails.append(f"{side} repository checks lack introduction diffs: {', '.join(missing)}")
            if invalid:
                fails.append(f"{side} introduction commits follow the repository snapshot: {', '.join(invalid)}")
            if unpaired:
                fails.append(f"{side} arm has {len(unpaired)} new supported issues without paired introduction diffs")

    if structural:
        try:
            from evals.benchmarks.coverage import coverage_problems

            coverage_problems()
        except ValueError as exc:
            fails.append(f"benchmark contract validation failed: {exc}")

    return fails


def format_gate(fails: list[str], target: str) -> str:
    """Keep gate status stable for terminal output and CI logs."""
    if not fails:
        return f"gate PASS: {target}"
    lines = [f"gate FAIL: {target}, {len(fails)} blocking"]
    lines += [f"  - {f}" for f in fails]
    return "\n".join(lines)
