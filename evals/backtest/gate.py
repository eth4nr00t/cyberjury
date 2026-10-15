"""Apply the regression policy to detection quality results.

Source-reviewed diff adjudication is the measure of record. `reviewed_gate` and `certify`
read saved `adjudicate-diff` outputs and keep strict raw matches beside reviewed matches.
`gate` applies the same policy to a repository result through its source assessment ledger.
Strict raw matches never decide a gate. Extra unkeyed reports remain for human review.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evals.adjudication import DiffAdjudicationResult

    Reviewed = Mapping[str, Sequence[DiffAdjudicationResult]]


def gate(
    after: dict,
    baseline: dict | None = None,
    *,
    precision_floor: float = 0.0,
    adjudication: dict,
    baseline_adjudication: dict | None = None,
    require_introductions: bool = False,
) -> list[str]:
    """The failures that should block landing, empty when the result passes.

    A baseline lets the gate judge a move, a findings check newly missed by source
    assessment, rather than an absolute that a noisy run could trip.
    """
    fails: list[str] = []

    if after.get("errors", 0):
        fails.append(f"{after['errors']} failed review steps, a failed step is not a clean pass")

    if precision_floor:
        precision = adjudication["report_precision"]
        if precision is None:
            fails.append("overall report precision is unknown while source assessments are pending")
        elif precision < precision_floor:
            fails.append(f"unique report precision {precision:.0%} is below the floor {precision_floor:.0%}")

    if baseline:
        if baseline.get("target") != after.get("target") or not after.get("target"):
            fails.append("baseline and changed results identify different targets")
        if ("runs" in baseline or "runs" in after) and baseline.get("runs") != after.get("runs"):
            fails.append("baseline and changed results use different run counts")
        if "n_findings" in baseline and "n_findings" in after and baseline["n_findings"] != after["n_findings"]:
            fails.append("baseline and changed results use different findings denominators")
        if baseline_adjudication is None:
            fails.append("both comparison arms require source assessments")
        else:
            newly_missed = sorted(set(baseline_adjudication["known_found"]) - set(adjudication["known_found"]))
            if newly_missed:
                fails.append(f"findings check newly missed, it was caught at baseline: {', '.join(newly_missed)}")
    elif baseline_adjudication is not None:
        fails.append("baseline source assessment requires a baseline result")

    for side, assessment, score in (("changed", adjudication, after), ("baseline", baseline_adjudication, baseline)):
        if assessment is None or score is None:
            continue
        if sum(assessment["counts"].values()) != score.get("n_reports"):
            fails.append(f"{side} adjudication candidate count does not match scored reports")
        if pending := assessment["pending"]:
            fails.append(f"{side} arm has {len(pending)} reports still needing source assessment")
        if assessment.get("machine_status_mismatch"):
            fails.append(f"{side} machine confirmed labels disagree with independent verification count")
        if require_introductions:
            if missing := assessment["missing_introductions"]:
                fails.append(f"{side} repository checks lack introduction diffs: {', '.join(missing)}")
            if invalid := assessment["introduction_not_ancestor"]:
                fails.append(f"{side} introduction commits follow the repository snapshot: {', '.join(invalid)}")
            if unpaired := assessment["new_supported"]:
                fails.append(f"{side} arm has {len(unpaired)} new supported issues without paired introduction diffs")

    return fails


def _checks(attempts: Sequence[DiffAdjudicationResult]) -> set[str]:
    return set(attempts[0].reviewed_found) | set(attempts[0].reviewed_missed)


def _pending(reviewed: Reviewed) -> int:
    return sum(len(attempt.pending) for attempts in reviewed.values() for attempt in attempts)


def reviewed_precision(reviewed: Reviewed) -> float | None:
    """Return unique supported reports over all reports, unknown while any report is pending."""
    if _pending(reviewed):
        return None
    counts = Counter()
    for attempts in reviewed.values():
        for attempt in attempts:
            counts.update(attempt.report_counts)
    total = sum(counts.values())
    return counts["supported"] / total if total else 1.0


def reviewed_gate(after: Reviewed, baseline: Reviewed | None = None, *, precision_floor: float = 0.0) -> list[str]:
    """Gate source-reviewed diff attempts, comparing per-case reviewed frequencies with a baseline.

    The attempts are saved `adjudicate-diff` summaries read as trusted inputs. Their attempt and
    ledger hashes are not re-verified here.
    """
    fails: list[str] = []
    for side, reviewed in (("changed", after), ("baseline", baseline)):
        if reviewed is not None and (pending := _pending(reviewed)):
            fails.append(f"{side} arm has {pending} reports still needing source assessment")
    if precision_floor:
        precision = reviewed_precision(after)
        if precision is None:
            fails.append("overall report precision is unknown while source assessments are pending")
        elif precision < precision_floor:
            fails.append(f"unique report precision {precision:.0%} is below the floor {precision_floor:.0%}")
    if baseline is None:
        return fails
    if set(baseline) != set(after):
        fails.append("baseline and changed arms cover different cases")
    for case in sorted(set(baseline) & set(after)):
        before, now = baseline[case], after[case]
        if len(before) != len(now):
            fails.append(f"{case} baseline and changed arms use different run counts")
            continue
        if _checks(before) != _checks(now):
            fails.append(f"{case} baseline and changed arms use different checks")
            continue
        runs = len(now)
        before_count = Counter(check for attempt in before for check in attempt.reviewed_found)
        after_count = Counter(check for attempt in now for check in attempt.reviewed_found)
        checks = sorted(_checks(now))
        newly_missed = [check for check in checks if before_count[check] * 2 > runs and after_count[check] * 2 <= runs]
        lost = [
            check for check in checks if before_count[check] and not after_count[check] and check not in newly_missed
        ]
        if newly_missed:
            fails.append(f"{case} findings check newly missed, it was caught at baseline: {', '.join(newly_missed)}")
        if lost:
            fails.append(f"{case} findings check lost every reviewed detection: {', '.join(lost)}")
    return fails


def reviewed_summary(reviewed: Reviewed) -> dict[str, int]:
    """Count reviewed and strict raw check matches across every attempt."""
    attempts = [attempt for case_attempts in reviewed.values() for attempt in case_attempts]
    return {
        "cases": len(reviewed),
        "attempts": len(attempts),
        "check_attempts": sum(len(attempt.reviewed_found) + len(attempt.reviewed_missed) for attempt in attempts),
        "reviewed_found": sum(len(attempt.reviewed_found) for attempt in attempts),
        "raw_found": sum(len(attempt.raw_found) for attempt in attempts),
        "pending": _pending(reviewed),
    }


def certify(
    reviewed: Reviewed,
    expected_cases: Mapping[str, frozenset[str]],
    *,
    runs: int = 3,
    required_passes: int = 2,
) -> dict[str, object]:
    """Require every expected findings case to pass enough source-reviewed whole-case attempts.

    `expected_cases` maps each case to the findings check ids of the current answer key, and saved
    attempts scored against another check set are rejected. An attempt passes when no report is
    pending and the ledger credits every findings check.
    Strict raw passes are reported beside reviewed passes and do not decide the result.
    The attempts are saved `adjudicate-diff` summaries read as trusted inputs. Their attempt and
    ledger hashes are not re-verified here.
    """
    if not expected_cases:
        raise ValueError("certification needs expected cases")
    if runs < 1 or not 1 <= required_passes <= runs:
        raise ValueError("certification run requirements are invalid")
    cases = []
    for case in expected_cases:
        attempts = tuple(reviewed.get(case, ()))
        if attempts and not _checks(attempts):
            raise ValueError(f"certification accepts findings cases only: {case}")
        if attempts and _checks(attempts) != expected_cases[case]:
            raise ValueError(f"certification attempts for {case} were scored against another answer key")
        passes = [
            attempt.attempt
            for attempt in attempts
            if not attempt.pending and attempt.reviewed_found and not attempt.reviewed_missed
        ]
        raw_passes = [attempt.attempt for attempt in attempts if attempt.raw_found and not attempt.raw_missed]
        pending = [attempt.attempt for attempt in attempts if attempt.pending]
        cases.append(
            {
                "case": case,
                "attempts": [attempt.attempt for attempt in attempts],
                "passes": passes,
                "raw_passes": raw_passes,
                "pending_attempts": pending,
                "passed": len(attempts) == runs and not pending and len(passes) >= required_passes,
            }
        )
    failed = [item["case"] for item in cases if not item["passed"]]
    unexpected = sorted(set(reviewed) - set(expected_cases))
    return {
        "runs": runs,
        "required_passes": required_passes,
        "passed": not failed and not unexpected,
        "passed_cases": len(cases) - len(failed),
        "raw_passed_cases": sum(len(item["raw_passes"]) >= required_passes for item in cases),
        "total_cases": len(cases),
        "failed_cases": failed,
        "unexpected_cases": unexpected,
        "cases": cases,
    }


def format_gate(fails: list[str], target: str) -> str:
    """Keep gate status stable for terminal output and CI logs."""
    if not fails:
        return f"gate PASS: {target}"
    lines = [f"gate FAIL: {target}, {len(fails)} blocking"]
    lines += [f"  - {f}" for f in fails]
    return "\n".join(lines)
