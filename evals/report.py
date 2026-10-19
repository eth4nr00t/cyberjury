"""Report reviewed recall, report precision, and model call cost of adjudicated runs.

A runs directory holds attempt records with their ledgers. Every ledger is checked again against
its attempt bytes, the current case checks, and the pinned commit. Evidence lines were checked
against the source when the ledger was written. Recall counts checks credited by a
supported or duplicate report, once per attempt. Precision is supported / (supported +
not_actionable). Duplicate and needs_review reports are outside that ratio and reported as separate
counts. Precision stays unknown while any report needs review or when no report is supported or
not actionable. Issues are measured against the supported and duplicate verdicts: duplicate
issues count a root cause spread over several issues, and mixed issues hold reports of two root
causes.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path

from cyberjury.providers.metering import validate_model_calls_document
from evals.adjudication import VERDICTS, adjudicate
from evals.attempts import find_attempts, read_json
from evals.benchmarks.cases import BenchmarkCase

PRECISION_DEFINITION = (
    "precision = supported / (supported + not_actionable), and duplicate and needs_review reports are excluded "
    "from the ratio and counted separately"
)
_TOKENS = ("input_tokens", "cache_read_tokens", "cache_write_tokens", "output_tokens")


def summarize(cases: dict[str, BenchmarkCase], runs: Path, calls: Sequence[Path] = ()) -> dict[str, object]:
    """Summarize every attempt under one runs directory and the model call receipts of the same runs."""
    failed, unadjudicated, adjudicated = [], [], []
    for attempt in find_attempts(runs):
        if attempt.case not in cases:
            raise ValueError(f"{attempt.path} names an unknown case {attempt.case!r}")
        if not attempt.complete:
            failed.append(f"{attempt.case} attempt {attempt.number}: {attempt.error}")
        elif not attempt.ledger_path.is_file():
            unadjudicated.append(str(attempt.path))
        else:
            adjudicated.append(adjudicate(cases[attempt.case], attempt, read_json(attempt.ledger_path), None))
    counts = Counter()
    by_run: dict[int, Counter] = defaultdict(Counter)
    checks: dict[str, Counter] = defaultdict(Counter)
    for item in adjudicated:
        counts.update(item.counts)
        by_run[item.attempt].update(found=len(item.found), total=len(item.found) + len(item.missed))
        for check in item.found:
            checks[f"{item.case}:{check}"].update(found=1, attempts=1)
        for check in item.missed:
            checks[f"{item.case}:{check}"].update(found=0, attempts=1)
    reports = sum(counts.values())
    pending = counts["needs_review"]
    judged = counts["supported"] + counts["not_actionable"]
    return {
        "runs": str(runs),
        "cases": len({item.case for item in adjudicated}),
        "attempts": len(adjudicated),
        "failed": failed,
        "unadjudicated": unadjudicated,
        "recall": {
            "found": sum(run["found"] for run in by_run.values()),
            "total": sum(run["total"] for run in by_run.values()),
        },
        "recall_by_run": {number: dict(by_run[number]) for number in sorted(by_run)},
        "checks": {
            name: {"found": count["found"], "attempts": count["attempts"]} for name, count in sorted(checks.items())
        },
        "verdicts": {verdict: counts[verdict] for verdict in VERDICTS},
        "reports": reports,
        "issues": {
            "issues": sum(item.issues for item in adjudicated),
            "duplicate_issues": sum(item.duplicate_issues for item in adjudicated),
            "mixed_issues": sum(item.mixed_issues for item in adjudicated),
        },
        "precision": round(counts["supported"] / judged, 4) if judged and not pending else None,
        "precision_definition": PRECISION_DEFINITION,
        "ledger_rounds": sorted({(item.round_id, item.rubric_sha256) for item in adjudicated}),
        "cost": _cost(calls),
        "adjudications": adjudicated,
    }


def _receipts(paths: Sequence[Path]) -> list[Path]:
    found = []
    for path in paths:
        found.extend(sorted(path.rglob("*model-calls.json")) if path.is_dir() else [path])
    return found


def _cost(paths: Sequence[Path]) -> dict[str, object]:
    stages: dict[str, Counter] = defaultdict(Counter)
    receipts = _receipts(paths)
    for path in receipts:
        for call in validate_model_calls_document(read_json(path))["calls"]:
            stage = stages[f"{call['trigger']} {call['role']}"]
            stage.update(
                requests=1, failed=call["status"] == "failed", **{field: call.get(field, 0) for field in _TOKENS}
            )
    total = sum(stages.values(), Counter())
    return {
        "receipts": len(receipts),
        "total": {key: total[key] for key in ("requests", "failed", *_TOKENS)},
        "stages": {
            name: {key: stage[key] for key in ("requests", "failed", *_TOKENS)}
            for name, stage in sorted(stages.items())
        },
    }


def failures(summary: dict[str, object], *, precision_floor: float) -> list[str]:
    """Return the failures that block a run: incomplete work, mixed rubrics, a precision floor."""
    fails = []
    if summary["failed"]:
        fails.append(f"{len(summary['failed'])} failed attempts")
    if summary["unadjudicated"]:
        fails.append(f"{len(summary['unadjudicated'])} attempts without a ledger")
    if pending := summary["verdicts"]["needs_review"]:
        fails.append(f"{pending} reports still needing source assessment")
    if len({rubric for _round, rubric in summary["ledger_rounds"]}) > 1:
        fails.append("run mixes ledgers adjudicated under different rubrics")
    precision = summary["precision"]
    if precision_floor and precision is not None and precision < precision_floor:
        fails.append(f"report precision {precision:.0%} is below the floor {precision_floor:.0%}")
    return fails


def format_summary(summary: dict[str, object]) -> str:
    """Render one run for the terminal."""
    recall = summary["recall"]
    precision = "unknown" if summary["precision"] is None else f"{summary['precision']:.1%}"
    verdicts = ", ".join(f"{name} {count}" for name, count in summary["verdicts"].items())
    lines = [
        f"=== run: {summary['runs']} ===",
        f"  cases {summary['cases']}, adjudicated attempts {summary['attempts']}, "
        f"failed {len(summary['failed'])}, without ledger {len(summary['unadjudicated'])}",
        f"  reviewed recall {recall['found']}/{recall['total']}",
    ]
    lines += [f"    run {number}: {run['found']}/{run['total']}" for number, run in summary["recall_by_run"].items()]
    partial = [
        f"{name} {count['found']}/{count['attempts']}"
        for name, count in summary["checks"].items()
        if count["found"] < count["attempts"]
    ]
    if partial:
        lines.append("  checks not found in every attempt:")
        lines += [f"    {item}" for item in partial]
    counts = summary["verdicts"]
    lines += [
        f"  report precision {precision} = supported {counts['supported']} / (supported {counts['supported']} "
        f"+ not_actionable {counts['not_actionable']}), over {summary['reports']} reports",
        f"    excluded from precision: duplicate {counts['duplicate']}, needs_review {counts['needs_review']}",
        f"    {summary['precision_definition']}",
        f"  verdicts: {verdicts}",
        f"  issues {summary['issues']['issues']}: duplicate issues {summary['issues']['duplicate_issues']}, "
        f"mixed issues {summary['issues']['mixed_issues']}",
    ]
    lines += [f"  ledger round {round_id}, rubric sha256 {rubric}" for round_id, rubric in summary["ledger_rounds"]]
    lines += [f"  failed: {item}" for item in summary["failed"]]
    lines += [f"  without ledger: {item}" for item in summary["unadjudicated"]]
    cost = summary["cost"]
    if cost["receipts"]:
        lines.append(f"  model calls from {cost['receipts']} receipts: {_format_cost(cost['total'])}")
        lines += [f"    {name}: {_format_cost(stage)}" for name, stage in cost["stages"].items()]
    return "\n".join(lines)


def _format_cost(stage: dict[str, int]) -> str:
    total_input = stage["input_tokens"] + stage["cache_read_tokens"] + stage["cache_write_tokens"]
    return (
        f"requests {stage['requests']}, failed {stage['failed']}, input tokens {total_input} "
        f"(cache read {stage['cache_read_tokens']}), output tokens {stage['output_tokens']}"
    )


def to_json(summary: dict[str, object]) -> dict[str, object]:
    """Return the JSON form of one run."""
    return {key: value for key, value in summary.items() if key != "adjudications"} | {
        "ledger_rounds": [
            {"round_id": round_id, "rubric_sha256": rubric} for round_id, rubric in summary["ledger_rounds"]
        ],
        "adjudications": [
            {
                "case": item.case,
                "attempt": item.attempt,
                "found": list(item.found),
                "missed": list(item.missed),
                "pending": list(item.pending),
                "verdicts": item.counts,
                "issues": item.issues,
                "duplicate_issues": item.duplicate_issues,
                "mixed_issues": item.mixed_issues,
                "round_id": item.round_id,
            }
            for item in summary["adjudications"]
        ],
    }


def write_json(path: str, summary: dict[str, object], fails: list[str]) -> None:
    """Write the run summary and its failures."""
    document = {"run": to_json(summary), "failures": fails}
    Path(path).write_text(json.dumps(document, indent=2), encoding="utf-8")
