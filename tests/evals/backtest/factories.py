"""Factories shared by backtest tests."""

from __future__ import annotations

import json


def result(target, found, missed, fps, n_findings, n_reports=0, errors=0, file_found=(), file_missed=(), extra=()):
    from evals.score.result import Result

    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        extra=list(extra),
        file_found=list(file_found),
        file_missed=list(file_missed),
        n_findings=n_findings,
        n_file_findings=len(file_found) + len(file_missed),
        n_reports=n_reports,
        errors=errors,
    )


def arm(
    workspace,
    *,
    errors=0,
    verify_errors=0,
    incomplete=0,
    unlocatable=0,
    complete=True,
    requests=100,
    seconds=60.0,
):
    leaf = workspace / "leaf"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": errors,
                "verify_errors": verify_errors,
                "incomplete": incomplete,
                "unlocatable": unlocatable,
                "complete": complete,
                "timing": {"total_seconds": seconds},
                "usage": {
                    "model_requests": requests,
                    "total_input_tokens": requests * 100,
                    "output_tokens": requests * 10,
                    "unit_review_calls": 20,
                },
            }
        ),
        encoding="utf-8",
    )
    return workspace
