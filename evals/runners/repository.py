"""Repository eval runner.

Score a repository review's output against an answer key. This does not run the
review, it reads the findings the review wrote and scores them. Reports come from the
confirmed `findings/*.md` a finalize produced, or a `findings.json`, or any json list of
reports, so one answer key scores both paths.
"""

from __future__ import annotations

from evals.results import Result
from evals.schema import AnswerKey, Report
from evals.scorers.parse import reports_from_findings_dir, reports_from_json
from evals.scorers.score import score

__all__ = ["reports_from_findings_dir", "reports_from_json", "score_repository"]


def score_repository(key: AnswerKey, reports: list[Report], *, source_root: str | None = None) -> Result:
    """Score repository review reports against an answer key."""
    return score(key, reports, source_root=source_root)
