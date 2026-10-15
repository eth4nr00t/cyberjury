"""Score stored Repository Review output against benchmark answer keys."""

from __future__ import annotations

from pathlib import Path

from cyberjury.review.request import ReviewIntent
from cyberjury.workspace import read_json_object
from evals.benchmarks.cases import find_repository_case
from evals.benchmarks.contract import RepositoryCase, load_answer_key
from evals.review.source import review_scope
from evals.score.engine import score as score_reports
from evals.score.report import Report, reports_from_json
from evals.score.result import Result


def score(
    name: str,
    *,
    workspace: str | Path | None = None,
    findings_json: str | Path | None = None,
    source_root: str | None = None,
) -> Result:
    """Load one Repository Review output and score it."""
    case = find_repository_case(name)
    reports = _reports(case, workspace=workspace, findings_json=findings_json, source=source_root)
    return score_case(case, reports, source_root=source_root)


def score_case(case: RepositoryCase, reports: list[Report], *, source_root: str | None = None) -> Result:
    """Score parsed reports for one materialized repository case."""
    key = load_answer_key(case.answer_key, task_id=case.task_id)
    return score_reports(key, reports, source_root=source_root)


def _reports(
    case: RepositoryCase,
    *,
    workspace: str | Path | None,
    findings_json: str | Path | None,
    source: str | None,
) -> list[Report]:
    if findings_json is not None:
        return reports_from_json(findings_json)
    if workspace is not None:
        return reports_from_json(_workspace_reports(Path(workspace), case, source_root=source))
    raise ValueError("repository evaluation requires a workspace or findings input")


def _workspace_reports(workspace: Path, case: RepositoryCase, *, source_root: str | None = None) -> Path:
    """Select one completed session for the benchmark target.

    `source_root` is the checkout root; the session must have reviewed the case's scope inside it.
    """
    sessions = (
        [workspace] if (workspace / "review.json").is_file() else sorted((workspace / "reviews").glob("review-*"))
    )
    leaves = {case.project_id or case.id.split(":", 1)[0], Path(str(case.target.get("path") or "")).name}
    requested_source = review_scope(Path(source_root), case.target).resolve() if source_root is not None else None
    matching: list[tuple[Path, Path]] = []
    for session in sessions:
        if session.is_symlink() or not session.is_dir():
            raise ValueError(f"review session path is invalid: {session}")
        intent = ReviewIntent.from_dict(read_json_object(session / "review.json"))
        if intent.target.kind != "repository" or intent.requested_profile not in {case.profile, "auto"}:
            continue
        target = Path(intent.target.repository).resolve()
        if requested_source is not None and target != requested_source:
            continue
        if requested_source is None and target.name not in leaves:
            continue
        matching.append((session, target))
    if not matching:
        raise FileNotFoundError(f"{workspace} has no review session for {case.id}")
    if len(matching) != 1:
        raise ValueError(f"{workspace} has multiple review sessions for {case.id}, select one review directory")
    session, target = matching[0]
    project = session / "work" / target.name
    if project.is_symlink():
        raise ValueError(f"review project path is invalid: {project}")
    status = read_json_object(project / "_run.json")
    if (
        status.get("schema") != "cyberjury.repository-run/v3"
        or status.get("complete") is not True
        or status.get("state") != "complete"
        or status.get("errors") != 0
        or status.get("verify_errors") != 0
    ):
        raise ValueError(f"{project} has no complete repository run")
    findings = project / "findings.json"
    if not findings.is_file():
        raise FileNotFoundError(f"{project} has no findings.json")
    return findings
