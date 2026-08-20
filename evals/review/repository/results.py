"""Score stored Repository Review output against benchmark answer keys."""

from __future__ import annotations

import os
from pathlib import Path

from evals.benchmarks.cases import find_repository_case
from evals.benchmarks.contract import RepositoryCase, load_answer_key
from evals.score.engine import score as score_reports
from evals.score.report import Report, reports_from_findings_dir, reports_from_json
from evals.score.result import Result


def score(
    name: str,
    *,
    workspace: str | Path | None = None,
    findings_json: str | Path | None = None,
    findings_dir: str | Path | None = None,
    source_root: str | None = None,
) -> Result:
    """Load one Repository Review output and score it."""
    case = find_repository_case(name)
    reports = _reports(case, workspace=workspace, findings_json=findings_json, findings_dir=findings_dir)
    return score_case(case, reports, source_root=source_root or _source_root(name))


def score_case(case: RepositoryCase, reports: list[Report], *, source_root: str | None = None) -> Result:
    """Score parsed reports for one materialized repository case."""
    key = load_answer_key(case.answer_key, task_id=case.task_id)
    return score_reports(key, reports, source_root=source_root)


def score_findings(case: RepositoryCase, findings_json: Path, *, source_root: Path) -> Result:
    """Score the machine output written by one completed coded run."""
    return score_case(case, reports_from_json(findings_json), source_root=str(source_root))


def failure_result(case: RepositoryCase, failure: Exception | str) -> Result:
    """Keep answer key denominators when repository execution fails."""
    key = load_answer_key(case.answer_key, task_id=case.task_id)
    detail = f"{type(failure).__name__}: {failure}" if isinstance(failure, Exception) else failure
    return Result(
        target=key.benchmark_id,
        n_findings=len(key.findings),
        n_file_findings=sum(1 for check in key.findings if check.files),
        missed=[check.id for check in key.findings],
        file_missed=[check.id for check in key.findings if check.files],
        errors=1,
        error_details=[f"{case.id}: {detail}"],
    )


def _reports(
    case: RepositoryCase,
    *,
    workspace: str | Path | None,
    findings_json: str | Path | None,
    findings_dir: str | Path | None,
) -> list[Report]:
    if findings_json is not None:
        return reports_from_json(findings_json)
    if findings_dir is not None:
        return reports_from_findings_dir(findings_dir)
    if workspace is not None:
        kind, path = _workspace_reports(Path(workspace), case.id, case.target)
        return reports_from_json(path) if kind == "json" else reports_from_findings_dir(path)
    raise ValueError("repository evaluation requires a workspace or findings input")


def _workspace_reports(workspace: Path, name: str, target: dict) -> tuple[str, Path]:
    """Resolve output only from the benchmark id or selected scope."""
    leaves = [name]
    scope = Path(str(target.get("path") or "")).name
    if scope and scope != "." and scope not in leaves:
        leaves.insert(0, scope)
    for leaf in leaves:
        project = workspace / leaf
        findings_json = project / "findings.json"
        if findings_json.is_file():
            return ("json", findings_json)
        findings_dir = project / "findings"
        if findings_dir.is_dir():
            return ("dir", findings_dir)

    raise FileNotFoundError(f"{workspace} has no findings.json or findings/ output for {name}")


def _source_root(name: str) -> str | None:
    """Resolve the source root used for symbol span scoring."""
    backtest_dir = os.environ.get("CYBERJURY_BACKTEST_DIR")
    if not backtest_dir:
        return None
    clone = Path(backtest_dir).expanduser() / "repositories" / name
    return str(clone) if clone.is_dir() else None
