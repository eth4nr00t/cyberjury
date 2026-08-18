"""Evaluate stored Repository Review output against an answer key."""

from __future__ import annotations

import os
from pathlib import Path

from evals.benchmarks.cases import find_repository_case
from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.report import reports_from_findings_dir, reports_from_json
from evals.score.result import Result


def evaluate(
    name: str,
    *,
    workspace: str | Path | None = None,
    findings_json: str | Path | None = None,
    findings_dir: str | Path | None = None,
    source_root: str | None = None,
) -> Result:
    """Load one Repository Review output and score it."""
    benchmark = find_repository_case(name)
    key = load_answer_key(benchmark.answer_key, task_id=benchmark.task_id)
    if findings_json is not None:
        reports = reports_from_json(findings_json)
    elif findings_dir is not None:
        reports = reports_from_findings_dir(findings_dir)
    elif workspace is not None:
        kind, path = _workspace_reports(Path(workspace), name, benchmark.target)
        reports = reports_from_json(path) if kind == "json" else reports_from_findings_dir(path)
    else:
        raise ValueError("repository evaluation requires a workspace or findings input")
    return score(key, reports, source_root=_source_root(name, source_root))


def _workspace_reports(workspace: Path, name: str, target: dict) -> tuple[str, Path]:
    """Resolve one review output without guessing between multiple candidates."""
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

    json_hits = sorted(workspace.rglob("findings.json"))
    if len(json_hits) == 1:
        return ("json", json_hits[0])
    dir_hits = sorted(path for path in workspace.rglob("findings") if path.is_dir())
    if len(dir_hits) == 1:
        return ("dir", dir_hits[0])
    if json_hits or dir_hits:
        raise ValueError(f"{workspace} contains multiple findings outputs, pass --findings-json or --findings-dir")
    raise FileNotFoundError(f"{workspace} has no findings.json or findings/ output for {name}")


def _source_root(name: str, explicit: str | None) -> str | None:
    """Resolve the source root used for symbol span scoring."""
    if explicit:
        return explicit
    backtest_dir = os.environ.get("CYBERJURY_BACKTEST_DIR")
    if not backtest_dir:
        return None
    clone = Path(backtest_dir).expanduser() / "repositories" / name
    return str(clone) if clone.is_dir() else None
