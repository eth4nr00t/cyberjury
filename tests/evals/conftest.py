"""Evaluation fixtures build real git benchmark projects and recorded attempts."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.support import git


@pytest.fixture
def benchmark_project(tmp_path):
    """A local git repository with one repository task and one findings diff task over it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test User")
    (repo / "views.py").write_text("def create():\n    return save()\n", encoding="utf-8")
    git(repo, "add", "views.py")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "views.py").write_text("def create():\n    return save(owner=None)\n", encoding="utf-8")
    git(repo, "commit", "-am", "ref")
    ref = git(repo, "rev-parse", "HEAD")
    project = tmp_path / "demo"
    project.mkdir()
    repository_task, diff_task = f"repository-{ref[:7]}", f"diff-{ref[:7]}-1"
    (project / "benchmark.yaml").write_text(
        "schema_version: 2\nbenchmark_id: demo\n"
        f"source:\n  kind: git\n  identity:\n    repository_path: {repo}\n    commit: {ref}\n  path: .\n"
        f"tasks:\n  - id: {repository_task}\n    kind: repository\n"
        f"  - id: {diff_task}\n    kind: diff\n    revision:\n      base_commit: {base}\n      commit: {ref}\n"
        "    expectation: findings\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        f"  - id: object-authorization\n    applies_to: [{diff_task}]\n    expectation: findings\n"
        "    locations: [{file: views.py, symbol: create}]\n"
        "    changes: [{file: views.py, line: 2, side: new}]\n"
        f"  - id: object-authorization\n    applies_to: [{repository_task}]\n    expectation: findings\n"
        "    locations: [{file: views.py, line: 2}]\n",
        encoding="utf-8",
    )
    return SimpleNamespace(
        manifest=project / "benchmark.yaml",
        repo=repo,
        base=base,
        ref=ref,
        diff_case=f"demo:{diff_task}",
        repository_case=f"demo:{repository_task}",
    )


@pytest.fixture
def write_attempt(benchmark_project):
    """Record an attempt of the diff case with one finding per candidate id."""
    from evals.adjudication import attempt_path
    from evals.benchmarks.cases import expected_checks, find_case

    def write(runs: Path, number: int, candidates: tuple[str, ...], *, complete: bool = True) -> Path:
        case = find_case(benchmark_project.diff_case, [benchmark_project.manifest])
        path = attempt_path(runs, case.name, number)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "case": case.name,
            "attempt": number,
            "complete": complete,
            "error": "" if complete else "finder failed",
            "expected_checks": expected_checks(case),
            "findings": [
                {
                    "id": identity,
                    "file": "views.py",
                    "line": 2,
                    "title": f"Claim {identity}",
                    "category": "missing-authorization",
                    "candidate_id": identity,
                    "supporting_reviewers": ["seat-a"],
                }
                for identity in candidates
            ],
        }
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    return write


@pytest.fixture
def write_ledger(benchmark_project):
    """Write the ledger beside an attempt with one record per given verdict."""
    import hashlib

    def write(attempt: Path, verdicts: dict[str, tuple[str, tuple[str, ...]]], **overrides) -> Path:
        data = json.loads(attempt.read_text(encoding="utf-8"))
        records = [
            {
                "candidate_id": identity,
                "verdict": verdict,
                "canonical_id": next(iter(set(verdicts) - {identity})) if verdict == "duplicate" else None,
                "check_ids": list(checks),
                "reason": "The view saves without an ownership check at views.py:2.",
                "proof_gap": "Need the caller scope" if verdict == "needs_review" else "",
                "evidence": [{"file": "views.py", "line": 2}],
            }
            for identity, (verdict, checks) in verdicts.items()
        ]
        ledger = {
            "schema": "cyberjury.eval-ledger/v2",
            "case": data["case"],
            "attempt": data["attempt"],
            "source_commit": benchmark_project.ref,
            "attempt_sha256": hashlib.sha256(attempt.read_bytes()).hexdigest(),
            "round_id": "round-" + "0" * 16,
            "rubric_sha256": "f" * 64,
            "records": records,
        } | overrides
        path = attempt.with_name(f"ledger-{data['attempt']:02d}.json")
        path.write_text(json.dumps(ledger), encoding="utf-8")
        return path

    return write
