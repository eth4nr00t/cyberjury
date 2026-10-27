"""Evaluation fixtures build real git benchmark projects and recorded attempts."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.attempts import attempt_path
from evals.benchmarks.cases import checks_sha256, find_case, load_cases
from tests.support import git


@pytest.fixture
def benchmark_project(tmp_path):
    """A local git repository with one repository case and one diff case over it."""
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
    git(repo, "commit", "-am", "change")
    commit = git(repo, "rev-parse", "HEAD")
    project = tmp_path / "demo"
    project.mkdir()
    repository_case, diff_case = f"repository-{commit[:7]}", f"diff-{commit[:7]}"
    (project / "benchmark.yaml").write_text(
        f"id: demo\nrepository:\n  local_path: {repo}\n  commit: {commit}\n"
        f"cases:\n  - id: {repository_case}\n    kind: repository\n    checks:\n"
        "      - id: create-missing-owner\n        root_cause: create saves without an owner check\n"
        "        locations: [{file: views.py, line: 2}]\n"
        f"  - id: {diff_case}\n    kind: diff\n    base: {base}\n    commit: {commit}\n    checks:\n"
        "      - id: create-missing-owner\n        root_cause: create saves without an owner check\n"
        "        locations: [{file: views.py, symbol: create}]\n"
        "        change_anchors: [{file: views.py, line: 2, side: new}]\n",
        encoding="utf-8",
    )
    return SimpleNamespace(
        benchmark=project / "benchmark.yaml",
        repo=repo,
        base=base,
        commit=commit,
        diff_case=f"demo:{diff_case}",
        repository_case=f"demo:{repository_case}",
    )


@pytest.fixture
def case(benchmark_project):
    """Return the benchmark project's diff case."""
    return find_case(benchmark_project.diff_case, [benchmark_project.benchmark])


@pytest.fixture
def cases(benchmark_project):
    """Load every case of the benchmark project."""
    return load_cases([benchmark_project.benchmark])


@pytest.fixture
def write_attempt(benchmark_project):
    """Record an attempt of the diff case with one finding per candidate id, each its own issue unless given."""

    def write(
        runs: Path,
        number: int,
        candidates: tuple[str, ...],
        *,
        complete: bool = True,
        issues: tuple[tuple[str, ...], ...] | None = None,
    ) -> Path:
        case = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])
        path = attempt_path(runs, case.name, number)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "case": case.name,
            "attempt": number,
            "complete": complete,
            "error": "" if complete else "finder failed",
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
            "issues": [
                {"representative": members[0], "members": list(members)}
                for members in (issues if issues is not None else tuple((identity,) for identity in candidates))
            ],
        }
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    return write


@pytest.fixture
def write_ledger(benchmark_project):
    """Write the ledger beside an attempt with one record per given verdict."""

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
            "schema": "cyberjury.eval-ledger/v1",
            "case": data["case"],
            "attempt": data["attempt"],
            "source_commit": benchmark_project.commit,
            "attempt_sha256": hashlib.sha256(attempt.read_bytes()).hexdigest(),
            "round_id": "round-" + "0" * 16,
            "rubric_sha256": "f" * 64,
            "checks_sha256": checks_sha256(find_case(data["case"], [benchmark_project.benchmark])),
            "records": records,
        } | overrides
        path = attempt.with_name(f"ledger-{data['attempt']:02d}.json")
        path.write_text(json.dumps(ledger), encoding="utf-8")
        return path

    return write
