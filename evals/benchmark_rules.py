"""Benchmark library invariants."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from evals import registry
from evals.coverage import coverage_matrix, scan_knowledge
from evals.schema import KeyEntry, load_answer_key, require_schema_version

_HERE = Path(__file__).resolve().parent
_GITHUB_ORGS = _HERE / "github-organizations.yaml"
_GITHUB_RE = re.compile(r"github\.com[:/]([^/]+)/([^/#?]+)", re.IGNORECASE)


@dataclass(frozen=True, kw_only=True)
class BenchmarkRuleProblem:
    """One benchmark data problem found by an invariant check."""

    kind: str
    path: Path
    detail: str


@dataclass(frozen=True, kw_only=True)
class GitHubURL:
    """One GitHub URL found anywhere in a benchmark YAML file."""

    path: Path
    yaml_path: str
    url: str
    owner: str
    repo: str


def github_organization_owners(path: Path = _GITHUB_ORGS) -> frozenset[str]:
    """Load owners that were externally verified as GitHub organizations."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    require_schema_version(data, path, "GitHub organization registry")
    owners = data.get("owners")
    if not isinstance(owners, list) or not owners:
        raise ValueError(f"{path} has no owners list")
    out = frozenset(str(owner) for owner in owners)
    bad = [owner for owner in out if owner != owner.lower() or "_" in owner]
    if bad:
        raise ValueError(f"{path} contains invalid GitHub owner names: {', '.join(sorted(bad))}")
    return out


def github_urls(root: Path) -> tuple[GitHubURL, ...]:
    """Find every GitHub URL nested anywhere under benchmark YAML data."""
    found: list[GitHubURL] = []
    for path in sorted(root.rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for yaml_path, value in _walk_scalars(data):
            if not isinstance(value, str) or "github.com" not in value.lower():
                continue
            match = _GITHUB_RE.search(value)
            if not match:
                found.append(GitHubURL(path=path, yaml_path=yaml_path, url=value, owner="", repo=""))
                continue
            found.append(
                GitHubURL(
                    path=path,
                    yaml_path=yaml_path,
                    url=value,
                    owner=match.group(1),
                    repo=match.group(2).removesuffix(".git"),
                )
            )
    return tuple(found)


def github_url_problems(root: Path) -> list[BenchmarkRuleProblem]:
    """Check GitHub URL spelling and owner class without a network call."""
    orgs = github_organization_owners()
    problems: list[BenchmarkRuleProblem] = []
    for url in github_urls(root):
        if not url.owner or not url.repo:
            problems.append(
                BenchmarkRuleProblem(
                    kind="invalid-github-url",
                    path=url.path,
                    detail=f"{url.yaml_path} is not a canonical GitHub repository URL: {url.url}",
                )
            )
            continue
        owner_repo = f"{url.owner}/{url.repo}"
        if owner_repo != owner_repo.lower() or "_" in owner_repo:
            problems.append(
                BenchmarkRuleProblem(
                    kind="noncanonical-github-url",
                    path=url.path,
                    detail=f"{url.yaml_path} uses {owner_repo}, expected lowercase names without underscores",
                )
            )
        if url.owner.lower() not in orgs:
            problems.append(
                BenchmarkRuleProblem(
                    kind="personal-github-owner",
                    path=url.path,
                    detail=f"{url.yaml_path} uses owner {url.owner}, which is not in the organization registry",
                )
            )
    return problems


def repository_diff_coverage_problems(root: Path) -> list[BenchmarkRuleProblem]:
    """Require GitHub repository findings to have matching finding diff coverage."""
    problems: list[BenchmarkRuleProblem] = []
    for manifest in sorted(root.rglob("benchmark.yaml")):
        data = registry.load_project_manifest(manifest)
        target = data.get("target") or {}
        if not _is_github_git_target(target):
            if _has_repository_tasks(data) and not _is_explorer_target(target) and not _has_diff_tasks(data):
                problems.append(
                    BenchmarkRuleProblem(
                        kind="repository-without-diff",
                        path=manifest,
                        detail="repository benchmark has no GitHub URL, no explorer target, and no diff tasks",
                    )
                )
            continue
        repo_tasks = [task for task in data.get("tasks") or [] if task.get("kind") == "repository"]
        if not repo_tasks:
            continue
        diff_tasks = [
            task
            for task in data.get("tasks") or []
            if task.get("kind") == "diff" and str(task.get("expectation") or "findings") == "findings"
        ]
        if not diff_tasks:
            problems.append(
                BenchmarkRuleProblem(
                    kind="github-repository-without-finding-diff",
                    path=manifest,
                    detail="GitHub repository benchmark has no finding diff task",
                )
            )
            continue
        key_path = manifest.parent / "answer-key.yaml"
        diff_entries = []
        for task in diff_tasks:
            diff_entries.extend(load_answer_key(key_path, task_id=str(task["id"])).planted)
        for task in repo_tasks:
            for entry in load_answer_key(key_path, task_id=str(task["id"])).planted:
                if not any(_same_finding(entry, diff_entry) for diff_entry in diff_entries):
                    problems.append(
                        BenchmarkRuleProblem(
                            kind="repository-finding-missing-diff",
                            path=manifest,
                            detail=f"{task['id']} entry {entry.id} has no matching finding diff entry",
                        )
                    )
    return problems


def knowledge_coverage_problems() -> list[BenchmarkRuleProblem]:
    """Require every knowledge file to be exercised by at least one benchmark entry."""
    covered = coverage_matrix()
    known = scan_knowledge()
    problems: list[BenchmarkRuleProblem] = []
    for ref, item in sorted(known.items()):
        if not covered[ref].covered:
            problems.append(
                BenchmarkRuleProblem(
                    kind="knowledge-without-benchmark",
                    path=item.path,
                    detail=f"{ref} has no benchmark coverage",
                )
            )
    return problems


def _walk_scalars(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk_scalars(child, child_path)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _walk_scalars(child, f"{path}[{i}]")
    else:
        yield path, value


def _is_github_git_target(target: dict) -> bool:
    return target.get("type") == "git" and "github.com" in str(target.get("url") or "").lower()


def _is_explorer_target(target: dict) -> bool:
    if target.get("type") == "explorer":
        return True
    url = str(target.get("url") or "").lower()
    return "etherscan.io" in url or "bscscan.com" in url


def _has_repository_tasks(data: dict) -> bool:
    return any(task.get("kind") == "repository" for task in data.get("tasks") or [])


def _has_diff_tasks(data: dict) -> bool:
    return any(task.get("kind") == "diff" for task in data.get("tasks") or [])


def _same_finding(left: KeyEntry, right: KeyEntry) -> bool:
    if left.id != right.id:
        return False
    if left.category != right.category:
        return False
    if set(left.knowledge) != set(right.knowledge):
        return False
    if left.files and right.files and not set(left.files).intersection(right.files):
        return False
    return not (left.symbols and right.symbols and not set(left.symbols).intersection(right.symbols))
