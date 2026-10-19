"""Materialize the cases of benchmark definitions as review cases.

A case of a project's `benchmark.yaml` is named `<project id>:<case id>` and carries its nested
checks. Public projects live under `evals/projects/<project-id>`. This module is engine-free so
listing and adjudication do not import the review runner.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from evals.benchmarks.contract import Check, case_checks
from evals.benchmarks.validate import benchmark_path, validate_benchmark

PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@dataclass(frozen=True, kw_only=True)
class BenchmarkCase:
    """One benchmark case with its pinned git target and its checks."""

    name: str
    kind: str
    target: dict[str, str]
    checks: tuple[Check, ...]


def expected_checks(case: BenchmarkCase) -> list[dict]:
    """Return the case checks in their benchmark.yaml form."""
    return [check.to_dict() for check in case.checks]


def checks_sha256(case: BenchmarkCase) -> str:
    """Return the digest of the case checks that a ledger is adjudicated against."""
    return sha256(json.dumps(expected_checks(case), sort_keys=True).encode()).hexdigest()


def public_benchmarks() -> list[Path]:
    """Return every public project benchmark definition."""
    return sorted(PROJECTS_DIR.glob("*/benchmark.yaml"))


def load_cases(benchmarks: Sequence[str | Path] | None = None) -> dict[str, BenchmarkCase]:
    """Load every case of the given benchmark definitions, defaulting to the public projects."""
    cases: dict[str, BenchmarkCase] = {}
    for path in benchmarks or public_benchmarks():
        benchmark = validate_benchmark(benchmark_path(path))
        for case in benchmark["cases"]:
            name = f"{benchmark['id']}:{case['id']}"
            if name in cases:
                raise ValueError(f"two benchmark definitions define case {name!r}")
            cases[name] = BenchmarkCase(
                name=name,
                kind=case["kind"],
                target=case_target(benchmark["repository"], case),
                checks=case_checks(case["checks"]),
            )
    return cases


def find_case(name: str, benchmarks: Sequence[str | Path] | None = None) -> BenchmarkCase:
    """Resolve one case and fail loud with the known names."""
    cases = load_cases(benchmarks)
    if name not in cases:
        raise ValueError(f"unknown benchmark case {name!r}. Known: {', '.join(cases) or 'none'}")
    return cases[name]


def case_target(repository: Mapping, case: Mapping) -> dict[str, str]:
    """Translate a validated repository and case into the pinned whole-repository review target."""
    target = {"commit": case["commit"] if case["kind"] == "diff" else repository["commit"]}
    if repository.get("url"):
        target["url"] = repository["url"]
    else:
        target["local_path"] = repository["local_path"]
    if case["kind"] == "diff":
        target["base"] = case["base"]
    return target


def target_repository(target: Mapping[str, str]) -> Path:
    """Return the local repository path of a git target without touching it."""
    if url := target.get("url"):
        name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
        digest = sha256(url.encode("utf-8")).hexdigest()[:12]
        return Path.home() / ".cache" / "cyberjury" / "diff-targets" / f"{name}-{digest}"
    return Path(target["local_path"])


def git_target_root(target: Mapping[str, str]) -> Path:
    """Resolve a git target to a local repository root, cloning or updating a URL target in the user cache."""
    root = target_repository(target)
    if url := target.get("url"):
        _sync_clone(url, root)
    return root


def ensure_git_target_refs(target: Mapping[str, str], root: Path) -> None:
    """Fetch exact commit targets that are not advertised by branch or tag refs."""
    if not target.get("url"):
        return
    for ref in (target.get("base"), target.get("commit")):
        if ref and ref != EMPTY_TREE:
            _ensure_commit(root, ref)


def _ensure_commit(root: Path, ref: str) -> None:
    exists = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if exists.returncode == 0:
        return
    subprocess.run(
        ["git", "-C", str(root), "fetch", "origin", ref],
        capture_output=True,
        text=True,
        check=True,
    )


def _sync_clone(url: str, root: Path) -> None:
    if (root / ".git").is_dir():
        subprocess.run(
            ["git", "-C", str(root), "fetch", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*"],
            capture_output=True,
            text=True,
            check=True,
        )
        return
    root.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(root)],
        capture_output=True,
        text=True,
        check=True,
    )


def validate_change_anchors(case: BenchmarkCase, diff: str) -> None:
    """Reject change anchors absent from the patch the review reads."""
    if not any(check.change_anchors for check in case.checks):
        return
    from cyberjury.detection import load_detection
    from cyberjury.review.diff.model import diff_line_ranges

    ranges = diff_line_ranges(diff, load_detection())
    sides = {"old": ranges.old, "new": ranges.new}
    for check in case.checks:
        for anchor in check.change_anchors:
            line_ranges = sides[anchor.side].get(anchor.file, ())
            if any(start <= anchor.line <= end for start, end in line_ranges):
                continue
            raise ValueError(
                f"diff case {case.name!r} check {check.id!r} change anchor "
                f"{anchor.file}:{anchor.line}:{anchor.side} is absent from the reviewed patch"
            )
