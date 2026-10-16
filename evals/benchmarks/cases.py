"""Materialize benchmark tasks as review cases.

A case is one task of a project manifest, named `<benchmark_id>:<task_id>`, with the answer key
checks scoped to that task. Public projects live under `evals/projects/<project-id>`. This module is
engine-free so listing and adjudication do not import the review runner.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path

from evals.benchmarks.contract import KeyCheck, key_checks
from evals.benchmarks.validate import manifest_path, validate_benchmark

PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@dataclass(frozen=True, kw_only=True)
class BenchmarkCase:
    """One benchmark task with its pinned git target and the answer key checks scoped to it."""

    name: str
    kind: str
    expectation: str
    target: dict[str, str]
    checks: tuple[KeyCheck, ...]

    @property
    def findings(self) -> tuple[KeyCheck, ...]:
        """Return checks that expect findings."""
        return tuple(check for check in self.checks if check.expectation == "findings")


def expected_checks(case: BenchmarkCase) -> list[dict]:
    """Return the JSON form of the case checks."""
    return json.loads(json.dumps([asdict(check) for check in case.checks]))


def checks_sha256(case: BenchmarkCase) -> str:
    """Return the digest of the case checks that a ledger is adjudicated against."""
    return sha256(json.dumps(expected_checks(case), sort_keys=True).encode()).hexdigest()


def public_manifests() -> list[Path]:
    """Return every public project manifest."""
    return sorted(PROJECTS_DIR.glob("*/benchmark.yaml"))


def load_cases(manifests: Sequence[str | Path] | None = None) -> dict[str, BenchmarkCase]:
    """Load every task of the given manifests, defaulting to the public projects."""
    cases: dict[str, BenchmarkCase] = {}
    for path in manifests or public_manifests():
        manifest, answer_key = validate_benchmark(manifest_path(path))
        checks = key_checks(answer_key)
        for task in manifest["tasks"]:
            name = f"{manifest['benchmark_id']}:{task['id']}"
            if name in cases:
                raise ValueError(f"two manifests define benchmark case {name!r}")
            cases[name] = BenchmarkCase(
                name=name,
                kind=task["kind"],
                expectation=task.get("expectation", "findings"),
                target=target_for_task(manifest["source"], task),
                checks=tuple(check for check in checks if task["id"] in check.applies_to),
            )
    return cases


def find_case(name: str, manifests: Sequence[str | Path] | None = None) -> BenchmarkCase:
    """Resolve one case and fail loud with the known names."""
    cases = load_cases(manifests)
    if name not in cases:
        raise ValueError(f"unknown benchmark case {name!r}. Known: {', '.join(cases) or 'none'}")
    return cases[name]


def target_for_task(source: Mapping, task: Mapping) -> dict[str, str]:
    """Translate a validated git source and task into the pinned review target."""
    identity = source["identity"]
    revision = task.get("revision") or {}
    target = {"ref": revision.get("commit") or identity["commit"], "path": source["path"]}
    if identity.get("url"):
        target["url"] = identity["url"]
    else:
        target["root"] = identity["repository_path"]
    if task["kind"] == "diff":
        target["base"] = revision["base_commit"]
    return target


def target_repository(target: Mapping[str, str]) -> Path:
    """Return the local repository path of a git target without touching it."""
    if url := target.get("url"):
        name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
        digest = sha256(url.encode("utf-8")).hexdigest()[:12]
        return Path.home() / ".cache" / "cyberjury" / "diff-targets" / f"{name}-{digest}"
    return Path(target["root"]).expanduser()


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
    for ref in (target.get("base"), target.get("ref")):
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
    """Reject answer key changes absent from the patch the review reads."""
    if not any(check.changes for check in case.checks):
        return
    from cyberjury.detection import load_detection
    from cyberjury.review.diff.model import diff_line_ranges

    ranges = diff_line_ranges(diff, load_detection())
    sides = {"old": ranges.old, "new": ranges.new}
    for check in case.checks:
        for anchor in check.changes:
            line_ranges = sides[anchor.side].get(anchor.file, ())
            if any(start <= anchor.line <= end for start, end in line_ranges):
                continue
            raise ValueError(
                f"diff case {case.name!r} answer-key check {check.id!r} change anchor "
                f"{anchor.file}:{anchor.line}:{anchor.side} is absent from the reviewed patch"
            )
