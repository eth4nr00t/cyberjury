"""Materialize benchmark tasks as executable review cases.

Real commit diff targets use project benchmark tasks under the project data root, so diff and repository
evidence share one target definition. A findings task carries findings checks, a clean task carries clean
lookalikes. This module is engine-free so listing and adjudication do not import the review runner.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from evals.benchmarks import registry
from evals.benchmarks.contract import (
    AnswerKey,
    BenchmarkProject,
    RepositoryCase,
    load_answer_key,
)

PROJECTS_DIR = registry.PUBLIC_PROJECTS_DIR
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def git_target_root(target: dict) -> Path | None:
    """Resolve a git target to a local repository root."""
    if target.get("type") != "git":
        return None
    url = target.get("url")
    if url:
        return _cloned_target_root(str(url))
    path = target.get("root") or target.get("path")
    if path:
        return Path(str(path)).expanduser()
    return None


def ensure_git_target_refs(target: dict, root: Path | None = None) -> None:
    """Fetch exact commit targets that are not advertised by branch or tag refs."""
    if target.get("type") != "git" or not target.get("url"):
        return
    root = root or git_target_root(target)
    if root is None:
        return
    for ref in (target.get("base"), target.get("ref")):
        if ref and ref != EMPTY_TREE:
            _ensure_commit(root, str(ref))


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


def _cloned_target_root(url: str) -> Path:
    name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
    digest = sha256(url.encode("utf-8")).hexdigest()[:12]
    root = Path.home() / ".cache" / "cyberjury" / "diff-targets" / f"{name}-{digest}"
    if (root / ".git").is_dir():
        subprocess.run(
            ["git", "-C", str(root), "fetch", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*"],
            capture_output=True,
            text=True,
            check=True,
        )
        return root
    root.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(root)],
        capture_output=True,
        text=True,
        check=True,
    )
    return root


@dataclass(frozen=True, kw_only=True)
class DiffCase:
    """One diff benchmark case with its expected answer key checks."""

    name: str
    answer_key: AnswerKey
    target: dict = field(default_factory=dict)
    provenance: str = "public"
    profile: str = "web"
    expectation: str = "findings"

    @property
    def is_positive(self) -> bool:
        """Report whether the case has a findings check."""
        return bool(self.answer_key.findings)


def diff_text(case: DiffCase) -> str:
    """Derive the case diff from its pinned git target and check the answer-key changes against it."""
    diff = _target_diff(case.target)
    if not diff:
        raise ValueError(f"diff case '{case.name}' has no diff")
    _validate_case_change_anchors(case, diff)
    return diff


def _validate_case_change_anchors(case: DiffCase, diff: str) -> None:
    """Reject answer key changes absent from the materialized patch."""
    if not any(check.changes for check in case.answer_key.checks):
        return
    from cyberjury.detection import load_detection
    from cyberjury.profiles.registry import get_profile
    from cyberjury.review.diff.model import diff_line_ranges

    profile = get_profile(case.profile)
    ranges = diff_line_ranges(diff, load_detection(profile.paths.detection_file))
    sides = {"old": ranges.old, "new": ranges.new}
    for check in case.answer_key.checks:
        for anchor in check.changes:
            line_ranges = sides[anchor.side].get(anchor.file, ())
            if any(start <= anchor.line <= end for start, end in line_ranges):
                continue
            raise ValueError(
                f"diff case {case.name!r} answer-key check {check.id!r} change anchor "
                f"{anchor.file}:{anchor.line}:{anchor.side} is absent from the materialized patch"
            )


def load_project_diff_cases(path: str | Path, *, provenance: str = "public") -> list[DiffCase]:
    """Load diff tasks from one project benchmark."""
    manifest = Path(path)
    data = registry.load_project_manifest(manifest)
    key_file = manifest.parent / "answer-key.yaml"
    if not key_file.is_file():
        raise ValueError(f"project benchmark {manifest} has no answer-key.yaml")
    project_id = str(data["benchmark_id"])
    source = data["source"]
    cases: list[DiffCase] = []
    for task in data["tasks"]:
        if str(task.get("kind")) != "diff":
            continue
        task_id = str(task["id"])
        target = registry.target_for_task(source, task)
        expectation = str(task["expectation"])
        key = _diff_answer_key(load_answer_key(key_file, task_id=task_id), expectation)
        if expectation == "findings" and not key.findings:
            raise ValueError(f"diff task {task_id} in {manifest} has no findings checks")
        if expectation == "clean" and not key.clean:
            raise ValueError(f"clean diff task {task_id} in {manifest} has no clean checks")
        cases.append(
            DiffCase(
                name=f"{project_id}:{task_id}",
                answer_key=key,
                target=target,
                provenance=provenance,
                profile=str(data["profile"]),
                expectation=expectation,
            )
        )
    return cases


def _project_repository_cases(project: BenchmarkProject) -> dict[str, RepositoryCase]:
    manifest = project.manifest
    data = registry.load_project_manifest(manifest)
    project_id = str(data["benchmark_id"])
    source = data["source"]
    tasks = [task for task in data.get("tasks") or [] if str(task.get("kind")) == "repository"]
    found: dict[str, RepositoryCase] = {}
    for task in tasks:
        task_id = str(task["id"])
        name = project_id if len(tasks) == 1 else f"{project_id}:{task_id}"
        if name in found:
            raise ValueError(f"two repository tasks share the benchmark name '{name}' in {manifest}")
        found[name] = RepositoryCase(
            id=name,
            kind="repository",
            answer_key=manifest.with_name("answer-key.yaml"),
            provenance=project.provenance,
            manifest=manifest,
            target=registry.target_for_task(source, task),
            project_id=project_id,
            task_id=task_id,
            profile=str(data["profile"]),
        )
    return found


def repository_cases() -> dict[str, RepositoryCase]:
    """Materialize every repository task from the discovered benchmark projects."""
    merged: dict[str, RepositoryCase] = {}
    for project in registry.all_projects().values():
        for name, case in _project_repository_cases(project).items():
            if name in merged:
                raise ValueError(f"two repository tasks share the benchmark name '{name}'")
            merged[name] = case
    return merged


def find_repository_case(name: str) -> RepositoryCase:
    """Resolve one repository case and fail loud with the known names."""
    cases = repository_cases()
    if name not in cases:
        known = ", ".join(sorted(cases)) or "none"
        raise ValueError(f"no repository benchmark '{name}'. Known: {known}")
    return cases[name]


def _diff_answer_key(key: AnswerKey, expectation: str) -> AnswerKey:
    if expectation == "findings":
        return key
    return AnswerKey(benchmark_id=key.benchmark_id, checks=(*key.clean, *key.findings))


def _target_diff(target: dict) -> str:
    base = target.get("base")
    ref = target.get("ref")
    root = git_target_root(target)
    if not (root and base and ref):
        return ""
    ensure_git_target_refs(target, root)
    cmd = ["git", "-C", str(root), "diff", f"{base}..{ref}"]
    pathspecs = _target_pathspecs(target)
    if pathspecs:
        cmd.extend(["--", *pathspecs])
    return subprocess.run(
        cmd,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        check=True,
    ).stdout


def _target_pathspecs(target: dict) -> tuple[str, ...]:
    if not target.get("url") and not target.get("root"):
        return ()
    path = str(target.get("path") or "").strip()
    if not path or path == ".":
        return ()
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"target path {path!r} must stay inside the repository")
    return (path,)


def diff_cases() -> list[DiffCase]:
    """Every discovered diff benchmark task from public and configured private eval sources."""
    projects = registry.all_projects()
    if not projects:
        raise ValueError(f"no diff benchmark projects under {PROJECTS_DIR}")
    return [
        case
        for project in projects.values()
        for case in load_project_diff_cases(project.manifest, provenance=project.provenance)
    ]
