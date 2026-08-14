"""Diff benchmark discovery.

Real commit diff targets use project benchmark tasks under benchmarks, so diff and repository
evidence share one target definition. Benchmarks mirror the knowledge guides taxonomy.
Each manifest names the knowledge it exercises so the coverage matrix attributes it. A
positive carries a planted answer key entry, a safe case carries only safe lookalikes.
This module is engine-free on purpose, so the coverage matrix can read the cases without
importing the audit runner.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from evals import registry
from evals.schema import AnswerKey, knowledge_refs, load_answer_key

BENCHMARKS_DIR = Path(__file__).resolve().parent / "benchmarks"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def git_target_root(target: dict) -> Path | None:
    """Resolve a git target to a local repository root."""
    if target.get("type") != "git":
        return None
    url = target.get("url")
    if url:
        return _cloned_target_root(str(url))
    path = target.get("path")
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
    """One diff benchmark case with its expected answer key entry."""

    name: str
    diff: str
    category: str = ""
    knowledge: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    context: str = ""
    target: dict = field(default_factory=dict)
    provenance: str = "public"
    answer_key: AnswerKey | None = None
    profile: str = "web"
    expectation: str = "findings"
    review_context: str = "repository"
    review_mode: str = "standard"

    def __post_init__(self) -> None:
        """Reject review requirements the runner would otherwise misinterpret."""
        if self.review_context not in registry.TASK_REVIEW_CONTEXTS:
            raise ValueError(f"invalid diff review context: {self.review_context!r}")
        if self.review_mode not in registry.TASK_REVIEW_MODES:
            raise ValueError(f"invalid diff review mode: {self.review_mode!r}")

    @property
    def is_positive(self) -> bool:
        """Report whether the case has a planted positive finding."""
        if self.answer_key is not None:
            return bool(self.answer_key.planted)
        return bool(self.category)


def diff_text(case: DiffCase) -> str:
    """Return the case diff, deriving a git target diff only when the caller needs it."""
    if case.diff:
        return case.diff
    diff = _target_diff(case.target)
    if not diff:
        raise ValueError(f"diff case '{case.name}' has no diff")
    return diff


def _case(row, i: int, *, provenance: str) -> DiffCase:
    diff = str(row.get("diff") or "")
    if not diff and not _has_diff_target(row.get("target") or {}):
        raise ValueError(f"cases[{i}] ({row.get('name', '?')}) has no diff")
    return DiffCase(
        name=str(row["name"]),
        diff=diff,
        category=str(row.get("category") or ""),
        knowledge=knowledge_refs(row.get("knowledge")),
        tags=tuple(row.get("tags") or ()),
        context=str(row.get("context") or ""),
        target=dict(row.get("target") or {}),
        provenance=provenance,
        answer_key=row.get("answer_key"),
        profile=str(row.get("profile") or "web"),
        expectation=str(row.get("expectation") or "findings"),
        review_context=str(row.get("review_context") or "repository"),
        review_mode=str(row.get("review_mode") or "standard"),
    )


def load_project_diff_cases(path: str | Path, *, provenance: str = "public") -> list[DiffCase]:
    """Load diff tasks from one project benchmark."""
    manifest = Path(path)
    data = registry.load_project_manifest(manifest)
    key_file = manifest.parent / "answer-key.yaml"
    if not key_file.is_file():
        raise ValueError(f"project benchmark {manifest} has no answer-key.yaml")
    project_id = str(data["id"])
    base_target = data.get("target") or {}
    base_knowledge = data.get("knowledge") or {}
    cases: list[DiffCase] = []
    for i, task in enumerate(data.get("tasks") or []):
        if str(task.get("kind")) != "diff":
            continue
        task_id = str(task.get("id") or f"diff-{i}")
        target = registry.target_for_task(base_target, task)
        knowledge = registry.merge_manifest_block(base_knowledge, task.get("knowledge") or {})
        expectation = str(task.get("expectation") or "findings")
        review = task.get("review", {})
        key = _diff_answer_key(load_answer_key(key_file, task_id=task_id), expectation)
        if expectation == "findings" and not key.planted:
            raise ValueError(f"diff task {task_id} in {manifest} expects findings but has no planted entries")
        if expectation == "clean" and not key.safe:
            raise ValueError(f"clean diff task {task_id} in {manifest} has no safe entries")
        row = {
            "name": f"{project_id}:{task_id}",
            "knowledge": knowledge,
            "tags": tuple(data.get("tags") or ()) + tuple(task.get("tags") or ()),
            "target": target,
            "profile": str(task.get("profile") or data.get("profile") or "web"),
            "answer_key": key,
            "expectation": expectation,
            "review_context": str(review.get("context") or "repository"),
            "review_mode": str(review.get("mode") or "standard"),
        }
        if key.planted:
            row["category"] = key.planted[0].category
        row["diff"] = str(task.get("diff") or "")
        cases.append(_case(row, i, provenance=provenance))
    return cases


def _diff_answer_key(key: AnswerKey, expectation: str) -> AnswerKey:
    if expectation == "findings":
        return key
    return AnswerKey(target=key.target, planted=(), safe=(*key.safe, *key.planted))


def _target_diff(target: dict) -> str:
    if target.get("type") != "git":
        return str(target.get("diff") or "")
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
    forbidden = sorted(set(target).intersection({"diff_path", "diff_paths"}))
    if forbidden:
        raise ValueError(
            f"target scopes a commit with {', '.join(forbidden)}, but diff tasks must review the whole target commit"
        )
    if not target.get("url"):
        return ()
    path = str(target.get("path") or "").strip()
    if not path or path == ".":
        return ()
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"target path {path!r} must stay inside the repository")
    return (path,)


def _has_diff_target(target: dict) -> bool:
    return bool(
        target.get("type") == "git"
        and target.get("base")
        and target.get("ref")
        and (target.get("path") or target.get("url"))
    )


def _case_sources() -> list[tuple[Path, str, bool]]:
    files: list[tuple[Path, str, bool]] = []
    for root, provenance, override in registry.source_roots():
        if root.is_dir():
            files.extend((f, provenance, override) for f in sorted(root.rglob("benchmark.yaml")))
    return files


def default_cases() -> list[DiffCase]:
    """Every discovered diff benchmark task from public and configured private eval sources."""
    files = _case_sources()
    if not files:
        raise ValueError(f"no diff benchmarks under {BENCHMARKS_DIR}")
    cases: list[DiffCase] = []
    seen: dict[str, Path] = {}
    for f, provenance, override in files:
        loaded = load_project_diff_cases(f, provenance=provenance)
        for case in loaded:
            if case.name in seen and not override:
                raise ValueError(
                    f"diff benchmark '{case.name}' is defined in two files, {seen[case.name]} "
                    f"and {f}. A benchmark name must be unique across the library, rename one."
                )
            if case.name in seen:
                cases = [c for c in cases if c.name != case.name]
            seen[case.name] = f
            cases.append(case)
    return cases
