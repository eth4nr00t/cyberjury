"""Benchmark discovery across public and locally configured private sources.

The repository ships public OSS benchmarks under `evals/benchmarks`. Private benchmarks
stay where they already live. A gitignored local config can list them by path or private
git repository, then this module merges them into the same named view. Nothing private
moves into the repository and nothing private commits. A source root uses the taxonomy
layout, `<group>/<name>/benchmark.yaml` plus `answer-key.yaml`, where repository tasks
are exposed as score targets. A name that appears in two roots fails loud unless the
private source sets `override: true` to shadow a public one on purpose.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_PUBLIC = _HERE / "benchmarks"
_CACHE = Path.home() / ".cache" / "cyberjury" / "eval-sources"
TASK_REVIEW_CONTEXTS = frozenset({"diff", "repository"})
TASK_REVIEW_MODES = frozenset({"standard", "adversarial"})


@dataclass(frozen=True, kw_only=True)
class Benchmark:
    """One benchmark the registry knows about, public or private."""

    id: str
    kind: str
    answer_key: Path
    provenance: str
    manifest: Path | None = None
    target: dict[str, object] = field(default_factory=dict)
    stack: dict[str, list[str]] = field(default_factory=dict)
    knowledge: dict[str, list[str]] = field(default_factory=dict)
    project_id: str = ""
    task_id: str = ""
    profile: str = "web"


def _config_path() -> Path | None:
    override = os.environ.get("CYBERJURY_EVAL_CONFIG")
    if override:
        return Path(override)
    local = _HERE / "local.yaml"
    return local if local.is_file() else None


def _clone(repository: str, ref: str | None) -> Path:
    """Clone or update a private benchmark repository into the cache.

    This lets a private source be a git URL rather than a repository path. Network and
    credentials are the operator's.
    """
    slug = "".join(c if c.isalnum() else "-" for c in repository).strip("-")
    dest = _CACHE / slug
    if dest.is_dir():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True, capture_output=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [repository, str(dest)]
        subprocess.run(cmd, check=True, capture_output=True)
    return dest


def _sources() -> list[tuple[Path, str, bool]]:
    """Each search root with its provenance and whether it may shadow an earlier name."""
    sources: list[tuple[Path, str, bool]] = [(_PUBLIC, "public", False)]
    cfg = _config_path()
    if cfg is None:
        return sources
    data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    for src in data.get("benchmark_sources", []):
        override = bool(src.get("override", False))
        if "path" in src:
            sources.append((Path(src["path"]).expanduser(), "private", override))
        elif "repository" in src:
            sources.append((_clone(src["repository"], src.get("ref")), "private", override))
        else:
            raise ValueError(f"benchmark source {src} has neither path nor repository")
    return sources


def source_roots() -> list[tuple[Path, str, bool]]:
    """Every eval source root, public first, then local private roots."""
    return _sources()


def target_for_task(source: Mapping[str, object], task: Mapping[str, object]) -> dict[str, object]:
    """Translate a versioned source and task into the runner target shape."""
    source_kind = str(source.get("kind") or "")
    path = str(source.get("path") or ".")
    if source_kind == "git":
        identity = source["identity"]
        revision = task.get("revision") or {}
        target = {"type": "git", "ref": str(revision.get("commit") or identity["commit"]), "path": path}
        if identity.get("url"):
            target["url"] = str(identity["url"])
        if identity.get("repository_path"):
            target["root"] = str(identity["repository_path"])
        if task.get("kind") == "diff":
            target["base"] = str(revision["base_commit"])
        if isinstance(source.get("prepare"), dict):
            target["prepare"] = dict(source["prepare"])
        return target
    if source_kind == "explorer":
        identity = source["identity"]
        target = {
            "type": "explorer",
            "chain": str(identity["chain"]),
            "address": str(identity["address"]),
            "path": path,
        }
        if isinstance(source.get("prepare"), dict):
            target["prepare"] = dict(source["prepare"])
        return target
    raise ValueError(f"unsupported benchmark source kind: {source_kind!r}")


def load_project_manifest(path: str | Path) -> dict[str, object]:
    """Load and validate one benchmark manifest and its sibling answer key."""
    from evals.validate import validate_benchmark

    manifest = Path(path)
    validate_benchmark(manifest)
    return yaml.safe_load(manifest.read_text(encoding="utf-8"))


def _project_benchmarks(root: Path, provenance: str) -> dict[str, Benchmark]:
    found: dict[str, Benchmark] = {}
    if not root.is_dir():
        return found
    for manifest in sorted(root.rglob("benchmark.yaml")):
        key = manifest.parent / "answer-key.yaml"
        if not key.is_file():
            raise ValueError(f"project benchmark {manifest} has no answer-key.yaml")
        data = load_project_manifest(manifest)
        project_id = str(data["benchmark_id"])
        source = data["source"]
        stack = data.get("stack") or {}
        knowledge = data.get("knowledge") or {}
        repository_tasks = [task for task in data.get("tasks") or [] if str(task.get("kind")) == "repository"]
        for task in repository_tasks:
            task_id = str(task.get("id") or "repository")
            target = target_for_task(source, task)
            name = project_id if len(repository_tasks) == 1 else f"{project_id}:{task_id}"
            if name in found:
                raise ValueError(
                    f"two project repository tasks share the benchmark name '{name}' under {root}, "
                    f"at {found[name].manifest} and {manifest}."
                )
            found[name] = Benchmark(
                id=name,
                kind="repository",
                answer_key=key,
                provenance=provenance,
                manifest=manifest,
                target=target,
                stack=stack,
                knowledge=knowledge,
                project_id=project_id,
                task_id=task_id,
                profile=str(data["profile"]),
            )
    return found


def _discover(root: Path, provenance: str) -> dict[str, Benchmark]:
    """Find every benchmark under one source root."""
    return _project_benchmarks(root, provenance)


def all_benchmarks() -> dict[str, Benchmark]:
    """Every benchmark across the public root and the configured private sources, merged.

    A name in two non-override roots fails loud, so a private benchmark cannot silently
    shadow a public one, invariant 4 applied to discovery.
    """
    merged: dict[str, Benchmark] = {}
    for root, provenance, override in _sources():
        for name, bench in _discover(root, provenance).items():
            if name in merged and not override:
                raise ValueError(
                    f"benchmark '{name}' is defined in two roots, {merged[name].answer_key} "
                    f"and {bench.answer_key}. Rename one, or set override: true on the private source."
                )
            merged[name] = bench
    return merged


def find_benchmark(name: str) -> Benchmark:
    """Resolve a benchmark by name and fail loud with the known names.

    A typo or unconfigured private source should be obvious rather than a silent empty
    score.
    """
    benches = all_benchmarks()
    if name not in benches:
        known = ", ".join(sorted(benches)) or "none"
        raise ValueError(f"no benchmark '{name}'. Known: {known}")
    return benches[name]
