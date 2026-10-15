"""Discover public and locally configured private benchmark projects.

Evaluation code lives under `evals/benchmarks`, while public project data lives under
`evals/projects/<project-id>`. The YAML file named by CYBERJURY_EVAL_CONFIG lists private source paths under
`benchmark_sources`, which may keep grouping directories because
their manifest owns identity. A project name that appears in two roots fails loud
unless the private source explicitly shadows it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import yaml

from evals.benchmarks.contract import BenchmarkProject

_HERE = Path(__file__).resolve().parent
PUBLIC_PROJECTS_DIR = _HERE.parent / "projects"


def _config_path() -> Path | None:
    override = os.environ.get("CYBERJURY_EVAL_CONFIG")
    return Path(override) if override else None


def _sources() -> list[tuple[Path, str, bool]]:
    """Each search root with its provenance and whether it may shadow an earlier name."""
    sources: list[tuple[Path, str, bool]] = [(PUBLIC_PROJECTS_DIR, "public", False)]
    cfg = _config_path()
    if cfg is None:
        return sources
    data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    for src in data.get("benchmark_sources", []):
        override = bool(src.get("override", False))
        if "path" not in src:
            raise ValueError(f"benchmark source {src} has no path")
        sources.append((Path(src["path"]).expanduser(), "private", override))
    return sources


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
        return target
    raise ValueError(f"unsupported benchmark source kind: {source_kind!r}")


def load_project_manifest(path: str | Path) -> dict[str, object]:
    """Load and validate one benchmark manifest and its sibling answer key."""
    from evals.benchmarks.validate import validate_benchmark

    manifest = Path(path)
    validate_benchmark(manifest)
    return yaml.safe_load(manifest.read_text(encoding="utf-8"))


def _projects_in(root: Path, provenance: str, *, flat: bool) -> dict[str, BenchmarkProject]:
    """Load one project collection, enforcing the public data layout when requested."""
    found: dict[str, BenchmarkProject] = {}
    if not root.is_dir():
        return found
    manifests = sorted(root.rglob("benchmark.yaml"))
    if flat:
        nested = [manifest for manifest in manifests if manifest.parent.parent.resolve() != root.resolve()]
        if nested:
            raise ValueError(f"benchmark project must be an immediate child of {root}: {nested[0]}")
        missing = [path for path in sorted(root.iterdir()) if path.is_dir() and not (path / "benchmark.yaml").is_file()]
        if missing:
            raise ValueError(f"public benchmark project directory has no benchmark.yaml: {missing[0]}")
    for manifest in manifests:
        key = manifest.parent / "answer-key.yaml"
        if not key.is_file():
            raise ValueError(f"project benchmark {manifest} has no answer-key.yaml")
        data = load_project_manifest(manifest)
        project_id = str(data["benchmark_id"])
        if flat and manifest.parent.name != project_id:
            raise ValueError(
                f"benchmark project directory {manifest.parent.name!r} does not match benchmark_id {project_id!r}"
            )
        if project_id in found:
            raise ValueError(
                f"two project manifests share the benchmark name '{project_id}' under {root}, "
                f"at {found[project_id].manifest} and {manifest}."
            )
        found[project_id] = BenchmarkProject(id=project_id, manifest=manifest, provenance=provenance)
    return found


def all_projects() -> dict[str, BenchmarkProject]:
    """Discover and merge each public and private benchmark project once."""
    merged: dict[str, BenchmarkProject] = {}
    for root, provenance, override in _sources():
        for project_id, project in _projects_in(root, provenance, flat=provenance == "public").items():
            if project_id in merged and not override:
                raise ValueError(
                    f"benchmark '{project_id}' is defined in two roots, {merged[project_id].manifest} "
                    f"and {project.manifest}. Rename one, or set override: true on the private source."
                )
            merged[project_id] = project
    return merged
