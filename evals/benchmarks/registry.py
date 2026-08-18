"""Discover public and locally configured private benchmarks.

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
from pathlib import Path

import yaml

from evals.benchmarks.contract import BenchmarkProject

_HERE = Path(__file__).resolve().parent
_PUBLIC = _HERE
_LOCAL_CONFIG = _HERE.parent / "local.yaml"
_CACHE = Path.home() / ".cache" / "cyberjury" / "eval-sources"


def _config_path() -> Path | None:
    override = os.environ.get("CYBERJURY_EVAL_CONFIG")
    if override:
        return Path(override)
    return _LOCAL_CONFIG if _LOCAL_CONFIG.is_file() else None


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
    from evals.benchmarks.validate import validate_benchmark

    manifest = Path(path)
    validate_benchmark(manifest)
    return yaml.safe_load(manifest.read_text(encoding="utf-8"))


def _projects_in(root: Path, provenance: str) -> dict[str, BenchmarkProject]:
    found: dict[str, BenchmarkProject] = {}
    if not root.is_dir():
        return found
    for manifest in sorted(root.rglob("benchmark.yaml")):
        key = manifest.parent / "answer-key.yaml"
        if not key.is_file():
            raise ValueError(f"project benchmark {manifest} has no answer-key.yaml")
        data = load_project_manifest(manifest)
        project_id = str(data["benchmark_id"])
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
        for project_id, project in _projects_in(root, provenance).items():
            if project_id in merged and not override:
                raise ValueError(
                    f"benchmark '{project_id}' is defined in two roots, {merged[project_id].manifest} "
                    f"and {project.manifest}. Rename one, or set override: true on the private source."
                )
            merged[project_id] = project
    return merged
