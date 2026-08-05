"""Benchmark discovery: the public benchmarks in the repository plus private sources from a
local, uncommitted config, merged into one named view.

The repository ships only public OSS benchmarks under `evals/benchmarks`. Private benchmarks
stay wherever they already live: a local config, gitignored, lists their sources as a path
or a private git repository, and they plug in under the same names. Nothing private moves into
the repository and nothing private commits. A source root may use the per-benchmark layout,
`repository/<name>/benchmark.yaml` plus `answer-key.yaml`, optionally grouped under a frameworks
path such as `repository/frameworks/python/flask/<name>`, or the legacy `groundtruth/<name>.yaml`,
so an existing private benchmark scores without being reshaped. A name that appears in two
roots fails loud, unless the private source sets `override: true` to shadow a public one on
purpose.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_PUBLIC = _HERE / "benchmarks"
_CACHE = Path.home() / ".cache" / "cyberjury" / "eval-sources"


@dataclass(frozen=True, kw_only=True)
class Benchmark:
    """One benchmark the registry knows about, public or private. The manifest fields stay
    empty for a legacy answer key that ships no benchmark.yaml, the coverage matrix then
    attributes it from the per-entry knowledge in the answer key instead."""

    id: str
    kind: str
    answer_key: Path
    provenance: str  # public or private, the matrix splits coverage by this
    manifest: Path | None = None
    target: dict = field(default_factory=dict)
    stack: dict = field(default_factory=dict)
    knowledge: dict = field(default_factory=dict)
    tags: tuple[str, ...] = ()


def _config_path() -> Path | None:
    override = os.environ.get("CYBERJURY_EVAL_CONFIG")
    if override:
        return Path(override)
    local = _HERE / "local.yaml"
    return local if local.is_file() else None


def _clone(repository: str, ref: str | None) -> Path:
    """Clone or update a private benchmark repository into the cache, so a private source can be
    a git url rather than a path in the repository. Network and credentials are the operator's."""
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


def _read_manifest(path: Path) -> tuple[str, dict, dict, dict, tuple[str, ...]]:
    """Read kind, target, stack, knowledge, and tags from a benchmark.yaml. A legacy target.yaml
    carries only the clone pointer and a kind, so stack, knowledge, and tags come back
    empty and the matrix falls back to the answer key for attribution."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    kind = str(data.get("kind", "repository"))
    target = data.get("target") or {}
    stack = data.get("stack") or {}
    knowledge = data.get("knowledge") or {}
    tags = tuple(data.get("tags") or ())
    return kind, target, stack, knowledge, tags


def _benchmark_at(name: str, answer_key: Path, manifest: Path | None, provenance: str) -> Benchmark:
    kind, target, stack, knowledge, tags = "repository", {}, {}, {}, ()
    if manifest is not None:
        kind, target, stack, knowledge, tags = _read_manifest(manifest)
    return Benchmark(
        id=name,
        kind=kind,
        answer_key=answer_key,
        provenance=provenance,
        manifest=manifest,
        target=target,
        stack=stack,
        knowledge=knowledge,
        tags=tags,
    )


def _discover(root: Path, provenance: str) -> dict[str, Benchmark]:
    """Find every benchmark under one root, the per-benchmark layout and the legacy
    groundtruth layout alike. The per-benchmark layout wins when both name the same id.

    A benchmark is any directory holding an answer-key.yaml, or the legacy answer_key.yaml,
    so a target may sit flat at repository/<name> or grouped at
    repository/frameworks/<language>/<framework>/<name>, mirroring the knowledge guides
    taxonomy. The id is the leaf directory name regardless of the grouping path, so moving
    a target between groups does not rename it. Two targets with the same leaf name fail
    loud, an id collision is a mistake not a silent last-wins."""
    found: dict[str, Benchmark] = {}
    repository_dir = root / "repository"
    if repository_dir.is_dir():
        # answer-key.yaml is canonical, answer_key.yaml is the legacy name still read so a
        # private benchmark need not be reshaped. The hyphen form wins when a dir has both.
        by_dir: dict[Path, Path] = {}
        for key in sorted(repository_dir.rglob("answer_key.yaml")):
            by_dir[key.parent] = key
        for key in sorted(repository_dir.rglob("answer-key.yaml")):
            by_dir[key.parent] = key
        for d, key in sorted(by_dir.items()):
            manifest = next((d / m for m in ("benchmark.yaml", "target.yaml") if (d / m).is_file()), None)
            if d.name in found:
                raise ValueError(
                    f"two repository benchmarks share the leaf name '{d.name}' under {repository_dir}, "
                    f"at {found[d.name].answer_key} and {key}. The id is the leaf directory "
                    f"name, so rename one of the two target directories."
                )
            found[d.name] = _benchmark_at(d.name, key, manifest, provenance)
    gt_dir = root / "groundtruth"
    if gt_dir.is_dir():
        for f in sorted(gt_dir.glob("*.yaml")):
            found.setdefault(f.stem, _benchmark_at(f.stem, f, None, provenance))
    return found


def all_benchmarks() -> dict[str, Benchmark]:
    """Every benchmark across the public root and the configured private sources, merged.
    A name in two non-override roots fails loud, so a private benchmark cannot silently
    shadow a public one, invariant 4 applied to discovery."""
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
    """Resolve a benchmark by name, failing loud with the known names so a typo or an
    unconfigured private source is obvious rather than a silent empty score."""
    benches = all_benchmarks()
    if name not in benches:
        known = ", ".join(sorted(benches)) or "none"
        raise ValueError(f"no benchmark '{name}'. Known: {known}")
    return benches[name]


def find_answer_key(name: str) -> Path:
    """The answer key path for a benchmark, by name, across public and private sources."""
    return find_benchmark(name).answer_key
