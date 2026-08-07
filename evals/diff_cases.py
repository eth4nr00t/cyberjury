"""The diff probe cases and their loader. Small realistic patches, one or more per
vulnerability class, plus safe lookalikes that must stay clean. Public probe batches live as
cases.yaml under benchmarks/diff. Real patch targets may use benchmark.yaml plus answer-key.yaml,
the same per-target shape as repository benchmarks. Private cases stay in local eval sources and
are discovered through the same layout. Cases mirror the knowledge guides taxonomy. Each row or
manifest names the knowledge it exercises so the coverage matrix attributes it. A positive carries
a category and should yield a finding, a safe case carries none and should stay clean.

This module is engine-free on purpose, so the coverage matrix can read the cases without
importing the audit runner.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

import yaml

from evals import registry
from evals.schema import AnswerKey, knowledge_refs, load_answer_key

CASES_DIR = Path(__file__).resolve().parent / "benchmarks" / "diff"


def git_target_root(target: dict) -> Path | None:
    """Resolve a git target to a local repository root."""
    if target.get("type") != "git":
        return None
    path = target.get("path")
    if path:
        return Path(str(path)).expanduser()
    url = target.get("url")
    if not url:
        return None
    return _cloned_target_root(str(url))


def _cloned_target_root(url: str) -> Path:
    name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
    digest = sha256(url.encode("utf-8")).hexdigest()[:12]
    root = Path.home() / ".cache" / "cyberjury" / "diff-targets" / f"{name}-{digest}"
    if (root / ".git").is_dir():
        subprocess.run(
            ["git", "-C", str(root), "fetch", "--tags", "--force", "origin"],
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
    name: str
    diff: str
    category: str = ""
    knowledge: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    context: str = ""
    target: dict = field(default_factory=dict)
    provenance: str = "public"
    answer_key: AnswerKey | None = None
    # the review domain whose knowledge and prompt the probe runs the case under, so a
    # Solidity case scores against the evm domain, not the web default
    domain: str = "web"

    @property
    def is_positive(self) -> bool:
        return bool(self.category)


def diff_text(case: DiffCase) -> str:
    """Return the case diff, deriving a git target diff only when the caller needs it."""
    if case.diff:
        return case.diff
    diff = _target_diff(case.target)
    if not diff:
        raise ValueError(f"diff case '{case.name}' has no diff")
    return diff


def _read_case_text(row: dict, key: str, file_key: str, base_dir: Path, i: int) -> str:
    has_inline = row.get(key) is not None
    has_file = row.get(file_key) is not None
    if has_inline and has_file:
        raise ValueError(f"cases[{i}] ({row.get('name', '?')}) has both {key} and {file_key}")
    if has_inline:
        return str(row[key])
    if has_file:
        return (base_dir / str(row[file_key])).read_text(encoding="utf-8")
    return ""


def _case(row, i: int, *, base_dir: Path, provenance: str) -> DiffCase:
    diff = _read_case_text(row, "diff", "diff_file", base_dir, i)
    if not diff and not _has_git_diff_target(row.get("target") or {}):
        raise ValueError(f"cases[{i}] ({row.get('name', '?')}) has no diff")
    return DiffCase(
        name=str(row["name"]),
        diff=diff,
        category=str(row.get("category") or ""),
        knowledge=knowledge_refs(row.get("knowledge")),
        tags=tuple(row.get("tags") or ()),
        context=_read_case_text(row, "context", "context_file", base_dir, i),
        target=dict(row.get("target") or {}),
        provenance=provenance,
        answer_key=row.get("answer_key"),
        domain=str(row.get("domain") or "web"),
    )


def load_cases(path: str | Path, *, provenance: str = "public") -> list[DiffCase]:
    """Load cases from a YAML list of {name, category, diff, knowledge, tags, domain}, failing loud
    on a row with no diff rather than silently probing nothing."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rows = data.get("cases") if isinstance(data, dict) else data
    if not rows:
        raise ValueError(f"no cases in {path}")
    base_dir = Path(path).resolve().parent
    return [_case(r, i, base_dir=base_dir, provenance=provenance) for i, r in enumerate(rows)]


def load_benchmark_case(path: str | Path, *, provenance: str = "public") -> DiffCase:
    """Load one per-target diff benchmark from benchmark.yaml plus answer-key.yaml."""
    manifest = Path(path)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    if str(data.get("kind", "diff")) != "diff":
        raise ValueError(f"diff benchmark {manifest} has kind {data.get('kind')!r}, expected diff")
    target = data.get("target") or {}
    row = {
        "name": str(data.get("id") or manifest.parent.name),
        "context": data.get("context"),
        "context_file": data.get("context_file") or target.get("context_file"),
        "knowledge": data.get("knowledge"),
        "tags": tuple(data.get("tags") or ()),
        "target": target,
        "domain": str(data.get("domain") or "web"),
    }
    diff = data.get("diff")
    if diff is not None:
        row["diff"] = diff
    else:
        if _has_git_diff_target(target):
            if target.get("url") and not target.get("path"):
                row["diff"] = ""
            else:
                row["diff"] = _target_diff(target)
        else:
            row["diff_file"] = data.get("diff_file") or target.get("diff_file")
    key_file = next(
        (
            manifest.parent / name
            for name in ("answer-key.yaml", "answer_key.yaml")
            if (manifest.parent / name).is_file()
        ),
        None,
    )
    if key_file is None:
        raise ValueError(f"diff benchmark {manifest} has no answer-key.yaml")
    key = load_answer_key(key_file)
    if key.planted:
        row["category"] = key.planted[0].category
    elif not key.safe:
        raise ValueError(f"diff benchmark {manifest} has neither planted nor safe entries")
    row["answer_key"] = key
    return _case(row, 0, base_dir=manifest.parent, provenance=provenance)


def _target_diff(target: dict) -> str:
    if target.get("type") != "git":
        return ""
    base = target.get("base")
    ref = target.get("ref")
    root = git_target_root(target)
    if not (root and base and ref):
        return ""
    return subprocess.run(
        ["git", "-C", str(root), "diff", f"{base}..{ref}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _has_git_diff_target(target: dict) -> bool:
    return bool(
        target.get("type") == "git"
        and target.get("base")
        and target.get("ref")
        and (target.get("path") or target.get("url"))
    )


def _case_sources() -> list[tuple[Path, str, bool, str]]:
    files: list[tuple[Path, str, bool, str]] = []
    for root, provenance, override in registry.source_roots():
        diff_dir = root / "diff"
        if not diff_dir.is_dir():
            continue
        files.extend((f, provenance, override, "cases") for f in sorted(diff_dir.rglob("cases.yaml")))
        files.extend((f, provenance, override, "benchmark") for f in sorted(diff_dir.rglob("benchmark.yaml")))
    return files


def default_cases() -> list[DiffCase]:
    """Every discovered diff case from public and configured private eval sources."""
    files = _case_sources()
    if not files:
        raise ValueError(f"no cases.yaml under {CASES_DIR}")
    cases: list[DiffCase] = []
    seen: dict[str, Path] = {}
    for f, provenance, override, source_kind in files:
        if source_kind == "benchmark":
            loaded = [load_benchmark_case(f, provenance=provenance)]
        else:
            loaded = load_cases(f, provenance=provenance)
        for case in loaded:
            if case.name in seen and not override:
                raise ValueError(
                    f"diff case '{case.name}' is defined in two files, {seen[case.name]} "
                    f"and {f}. A case name must be unique across the library, rename one."
                )
            if case.name in seen:
                cases = [c for c in cases if c.name != case.name]
            seen[case.name] = f
            cases.append(case)
    return cases
