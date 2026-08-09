"""Whole-repository review scaffold: set up the fan-out workspace, do not run a pipeline.

The `review repository` path. Whole-repository review is too large for a single LLM call
and a single pass over a large repository dilutes, so it ships as a methodology an
interactive agent runs by fanning out: it enumerates the attack surface, splits it into
units, and runs a focused sub-review on each. This module scaffolds the workspace for
that methodology: it creates the inventory/units/candidates/findings/pocs directories,
seeds the detected stack guides and the candidate entrypoint files, and returns the
methodology text to print. It does not find issues itself.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.domains.base import BackendUnavailable, Domain
from cyberjury.domains.registry import default_domain
from cyberjury.guides import (
    Guide,
    api_patterns,
    entrypoint_globs,
    entrypoint_markers,
    load_guides,
    logic_layer_globs,
    select_guides,
)
from cyberjury.review.repository.model import (
    build_repository_model_from_dir,
    candidate_entrypoint_files,
    char_spans,
    logic_layer_files,
    public_api_files,
    span_line_range,
)
from cyberjury.review.vulnerabilities import vulnerability_knowledge

_DETECT_PER_FILE = 16_000
_DETECT_TOTAL = 8_000_000

_DIRS = ("inventory", "units", "candidates", "findings", "pocs")

_MARKER = ".cyberjury-workspace"


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    """Workspace paths and methodology produced by scaffold."""

    project: str
    workspace: Path
    methodology: str
    candidate_files: tuple[str, ...] = ()
    trace_targets: tuple[str, ...] = ()
    guides: tuple[str, ...] = ()
    created: list[str] = field(default_factory=list)
    had_prior_run: bool = False
    cleared: list[str] = field(default_factory=list)
    fallback_note: str = ""


def _read_manifests(target: Path, detection: Detection) -> str:
    parts: list[str] = []
    for name in detection.manifests:
        p = target / name
        try:
            if p.is_file():
                parts.append(p.read_text(encoding="utf-8"))
        except OSError:
            pass
    return "\n".join(parts)


def _source_sample(target: Path, files: list[str], detection: Detection) -> str:
    """A bounded sample of source and config content.

    so detection can fire on import markers and language-neutral content tokens such as a
    protocol's wire fields. Kept separate from the manifests so a dependency name does not
    false-match a word in source.
    """
    detection_extensions = detection.detection_extensions
    parts: list[str] = []
    total = 0
    for f in files:
        if Path(f).suffix.lower() not in detection_extensions:
            continue
        try:
            chunk = (target / f).read_text(encoding="utf-8")[:_DETECT_PER_FILE]
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(chunk)
        total += len(chunk)
        if total >= _DETECT_TOTAL:
            break
    return "\n".join(parts)


def _stack_md(guides: list[Guide]) -> str:
    if not guides:
        return (
            "# Detected stack\n\n"
            "No language or framework guide matched. Rely on the methodology and "
            "your own knowledge of the stack.\n"
        )
    langs = [g.id for g in guides if g.kind == "language"]
    fws = [g for g in guides if g.kind == "framework"]
    protocols = [g.id for g in guides if g.kind == "protocol"]
    fw_labels = [f"{g.id} ({g.language})" if g.language else g.id for g in fws]
    lines = [
        "# Detected stack",
        "",
        f"Languages: {', '.join(langs) or '-'}",
        f"Frameworks: {', '.join(fw_labels) or '-'}",
        f"Protocols: {', '.join(protocols) or '-'}",
        "",
    ]
    for g in guides:
        lines += ["---", "", g.body, ""]
    return "\n".join(lines) + "\n"


_FACTS_SCHEMA = "2"


def _facts_cache_key(target: Path, files: tuple[str, ...], domain: Domain) -> str:
    """A content hash over the source in scope.

    so a re-run reuses the extracted facts instead of paying the backend's extraction again,
    while a source edit invalidates the entry.
    """
    h = hashlib.sha256()
    h.update(f"{_FACTS_SCHEMA}\x00{domain.name}".encode())
    for rel in sorted(files):
        try:
            data = (target / rel).read_bytes()
        except OSError:
            continue
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def _write_facts(
    ws: Path,
    target: Path,
    domain: Domain,
    files: tuple[str, ...],
    *,
    cache_root: Path,
    detection: Detection,
) -> None:
    """Extract deterministic facts and persist them to `_facts.md` plus whichever of.

    `_facts_by_file.json`, `_facts_units.json` and `_facts_graph.json` the backend emits,
    the way `_stack.md` persists the stack, so the run, resume, and finalize steps read the
    same grounding from the workspace. The extraction is cached by source content hash under
    `cache_root`, so a fresh scaffold or a second target on the same source reuses it rather
    than re-extracting. A domain that binds a backend grounds every review, there is no
    ungrounded tier and no flag to turn it off. So a backend that cannot run, or an
    extraction that fails, raises rather than quietly returning a review without cross-
    function units. Coverage that drops silently is a reduced review reported as a whole
    one, and it hides a broken toolchain for as long as nobody reads stderr, invariant 4.
    `_facts_error.txt` still records the failure for the operator.
    """
    backend = domain.facts_backend
    if backend is None:
        return
    if not backend.available():
        raise BackendUnavailable(
            f"the facts backend cannot run, so this review has no grounding. {backend.install_hint}"
        )
    dest = ws / "_facts.md"
    dest_by_file = ws / "_facts_by_file.json"
    dest_units = ws / "_facts_units.json"
    dest_graph = ws / "_facts_graph.json"
    if dest.is_file():
        return
    error = ws / "_facts_error.txt"
    if error.exists():
        error.unlink()
    key = _facts_cache_key(target, files, domain)
    cached = cache_root / f"{key}.md"
    cached_by_file = cache_root / f"{key}.json"
    cached_units = cache_root / f"{key}.units.json"
    cached_graph = cache_root / f"{key}.graph.json"
    if cached.is_file():
        dest.write_text(cached.read_text(encoding="utf-8"), encoding="utf-8")
        if cached_by_file.is_file():
            dest_by_file.write_text(cached_by_file.read_text(encoding="utf-8"), encoding="utf-8")
        if cached_units.is_file():
            dest_units.write_text(cached_units.read_text(encoding="utf-8"), encoding="utf-8")
        if cached_graph.is_file():
            dest_graph.write_text(cached_graph.read_text(encoding="utf-8"), encoding="utf-8")
        return
    try:
        facts = backend.extract(target)
    except Exception as exc:
        error.write_text(f"facts extraction failed: {exc}\n", encoding="utf-8")
        raise BackendUnavailable(f"facts extraction failed, so this review has no grounding: {exc}") from exc
    if not facts.empty:
        dest.write_text(facts.summary, encoding="utf-8")
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        cached.write_text(facts.summary, encoding="utf-8")
        by_file = facts.data.get("by_file") if isinstance(facts.data, dict) else None
        if by_file:
            payload = json.dumps(by_file)
            dest_by_file.write_text(payload, encoding="utf-8")
            cached_by_file.write_text(payload, encoding="utf-8")
        units = facts.data.get("units") if isinstance(facts.data, dict) else None
        if units:
            units = [u for u in units if not any(detection.is_test_path(str(f[0])) for f in u.get("fragments", []))]
        if units:
            payload = json.dumps(units)
            dest_units.write_text(payload, encoding="utf-8")
            cached_units.write_text(payload, encoding="utf-8")
        graph = facts.data.get("graph") if isinstance(facts.data, dict) else None
        if graph:
            payload = json.dumps(graph)
            dest_graph.write_text(payload, encoding="utf-8")
            cached_graph.write_text(payload, encoding="utf-8")


_SURFACE_TEMPLATE = """\
# Attack Surface Inventory

Enumerate EVERY attacker-influenced entrypoint, one row each, grouped by module.
This is the coverage denominator: a unit you never list is a unit you never review.
See "Phase 1: Map the Attack Surface" in METHODOLOGY.md. The seeded entrypoints in
`_entrypoints.md` are a starting subset, not the whole surface, add non-HTTP sources
such as deserializers, queue consumers, and file parsers.

Status legend: `open` not assigned to a unit yet, `assigned` assigned to a unit in `units/`.

| Module | Entrypoint, METHOD path or non-HTTP source | Auth method | Unit | Status |
|---|---|---|---|---|
"""

_AUTH_MODEL_TEMPLATE = """\
# Authorization Model, Trust Boundaries, Sensitive Data

Built once in Phase 1, every unit refers to this instead of re-deriving it. See
"Phase 1: Map the Attack Surface" in METHODOLOGY.md.

## Access control mechanism

## Actors and trust boundaries

## Sensitive data map
"""


def _entrypoints_md(candidates: list[str], layers: list[str], *, fallback_note: str = "") -> str:
    lines = [
        "# Seeded Entrypoints, a Starting Subset",
        "",
        "Files the detected stack flags as likely to define entrypoints, and the",
        "downstream logic-layer files to trace into. A starting point for the",
        "Phase 1 surface map and the Phase 2 traces, not the whole surface.",
        "",
    ]
    if fallback_note:
        lines += [f"NOTE: {fallback_note}.", ""]
    lines += ["## Candidate entrypoint files", ""]
    lines += [f"- {f}" for f in candidates] or ["(none flagged, enumerate by reading the code)"]
    lines += ["", "## Downstream logic layers to trace into", ""]
    lines += [f"- {f}" for f in layers] or ["(none flagged, follow the calls out of each entrypoint)"]
    return "\n".join(lines) + "\n"


def unit_slug(path: str) -> str:
    """The slug a unit file is named by, derived from the path it owns.

    Public so the engine can recompute the same name when resuming, instead of reaching for
    a private.
    """
    s = path.replace("\\", "/").removesuffix(".py")
    return "".join(c if c.isalnum() else "-" for c in s).strip("-").lower() or "unit"


def _unit_md(
    name: str, mandate: str, *, owned_path: str | None = None, line_range: tuple[int, int] | None = None
) -> str:
    """A seeded unit: the code it owns plus the fixed deep-review mandate.

    the same mandate for every unit so per-unit depth does not vary with the agent's mood.
    The orchestrator spawns one sub-review per unit file, it does not decide the units or
    the depth. A large entrypoint file is seeded as several slice units, each owning one
    line range of the file, so a sub-review concentrates on a handful of handlers instead of
    diluting across the whole file. `owned_path` is the real file a slice belongs to, since
    `name` carries a `#n` suffix, and `line_range` names the slice by line.
    """
    path = owned_path or name
    if line_range is not None:
        owns = (
            f"`{path}` lines {line_range[0]} to {line_range[1]}, deep-review this slice, "
            f"the file is split so each slice gets full attention"
        )
    else:
        owns = f"`{path}`"
    return (
        f"# Unit: {name}\n\n"
        f"- Status: open\n"
        f"- Owns: {owns}\n"
        f"- Trace into: the managers, controllers, dao, and libraries this file "
        f"calls, see `inventory/_entrypoints.md`\n\n---\n\n{mandate}"
    )


def _has_prior_run(ws: Path) -> bool:
    """True when the workspace already holds a previous review's output.

    not just a bare scaffold. Seeded but un-reviewed units do not count, the scaffold seeds
    them. A reviewed unit, a finding, a PoC, or an edited surface does.
    """
    if not ws.exists():
        return False
    for sub in ("candidates", "findings", "pocs"):
        d = ws / sub
        if d.is_dir() and any(d.iterdir()):
            return True
    units = ws / "units"
    if units.is_dir() and any("status: reviewed" in u.read_text(encoding="utf-8").lower() for u in units.glob("*.md")):
        return True
    surface = ws / "inventory" / "_surface.md"
    return surface.exists() and surface.read_text(encoding="utf-8") != _SURFACE_TEMPLATE


def _clear_prior_run(ws: Path) -> list[str]:
    """Remove a previous review's output so a fresh run starts clean.

    so no stale judgment suppresses a finding. Refuse to wipe a non-empty directory this did
    not create: --workspace is arbitrary and a target name such as `api` or `app` is common,
    so a marker check stops this helper from deleting unrelated data.
    """
    if any(ws.iterdir()) and not (ws / _MARKER).is_file():
        raise ValueError(
            f"{ws} is not empty and has no {_MARKER} marker, so it was not created here. "
            "Refusing to clear it. Choose another --workspace or remove the directory by hand."
        )
    removed: list[str] = []
    for child in ws.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
        removed.append(str(child))
    return removed


def _refuse_legacy_layout(ws: Path) -> None:
    """A pre-split workspace kept proposals in issues/.

    Reading that as the new candidates/ would surface nothing, so refuse loud rather than
    report an empty review on stale state. Invariant 4.
    """
    issues = ws / "issues"
    candidates = ws / "candidates"
    legacy = issues.is_dir() and any(issues.iterdir())
    migrated = candidates.is_dir() and any(candidates.iterdir())
    if legacy and not migrated:
        raise ValueError(
            f"{ws} uses the old issues/ layout. Rename issues to candidates, or remove the workspace and start over."
        )


def _vulnerabilities_md(vulnerabilities_dir: Path) -> str:
    """Concatenate the shipped vulnerability class definitions into one seeded file.

    so the workspace carries the knowledge the methodology has each unit apply, rather than
    the agent working from memory. Same shape as the seeded stack notes.
    """
    parts = [
        "# Vulnerability Classes",
        "",
        "The shipped class definitions, each with vulnerable and secure examples. A unit "
        "applies the relevant ones to the code it reads, not from memory.",
        "",
        "---",
        "",
        vulnerability_knowledge("", directory=vulnerabilities_dir, limit=None).rstrip(),
        "",
    ]
    return "\n".join(parts) + "\n"


def scaffold(
    target: str | Path,
    workspace: str | Path,
    *,
    fresh: bool = False,
    domain: Domain | None = None,
) -> ScaffoldResult:
    """Build or refresh a repository review workspace."""
    dom = domain or default_domain()
    paths = dom.paths
    detection = load_detection(paths.detection_file)
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    if not fresh:
        _refuse_legacy_layout(ws)
    had_prior_run = _has_prior_run(ws)
    cleared = _clear_prior_run(ws) if (fresh and ws.exists()) else []

    ws.mkdir(parents=True, exist_ok=True, mode=0o700)
    ws.chmod(0o700)
    (ws / _MARKER).write_text(f"{project}\n", encoding="utf-8")

    created: list[str] = []
    for sub in _DIRS:
        d = ws / sub
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            created.append(str(d))

    model = build_repository_model_from_dir(target, detection)
    guides = select_guides(
        model.files,
        manifest_text=_read_manifests(target, detection),
        source_text=_source_sample(target, model.files, detection),
        guides=load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir),
    )
    (ws / "_stack.md").write_text(_stack_md(guides), encoding="utf-8")
    _write_facts(ws, target, dom, model.files, cache_root=Path(workspace) / ".facts-cache", detection=detection)

    candidates = candidate_entrypoint_files(
        model.files,
        root=target,
        globs=entrypoint_globs(guides),
        markers=entrypoint_markers(guides),
        detection=detection,
    )
    layers = logic_layer_files(model.files, globs=logic_layer_globs(guides), detection=detection)

    fallback_note = ""
    if not candidates:
        api = public_api_files(model.files, root=target, patterns=api_patterns(guides), detection=detection)
        if api:
            candidates = api
            fallback_note = (
                f"no application entrypoints matched, seeding {len(api)} public API files as "
                "the library entry surface, coverage is by public API not by entrypoint"
            )
    (ws / "inventory" / "_entrypoints.md").write_text(
        _entrypoints_md(candidates, layers, fallback_note=fallback_note), encoding="utf-8"
    )

    mandate = paths.unit_review_file.read_text(encoding="utf-8")
    for cand in candidates:
        try:
            text = (target / cand).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        spans = char_spans(text)
        seeds = [(cand, None)] if len(spans) == 1 else [(f"{cand}#{i + 1}", span) for i, span in enumerate(spans)]
        for name, span in seeds:
            up = ws / "units" / f"{unit_slug(name)}.md"
            if up.exists():
                continue
            if span is None:
                body = _unit_md(name, mandate)
            else:
                body = _unit_md(name, mandate, owned_path=cand, line_range=span_line_range(text, span))
            up.write_text(body, encoding="utf-8")
            created.append(str(up))

    for name, template in (
        ("_surface.md", _SURFACE_TEMPLATE),
        ("_auth_model.md", _AUTH_MODEL_TEMPLATE),
    ):
        p = ws / "inventory" / name
        if not p.exists():
            p.write_text(template, encoding="utf-8")
            created.append(str(p))

    sev = ws / "inventory" / "_severity.md"
    if not sev.exists():
        sev.write_text(paths.severity_rubric_file.read_text(encoding="utf-8"), encoding="utf-8")
        created.append(str(sev))

    (ws / "_false_positive_traps.md").write_text(
        paths.false_positive_traps_file.read_text(encoding="utf-8"), encoding="utf-8"
    )

    (ws / "_vulnerabilities.md").write_text(_vulnerabilities_md(paths.vulnerabilities_dir), encoding="utf-8")

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=paths.methodology_file.read_text(encoding="utf-8"),
        candidate_files=tuple(candidates),
        trace_targets=tuple(layers),
        guides=tuple(g.id for g in guides),
        created=created,
        had_prior_run=had_prior_run,
        cleared=cleared,
        fallback_note=fallback_note,
    )
