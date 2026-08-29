"""Repository Review scaffold: set up the workspace, do not run a pipeline.

Repository review is too large for a single LLM call. A single pass over a large repository
dilutes attention. The scaffold creates inventory, units, candidates, findings, and PoC
directories, seeds stack guides and candidate entrypoint files, and returns the
methodology text to print. It does not find issues itself.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.guides import (
    Guide,
    entrypoint_globs,
    entrypoint_markers,
    exported_symbol_patterns,
    load_guides,
    logic_layer_globs,
    select_guides,
)
from cyberjury.profiles.base import ReviewProfile, profile_content_fingerprint
from cyberjury.profiles.registry import default_profile
from cyberjury.review.facts import extract_facts
from cyberjury.review.repository.context import AUTH_MODEL_TEMPLATE
from cyberjury.review.repository.model import (
    build_repository_model_from_dir,
    candidate_entrypoint_files,
    char_spans,
    files_with_exported_symbols,
    logic_layer_files,
    span_line_range,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.storage import FactsStore, facts_cache_key
from cyberjury.review.vulnerabilities import allowed_categories, load_vulnerabilities, render_vulnerabilities

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository

_DIRS = ("inventory", "units", "candidates", "findings", "pocs")
_MARKER = Path(".cyberjury") / "workspace.json"
WORKSPACE_MARKER = str(_MARKER)


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


@dataclass(kw_only=True)
class _WorkspaceSetup:
    """Initialized workspace state shared by scaffold stages."""

    target: Path
    root: Path
    project: str
    workspace: Path
    had_prior_run: bool
    cleared: list[str]
    reuse_facts: bool
    created: list[str] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class _TargetAnalysis:
    """Deterministic target inventory used to seed workspace artifacts."""

    files: tuple[str, ...]
    guides: tuple[Guide, ...]
    candidate_files: tuple[str, ...]
    trace_targets: tuple[str, ...]
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

    Detection can fire on import markers and language-neutral content tokens such as a
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
            chunk = (target / f).read_text(encoding="utf-8")[: _SETTINGS.max_stack_detection_chars_per_file]
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(chunk)
        total += len(chunk)
        if total >= _SETTINGS.target_stack_detection_chars_total:
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


def _write_facts(
    ws: Path,
    target: Path,
    profile: ReviewProfile,
    *,
    cache_root: Path,
    cache_key: str,
    reuse_workspace: bool,
    detection: Detection,
) -> None:
    """Extract deterministic facts and persist the backend's supported workspace artifacts.

    The backend may emit `_facts_by_file.json`, `_facts_units.json`, and `_facts_graph.json`
    alongside `_stack.md`, so the run, resume, and finalize steps read the same grounding
    from the workspace. The extraction is cached by source content hash under
    `cache_root`, so a fresh scaffold or a second target on the same source reuses it rather
    than re-extracting. A profile that binds a backend grounds every review, there is no
    ungrounded tier and no flag to turn it off. So a backend that cannot run, or an
    extraction that fails, raises rather than quietly returning a review without cross-
    function units. Coverage that drops silently is a reduced review reported as complete,
    and it hides a broken toolchain for as long as nobody reads stderr, invariant 4.
    `_facts_error.txt` still records the failure for the operator.
    """
    backend = profile.facts_backend
    if backend is None:
        return
    store = FactsStore(workspace=ws, cache_root=cache_root)
    if reuse_workspace and store.complete():
        return
    store.clear()
    error = ws / "_facts_error.txt"
    if error.exists():
        error.unlink()
    try:
        if store.restore(cache_key):
            return
        facts = extract_facts(backend, target, purpose="repository review")
        store.persist(facts, cache_key, is_test_path=detection.is_test_path)
    except Exception as exc:
        error.write_text(f"facts extraction failed: {exc}\n", encoding="utf-8")
        raise


_SURFACE_TEMPLATE = """\
# Attack Surface Inventory

Enumerate EVERY attacker-influenced entrypoint, one row each, grouped by module.
This is the coverage denominator: a unit you never list is a unit you never review.
See "Phase 1: Map the Attack Surface" in methodology.md. The seeded entrypoints in
`_entrypoints.md` are a starting subset, not the full surface, add non-HTTP sources
such as deserializers, queue consumers, and file parsers.

Status legend: `open` not assigned to a unit yet, `assigned` assigned to a unit in `units/`.

| Module | Entrypoint, METHOD path or non-HTTP source | Auth method | Unit | Status |
|---|---|---|---|---|
"""


def _entrypoints_md(candidates: list[str], layers: list[str], *, fallback_note: str = "") -> str:
    lines = [
        "# Seeded Entrypoints, a Starting Subset",
        "",
        "Files the detected stack flags as likely to define entrypoints, and the",
        "downstream logic-layer files to trace into. A starting point for the",
        "Phase 1 surface map and the Phase 2 traces, not the full surface.",
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
    """Build a readable collision resistant marker identity for one unit.

    This remains public so the engine can recompute the name when resuming.
    """
    normalized = path.replace("\\", "/")
    readable = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-") or "unit"
    digest = sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{readable[:64]}-{digest}"


def _unit_md(
    name: str, mandate: str, *, owned_path: str | None = None, line_range: tuple[int, int] | None = None
) -> str:
    """Render a seeded unit with its owned code and fixed review mandate.

    The same mandate for every unit keeps review depth consistent.
    The orchestrator spawns one sub-review per unit file, it does not decide the units or
    the depth. A large entrypoint file is seeded as several slice units, each owning one
    line range of the file, so a sub-review concentrates on a handful of handlers instead of
    diluting across the file. `owned_path` is the real file a slice belongs to, since
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
    """Return whether the workspace holds output beyond a bare scaffold.

    Seeded but unreviewed units do not count because the scaffold creates
    them. A reviewed unit, a finding, a PoC, or an edited surface does.
    """
    if not ws.exists():
        return False
    if any((ws / name).is_file() for name in ("_run.json", "_union.json", "_finalize.json")):
        return True
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

    This prevents stale judgment from suppressing a finding. Refuse to wipe a non-empty directory this process did
    not create: --workspace is arbitrary and a target name such as `api` or `app` is common,
    so a marker check stops this helper from deleting unrelated data.
    """
    marker = ws / _MARKER
    if any(ws.iterdir()) and not marker.is_file():
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


def _vulnerabilities_md(vulnerabilities_dir: Path) -> str:
    """Keep the full library available to agent workflows that select classes while reading."""
    categories = allowed_categories(vulnerabilities_dir)
    knowledge = render_vulnerabilities(load_vulnerabilities(vulnerabilities_dir)).rstrip()
    parts = [
        "# Vulnerability Classes",
        "",
        "Allowed categories:",
        "",
        *[f"- `{category}`" for category in categories],
        "",
        "Class definitions follow, each with vulnerable and secure examples. A unit applies the "
        "relevant ones to the code it reads, not from memory.",
        "",
        "---",
        "",
        knowledge,
        "",
    ]
    return "\n".join(parts) + "\n"


def _read_workspace_identity(marker: Path) -> dict[str, object] | None:
    if not marker.is_file():
        return None
    try:
        identity = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"review workspace marker at {marker} is malformed") from exc
    if not isinstance(identity, dict):
        raise ValueError(f"review workspace marker at {marker} is malformed")
    return identity


def _require_fresh_workspace_owner(
    workspace: Path,
    prior: dict[str, object] | None,
    identity: dict[str, object],
) -> None:
    if prior is None:
        return
    prior_owner = (prior.get("project"), prior.get("target"))
    owner = (identity["project"], identity["target"])
    if prior_owner != owner:
        raise ValueError(f"review workspace at {workspace} belongs to a different target")


def _initialize_workspace(
    target: Path,
    root: Path,
    profile: ReviewProfile,
    *,
    fresh: bool,
    source_fingerprint: str,
    profile_fingerprint: str,
) -> _WorkspaceSetup:
    """Create the private workspace only when its review identity is reusable."""
    project = target.name
    workspace = root / project
    had_prior_run = _has_prior_run(workspace)
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace.chmod(0o700)
    marker = workspace / _MARKER
    identity = {
        "project": project,
        "profile": profile.name,
        "profile_fingerprint": profile_fingerprint,
        "target": str(target),
        "source_fingerprint": source_fingerprint,
    }
    prior_identity = _read_workspace_identity(marker)
    if fresh:
        _require_fresh_workspace_owner(workspace, prior_identity, identity)
    cleared = _clear_prior_run(workspace) if fresh and workspace.exists() else []
    if fresh:
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        workspace.chmod(0o700)
        marker = workspace / _MARKER
    reuse_facts = prior_identity == identity
    if had_prior_run and not fresh and not reuse_facts:
        raise ValueError(
            f"repository source or profile changed since the review workspace at {workspace} was created. "
            "Re-run with --fresh so stale reviewed units and findings cannot be reused."
        )
    if not fresh and not had_prior_run and prior_identity is not None and not reuse_facts:
        cleared = _clear_prior_run(workspace)
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        workspace.chmod(0o700)
        marker = workspace / _MARKER
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(identity) + "\n", encoding="utf-8")
    setup = _WorkspaceSetup(
        target=target,
        root=root,
        project=project,
        workspace=workspace,
        had_prior_run=had_prior_run,
        cleared=cleared,
        reuse_facts=reuse_facts,
    )
    for subdirectory in _DIRS:
        path = workspace / subdirectory
        if path.exists():
            continue
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        setup.created.append(str(path))
    return setup


def _analyze_target(target: Path, profile: ReviewProfile, detection: Detection) -> _TargetAnalysis:
    """Select stack guides, entry surfaces, and downstream trace targets."""
    paths = profile.paths
    model = build_repository_model_from_dir(target, detection)
    guides = select_guides(
        model.files,
        manifest_text=_read_manifests(target, detection),
        source_text=_source_sample(target, model.files, detection),
        guides=load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir),
    )
    candidates = candidate_entrypoint_files(
        model.files,
        root=target,
        globs=entrypoint_globs(guides),
        markers=entrypoint_markers(guides),
        detection=detection,
    )
    trace_targets = logic_layer_files(
        model.files,
        globs=logic_layer_globs(guides),
        detection=detection,
    )
    fallback_note = ""
    if not candidates:
        exported_files = files_with_exported_symbols(
            model.files,
            root=target,
            patterns=exported_symbol_patterns(guides),
            detection=detection,
        )
        if exported_files:
            candidates = exported_files
            fallback_note = (
                f"no application entrypoints matched, seeding {len(exported_files)} files containing exported "
                "symbols as the library entry surface, coverage starts from exported symbols rather than "
                "application entrypoints"
            )
    return _TargetAnalysis(
        files=model.files,
        guides=tuple(guides),
        candidate_files=tuple(candidates),
        trace_targets=tuple(trace_targets),
        fallback_note=fallback_note,
    )


def _write_analysis_assets(
    setup: _WorkspaceSetup,
    analysis: _TargetAnalysis,
    profile: ReviewProfile,
    detection: Detection,
    source_fingerprint: str,
) -> None:
    """Persist stack, facts, and seeded entrypoint inventory."""
    (setup.workspace / "_stack.md").write_text(_stack_md(list(analysis.guides)), encoding="utf-8")
    _write_facts(
        setup.workspace,
        setup.target,
        profile,
        cache_root=setup.root / ".facts-cache",
        cache_key=source_fingerprint,
        reuse_workspace=setup.reuse_facts,
        detection=detection,
    )
    (setup.workspace / "inventory" / "_entrypoints.md").write_text(
        _entrypoints_md(
            list(analysis.candidate_files),
            list(analysis.trace_targets),
            fallback_note=analysis.fallback_note,
        ),
        encoding="utf-8",
    )


def _seed_units(setup: _WorkspaceSetup, candidates: tuple[str, ...], mandate: str) -> None:
    """Create each missing source unit without replacing review progress."""
    for candidate in candidates:
        try:
            text = (setup.target / candidate).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        spans = char_spans(text)
        seeds = (
            [(candidate, None)]
            if len(spans) == 1
            else [(f"{candidate}#{index + 1}", span) for index, span in enumerate(spans)]
        )
        for name, span in seeds:
            unit_path = setup.workspace / "units" / f"{unit_slug(name)}.md"
            if unit_path.exists():
                continue
            body = (
                _unit_md(name, mandate)
                if span is None
                else _unit_md(
                    name,
                    mandate,
                    owned_path=candidate,
                    line_range=span_line_range(text, span),
                )
            )
            unit_path.write_text(body, encoding="utf-8")
            setup.created.append(str(unit_path))


def _write_review_assets(setup: _WorkspaceSetup, profile: ReviewProfile) -> None:
    """Write stable inventory, policy, and vulnerability reference assets."""
    paths = profile.paths
    for name, template in (
        ("_surface.md", _SURFACE_TEMPLATE),
        ("_auth_model.md", AUTH_MODEL_TEMPLATE),
    ):
        path = setup.workspace / "inventory" / name
        if path.exists():
            continue
        path.write_text(template, encoding="utf-8")
        setup.created.append(str(path))
    severity = setup.workspace / "inventory" / "_severity.md"
    if not severity.exists():
        severity.write_text(paths.severity_rubric_file.read_text(encoding="utf-8"), encoding="utf-8")
        setup.created.append(str(severity))
    (setup.workspace / "_false_positive_traps.md").write_text(
        paths.false_positive_traps_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (setup.workspace / "_vulnerabilities.md").write_text(
        _vulnerabilities_md(paths.vulnerabilities_dir),
        encoding="utf-8",
    )


def scaffold(
    target: str | Path,
    workspace: str | Path,
    *,
    fresh: bool = False,
    profile: ReviewProfile | None = None,
) -> ScaffoldResult:
    """Build or refresh a repository review workspace."""
    selected_profile = profile or default_profile()
    paths = selected_profile.paths
    detection = load_detection(paths.detection_file)
    target = Path(target).resolve()
    workspace_root = Path(workspace)
    analysis = _analyze_target(target, selected_profile, detection)
    profile_fingerprint = profile_content_fingerprint(selected_profile)
    try:
        source_fingerprint = facts_cache_key(
            target,
            analysis.files,
            selected_profile.name,
            profile_fingerprint=profile_fingerprint,
        )
    except OSError as exc:
        failed_workspace = workspace_root / target.name
        failed_workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        (failed_workspace / "_facts_error.txt").write_text(
            f"facts extraction failed: {exc}\n",
            encoding="utf-8",
        )
        raise
    setup = _initialize_workspace(
        target,
        workspace_root,
        selected_profile,
        fresh=fresh,
        source_fingerprint=source_fingerprint,
        profile_fingerprint=profile_fingerprint,
    )
    _write_analysis_assets(setup, analysis, selected_profile, detection, source_fingerprint)
    _seed_units(setup, analysis.candidate_files, paths.unit_review_file.read_text(encoding="utf-8"))
    _write_review_assets(setup, selected_profile)
    return ScaffoldResult(
        project=setup.project,
        workspace=setup.workspace,
        methodology=paths.methodology_file.read_text(encoding="utf-8"),
        candidate_files=analysis.candidate_files,
        trace_targets=analysis.trace_targets,
        guides=tuple(guide.id for guide in analysis.guides),
        created=setup.created,
        had_prior_run=setup.had_prior_run,
        cleared=setup.cleared,
        fallback_note=analysis.fallback_note,
    )
