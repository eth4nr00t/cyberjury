"""Build bounded review units from every readable production source file."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path
from time import perf_counter

from cyberjury.detection import load_detection
from cyberjury.profiles.base import ReviewProfile, bind_profile_content, profile_binding
from cyberjury.profiles.registry import default_profile
from cyberjury.review.facts import BackendUnavailable, FactsResolutionReceipt, NativeAnalysisReceipt, extract_facts
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.paths import source_navigation_files
from cyberjury.review.repository.context import (
    Unit,
    ground_units,
    load_facts_by_file,
    load_facts_graph,
    load_facts_limitations,
    load_relationship_evidence,
)
from cyberjury.review.repository.model import build_units, repository_unit_plan_receipt
from cyberjury.review.storage import FactsStore, facts_cache_key_from_snapshot
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.selection import source_files
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError, source_snapshot_files

_MARKER = Path(".cyberjury") / "workspace.json"
_MARKER_SCHEMA = "cyberjury.repository-workspace/v1"
WORKSPACE_MARKER = str(_MARKER)


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    """Workspace paths and receipts produced by scaffold."""

    project: str
    workspace: Path
    profile_sha256: str
    native_analysis: NativeAnalysisReceipt
    facts_resolution: FactsResolutionReceipt
    unit_plan: UnitPlanReceipt
    grounding_receipt: GroundingReceipt
    grounding_seconds: float
    units: tuple[Unit, ...]
    source_snapshot: SourceSnapshot
    candidate_files: tuple[str, ...] = ()
    had_prior_run: bool = False
    cleared: list[str] = field(default_factory=list)


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


@dataclass(frozen=True, kw_only=True)
class _FactsReceipts:
    """Bind native analysis and shared facts resolution as one extraction result."""

    native_analysis: NativeAnalysisReceipt
    facts_resolution: FactsResolutionReceipt


def _write_facts(
    ws: Path,
    target: Path,
    profile: ReviewProfile,
    *,
    cache_root: Path,
    cache_key: str,
    reuse_workspace: bool,
) -> _FactsReceipts:
    """Extract facts, cache by source content hash, and raise on failure, recording `_facts_error.txt`."""
    store = FactsStore(workspace=ws, cache_root=cache_root)
    if reuse_workspace and store.complete():
        native_analysis = store.native_analysis()
        facts_resolution = store.facts_resolution()
        if native_analysis is not None and facts_resolution is not None:
            store.populate_cache_from_workspace(cache_key)
            return _FactsReceipts(
                native_analysis=native_analysis,
                facts_resolution=facts_resolution,
            )
    store.clear()
    error = ws / "_facts_error.txt"
    if error.exists():
        error.unlink()
    try:
        if store.restore(cache_key):
            native_analysis = store.native_analysis()
            facts_resolution = store.facts_resolution()
            if native_analysis is not None and facts_resolution is not None:
                return _FactsReceipts(
                    native_analysis=native_analysis,
                    facts_resolution=facts_resolution,
                )
            store.clear()
            store.remove_cache(cache_key)
        facts = extract_facts(profile.facts_backend, target, purpose="repository review")
        if facts.native_analysis is None or facts.facts_resolution is None:
            raise BackendUnavailable("facts backend produced no analysis receipts for repository review")
        store.persist(facts, cache_key)
        return _FactsReceipts(
            native_analysis=facts.native_analysis,
            facts_resolution=facts.facts_resolution,
        )
    except Exception as exc:
        error.write_text(f"facts extraction failed: {exc}\n", encoding="utf-8")
        raise


def _has_prior_run(ws: Path) -> bool:
    """Return whether the workspace holds review output beyond a bare scaffold."""
    if any((ws / name).is_file() for name in ("_run.json", "_union.json", "findings.json", "outcome.json")):
        return True
    pocs = ws / "pocs"
    return pocs.is_dir() and any(pocs.iterdir())


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


def _read_workspace_identity(marker: Path) -> dict[str, object] | None:
    if not marker.is_file():
        return None
    try:
        identity = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"review workspace marker at {marker} is malformed") from exc
    if not isinstance(identity, dict):
        raise ValueError(f"review workspace marker at {marker} is malformed")
    fields = {
        "schema",
        "project",
        "profile",
        "profile_sha256",
        "target",
        "source_snapshot_id",
        "facts_cache_key",
    }
    if set(identity) != fields or identity["schema"] != _MARKER_SCHEMA:
        raise ValueError(f"review workspace marker at {marker} has an unsupported schema")
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
    source_snapshot_id: str,
    facts_cache_key: str,
    profile_sha256: str,
    target_identity: Path,
) -> _WorkspaceSetup:
    """Create the private workspace only when its review identity is reusable."""
    project = target.name
    workspace = root / project
    had_prior_run = _has_prior_run(workspace)
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace.chmod(0o700)
    marker = workspace / _MARKER
    identity = {
        "schema": _MARKER_SCHEMA,
        "project": project,
        "profile": profile.name,
        "profile_sha256": profile_sha256,
        "target": str(target_identity),
        "source_snapshot_id": source_snapshot_id,
        "facts_cache_key": facts_cache_key,
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
    return setup


def scaffold(
    target: str | Path,
    workspace: str | Path,
    *,
    fresh: bool = False,
    profile: ReviewProfile | None = None,
    expected_snapshot_id: str = "",
    target_identity: str | Path | None = None,
) -> ScaffoldResult:
    """Build or refresh a repository review workspace."""
    selected_profile = bind_profile_content(profile or default_profile())
    paths = selected_profile.paths
    detection = load_detection(paths.detection_file)
    target = Path(target).resolve()
    identity_target = Path(target_identity).resolve() if target_identity is not None else target
    workspace_root = Path(workspace)
    binding = profile_binding(selected_profile)
    try:
        source_snapshot = SourceSnapshot.capture(
            target,
            source_snapshot_files(target),
            scope_provider=lambda: source_snapshot_files(target),
        )
    except (OSError, SourceSnapshotError) as exc:
        failed_workspace = workspace_root / target.name
        failed_workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        (failed_workspace / "_facts_error.txt").write_text(
            f"facts extraction failed: {exc}\n",
            encoding="utf-8",
        )
        raise
    if expected_snapshot_id and source_snapshot.snapshot_id != expected_snapshot_id:
        raise ValueError("repository source changed after the attempt snapshot was captured")
    candidate_files = source_files(target, detection)
    facts_key = facts_cache_key_from_snapshot(
        source_snapshot.snapshot_id,
        selected_profile.name,
        profile_content_snapshot_id=binding.content_snapshot_id,
        backend_identity=binding.facts_backend_id,
    )
    setup = _initialize_workspace(
        target,
        workspace_root,
        selected_profile,
        fresh=fresh,
        source_snapshot_id=source_snapshot.snapshot_id,
        facts_cache_key=facts_key,
        profile_sha256=binding.profile_sha256,
        target_identity=identity_target,
    )
    facts_receipts = _write_facts(
        setup.workspace,
        setup.target,
        selected_profile,
        cache_root=setup.root / ".facts-cache",
        cache_key=facts_key,
        reuse_workspace=setup.reuse_facts,
    )
    if not source_snapshot.matches():
        store = FactsStore(workspace=setup.workspace, cache_root=setup.root / ".facts-cache")
        store.clear()
        store.remove_cache(facts_key)
        error = setup.workspace / "_facts_error.txt"
        error.write_text("facts extraction failed: repository source changed during analysis\n", encoding="utf-8")
        raise BackendUnavailable(
            "repository source changed during facts extraction, so no stable snapshot was reviewed"
        )
    limitations = load_facts_limitations(setup.workspace)
    review_files = tuple(
        dict.fromkeys(
            (
                *candidate_files,
                *(limitation.source for limitation in limitations),
            )
        )
    )
    facts_graph = load_facts_graph(setup.workspace)
    units = tuple(build_units(target, review_files, facts_graph))
    unit_plan = repository_unit_plan_receipt(
        target,
        units,
        facts_receipts.facts_resolution,
        expected_owned_paths=review_files,
    )
    (setup.workspace / "_unit_plan.json").write_text(json.dumps(unit_plan.to_dict()), encoding="utf-8")
    units = tuple(replace(unit, id=record.id) for unit, record in zip(units, unit_plan.units, strict=True))
    grounding_started = perf_counter()
    navigation_files = source_navigation_files(target, detection)
    navigator = SourceNavigator.from_graph(
        target,
        facts_graph,
        source_files=navigation_files,
        relationship_evidence=load_relationship_evidence(setup.workspace),
        test_files=(file for file in navigation_files if detection.is_test_path(file)),
        documentation_files=(
            file for file in navigation_files if Path(file).suffix.lower() in detection.doc_extensions
        ),
    )
    grounded_units = ground_units(
        units,
        facts_by_file=load_facts_by_file(setup.workspace),
        limitations=limitations,
        navigator=navigator,
        source_snapshot=source_snapshot,
    )
    grounding_receipt = GroundingReceipt.create(
        unit_plan=unit_plan,
        contexts=tuple(unit.grounding for unit in grounded_units if unit.grounding is not None),
    )
    (setup.workspace / "_grounding.json").write_text(
        json.dumps(grounding_receipt.to_dict()),
        encoding="utf-8",
    )
    grounding_seconds = round(perf_counter() - grounding_started, 3)
    if not source_snapshot.matches():
        raise BackendUnavailable("repository source changed while scaffold assets were being built")
    if profile_binding(selected_profile).profile_sha256 != binding.profile_sha256:
        raise BackendUnavailable("review profile changed while scaffold assets were being built")
    return ScaffoldResult(
        project=setup.project,
        workspace=setup.workspace,
        profile_sha256=binding.profile_sha256,
        native_analysis=facts_receipts.native_analysis,
        facts_resolution=facts_receipts.facts_resolution,
        unit_plan=unit_plan,
        grounding_receipt=grounding_receipt,
        grounding_seconds=grounding_seconds,
        units=grounded_units,
        candidate_files=candidate_files,
        had_prior_run=setup.had_prior_run,
        cleared=setup.cleared,
        source_snapshot=source_snapshot,
    )
