"""The Completeness Gate over a repository review workspace.

This does not run or judge the review. It reads the workspace's own bookkeeping and
refuses to call a review complete while its attack surface is not enumerated, a unit is
not reviewed, or a candidate is not graded. Completion comes only from the strict,
hash bound `outcome.json` and `findings.json` pair. Resume checkpoints do not control the
gate. This is a structural floor, not a recall guarantee. It verifies the inventory
denominator and persisted terminal state, never that every real issue was found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.markdown_docs import md_field
from cyberjury.review.paths import RepositoryPathError
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.severity import SEVERITIES
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError, source_snapshot_files
from cyberjury.workspace import WorkspaceCorruptionError, read_json_object

_LEVELS = tuple(severity.lower() for severity in SEVERITIES)


@dataclass(frozen=True)
class GateResult:
    """Completeness gate verdict with blocking errors and warnings."""

    passed: bool
    failures: list[str]
    checked: list[str]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return the stable machine gate result."""
        return {
            "schema": "cyberjury.repository-gate/v1",
            "passed": self.passed,
            "failures": self.failures,
            "checked": self.checked,
            "notes": self.notes,
        }


def _table_data_rows(text: str) -> list[list[str]]:
    """Data rows of a markdown table, header and separator rows skipped."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not "".join(cells) or set("".join(cells)) <= {"-", ":"}:
            continue
        if any(c.lower() == "module" for c in cells):
            continue
        rows.append(cells)
    return rows


def _line_value(text: str, key: str) -> str | None:
    v = md_field(text, key)
    return v.lower() if v is not None else None


def _check_surface(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    surface = project_dir / "inventory" / "_surface.md"
    if surface.is_symlink():
        failures.append("inventory/_surface.md cannot be a symlink")
    elif not surface.is_file():
        failures.append("inventory/_surface.md is missing, the attack-surface inventory was not built")
    elif not _table_data_rows(surface.read_text(encoding="utf-8")):
        failures.append("inventory/_surface.md has no enumerated entrypoint, the Phase 1 surface map was not built")
    else:
        checked.append("attack surface enumerated")


def _check_units(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    units_dir = project_dir / "units"
    if units_dir.is_symlink():
        failures.append("units/ cannot be a symlink")
        return
    unit_files = sorted(units_dir.glob("*.md")) if units_dir.is_dir() else []
    if not unit_files:
        failures.append("units/ has no unit files, the surface was not decomposed into units to fan out over")
        return
    linked = [file.name for file in unit_files if file.is_symlink()]
    if linked:
        failures.append(f"units/ contains symlink unit files: {', '.join(linked[:5])}")
        return
    open_units = [
        file.name
        for file in unit_files
        if (_line_value(file.read_text(encoding="utf-8"), "status") or "open") != "reviewed"
    ]
    if not open_units:
        checked.append("every unit reviewed")
        return
    shown = ", ".join(open_units[:5]) + (" ..." if len(open_units) > 5 else "")
    failures.append(f"{len(open_units)} unit(s) in units/ are not Status: reviewed, run their sub-review: {shown}")


def _check_candidates(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    candidates_dir = project_dir / "candidates"
    ungraded: list[str] = []
    if candidates_dir.is_symlink():
        failures.append("candidates/ cannot be a symlink")
        return
    if candidates_dir.is_dir():
        for file in sorted(candidates_dir.glob("*.md")):
            if file.is_symlink():
                ungraded.append(file.name)
                continue
            risk = _line_value(file.read_text(encoding="utf-8"), "(?:risk|severity)")
            if risk is None or not any(level in risk for level in _LEVELS):
                ungraded.append(file.name)
    for name in ungraded:
        failures.append(
            f"candidates/{name} has no calibrated Risk line, grade it CRITICAL, HIGH, "
            "MEDIUM, or LOW per inventory/_severity.md"
        )
    if not ungraded:
        checked.append("candidates graded by the rubric")


def _check_result(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    """Require one hash bound complete Repository Review result."""
    findings_path = project_dir / "findings.json"
    outcome_path = project_dir / "outcome.json"
    if not findings_path.is_file() or not outcome_path.is_file():
        failures.append("findings.json and outcome.json are required, re-run the repository review")
        return
    try:
        findings = FindingsArtifact.from_dict(read_json_object(findings_path))
        outcome = OutcomeArtifact.from_dict(read_json_object(outcome_path))
    except (ValueError, WorkspaceCorruptionError) as exc:
        failures.append(f"final review artifacts are invalid: {exc}")
        return
    if outcome.target != "repository":
        failures.append("outcome.json does not describe a repository review")
        return
    if outcome.findings_sha256 != findings.content_sha256:
        failures.append("outcome.json does not identify the persisted findings.json")
        return
    marker = project_dir / ".cyberjury" / "workspace.json"
    if marker.is_file():
        try:
            identity = read_json_object(marker)
        except WorkspaceCorruptionError as exc:
            failures.append(f"source snapshot binding is invalid: {exc}")
            return
        if identity.get("source_snapshot_id") != outcome.source_revision:
            failures.append("outcome.json does not match the repository workspace source snapshot")
            return
    if not outcome.complete:
        failures.append(
            "outcome.json records an incomplete review, inspect its counters and stage receipts before re-running"
        )
        return
    checked.append("final result complete and hash bound")


def _check_source_coverage(
    project_dir: Path,
    failures: list[str],
    checked: list[str],
) -> None:
    try:
        plan = UnitPlanReceipt.from_dict(read_json_object(project_dir / "_unit_plan.json"))
    except (ValueError, WorkspaceCorruptionError) as exc:
        failures.append(f"unit plan coverage artifact is invalid: {exc}")
        return
    unowned = plan.unowned_paths
    if not unowned:
        checked.append("unit plan source coverage complete")
        return
    shown = ", ".join(unowned[:8]) + (" ..." if len(unowned) > 8 else "")
    failures.append(f"{len(unowned)} planned source file(s) are owned by no review unit: {shown}")


def check_gate(project_dir: Path, *, root: Path | None = None) -> GateResult:
    """Check the review workspace `<workspace>/<project>` against the gate.

    This is the enforcement point that holds a run to the workspace completeness contract.
    Returns a GateResult. The caller decides the exit code. A missing or never scaffolded
    workspace is itself a failure, since nothing was reviewed. When `root` is given the
    source tree is the coverage denominator, so a production file owned by no unit blocks
    completion. It reads the target tree but runs no models.
    """
    failures: list[str] = []
    checked: list[str] = []
    notes: list[str] = []

    if not project_dir.is_dir() or project_dir.is_symlink():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])

    _check_surface(project_dir, failures, checked)
    _check_units(project_dir, failures, checked)
    _check_candidates(project_dir, failures, checked)
    _check_source_coverage(project_dir, failures, checked)
    _check_result(project_dir, failures, checked)
    if root is not None:
        _check_source_revision(project_dir, Path(root), failures, checked)

    return GateResult(not failures, failures, checked, notes)


def _check_source_revision(
    project_dir: Path,
    root: Path,
    failures: list[str],
    checked: list[str],
) -> None:
    marker = project_dir / ".cyberjury" / "workspace.json"
    try:
        if marker.parent.is_symlink():
            raise WorkspaceCorruptionError("workspace marker directory cannot be a symlink")
        identity = read_json_object(marker)
    except WorkspaceCorruptionError as exc:
        failures.append(f"source snapshot binding is unreadable: {exc}")
        return
    expected = identity.get("source_snapshot_id")
    if not isinstance(expected, str) or not expected:
        failures.append("source snapshot binding is missing, re-run --scaffold or --run")
        return
    try:
        snapshot = SourceSnapshot.capture(root, source_snapshot_files(root))
    except (RepositoryPathError, SourceSnapshotError) as exc:
        failures.append(f"source snapshot cannot be validated: {exc}")
        return
    if snapshot.snapshot_id != expected:
        failures.append("repository source changed after the review snapshot was captured")
        return
    checked.append("source snapshot unchanged")
