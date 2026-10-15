"""Check a finished repository review workspace without a model call.

The gate passes only when the hash bound `outcome.json` and `findings.json` pair records a
complete review of the workspace source snapshot, and the reviewed source is unchanged.
It checks persisted terminal state, never that every real issue was found.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.paths import RepositoryPathError
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError, source_snapshot_files
from cyberjury.workspace import WorkspaceCorruptionError, read_json_object


@dataclass(frozen=True)
class GateResult:
    """Gate verdict with blocking failures and passed checks."""

    passed: bool
    failures: list[str]
    checked: list[str]

    def to_dict(self) -> dict[str, object]:
        """Return the stable machine gate result."""
        return {
            "schema": "cyberjury.repository-gate/v2",
            "passed": self.passed,
            "failures": self.failures,
            "checked": self.checked,
        }


def _source_snapshot_id(project_dir: Path, failures: list[str]) -> str | None:
    marker = project_dir / ".cyberjury" / "workspace.json"
    try:
        if marker.parent.is_symlink():
            raise WorkspaceCorruptionError("workspace marker directory cannot be a symlink")
        identity = read_json_object(marker)
    except WorkspaceCorruptionError as exc:
        failures.append(f"source snapshot binding is unreadable: {exc}")
        return None
    expected = identity.get("source_snapshot_id")
    if not isinstance(expected, str) or not expected:
        failures.append("source snapshot binding is missing, re-run --scaffold or --run")
        return None
    return expected


def _check_result(project_dir: Path, snapshot_id: str, failures: list[str], checked: list[str]) -> None:
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
    if outcome.source_revision != snapshot_id:
        failures.append("outcome.json does not match the repository workspace source snapshot")
        return
    if not outcome.complete:
        failures.append(
            "outcome.json records an incomplete review, inspect its counters and stage receipts before re-running"
        )
        return
    checked.append("final result complete and hash bound")


def _check_source_revision(root: Path, snapshot_id: str, failures: list[str], checked: list[str]) -> None:
    try:
        snapshot = SourceSnapshot.capture(root, source_snapshot_files(root))
    except (RepositoryPathError, SourceSnapshotError) as exc:
        failures.append(f"source snapshot cannot be validated: {exc}")
        return
    if snapshot.snapshot_id != snapshot_id:
        failures.append("repository source changed after the review snapshot was captured")
        return
    checked.append("source snapshot unchanged")


def check_gate(project_dir: Path, *, root: Path | None = None) -> GateResult:
    """Check the hash bound terminal result and, given a root, its unchanged source."""
    if not project_dir.is_dir() or project_dir.is_symlink():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])
    failures: list[str] = []
    checked: list[str] = []
    snapshot_id = _source_snapshot_id(project_dir, failures)
    if snapshot_id is not None:
        _check_result(project_dir, snapshot_id, failures, checked)
        if root is not None:
            _check_source_revision(Path(root), snapshot_id, failures, checked)
    return GateResult(not failures, failures, checked)
