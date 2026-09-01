"""The Completeness Gate over a repository review workspace.

This does not run or judge the review. It reads the workspace's own bookkeeping and
refuses to call a review complete while it is unfinished: the attack surface not
enumerated, a unit left un-reviewed, or a candidate left ungraded by the rubric. It
requires the coded run record and refuses an absent, unreadable, or incomplete run. An
optional finalize record also fails when it is present but unreadable or incomplete. It
is a structural floor, not a recall guarantee: it verifies
the inventory denominator is built and every unit carries a verdict, never that every
real issue was found. Recall is a property the passes and the re-runs carry, not
something a checker can assert. Each check reads a structured cell, a table row, a
Status line, a Risk line, never a free-prose claim, so the agent cannot clear it by
writing a word.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.markdown_docs import md_field
from cyberjury.review.paths import RepositoryPathError
from cyberjury.severity import SEVERITIES
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError, source_snapshot_files

_LEVELS = tuple(severity.lower() for severity in SEVERITIES)
_RUN_STATES = frozenset({"running", "converged", "complete", "incomplete"})


@dataclass(frozen=True)
class GateResult:
    """Completeness gate verdict with blocking errors and warnings."""

    passed: bool
    failures: list[str]
    checked: list[str]
    notes: list[str] = field(default_factory=list)


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


def _counted(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else plural or singular + 's'}"


def _table_rows(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Markdown tables as header plus data rows."""
    tables: list[tuple[list[str], list[list[str]]]] = []
    headers: list[str] | None = None
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if headers is not None and rows:
                tables.append((headers, rows))
            headers = None
            rows = []
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not "".join(cells) or set("".join(cells)) <= {"-", ":"}:
            continue
        if headers is None:
            headers = cells
        else:
            rows.append(cells)
    if headers is not None and rows:
        tables.append((headers, rows))
    return tables


def _inventory_mentions(snippet: str, inventory: set[str]) -> set[str]:
    """Inventory paths named exactly inside a structured snippet."""
    text = snippet.replace("`", "")
    owned: set[str] = set()
    for rel in inventory:
        if re.search(rf"(?<![\w./\\-]){re.escape(rel)}(?![\w./\\-])", text):
            owned.add(rel)
    return owned


def _structured_owned_files(text: str, inventory: set[str]) -> set[str]:
    """Inventory paths mentioned in ownership fields and table cells."""
    owned: set[str] = set()
    for key in ("Owns", "Target", "Owned file", "Owned files", "File", "Files", "Source"):
        value = md_field(text, key)
        if value is not None:
            owned.update(_inventory_mentions(value, inventory))
    for _headers, rows in _table_rows(text):
        for row in rows:
            for cell in row:
                owned.update(_inventory_mentions(cell, inventory))
    return owned


def _check_surface(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    surface = project_dir / "inventory" / "_surface.md"
    if not surface.is_file():
        failures.append("inventory/_surface.md is missing, the attack-surface inventory was not built")
    elif not _table_data_rows(surface.read_text(encoding="utf-8")):
        failures.append("inventory/_surface.md has no enumerated entrypoint, the Phase 1 surface map was not built")
    else:
        checked.append("attack surface enumerated")


def _check_units(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    units_dir = project_dir / "units"
    unit_files = sorted(units_dir.glob("*.md")) if units_dir.is_dir() else []
    if not unit_files:
        failures.append("units/ has no unit files, the surface was not decomposed into units to fan out over")
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
    if candidates_dir.is_dir():
        for file in sorted(candidates_dir.glob("*.md")):
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


def _status_shape(
    path: Path,
    data: dict[str, object],
    failures: list[str],
    *,
    booleans: tuple[str, ...] = (),
    counts: tuple[str, ...] = (),
    strings: tuple[str, ...] = (),
) -> bool:
    errors: list[str] = []
    for key in booleans:
        if key in data and not isinstance(data[key], bool):
            errors.append(f"{key} must be a boolean")
    for key in counts:
        value = data.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{key} must be a nonnegative integer")
    for key in strings:
        if key in data and not isinstance(data[key], str):
            errors.append(f"{key} must be a string")
    if not errors:
        return True
    failures.append(f"{path.name} has an invalid status record: {', '.join(errors)}")
    return False


def _check_run_status(project_dir: Path, failures: list[str], checked: list[str]) -> None:
    path = project_dir / "_run.json"
    if not path.is_file():
        failures.append("_run.json is missing, run the coded repository review before checking completeness")
        return
    data = _read_status(path, failures)
    if data is None:
        return
    if not _status_shape(
        path,
        data,
        failures,
        booleans=("complete", "converged"),
        counts=("errors", "verify_errors", "facts_limitations"),
        strings=("state",),
    ):
        return
    completion_failure = _run_completion_failure(path, data)
    if completion_failure:
        failures.append(completion_failure)
    else:
        checked.append("coded run complete")
    errors = data.get("errors", 0) + data.get("verify_errors", 0)
    if errors:
        failures.append(
            f"_run.json records {_counted(errors, 'failed model call')} during the run, "
            "re-run it so a failed step is not a clean pass, invariant 4"
        )
    limitations = data.get("facts_limitations", 0)
    if limitations:
        failures.append(
            f"_run.json records {_counted(limitations, 'source facts limitation')}, "
            "inspect _facts_limitations.json and re-run with --fresh after parser support is available"
        )


def _run_completion_failure(path: Path, data: dict[str, object]) -> str:
    """Reject terminal states that do not match the writer's completion contract."""
    if "complete" not in data and "converged" not in data:
        return f"{path.name} has an invalid status record: complete or converged is required"
    state = data.get("state")
    if state is not None and state not in _RUN_STATES:
        return f"{path.name} has an invalid status record: state {state!r} is not recognized"
    complete = data.get("complete", data.get("converged"))
    if state in {"complete", "converged"} and not complete:
        return f"{path.name} has an invalid status record: state {state!r} requires complete true"
    if state == "converged" and data.get("converged") is not True:
        return f"{path.name} has an invalid status record: state 'converged' requires converged true"
    if state == "incomplete" and complete:
        return f"{path.name} has an invalid status record: state 'incomplete' requires complete false"
    if state == "running":
        return (
            "_run.json state is running, the coded run was killed mid-pass and never finished, "
            "re-run it to completion, invariant 4"
        )
    if not complete:
        return (
            "_run.json shows the coded run did not complete, some units still failing, run another round, invariant 4"
        )
    return ""


def _check_finalize_status(project_dir: Path, failures: list[str]) -> None:
    path = project_dir / "_finalize.json"
    data = _read_status(path, failures)
    if data is None or not _status_shape(
        path,
        data,
        failures,
        booleans=("complete",),
        counts=("verify_errors", "incomplete", "unlocatable", "facts_limitations"),
    ):
        return
    if "complete" not in data:
        failures.append(f"{path.name} has an invalid status record: complete is required")
    elif data["complete"] is False:
        failures.append("_finalize.json shows finalize did not complete, re-run --finalize, invariant 4")
    errors = data.get("verify_errors", 0)
    if errors:
        failures.append(
            f"_finalize.json records {_counted(errors, 'failed verification')}, re-run --finalize rather "
            "than reading those candidates as verified, invariant 4"
        )
    kept = data.get("incomplete", 0) + data.get("unlocatable", 0)
    if kept:
        failures.append(
            f"_finalize.json records {_counted(kept, 'finding', 'findings')} kept without a "
            "completed verification, re-run --finalize so they are verified rather than assumed, invariant 4"
        )


def _check_source_coverage(
    project_dir: Path,
    root: Path,
    detection: Detection | None,
    failures: list[str],
    checked: list[str],
) -> None:
    try:
        inventory = _source_inventory(root, detection or load_detection())
    except RepositoryPathError as exc:
        failures.append(f"source inventory cannot be read safely: {exc}")
        return
    unowned = sorted(inventory - _owned_files(project_dir, inventory)) if inventory else []
    if not unowned:
        checked.append("source inventory covered")
        return
    shown = ", ".join(unowned[:8]) + (" ..." if len(unowned) > 8 else "")
    failures.append(
        f"{len(unowned)} of {len(inventory)} source file(s) are owned by no unit or "
        f"surface row, they sit outside the coverage denominator: {shown}"
    )


def check_gate(project_dir: Path, *, root: Path | None = None, detection: Detection | None = None) -> GateResult:
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

    if not project_dir.is_dir():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])

    _check_surface(project_dir, failures, checked)
    _check_units(project_dir, failures, checked)
    _check_candidates(project_dir, failures, checked)
    _check_run_status(project_dir, failures, checked)
    _check_finalize_status(project_dir, failures)
    if root is not None:
        _check_source_revision(project_dir, Path(root), detection, failures, checked)
        _check_source_coverage(project_dir, Path(root), detection, failures, checked)

    return GateResult(not failures, failures, checked, notes)


def _check_source_revision(
    project_dir: Path,
    root: Path,
    detection: Detection | None,
    failures: list[str],
    checked: list[str],
) -> None:
    marker = project_dir / ".cyberjury" / "workspace.json"
    try:
        identity = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"source snapshot binding is unreadable: {exc}")
        return
    expected = identity.get("source_snapshot_id") if isinstance(identity, dict) else None
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


def _read_status(path: Path, failures: list[str]) -> dict[str, object] | None:
    """Return absent status as None and record unreadable present status as failure."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if isinstance(data, dict):
        return data
    failures.append(
        f"{path.name} exists but does not read as a status record, so whether that step completed "
        "is unknown, re-run it rather than treating it as clean"
    )
    return None


def _source_inventory(root: Path, detection: Detection) -> set[str]:
    """Keep every non-noise production file in the denominator."""
    from cyberjury.review.repository.model import build_repository_model_from_dir

    model = build_repository_model_from_dir(root, detection)
    return {f for f in model.files if not detection.is_noise_path(f)}


def _owned_files(project_dir: Path, inventory: set[str]) -> set[str]:
    """The inventory files a review claimed.

    A file is owned when a structured ownership field or table cell names it exactly.
    Free prose does not count, so a path that appears only in an explanation or example
    does not satisfy the coverage denominator.
    """
    owned: set[str] = set()
    surface = project_dir / "inventory" / "_surface.md"
    if surface.is_file():
        owned.update(_structured_owned_files(surface.read_text(encoding="utf-8"), inventory))
    for name in ("units", "candidates"):
        sub = project_dir / name
        if sub.is_dir():
            for f in sub.glob("*.md"):
                owned.update(_structured_owned_files(f.read_text(encoding="utf-8"), inventory))
    return owned
