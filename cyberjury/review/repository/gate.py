"""The Completeness Gate over a fan-out review workspace.

The whole-repository review runs as a coded pass or an agent fan-out, and either way
this does not run or judge the review. It reads the workspace's own bookkeeping and
refuses to call a review complete while it is unfinished: the attack surface not
enumerated, a unit left un-reviewed, or a candidate left ungraded by the rubric. It
refuses equally when a step's own record is present but cannot be read, since an unknown
state is not a clean one. It is a structural floor, not a recall guarantee: it verifies
the inventory denominator is built and every unit carries a verdict, never that every
real issue was found. Recall is a property the passes and the re-runs carry, not
something a checker can assert. Each check reads a structured cell, a table row, a
Status line, a Risk line, never a free-prose claim, so the agent cannot clear it by
writing a word.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.markdown_docs import md_field
from cyberjury.severity import SEVERITIES


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


def check_gate(project_dir: Path, *, root: Path | None = None, detection: Detection | None = None) -> GateResult:
    """Check the fan-out review workspace `<workspace>/<project>` against the gate.

    This is the one enforcement point that holds a coded run and an agent run to the same
    completeness contract, regardless of which produced the workspace. Returns a GateResult.
    The caller decides the exit code. A missing or never scaffolded workspace is itself a
    failure, since nothing was reviewed. When `root` is given the source tree is the
    coverage denominator, so a source file owned by no unit is reported as a note. It reads
    the target tree but runs no models.
    """
    failures: list[str] = []
    checked: list[str] = []
    notes: list[str] = []

    if not project_dir.is_dir():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])

    surface = project_dir / "inventory" / "_surface.md"
    if not surface.is_file():
        failures.append("inventory/_surface.md is missing, the attack-surface inventory was not built")
    elif not _table_data_rows(surface.read_text(encoding="utf-8")):
        failures.append("inventory/_surface.md has no enumerated entrypoint, the Phase 1 surface map was not built")
    else:
        checked.append("attack surface enumerated")

    units_dir = project_dir / "units"
    unit_files = sorted(units_dir.glob("*.md")) if units_dir.is_dir() else []
    if not unit_files:
        failures.append("units/ has no unit files, the surface was not decomposed into units to fan out over")
    else:
        open_units = [
            f.name for f in unit_files if (_line_value(f.read_text(encoding="utf-8"), "status") or "open") != "reviewed"
        ]
        if open_units:
            shown = ", ".join(open_units[:5]) + (" ..." if len(open_units) > 5 else "")
            failures.append(
                f"{len(open_units)} unit(s) in units/ are not Status: reviewed, run their sub-review: {shown}"
            )
        else:
            checked.append("every unit reviewed")

    _LEVELS = tuple(s.lower() for s in SEVERITIES)
    candidates_dir = project_dir / "candidates"
    ungraded: list[str] = []
    if candidates_dir.is_dir():
        for f in sorted(candidates_dir.glob("*.md")):
            risk = _line_value(f.read_text(encoding="utf-8"), "(?:risk|severity)")
            if risk is None or not any(lvl in risk for lvl in _LEVELS):
                ungraded.append(f.name)
    for name in ungraded:
        failures.append(
            f"candidates/{name} has no calibrated Risk line, grade it CRITICAL, HIGH, "
            "MEDIUM, or LOW per inventory/_severity.md"
        )
    if not ungraded:
        checked.append("candidates graded by the rubric")

    data = _read_status(project_dir / "_run.json", failures)
    if data is not None:
        if data.get("state") == "running":
            failures.append(
                "_run.json state is running, the coded run was killed mid-pass and never finished, "
                "re-run it to completion, invariant 4"
            )
        elif not data.get("complete", data.get("converged", True)):
            failures.append(
                "_run.json shows the coded run did not complete, some units still failing, "
                "run another round, invariant 4"
            )
        else:
            checked.append("coded run complete")
        errs = int(data.get("errors", 0)) + int(data.get("verify_errors", 0))
        if errs:
            failures.append(
                f"_run.json records {_counted(errs, 'failed model call')} during the run, "
                "re-run it so a failed step is not a clean pass, invariant 4"
            )

    fdata = _read_status(project_dir / "_finalize.json", failures)
    if fdata is not None:
        ferrs = int(fdata.get("verify_errors", 0))
        if ferrs:
            failures.append(
                f"_finalize.json records {_counted(ferrs, 'failed verification')}, re-run --finalize rather "
                "than reading those candidates as verified, invariant 4"
            )
        kept = int(fdata.get("incomplete", 0)) + int(fdata.get("unlocatable", 0))
        if kept:
            failures.append(
                f"_finalize.json records {_counted(kept, 'finding', 'findings')} kept without a "
                "completed verification, "
                "re-run --finalize so they are verified rather than assumed, invariant 4"
            )

    if root is not None:
        det = detection or load_detection()
        inventory = _source_inventory(Path(root), det)
        unowned = sorted(inventory - _owned_files(project_dir, inventory)) if inventory else []
        if unowned:
            shown = ", ".join(unowned[:8]) + (" ..." if len(unowned) > 8 else "")
            msg = (
                f"{len(unowned)} of {len(inventory)} source file(s) are owned by no unit or "
                f"surface row, they sit outside the coverage denominator: {shown}"
            )
            notes.append(msg)
        else:
            checked.append("source inventory covered")

    return GateResult(not failures, failures, checked, notes)


def _read_status(path: Path, failures: list[str]) -> dict | None:
    """A step's status record, or None when there is none.

    adding to `failures` when a file is present but unreadable. An unreadable file must not
    fall back to an empty record: every field would take its clean default and the gate
    would report an unknown as a pass, invariant 4.
    """
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
    """The source files under the target that are not tests, the true coverage denominator.

    so a file that no unit ever listed is still counted as surface that could have been
    missed.
    """
    from cyberjury.review.repository.model import build_repository_model_from_dir

    model = build_repository_model_from_dir(root, detection)
    return {f for f in model.files if Path(f).suffix in detection.source_extensions and not detection.is_test_path(f)}


def _owned_files(project_dir: Path, inventory: set[str]) -> set[str]:
    """The inventory files a review claimed.

    a file is owned when its path appears in the surface, a unit, or a candidate, so the
    definition is generous and the same for a coded and an agent workspace, both of which
    write these same artifacts.
    """
    blobs: list[str] = []
    surface = project_dir / "inventory" / "_surface.md"
    if surface.is_file():
        blobs.append(surface.read_text(encoding="utf-8"))
    for name in ("units", "candidates"):
        sub = project_dir / name
        if sub.is_dir():
            blobs.extend(f.read_text(encoding="utf-8") for f in sub.glob("*.md"))
    text = "\n".join(blobs)
    return {f for f in inventory if f in text}
