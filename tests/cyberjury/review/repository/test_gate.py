"""The completeness gate refuses incomplete repository review workspaces."""

import json

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.paths import repository_files
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord
from cyberjury.sources.snapshot import SourceSnapshot

_SURFACE = (
    "# Attack Surface Inventory\n\n"
    "| Module | Entrypoint | Auth method | Unit | Status |\n"
    "|---|---|---|---|---|\n"
    "| app | GET /users | require_auth | u1 | assigned |\n"
    "| app | DELETE /admin/users/<uid> | require_admin | u1 | assigned |\n"
)


def _complete_ws(root):
    """A workspace whose bookkeeping passes every gate item."""
    ws = root / "proj"
    (ws / "inventory").mkdir(parents=True)
    (ws / "units").mkdir()
    (ws / "candidates").mkdir()
    (ws / "findings").mkdir()
    (ws / "pocs").mkdir()
    (ws / "inventory" / "_surface.md").write_text(_SURFACE)
    (ws / "units" / "u1.md").write_text(
        "# Unit u1: user endpoints\n- Status: reviewed\n- Entrypoints: GET /users, DELETE /admin/users/<uid>\n"
    )
    (ws / "_run.json").write_text(
        json.dumps({"state": "complete", "complete": True, "converged": False, "errors": 0, "verify_errors": 0})
    )
    _write_unit_plan(ws)
    _write_result(ws)
    return ws


def _write_result(ws, *, source_revision="a" * 64, outcome=None, target="repository"):
    findings = FindingsArtifact.create(())
    review_outcome = outcome or ReviewOutcome(findings=(), requires_convergence=False)
    result = OutcomeArtifact.create(
        target=target,
        source_revision=source_revision,
        findings=findings,
        outcome=review_outcome,
    )
    (ws / "findings.json").write_text(json.dumps(findings.to_dict()))
    (ws / "outcome.json").write_text(json.dumps(result.to_dict()))


def _write_unit_plan(ws, *, owned=(), unowned=()):
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    facts = FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )
    units = tuple(UnitPlanRecord.create(kind="source", name=path, owned_paths=(path,)) for path in owned)
    plan = UnitPlanReceipt.create(
        facts_resolution=facts,
        units=units,
        expected_owned_paths=(*owned, *unowned),
    )
    (ws / "_unit_plan.json").write_text(json.dumps(plan.to_dict()))


def test_complete_workspace_passes(tmp_path):
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert result.failures == []
    assert result.checked


def test_missing_workspace_fails(tmp_path):
    result = check_gate(tmp_path / "never-scaffolded")
    assert not result.passed
    assert any("does not exist" in f for f in result.failures)


def test_empty_surface_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "inventory" / "_surface.md").write_text(
        "# Attack Surface Inventory\n\n| Module | Entrypoint | Auth method | Unit | Status |\n|---|---|---|---|---|\n"
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("surface" in f for f in result.failures)


def test_no_units_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    for f in (ws / "units").glob("*.md"):
        f.unlink()
    result = check_gate(ws)
    assert not result.passed
    assert any("no unit files" in f for f in result.failures)


def test_open_unit_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u2.md").write_text("# Unit u2\n- Status: open\n- Entrypoints: POST /transfers\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


def test_unit_without_status_counts_as_open(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u3.md").write_text("# Unit u3\n- Entrypoints: GET /thing\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


@pytest.mark.parametrize("name", ["units", "candidates"])
def test_gate_rejects_symlink_work_directories(tmp_path, name):
    ws = _complete_ws(tmp_path)
    real = tmp_path / f"real-{name}"
    real.mkdir()
    for child in (ws / name).iterdir():
        child.unlink()
    (ws / name).rmdir()
    (ws / name).symlink_to(real, target_is_directory=True)

    result = check_gate(ws)

    assert not result.passed
    assert any("symlink" in failure for failure in result.failures)


def test_medium_issue_passes(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "bounded-finding.md").write_text(
        "# Some finding\n\n- Risk: MEDIUM\n- Type: info disclosure\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_high_issue_passes(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "real-finding.md").write_text(
        "# Some finding\n\n- Risk: HIGH\n- Type: idor\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_ungraded_or_invalid_severity_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "no-risk.md").write_text("# Some finding\n\nNo risk stated.\n")
    (ws / "candidates" / "bogus.md").write_text("# Some finding\n\n- Risk: spicy\n- Type: idor\n")
    result = check_gate(ws)
    assert not result.passed
    assert sum("calibrated Risk" in f for f in result.failures) == 2


def _target_tree(root, files):
    """A throwaway source tree the gate reads as the coverage denominator."""
    target = root / "code"
    target.mkdir()
    for name in files:
        (target / name).write_text("x = 1\n")
    return target


def test_source_inventory_notes_a_file_owned_by_no_unit(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py", "orphan.py"])
    _write_unit_plan(ws, owned=("owned.py",), unowned=("orphan.py",))
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert not result.passed
    assert any("orphan.py" in failure for failure in result.failures)
    assert not any("owned.py" in failure for failure in result.failures)


def test_coverage_is_not_claimed_checked_while_a_file_is_unowned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    _write_unit_plan(ws, unowned=("orphan.py",))
    result = check_gate(ws, root=target)
    assert "unit plan source coverage complete" not in result.checked
    assert any("orphan.py" in failure for failure in result.failures)


def test_coverage_is_claimed_checked_once_every_source_file_is_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py"])
    _write_unit_plan(ws, owned=("owned.py",))
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert "unit plan source coverage complete" in result.checked
    assert not result.notes


def test_non_unit_manifest_context_is_not_a_second_coverage_denominator(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["migration.sql"])

    result = check_gate(ws, root=target)

    assert "unit plan source coverage complete" in result.checked
    assert not any("migration.sql" in failure for failure in result.failures)


@pytest.mark.parametrize("name", ["findings.json", "outcome.json"])
def test_missing_final_artifact_fails(tmp_path, name):
    ws = _complete_ws(tmp_path)
    (ws / name).unlink()

    result = check_gate(ws)

    assert not result.passed
    assert any("required" in failure for failure in result.failures)


@pytest.mark.parametrize("name", ["findings.json", "outcome.json"])
def test_unreadable_final_artifact_fails(tmp_path, name):
    ws = _complete_ws(tmp_path)
    (ws / name).write_text("{truncated")

    result = check_gate(ws)

    assert not result.passed
    assert any("artifacts are invalid" in failure for failure in result.failures)


def test_tampered_findings_fail_the_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    findings = json.loads((ws / "findings.json").read_text())
    findings["summary"]["HIGH"] = 1
    (ws / "findings.json").write_text(json.dumps(findings))

    result = check_gate(ws)

    assert not result.passed
    assert any("invalid" in failure for failure in result.failures)


def test_outcome_with_errors_fails_the_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    _write_result(
        ws,
        outcome=ReviewOutcome(findings=(), errors=1, requires_convergence=False),
    )

    result = check_gate(ws)

    assert not result.passed
    assert any("incomplete review" in failure for failure in result.failures)


def test_diff_outcome_cannot_pass_the_repository_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    _write_result(ws, target="diff")

    result = check_gate(ws)

    assert not result.passed
    assert any("repository review" in failure for failure in result.failures)


def test_outcome_revision_must_match_the_repository_workspace(tmp_path):
    ws = _complete_ws(tmp_path)
    marker = ws / ".cyberjury" / "workspace.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({"source_snapshot_id": "b" * 64}))

    result = check_gate(ws)

    assert not result.passed
    assert any("workspace source snapshot" in failure for failure in result.failures)


def test_legacy_status_cannot_override_an_incomplete_result(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"complete": True}))
    (ws / "_finalize.json").write_text(json.dumps({"complete": True}))
    _write_result(
        ws,
        outcome=ReviewOutcome(findings=(), incomplete=(object(),), requires_convergence=False),
    )

    assert not check_gate(ws).passed


def test_legacy_status_is_not_a_second_completion_authority(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("{truncated")
    (ws / "_finalize.json").write_text("{truncated")

    result = check_gate(ws)

    assert result.passed
    assert "final result complete and hash bound" in result.checked


def test_no_gate_item_is_claimed_checked_while_its_own_check_failed(tmp_path):
    ws = tmp_path / "proj"
    for d in ("inventory", "units", "candidates", "findings", "pocs"):
        (ws / d).mkdir(parents=True)
    (ws / "candidates" / "c.md").write_text("# f\n\nno risk stated\n")
    result = check_gate(ws)
    assert len(result.failures) == 5
    assert result.checked == []


def test_a_file_named_in_a_unit_counts_as_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    snapshot = SourceSnapshot.capture(target, repository_files(target))
    marker = ws / ".cyberjury" / "workspace.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"source_snapshot_id": snapshot.snapshot_id}))
    _write_result(ws, source_revision=snapshot.snapshot_id)
    _write_unit_plan(ws, owned=("handler.py",))
    (ws / "units" / "u1.md").write_text("# Unit u1\n- Status: reviewed\n- Target: handler.py\n")
    result = check_gate(ws, root=target)
    assert result.passed


@pytest.mark.parametrize("change", ["modify", "delete", "add"])
def test_gate_rejects_source_revision_drift(tmp_path, change):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    (ws / "units" / "u1.md").write_text("# Unit u1\n- Status: reviewed\n- Target: handler.py\n")
    snapshot = SourceSnapshot.capture(target, repository_files(target))
    marker = ws / ".cyberjury" / "workspace.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"source_snapshot_id": snapshot.snapshot_id}))
    _write_result(ws, source_revision=snapshot.snapshot_id)
    _write_unit_plan(ws, owned=("handler.py",))
    source = target / "handler.py"
    if change == "modify":
        source.write_text("changed\n")
    elif change == "delete":
        source.unlink()
    else:
        (target / "new.py").write_text("new\n")

    result = check_gate(ws, root=target)

    assert result.passed is False
    assert any("source changed" in failure for failure in result.failures)
    assert not any("handler.py" in n for n in result.notes)


def test_a_path_mentioned_only_in_unit_prose_does_not_count_as_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    _write_unit_plan(ws, unowned=("orphan.py",))
    (ws / "units" / "u1.md").write_text(
        "# Unit u1\n- Status: reviewed\n- Notes: this mentions orphan.py in prose only.\n"
    )
    result = check_gate(ws, root=target)
    assert not result.passed
    assert any("orphan.py" in failure for failure in result.failures)
