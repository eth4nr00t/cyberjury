"""The completeness gate refuses incomplete repository review workspaces."""

import json

from cyberjury.review.repository.gate import check_gate

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
    return ws


def test_complete_workspace_passes(tmp_path):
    """Complete workspace passes."""
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert result.failures == []
    assert result.checked


def test_missing_workspace_fails(tmp_path):
    """Missing workspace fails."""
    result = check_gate(tmp_path / "never-scaffolded")
    assert not result.passed
    assert any("does not exist" in f for f in result.failures)


def test_empty_surface_fails(tmp_path):
    """Empty surface fails."""
    ws = _complete_ws(tmp_path)
    (ws / "inventory" / "_surface.md").write_text(
        "# Attack Surface Inventory\n\n| Module | Entrypoint | Auth method | Unit | Status |\n|---|---|---|---|---|\n"
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("surface" in f for f in result.failures)


def test_no_units_fails(tmp_path):
    """No units fails."""
    ws = _complete_ws(tmp_path)
    for f in (ws / "units").glob("*.md"):
        f.unlink()
    result = check_gate(ws)
    assert not result.passed
    assert any("no unit files" in f for f in result.failures)


def test_open_unit_fails(tmp_path):
    """Open unit fails."""
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u2.md").write_text("# Unit u2\n- Status: open\n- Entrypoints: POST /transfers\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


def test_unit_without_status_counts_as_open(tmp_path):
    """Unit without status counts as open."""
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u3.md").write_text("# Unit u3\n- Entrypoints: GET /thing\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


def test_medium_issue_passes(tmp_path):
    """Medium issue passes."""
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "bounded-finding.md").write_text(
        "# Some finding\n\n- Risk: MEDIUM\n- Type: info disclosure\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_high_issue_passes(tmp_path):
    """High issue passes."""
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "real-finding.md").write_text(
        "# Some finding\n\n- Risk: HIGH\n- Type: idor\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_ungraded_or_invalid_severity_fails(tmp_path):
    """Ungraded or invalid severity fails."""
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
    """Source inventory notes a file owned by no unit."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py", "orphan.py"])
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert result.passed
    assert any("orphan.py" in n for n in result.notes)
    assert not any("owned.py" in n for n in result.notes)


def test_coverage_is_not_claimed_checked_while_a_file_is_unowned(tmp_path):
    """Coverage is not claimed checked while a file is unowned."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    result = check_gate(ws, root=target)
    assert "source inventory covered" not in result.checked
    assert any("orphan.py" in n for n in result.notes)


def test_coverage_is_claimed_checked_once_every_source_file_is_owned(tmp_path):
    """Coverage is claimed checked once every source file is owned."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py"])
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert "source inventory covered" in result.checked
    assert not result.notes


def test_an_unreadable_run_record_fails_rather_than_reading_as_clean(tmp_path):
    """Unreadable run record fails rather than reading as clean."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("{ this was truncated mid-write")
    result = check_gate(ws)
    assert not result.passed
    assert any("_run.json exists but does not read as a status record" in f for f in result.failures)
    assert "coded run complete" not in result.checked


def test_an_unreadable_finalize_record_fails_too(tmp_path):
    """Unreadable finalize record fails too."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text("not json at all")
    result = check_gate(ws)
    assert not result.passed
    assert any("_finalize.json exists but does not read as a status record" in f for f in result.failures)


def test_a_status_record_that_is_valid_json_but_not_an_object_fails(tmp_path):
    """Status record that is valid JSON but not an object fails."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("[]")
    result = check_gate(ws)
    assert not result.passed
    assert any("does not read as a status record" in f for f in result.failures)


def test_absent_status_records_are_not_a_failure(tmp_path):
    """Absent status records are not a failure."""
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert not any("status record" in f for f in result.failures)


def test_no_gate_item_is_claimed_checked_while_its_own_check_failed(tmp_path):
    """No gate item is claimed checked while its own check failed."""
    ws = tmp_path / "proj"
    for d in ("inventory", "units", "candidates", "findings", "pocs"):
        (ws / d).mkdir(parents=True)
    (ws / "candidates" / "c.md").write_text("# f\n\nno risk stated\n")
    result = check_gate(ws)
    assert len(result.failures) == 3
    assert result.checked == []


def test_run_completion_is_not_claimed_checked_while_the_run_says_otherwise(tmp_path):
    """Run completion is not claimed checked while the run says otherwise."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "final", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run complete" not in result.checked


def test_run_completion_is_not_claimed_checked_while_the_run_is_still_running(tmp_path):
    """Run completion is not claimed checked while the run is still running."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "running", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run complete" not in result.checked


def test_run_completion_is_claimed_checked_once_the_run_completed(tmp_path):
    """Run completion is claimed checked once the run completed."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "converged", "complete": True, "converged": True}))
    result = check_gate(ws)
    assert result.passed
    assert "coded run complete" in result.checked


def test_standard_run_can_complete_without_converging_the_union(tmp_path):
    """Standard run completion is distinct from adversarial convergence."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "converged", "complete": True, "converged": False}))
    result = check_gate(ws)
    assert result.passed
    assert "coded run complete" in result.checked


def test_a_failed_verification_in_a_standalone_finalize_is_not_a_clean_pass(tmp_path):
    """Failed verification in a standalone finalize is not a clean pass."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 3, "deduped": 2, "verify_errors": 2}))
    result = check_gate(ws)
    assert not result.passed
    assert any("2 failed verifications" in f for f in result.failures)


def test_a_single_failed_verification_uses_singular_text(tmp_path):
    """Single failed verification uses singular text."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "verify_errors": 1}))
    result = check_gate(ws)
    assert any("1 failed verification" in f for f in result.failures)
    assert not any("1 failed verifications" in f for f in result.failures)


def test_findings_kept_without_a_completed_verification_are_named(tmp_path):
    """Findings kept without a completed verification are named."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps({"parsed": 3, "deduped": 3, "verify_errors": 0, "incomplete": 1, "unlocatable": 2})
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("3 findings kept without a completed verification" in f for f in result.failures)


def test_one_finding_kept_without_verification_uses_singular_text(tmp_path):
    """One finding kept without verification uses singular text."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "incomplete": 1}))
    result = check_gate(ws)
    assert any("1 finding kept without a completed verification" in f for f in result.failures)
    assert not any("1 findings kept without a completed verification" in f for f in result.failures)


def test_a_finalize_that_verified_everything_adds_no_note(tmp_path):
    """Finalize that verified everything adds no note."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps({"parsed": 2, "deduped": 2, "verify_errors": 0, "confirmed": 2, "incomplete": 0, "unlocatable": 0})
    )
    result = check_gate(ws)
    assert result.passed
    assert not result.notes


def test_a_file_named_in_a_unit_counts_as_owned(tmp_path):
    """File named in a unit counts as owned."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    (ws / "units" / "u1.md").write_text("# Unit u1\n- Status: reviewed\n- Target: handler.py\n")
    result = check_gate(ws, root=target)
    assert result.passed
    assert not any("handler.py" in n for n in result.notes)


def test_legacy_run_status_without_complete_uses_converged_as_completion(tmp_path):
    """Legacy run status without complete uses converged as completion."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": false, "errors": 0, "verify_errors": 0}')
    result = check_gate(ws)
    assert not result.passed
    assert any("did not complete" in f for f in result.failures)


def test_run_status_errors_fail_the_gate(tmp_path):
    """Run status errors fail the gate."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 2, "verify_errors": 1}')
    result = check_gate(ws)
    assert not result.passed
    assert any("3 failed model call" in f for f in result.failures)


def test_single_run_status_error_uses_singular_text(tmp_path):
    """Single run status error uses singular text."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 1, "verify_errors": 0}')
    result = check_gate(ws)
    assert any("1 failed model call" in f for f in result.failures)
    assert not any("1 failed model calls" in f for f in result.failures)


def test_run_state_running_fails_the_gate_without_double_reporting(tmp_path):
    """Run state running fails the gate without double reporting."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"converged": False, "state": "running"}))
    result = check_gate(ws)
    assert not result.passed
    assert any("state is running" in f for f in result.failures)
    assert not any("did not complete" in f for f in result.failures)
