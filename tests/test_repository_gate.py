"""The Completeness Gate check over a fan-out workspace.

a structural floor that refuses to call a review complete while the surface is not
enumerated, a unit is left open, or a candidate is left ungraded by the rubric. It reads
structured cells, a table row, a Status line, a Risk line, not free prose.
"""

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
    """Exercise the complete workspace passes case."""
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert result.failures == []
    assert result.checked


def test_missing_workspace_fails(tmp_path):
    """Exercise the missing workspace fails case."""
    result = check_gate(tmp_path / "never-scaffolded")
    assert not result.passed
    assert any("does not exist" in f for f in result.failures)


def test_empty_surface_fails(tmp_path):
    """Exercise the empty surface fails case."""
    ws = _complete_ws(tmp_path)
    (ws / "inventory" / "_surface.md").write_text(
        "# Attack Surface Inventory\n\n| Module | Entrypoint | Auth method | Unit | Status |\n|---|---|---|---|---|\n"
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("surface" in f for f in result.failures)


def test_no_units_fails(tmp_path):
    """Exercise the no units fails case."""
    ws = _complete_ws(tmp_path)
    for f in (ws / "units").glob("*.md"):
        f.unlink()
    result = check_gate(ws)
    assert not result.passed
    assert any("no unit files" in f for f in result.failures)


def test_open_unit_fails(tmp_path):
    """Exercise the open unit fails case."""
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u2.md").write_text("# Unit u2\n- Status: open\n- Entrypoints: POST /transfers\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


def test_unit_without_status_counts_as_open(tmp_path):
    """Exercise the unit without status counts as open case."""
    ws = _complete_ws(tmp_path)
    (ws / "units" / "u3.md").write_text("# Unit u3\n- Entrypoints: GET /thing\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("not Status: reviewed" in f for f in result.failures)


def test_medium_issue_passes(tmp_path):
    """Exercise the medium issue passes case."""
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "bounded-finding.md").write_text(
        "# Some finding\n\n- Risk: MEDIUM\n- Type: info disclosure\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_high_issue_passes(tmp_path):
    """Exercise the high issue passes case."""
    ws = _complete_ws(tmp_path)
    (ws / "candidates" / "real-finding.md").write_text(
        "# Some finding\n\n- Risk: HIGH\n- Type: idor\n- Status: confirmed\n"
    )
    assert check_gate(ws).passed


def test_ungraded_or_invalid_severity_fails(tmp_path):
    """Exercise the ungraded or invalid severity fails case."""
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
    """Exercise the source inventory notes a file owned by no unit case."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py", "orphan.py"])
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert result.passed
    assert any("orphan.py" in n for n in result.notes)
    assert not any("owned.py" in n for n in result.notes)


def test_coverage_is_not_claimed_checked_while_a_file_is_unowned(tmp_path):
    """Exercise the coverage is not claimed checked while a file is unowned case."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    result = check_gate(ws, root=target)
    assert "source inventory covered" not in result.checked
    assert any("orphan.py" in n for n in result.notes)


def test_coverage_is_claimed_checked_once_every_source_file_is_owned(tmp_path):
    """Exercise the coverage is claimed checked once every source file is owned case."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py"])
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert "source inventory covered" in result.checked
    assert not result.notes


def test_an_unreadable_run_record_fails_rather_than_reading_as_clean(tmp_path):
    """Exercise an unreadable run record fails rather than reading as clean."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("{ this was truncated mid-write")
    result = check_gate(ws)
    assert not result.passed
    assert any("_run.json exists but does not read as a status record" in f for f in result.failures)
    assert "coded run converged" not in result.checked


def test_an_unreadable_finalize_record_fails_too(tmp_path):
    """Exercise an unreadable finalize record fails too."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text("not json at all")
    result = check_gate(ws)
    assert not result.passed
    assert any("_finalize.json exists but does not read as a status record" in f for f in result.failures)


def test_a_status_record_that_is_valid_json_but_not_an_object_fails(tmp_path):
    """Exercise a status record that is valid json but not an object fails."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("[]")
    result = check_gate(ws)
    assert not result.passed
    assert any("does not read as a status record" in f for f in result.failures)


def test_absent_status_records_are_not_a_failure(tmp_path):
    """Exercise the absent status records are not a failure case."""
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert not any("status record" in f for f in result.failures)


def test_no_gate_item_is_claimed_checked_while_its_own_check_failed(tmp_path):
    """Exercise the no gate item is claimed checked while its own check failed case."""
    ws = tmp_path / "proj"
    for d in ("inventory", "units", "candidates", "findings", "pocs"):
        (ws / d).mkdir(parents=True)
    (ws / "candidates" / "c.md").write_text("# f\n\nno risk stated\n")
    result = check_gate(ws)
    assert len(result.failures) == 3
    assert result.checked == []


def test_convergence_is_not_claimed_checked_while_the_run_says_otherwise(tmp_path):
    """Exercise the convergence is not claimed checked while the run says otherwise case."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "final", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run converged" not in result.checked


def test_convergence_is_not_claimed_checked_while_the_run_is_still_running(tmp_path):
    """Exercise the convergence is not claimed checked while the run is still running case."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "running", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run converged" not in result.checked


def test_convergence_is_claimed_checked_once_the_run_converged(tmp_path):
    """Exercise the convergence is claimed checked once the run converged case."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "converged", "converged": True}))
    result = check_gate(ws)
    assert result.passed
    assert "coded run converged" in result.checked


def test_a_failed_verification_in_a_standalone_finalize_is_not_a_clean_pass(tmp_path):
    """Exercise a failed verification in a standalone finalize is not a clean pass."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 3, "deduped": 2, "verify_errors": 2}))
    result = check_gate(ws)
    assert not result.passed
    assert any("2 failed verifications" in f for f in result.failures)


def test_a_single_failed_verification_uses_singular_text(tmp_path):
    """The gate failure text keeps count grammar readable."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "verify_errors": 1}))
    result = check_gate(ws)
    assert any("1 failed verification" in f for f in result.failures)
    assert not any("1 failed verifications" in f for f in result.failures)


def test_findings_kept_without_a_completed_verification_are_named(tmp_path):
    """Unverified findings keep the workspace incomplete."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps({"parsed": 3, "deduped": 3, "verify_errors": 0, "incomplete": 1, "unlocatable": 2})
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("3 findings kept without a completed verification" in f for f in result.failures)


def test_one_finding_kept_without_verification_uses_singular_text(tmp_path):
    """The unverified finding message keeps count grammar readable."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "incomplete": 1}))
    result = check_gate(ws)
    assert any("1 finding kept without a completed verification" in f for f in result.failures)
    assert not any("1 findings kept without a completed verification" in f for f in result.failures)


def test_a_finalize_that_verified_everything_adds_no_note(tmp_path):
    """Exercise a finalize that verified everything adds no note."""
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps({"parsed": 2, "deduped": 2, "verify_errors": 0, "confirmed": 2, "incomplete": 0, "unlocatable": 0})
    )
    result = check_gate(ws)
    assert result.passed
    assert not result.notes


def test_strict_coverage_fails_on_an_unowned_source_file(tmp_path):
    """Exercise the strict coverage fails on an unowned source file case."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    result = check_gate(ws, root=target, strict_coverage=True)
    assert not result.passed
    assert any("orphan.py" in f for f in result.failures)


def test_a_file_named_in_a_unit_counts_as_owned(tmp_path):
    """Exercise a file named in a unit counts as owned."""
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    (ws / "units" / "u1.md").write_text("# Unit u1\n- Status: reviewed\n- Target: handler.py\n")
    result = check_gate(ws, root=target)
    assert result.passed
    assert not any("handler.py" in n for n in result.notes)


def test_run_status_not_converged_fails_the_gate(tmp_path):
    """Exercise the run status not converged fails the gate case."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": false, "errors": 0, "verify_errors": 0}')
    result = check_gate(ws)
    assert not result.passed
    assert any("did not converge" in f for f in result.failures)


def test_run_status_errors_fail_the_gate(tmp_path):
    """Failed run calls keep the workspace incomplete after convergence."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 2, "verify_errors": 1}')
    result = check_gate(ws)
    assert not result.passed
    assert any("3 failed model call" in f for f in result.failures)


def test_single_run_status_error_uses_singular_text(tmp_path):
    """The failed call message keeps count grammar readable."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 1, "verify_errors": 0}')
    result = check_gate(ws)
    assert any("1 failed model call" in f for f in result.failures)
    assert not any("1 failed model calls" in f for f in result.failures)


def test_run_state_running_fails_the_gate_without_double_reporting(tmp_path):
    """Exercise the run state running fails the gate without double reporting case."""
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"converged": False, "state": "running"}))
    result = check_gate(ws)
    assert not result.passed
    assert any("state is running" in f for f in result.failures)
    assert not any("did not converge" in f for f in result.failures)
