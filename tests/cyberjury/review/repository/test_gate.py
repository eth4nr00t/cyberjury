"""The completeness gate refuses incomplete repository review workspaces."""

import json

import pytest

from cyberjury.review.paths import repository_files
from cyberjury.review.repository.gate import check_gate
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
    return ws


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
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert not result.passed
    assert any("orphan.py" in failure for failure in result.failures)
    assert not any("owned.py" in failure for failure in result.failures)


def test_coverage_is_not_claimed_checked_while_a_file_is_unowned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    result = check_gate(ws, root=target)
    assert "source inventory covered" not in result.checked
    assert any("orphan.py" in failure for failure in result.failures)


def test_coverage_is_claimed_checked_once_every_source_file_is_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["owned.py"])
    (ws / "inventory" / "_surface.md").write_text(_SURFACE + "| app | owned.py | none | u1 | assigned |\n")
    result = check_gate(ws, root=target)
    assert "source inventory covered" in result.checked
    assert not result.notes


def test_non_source_production_files_are_part_of_the_gate_inventory(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["migration.sql"])

    result = check_gate(ws, root=target)

    assert not result.passed
    assert any("migration.sql" in failure for failure in result.failures)


def test_an_unreadable_run_record_fails_rather_than_reading_as_clean(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("{ this was truncated mid-write")
    result = check_gate(ws)
    assert not result.passed
    assert any("_run.json exists but does not read as a status record" in f for f in result.failures)
    assert "coded run complete" not in result.checked


def test_an_unreadable_finalize_record_fails_too(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text("not json at all")
    result = check_gate(ws)
    assert not result.passed
    assert any("_finalize.json exists but does not read as a status record" in f for f in result.failures)


def test_a_status_record_that_is_valid_json_but_not_an_object_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text("[]")
    result = check_gate(ws)
    assert not result.passed
    assert any("does not read as a status record" in f for f in result.failures)


@pytest.mark.parametrize(
    "status",
    [
        {"complete": "false", "errors": 0, "verify_errors": 0},
        {"complete": True, "errors": "0", "verify_errors": 0},
        {"complete": True, "errors": 0, "verify_errors": []},
        {"state": 1, "complete": True},
        {"errors": 0},
    ],
)
def test_run_status_with_invalid_field_types_fails_cleanly(tmp_path, status):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps(status))

    result = check_gate(ws)

    assert not result.passed
    assert any("invalid status record" in failure for failure in result.failures)
    assert "coded run complete" not in result.checked


@pytest.mark.parametrize(
    "status",
    [
        {"verify_errors": "0"},
        {"incomplete": False},
        {"unlocatable": []},
    ],
)
def test_finalize_status_with_invalid_field_types_fails_cleanly(tmp_path, status):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps(status))

    result = check_gate(ws)

    assert not result.passed
    assert any("invalid status record" in failure for failure in result.failures)


@pytest.mark.parametrize(
    "status",
    [
        {"state": "nonsense", "complete": True},
        {"state": "complete", "complete": False},
        {"state": "converged", "complete": True, "converged": False},
        {"state": "incomplete", "complete": True},
    ],
)
def test_run_status_with_inconsistent_terminal_semantics_fails(tmp_path, status):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps(status))

    result = check_gate(ws)

    assert not result.passed
    assert any("invalid status record" in failure for failure in result.failures)
    assert "coded run complete" not in result.checked


def test_finalize_status_with_explicit_incomplete_state_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"complete": False}))

    result = check_gate(ws)

    assert not result.passed
    assert any("finalize did not complete" in failure for failure in result.failures)


@pytest.mark.parametrize("status", [{}, {"verify_errors": 0}])
def test_finalize_status_requires_an_explicit_completion_field(tmp_path, status):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps(status))

    result = check_gate(ws)

    assert not result.passed
    assert any("complete is required" in failure for failure in result.failures)


def test_reviewed_workspace_without_a_coded_run_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").unlink()

    result = check_gate(ws)

    assert not result.passed
    assert any("_run.json is missing" in failure for failure in result.failures)
    assert "coded run complete" not in result.checked


def test_no_gate_item_is_claimed_checked_while_its_own_check_failed(tmp_path):
    ws = tmp_path / "proj"
    for d in ("inventory", "units", "candidates", "findings", "pocs"):
        (ws / d).mkdir(parents=True)
    (ws / "candidates" / "c.md").write_text("# f\n\nno risk stated\n")
    result = check_gate(ws)
    assert len(result.failures) == 4
    assert result.checked == []


def test_run_completion_is_not_claimed_checked_while_the_run_says_otherwise(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "final", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run complete" not in result.checked


def test_run_completion_is_not_claimed_checked_while_the_run_is_still_running(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "running", "converged": False}))
    result = check_gate(ws)
    assert not result.passed
    assert "coded run complete" not in result.checked


def test_run_completion_is_claimed_checked_once_the_run_completed(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "converged", "complete": True, "converged": True}))
    result = check_gate(ws)
    assert result.passed
    assert "coded run complete" in result.checked


def test_standard_run_can_complete_without_converging_the_union(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"state": "complete", "complete": True, "converged": False}))
    result = check_gate(ws)
    assert result.passed
    assert "coded run complete" in result.checked


def test_a_failed_verification_in_a_standalone_finalize_is_not_a_clean_pass(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 3, "deduped": 2, "verify_errors": 2}))
    result = check_gate(ws)
    assert not result.passed
    assert any("2 failed verifications" in f for f in result.failures)


def test_a_single_failed_verification_uses_singular_text(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "verify_errors": 1}))
    result = check_gate(ws)
    assert any("1 failed verification" in f for f in result.failures)
    assert not any("1 failed verifications" in f for f in result.failures)


def test_findings_kept_without_a_completed_verification_are_named(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps({"parsed": 3, "deduped": 3, "verify_errors": 0, "incomplete": 1, "unlocatable": 2})
    )
    result = check_gate(ws)
    assert not result.passed
    assert any("3 findings kept without a completed verification" in f for f in result.failures)


def test_one_finding_kept_without_verification_uses_singular_text(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(json.dumps({"parsed": 1, "deduped": 1, "incomplete": 1}))
    result = check_gate(ws)
    assert any("1 finding kept without a completed verification" in f for f in result.failures)
    assert not any("1 findings kept without a completed verification" in f for f in result.failures)


def test_a_finalize_that_verified_everything_adds_no_note(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_finalize.json").write_text(
        json.dumps(
            {
                "parsed": 2,
                "deduped": 2,
                "complete": True,
                "verify_errors": 0,
                "confirmed": 2,
                "incomplete": 0,
                "unlocatable": 0,
            }
        )
    )
    result = check_gate(ws)
    assert result.passed
    assert not result.notes


def test_a_file_named_in_a_unit_counts_as_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    snapshot = SourceSnapshot.capture(target, repository_files(target))
    marker = ws / ".cyberjury" / "workspace.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"source_snapshot_id": snapshot.snapshot_id}))
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
    (ws / "units" / "u1.md").write_text(
        "# Unit u1\n- Status: reviewed\n- Notes: this mentions orphan.py in prose only.\n"
    )
    result = check_gate(ws, root=target)
    assert not result.passed
    assert any("orphan.py" in failure for failure in result.failures)


def test_legacy_run_status_without_complete_uses_converged_as_completion(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": false, "errors": 0, "verify_errors": 0}')
    result = check_gate(ws)
    assert not result.passed
    assert any("did not complete" in f for f in result.failures)


def test_run_status_errors_fail_the_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 2, "verify_errors": 1}')
    result = check_gate(ws)
    assert not result.passed
    assert any("3 failed model call" in f for f in result.failures)


def test_single_run_status_error_uses_singular_text(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 1, "verify_errors": 0}')
    result = check_gate(ws)
    assert any("1 failed model call" in f for f in result.failures)
    assert not any("1 failed model calls" in f for f in result.failures)


def test_run_status_facts_limitations_fail_the_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    status = json.loads((ws / "_run.json").read_text())
    status["facts_limitations"] = 2
    (ws / "_run.json").write_text(json.dumps(status))

    result = check_gate(ws)

    assert not result.passed
    assert any("2 source facts limitations" in failure for failure in result.failures)


def test_run_state_running_fails_the_gate_without_double_reporting(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"converged": False, "state": "running"}))
    result = check_gate(ws)
    assert not result.passed
    assert any("state is running" in f for f in result.failures)
    assert not any("did not complete" in f for f in result.failures)
