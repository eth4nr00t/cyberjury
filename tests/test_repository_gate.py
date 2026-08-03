"""The Completeness Gate check over a fan-out workspace: a structural floor that
refuses to call a review complete while the surface is not enumerated, a unit is
left open, or a candidate is left ungraded by the rubric. It reads structured cells, a
table row, a Status line, a Risk line, not free prose."""

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
    assert result.passed
    assert any("orphan.py" in n for n in result.notes)
    assert not any("owned.py" in n for n in result.notes)


def test_strict_coverage_fails_on_an_unowned_source_file(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["orphan.py"])
    result = check_gate(ws, root=target, strict_coverage=True)
    assert not result.passed
    assert any("orphan.py" in f for f in result.failures)


def test_a_file_named_in_a_unit_counts_as_owned(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    (ws / "units" / "u1.md").write_text("# Unit u1\n- Status: reviewed\n- Target: handler.py\n")
    result = check_gate(ws, root=target)
    assert result.passed
    assert not any("handler.py" in n for n in result.notes)


def test_run_status_not_converged_fails_the_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": false, "errors": 0, "verify_errors": 0}')
    result = check_gate(ws)
    assert not result.passed
    assert any("did not converge" in f for f in result.failures)


def test_run_status_errors_surface_as_a_note_not_a_failure(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text('{"converged": true, "errors": 2, "verify_errors": 1}')
    result = check_gate(ws)
    assert result.passed
    assert any("3 failed model call" in n for n in result.notes)


def test_run_state_running_fails_the_gate_without_double_reporting(tmp_path):
    # a killed run leaves _run.json state=running, which the gate must treat as unfinished, and it
    # reports that one clear reason rather than also complaining the run did not converge
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"converged": False, "state": "running"}))
    result = check_gate(ws)
    assert not result.passed
    assert any("state is running" in f for f in result.failures)
    assert not any("did not converge" in f for f in result.failures)
