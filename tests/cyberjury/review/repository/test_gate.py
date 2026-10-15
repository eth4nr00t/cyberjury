"""The gate passes only a complete, hash bound result for the unchanged reviewed source."""

import json

import pytest

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import default_profile
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.paths import repository_files
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.sources.snapshot import SourceSnapshot

_DETECTION = load_detection(default_profile().paths.detection_file)
_REVISION = "a" * 64


def _write_marker(ws, snapshot_id=_REVISION):
    marker = ws / ".cyberjury" / "workspace.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"source_snapshot_id": snapshot_id}))


def _write_result(ws, *, source_revision=_REVISION, outcome=None, target="repository"):
    findings = FindingsArtifact.create(())
    result = OutcomeArtifact.create(
        target=target,
        source_revision=source_revision,
        findings=findings,
        outcome=outcome or ReviewOutcome(findings=()),
    )
    (ws / "findings.json").write_text(json.dumps(findings.to_dict()))
    (ws / "outcome.json").write_text(json.dumps(result.to_dict()))


def _complete_ws(root):
    ws = root / "proj"
    ws.mkdir(parents=True)
    _write_marker(ws)
    _write_result(ws)
    return ws


def _target_tree(root, files):
    target = root / "target"
    target.mkdir()
    for name in files:
        (target / name).write_text("value = 1\n")
    return target


def test_complete_workspace_passes(tmp_path):
    result = check_gate(_complete_ws(tmp_path))
    assert result.passed
    assert result.failures == []
    assert result.checked == ["final result complete and hash bound"]
    assert result.to_dict()["schema"] == "cyberjury.repository-gate/v2"


def test_missing_workspace_fails(tmp_path):
    result = check_gate(tmp_path / "never-scaffolded")
    assert not result.passed
    assert any("does not exist" in f for f in result.failures)


def test_missing_source_binding_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / ".cyberjury" / "workspace.json").unlink()

    result = check_gate(ws)

    assert not result.passed
    assert result.checked == []
    assert any("source snapshot binding" in failure for failure in result.failures)


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
    _write_result(ws, outcome=ReviewOutcome(findings=(), errors=1))

    result = check_gate(ws)

    assert not result.passed
    assert result.checked == []
    assert any("incomplete review" in failure for failure in result.failures)


def test_diff_outcome_cannot_pass_the_repository_gate(tmp_path):
    ws = _complete_ws(tmp_path)
    _write_result(ws, target="diff")

    result = check_gate(ws)

    assert not result.passed
    assert any("repository review" in failure for failure in result.failures)


def test_outcome_revision_must_match_the_repository_workspace(tmp_path):
    ws = _complete_ws(tmp_path)
    _write_marker(ws, "b" * 64)

    result = check_gate(ws)

    assert not result.passed
    assert any("workspace source snapshot" in failure for failure in result.failures)


def test_run_status_is_not_a_second_completion_authority(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "_run.json").write_text(json.dumps({"complete": True}))
    _write_result(ws, outcome=ReviewOutcome(findings=(), incomplete=(object(),)))

    assert not check_gate(ws).passed


def test_unchanged_source_passes(tmp_path):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    snapshot = SourceSnapshot.capture(target, repository_files(target, _DETECTION))
    _write_marker(ws, snapshot.snapshot_id)
    _write_result(ws, source_revision=snapshot.snapshot_id)

    result = check_gate(ws, root=target)

    assert result.passed
    assert "source snapshot unchanged" in result.checked


@pytest.mark.parametrize("change", ["modify", "delete", "add"])
def test_gate_rejects_source_revision_drift(tmp_path, change):
    ws = _complete_ws(tmp_path)
    target = _target_tree(tmp_path, ["handler.py"])
    snapshot = SourceSnapshot.capture(target, repository_files(target, _DETECTION))
    _write_marker(ws, snapshot.snapshot_id)
    _write_result(ws, source_revision=snapshot.snapshot_id)
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
