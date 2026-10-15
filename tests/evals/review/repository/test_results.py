"""Repository scoring resolves one complete product review session."""

import json

import pytest

from cyberjury.review.request import ReviewIntent, TargetInput
from cyberjury.workspace import WorkspaceCorruptionError
from evals.benchmarks.contract import RepositoryCase
from evals.review.repository.results import _workspace_reports


def _case(tmp_path, *, name="paperless-ngx", project_id="", path="."):
    return RepositoryCase(
        id=name,
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"path": path},
        project_id=project_id,
        profile="web",
    )


def _session(workspace, source, *, suffix="a", complete=True):
    session = workspace / "reviews" / f"review-{suffix * 32}"
    project = session / "work" / source.name
    project.mkdir(parents=True)
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(source)), requested_profile="web")
    (session / "review.json").write_text(json.dumps(intent.to_dict()), encoding="utf-8")
    (project / "_run.json").write_text(
        json.dumps(
            {
                "schema": "cyberjury.repository-run/v3",
                "complete": complete,
                "state": "complete" if complete else "incomplete",
                "errors": 0,
                "verify_errors": 0,
            }
        ),
        encoding="utf-8",
    )
    findings = project / "findings.json"
    findings.write_text('{"findings": []}', encoding="utf-8")
    return findings


def test_workspace_reports_resolves_a_completed_session(tmp_path):
    source = tmp_path / "paperless-ngx"
    findings = _session(tmp_path / "workspace", source)

    assert _workspace_reports(tmp_path / "workspace", _case(tmp_path)) == findings


def test_workspace_reports_matches_an_explicit_source_path(tmp_path):
    source = tmp_path / "checkout"
    findings = _session(tmp_path / "workspace", source)

    assert _workspace_reports(tmp_path / "workspace", _case(tmp_path), source_root=str(source)) == findings


def test_workspace_reports_accepts_one_review_directory(tmp_path):
    source = tmp_path / "paperless-ngx"
    findings = _session(tmp_path / "workspace", source)

    assert _workspace_reports(findings.parents[2], _case(tmp_path)) == findings


def test_workspace_reports_matches_the_project_of_a_named_task(tmp_path):
    source = tmp_path / "paperless-ngx"
    findings = _session(tmp_path / "workspace", source)

    case = _case(tmp_path, name="paperless-ngx:repository-6f3451b", project_id="paperless-ngx")
    assert _workspace_reports(tmp_path / "workspace", case) == findings


def test_workspace_reports_matches_a_scoped_review_directory(tmp_path):
    source = tmp_path / "checkout" / "contracts"
    findings = _session(tmp_path / "workspace", source)

    case = _case(tmp_path, name="project", project_id="project", path="contracts")
    assert _workspace_reports(tmp_path / "workspace", case) == findings


def test_workspace_reports_selects_the_case_scope_inside_an_explicit_checkout_root(tmp_path):
    checkout = tmp_path / "checkout"
    source = checkout / "contracts"
    source.mkdir(parents=True)
    findings = _session(tmp_path / "workspace", source)
    _session(tmp_path / "workspace", checkout, suffix="b")
    case = RepositoryCase(
        id="project",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"type": "git", "url": "https://example.com/project.git", "path": "contracts"},
        project_id="project",
        profile="web",
    )

    assert _workspace_reports(tmp_path / "workspace", case, source_root=str(checkout)) == findings


def test_workspace_reports_rejects_an_incomplete_run(tmp_path):
    source = tmp_path / "paperless-ngx"
    _session(tmp_path / "workspace", source, complete=False)

    with pytest.raises(ValueError, match="no complete repository run"):
        _workspace_reports(tmp_path / "workspace", _case(tmp_path))


def test_workspace_reports_rejects_a_contradictory_complete_run(tmp_path):
    source = tmp_path / "paperless-ngx"
    findings = _session(tmp_path / "workspace", source)
    status = json.loads((findings.parent / "_run.json").read_text(encoding="utf-8"))
    status["errors"] = 1
    (findings.parent / "_run.json").write_text(json.dumps(status), encoding="utf-8")

    with pytest.raises(ValueError, match="no complete repository run"):
        _workspace_reports(tmp_path / "workspace", _case(tmp_path))


def test_workspace_reports_requires_a_run_receipt(tmp_path):
    source = tmp_path / "paperless-ngx"
    findings = _session(tmp_path / "workspace", source)
    (findings.parent / "_run.json").unlink()

    with pytest.raises(WorkspaceCorruptionError, match=r"_run\.json"):
        _workspace_reports(tmp_path / "workspace", _case(tmp_path))


def test_workspace_reports_rejects_multiple_matching_sessions(tmp_path):
    source = tmp_path / "paperless-ngx"
    workspace = tmp_path / "workspace"
    _session(workspace, source, suffix="a")
    _session(workspace, source, suffix="b")

    with pytest.raises(ValueError, match="multiple review sessions"):
        _workspace_reports(workspace, _case(tmp_path))


def test_workspace_reports_refuses_unrelated_source(tmp_path):
    source = tmp_path / "other-repository"
    workspace = tmp_path / "workspace"
    _session(workspace, source)

    with pytest.raises(FileNotFoundError, match="no review session"):
        _workspace_reports(workspace, _case(tmp_path))
