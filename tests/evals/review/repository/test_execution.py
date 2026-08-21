"""Repository benchmark execution stays on the coded product boundary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cyberjury.review.repository.engine import RepositoryRunOptions
from evals.benchmarks.contract import RepositoryCase
from evals.review.repository import execution
from evals.score.result import Result


def _case(tmp_path: Path) -> RepositoryCase:
    key = tmp_path / "answer-key.yaml"
    key.write_text(
        "schema_version: 1\n"
        "benchmark_id: demo\n"
        "checks:\n"
        "  - id: issue\n"
        "    applies_to: [repository-aaaaaaa]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n"
        "      files: [app.py]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n"
        "      guides: [languages/python]\n",
        encoding="utf-8",
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('review')\n", encoding="utf-8")
    return RepositoryCase(
        id="demo",
        kind="repository",
        answer_key=key,
        provenance="public",
        target={"type": "git", "root": str(source), "path": "."},
        task_id="repository-aaaaaaa",
        profile="web",
    )


def test_run_uses_product_engine_and_scores_its_workspace(tmp_path, monkeypatch):
    case = _case(tmp_path)
    seen = {}

    def fake_review(target, workspace, *, options):
        seen.update(target=target, workspace=workspace, options=options)
        leaf = Path(workspace) / "source"
        leaf.mkdir(parents=True)
        (leaf / "findings.json").write_text('{"findings": []}', encoding="utf-8")
        return SimpleNamespace(
            outcome=SimpleNamespace(degraded=False),
            scaffold=SimpleNamespace(workspace=leaf),
        )

    def fake_score(scored_case, findings_json, *, source_root):
        seen.update(scored_case=scored_case, findings_json=findings_json, source_root=source_root)
        return Result(target="demo", found=["issue"], n_findings=1, n_reports=1)

    monkeypatch.setattr(execution, "run_repository_review", fake_review)
    monkeypatch.setattr(execution, "score_findings", fake_score)

    result = execution.run(case, workspace=tmp_path / "workspace", options=RepositoryRunOptions())

    assert result.found == ["issue"]
    assert seen["target"] == tmp_path / "source"
    assert seen["source_root"] == tmp_path / "source"
    assert seen["options"].output.profile.name == "web"


def test_run_preserves_recall_denominator_when_product_run_degrades(tmp_path, monkeypatch):
    case = _case(tmp_path)

    def fake_review(target, workspace, *, options):
        return SimpleNamespace(
            outcome=SimpleNamespace(
                degraded=True,
                failures=[SimpleNamespace(reason="provider timed out")],
                failure_reason="",
                errors=1,
                incomplete=[],
                pending=[],
                requires_convergence=False,
                converged=False,
            )
        )

    monkeypatch.setattr(execution, "run_repository_review", fake_review)

    result = execution.run(case, workspace=tmp_path / "workspace", options=RepositoryRunOptions())

    assert result.errors == 1
    assert result.missed == ["issue"]
    assert result.n_findings == 1
    assert "provider timed out" in result.error_details[0]
