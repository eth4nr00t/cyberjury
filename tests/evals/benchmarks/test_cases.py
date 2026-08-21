"""Benchmark cases materialize repository and diff tasks from one project contract."""

from __future__ import annotations

import pytest

from evals.benchmarks.cases import find_repository_case
from evals.benchmarks.contract import load_answer_key
from tests.evals.benchmarks.factories import public_only as _public_only


def test_registry_finds_public_openwebui_benchmark(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    bench = find_repository_case("open-webui")
    assert bench.provenance == "public"
    assert bench.stack["frameworks"] == ["fastapi"]
    assert "insecure-direct-object-reference" in bench.knowledge["vulnerabilities"]
    key = load_answer_key(bench.answer_key)
    assert key.benchmark_id == "open-webui"
    assert any(p.category == "insecure-direct-object-reference" for p in key.findings)


def test_registry_exposes_repository_task_from_project_source(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        "    url: https://example.com/demo.git\n"
        "    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "  path: src/tools\n"
        "stack:\n"
        "  languages: [typescript]\n"
        "  frameworks: []\n"
        "  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        "  - id: repository-aaaaaaa\n"
        "    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        "  - id: diff-bbbbbbb-1\n"
        "    kind: diff\n"
        "    revision:\n"
        "      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        "    applies_to: [repository-aaaaaaa]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n"
        "      files: [src/tools/run.ts]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n"
        "  - id: diff-command\n"
        "    applies_to: [diff-bbbbbbb-1]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n"
        "      files: [src/tools/run.ts]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    bench = find_repository_case("demo-project")
    key = load_answer_key(bench.answer_key, task_id=bench.task_id)

    assert bench.project_id == "demo-project"
    assert bench.task_id == "repository-aaaaaaa"
    assert bench.target == {
        "type": "git",
        "url": "https://example.com/demo.git",
        "ref": "a" * 40,
        "path": "src/tools",
    }
    assert bench.stack["languages"] == ["typescript"]
    assert bench.knowledge == {
        "guides": ["languages/typescript", "protocols/mcp"],
        "vulnerabilities": ["command-injection"],
    }
    assert [entry.id for entry in key.findings] == ["repo-command"]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"review_context": "snapshot"}, "invalid diff review context"),
        ({"review_mode": "consensus"}, "invalid diff review mode"),
    ],
)
def test_diff_case_rejects_unknown_review_requirements(kwargs, message):
    """Direct diff cases enforce the same review vocabulary as manifests."""
    from evals.benchmarks.cases import DiffCase

    with pytest.raises(ValueError, match=message):
        DiffCase(name="invalid", diff="", **kwargs)
