"""Benchmark discovery rejects ambiguous, unknown, or malformed projects."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.benchmarks import registry
from evals.benchmarks.cases import find_repository_case, repository_cases


def test_public_real_benchmarks_use_root_taxonomy_layout(tmp_path, monkeypatch, public_only):
    public_only(tmp_path, monkeypatch)
    public_root = Path(registry.__file__).resolve().parent
    manifests = sorted(public_root.rglob("benchmark.yaml"))

    assert manifests
    assert not (public_root / "projects").exists()
    assert not (public_root / "repository").exists()
    assert not list((public_root / "diff").rglob("benchmark.yaml"))
    assert not list((public_root / "diff").rglob("cases.yaml"))
    assert all("schema_version: 1" in path.read_text(encoding="utf-8") for path in manifests)


def test_registry_rejects_project_manifest_without_schema_version(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "missing-version"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "id: missing-version\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/demo.git\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: missing-version\n"
        "planted:\n"
        "  - id: repo-command\n"
        "    category: command-injection\n"
        "    files: [run.ts]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    with pytest.raises(ValueError, match="schema_version"):
        repository_cases()


def test_registry_rejects_the_pre_version_manifest(tmp_path):
    """The registry accepts only the versioned manifest contract."""
    manifest = tmp_path / "benchmark.yaml"
    manifest.write_text("schema_version: 1\nid: old\nkind: project\ntarget: {}\n", encoding="utf-8")
    (tmp_path / "answer-key.yaml").write_text("schema_version: 1\nplanted: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        registry.load_project_manifest(manifest)


def test_registry_accepts_explicit_diff_review_requirements(tmp_path, write_contract_project):
    """Every task declares its review requirements in the versioned contract."""
    loaded = registry.load_project_manifest(write_contract_project(tmp_path))
    assert loaded["tasks"][1]["review"] == {"mode": "standard"}


def test_registry_rejects_removed_diff_review_context(tmp_path, write_contract_project):
    manifest = write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n    review:\n      mode: standard\n",
        "    expectation: findings\n    review:\n      context: diff\n      mode: standard\n",
    )
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        registry.load_project_manifest(manifest)


@pytest.mark.parametrize("review", ["[]", "standard", "null"])
def test_registry_rejects_non_mapping_diff_review_requirements(tmp_path, review, write_contract_project):
    """An explicit review field must be a mapping."""
    manifest = write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n    review:\n      mode: standard\n",
        f"    expectation: findings\n    review: {review}\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        registry.load_project_manifest(manifest)


def test_registry_rejects_unknown_diff_review_mode(tmp_path, write_contract_project):
    """A diff task cannot name unsupported review values."""
    manifest = write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n    review:\n      mode: standard\n",
        "    expectation: findings\n    review:\n      mode: consensus\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        registry.load_project_manifest(manifest)


def test_registry_rejects_unknown_manifest_fields(tmp_path, write_contract_project):
    """Closed versioned objects reject old target and diff scope fields."""
    manifest = write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n", "    expectation: findings\n    diff_path: src/app.py\n"
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        registry.load_project_manifest(manifest)


def test_registry_unknown_benchmark_fails_loud(tmp_path, monkeypatch, public_only):
    public_only(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="no repository benchmark 'nope'"):
        find_repository_case("nope")


def test_registry_duplicate_name_across_roots_fails_loud(tmp_path, monkeypatch, write_contract_project):
    src = tmp_path / "private"
    project = src / "frameworks" / "fastapi" / "open-webui-shadow"
    write_contract_project(project)
    for path in (project / "benchmark.yaml", project / "answer-key.yaml"):
        path.write_text(path.read_text(encoding="utf-8").replace("contract-project", "open-webui"), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    with pytest.raises(ValueError, match="defined in two roots"):
        find_repository_case("open-webui")


def test_registry_duplicate_project_task_name_fails_loud(tmp_path, monkeypatch, write_contract_project):
    src = tmp_path / "private"
    for name in ("one", "two"):
        project = src / "protocols" / "mcp" / name
        write_contract_project(project)
        for path in (project / "benchmark.yaml", project / "answer-key.yaml"):
            path.write_text(
                path.read_text(encoding="utf-8").replace("contract-project", "duplicate-project"),
                encoding="utf-8",
            )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    with pytest.raises(ValueError, match="share the benchmark name 'duplicate-project'"):
        repository_cases()
