"""Knowledge and benchmark coverage tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from .support import (
    _public_only,
    _write_contract_project,
)


def test_coverage_matrix_attributes_repository_checks_to_knowledge(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.coverage import coverage_matrix

    cov = coverage_matrix()
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repository_findings >= 3
    assert idor.repository_clean >= 2
    py = cov["guide:languages/python"]
    assert py.repository_findings >= 3
    assert py.public >= 1


def test_coverage_problems_flag_a_vulnerability_missing_repository_target(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.coverage import Coverage, KnowledgeItem, coverage_problems

    item = KnowledgeItem(ref="vuln:demo", kind="vulnerability", path=Path("demo.md"))
    cov = {"vuln:demo": Coverage(item=item, diff_positive=1)}
    kinds = {(p.kind, p.ref) for p in coverage_problems(cov)}
    assert ("missing-repository-target", "vuln:demo") in kinds


def test_coverage_rejects_unresolved_repository_reference(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "ghost"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "ghost"
    data["knowledge"]["vulnerabilities"] = ["no-such-class"]
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "ghost"
    for entry in answer["checks"]:
        entry["knowledge"]["vulnerabilities"] = ["no-such-class"]
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"knowledge\.vulnerabilities has unknown id"):
        coverage_problems()


def test_coverage_rejects_unresolved_diff_reference(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "ghost-diff"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "ghost-diff"
    data["knowledge"]["vulnerabilities"] = ["no-such-class"]
    data["tasks"] = [task for task in data["tasks"] if task["kind"] == "diff"]
    data["tasks"][0]["expectation"] = "findings"
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "ghost-diff"
    answer["checks"] = [entry for entry in answer["checks"] if entry["applies_to"] == [data["tasks"][0]["id"]]]
    for entry in answer["checks"]:
        entry["knowledge"]["vulnerabilities"] = ["no-such-class"]
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"knowledge\.vulnerabilities has unknown id"):
        coverage_problems()


def test_scan_knowledge_spans_profiles(tmp_path, monkeypatch):
    """Coverage must include content from every registered profile root."""
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.coverage import scan_knowledge

    items = scan_knowledge()
    assert items["vuln:sql-injection"].kind == "vulnerability"
    assert items["vuln:reentrancy"].kind == "vulnerability"
    assert "guide:languages/solidity" in items


def test_coverage_problems_flag_check_without_knowledge(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "bare"
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "bare"
    for entry in answer["checks"]:
        entry["knowledge"] = {"vulnerabilities": [], "guides": []}
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        coverage_problems()


def test_coverage_problems_flag_diff_only_check_without_knowledge(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare-diff"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "bare-diff"
    data["tasks"] = [task for task in data["tasks"] if task["kind"] == "diff"]
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "bare-diff"
    answer["checks"] = [answer["checks"][0]]
    answer["checks"][0]["applies_to"] = [data["tasks"][0]["id"]]
    answer["checks"][0]["knowledge"] = {"vulnerabilities": [], "guides": []}
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        coverage_problems()


def test_coverage_splits_diff_and_repository_dimensions():
    from evals.benchmarks.coverage import Coverage, KnowledgeItem

    it = KnowledgeItem(ref="vuln:x", kind="vulnerability", path=Path("x.md"))
    diff_only = Coverage(item=it, diff_positive=1, diff_clean=1)
    assert diff_only.diff_covered
    assert not diff_only.repository_covered
    assert diff_only.covered
    repository_only = Coverage(item=it, repository_findings=1)
    assert repository_only.repository_covered
    assert not repository_only.diff_covered
    assert repository_only.covered
    assert not Coverage(item=it).covered


def test_coverage_problems_flags_a_class_with_no_repository_target(tmp_path, monkeypatch):
    from evals.benchmarks import coverage
    from evals.benchmarks.coverage import Coverage, KnowledgeItem

    def item(ref):
        return KnowledgeItem(ref=ref, kind="vulnerability", path=Path(f"{ref}.md"))

    cov = {
        "vuln:diffonly": Coverage(item=item("vuln:diffonly"), diff_positive=1, diff_clean=1),
        "vuln:hasrepository": Coverage(
            item=item("vuln:hasrepository"), diff_positive=1, diff_clean=1, repository_findings=1
        ),
    }
    _public_only(tmp_path, monkeypatch)
    monkeypatch.setattr(coverage, "_coverage_cases", lambda: [])
    kinds = {(p.ref, p.kind) for p in coverage.coverage_problems(cov)}
    assert ("vuln:diffonly", "missing-repository-target") in kinds
    assert ("vuln:hasrepository", "missing-repository-target") not in kinds
