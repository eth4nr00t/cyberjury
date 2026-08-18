"""Tests for the versioned benchmark validation contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.validate import validate_benchmark


def _write_benchmark(root: Path, *, safe_task: bool = True) -> None:
    root.mkdir()
    (root / "benchmark.yaml").write_text(
        """schema_version: 1
benchmark_id: example-project
profile: web
source:
  kind: git
  identity:
    url: https://github.com/example/example-project.git
    commit: 0123456789abcdef0123456789abcdef01234567
  path: .
stack:
  languages: [python]
  frameworks: [fastapi]
  protocols: []
knowledge:
  vulnerabilities: [insecure-direct-object-reference]
  guides: [languages/python]
tasks:
  - id: repository-0123456
    kind: repository
    review:
      context: repository
      mode: standard
  - id: diff-a1b2c3d-1
    kind: diff
    revision:
      base_commit: 0123456789abcdef0123456789abcdef01234567
      commit: a1b2c3d456789abcdef0123456789abcdef01234
    expectation: clean
    review:
      context: repository
      mode: standard
""",
        encoding="utf-8",
    )
    expectation = "clean" if safe_task else "findings"
    severity = "" if safe_task else "    severity: HIGH\n"
    (root / "answer-key.yaml").write_text(
        f"""schema_version: 1
benchmark_id: example-project
checks:
  - id: record-owner-check
    applies_to: [diff-a1b2c3d-1]
    expectation: {expectation}
{severity}    locations:
      files: [models/records.py]
    knowledge:
      vulnerabilities: [insecure-direct-object-reference]
      guides: [languages/python]
""",
        encoding="utf-8",
    )


def test_validate_benchmark_accepts_the_versioned_contract(tmp_path):
    """Accept a manifest and answer key that follow version one."""
    root = tmp_path / "example"
    _write_benchmark(root)
    validate_benchmark(root)


def test_validate_benchmark_rejects_a_clean_task_without_clean_coverage(tmp_path):
    """Reject a clean task that has no clean answer check."""
    root = tmp_path / "example"
    _write_benchmark(root, safe_task=False)
    with pytest.raises(ValueError, match=r"clean task .* has no clean"):
        validate_benchmark(root)


def test_validate_benchmark_checks_answer_key_file_locations_when_source_is_given(tmp_path):
    """Reject an answer-key file location absent from the supplied source root."""
    root = tmp_path / "example"
    _write_benchmark(root)
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="location does not exist"):
        validate_benchmark(root, source_root=source)


def test_validate_benchmark_rejects_a_diff_id_that_disagrees_with_revision(tmp_path):
    """Reject a diff id whose commit prefix or sequence is wrong."""
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace("diff-a1b2c3d-1", "diff-bbbbbbb-1")
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="does not agree with revision"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_removed_review_rationale(tmp_path):
    """Reject the removed rationale review field."""
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "    review:\n      context: repository\n      mode: standard\n",
        "    review:\n      rationale: no\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_a_task_path_outside_source(tmp_path):
    """Reject a task path override because tasks use source.path."""
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "  - id: diff-a1b2c3d-1\n", "  - id: diff-a1b2c3d-1\n    path: .\n"
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_check_knowledge_outside_task_scope(tmp_path):
    """Reject answer-key knowledge that the task does not declare."""
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    text = key.read_text(encoding="utf-8").replace("guides: [languages/python]", "guides: [frameworks/python/fastapi]")
    key.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="knowledge outside its task scope"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_overlapping_check_ids(tmp_path):
    """Reject duplicate answer-check ids in overlapping task scopes."""
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    with key.open("a", encoding="utf-8") as stream:
        stream.write(
            """  - id: record-owner-check
    applies_to: [diff-a1b2c3d-1]
    expectation: clean
    locations:
      files: [models/records.py]
    knowledge:
      vulnerabilities: [insecure-direct-object-reference]
      guides: [languages/python]
"""
        )
    with pytest.raises(ValueError, match="overlapping task scope"):
        validate_benchmark(root)
