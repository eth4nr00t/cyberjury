"""Tests for the versioned benchmark validation contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.benchmarks.validate import validate_benchmark


def _write_benchmark(root: Path, *, safe_task: bool = True) -> None:
    root.mkdir()
    (root / "benchmark.yaml").write_text(
        """schema_version: 2
benchmark_id: example-project
source:
  kind: git
  identity:
    url: https://github.com/example/example-project.git
    commit: 0123456789abcdef0123456789abcdef01234567
  path: .
tasks:
  - id: repository-0123456
    kind: repository
  - id: diff-a1b2c3d-1
    kind: diff
    revision:
      base_commit: 0123456789abcdef0123456789abcdef01234567
      commit: a1b2c3d456789abcdef0123456789abcdef01234
    expectation: clean
""",
        encoding="utf-8",
    )
    expectation = "clean" if safe_task else "findings"
    (root / "answer-key.yaml").write_text(
        f"""schema_version: 1
benchmark_id: example-project
checks:
  - id: record-owner-check
    applies_to: [diff-a1b2c3d-1]
    expectation: {expectation}
    locations:
      - {{file: models/records.py, symbol: Record.owner}}
    changes:
      - {{file: producers/input.py, line: 12, side: new}}
""",
        encoding="utf-8",
    )


def test_validate_benchmark_accepts_the_versioned_contract(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    validate_benchmark(root)


def test_validate_benchmark_rejects_a_clean_task_without_clean_coverage(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root, safe_task=False)
    with pytest.raises(ValueError, match=r"clean task .* has no clean"):
        validate_benchmark(root)


def test_validate_benchmark_checks_answer_key_file_locations_when_source_is_given(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    key.write_text(
        key.read_text(encoding="utf-8")
        + """  - id: repository-location
    applies_to: [repository-0123456]
    expectation: clean
    locations: [{file: models/records.py, line: 1}]
""",
        encoding="utf-8",
    )
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="location does not exist"):
        validate_benchmark(root, source_root=source)


def test_validate_benchmark_does_not_apply_manifest_source_to_historical_diff_locations(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    source = tmp_path / "source"
    source.mkdir()

    validate_benchmark(root, source_root=source)


def test_validate_benchmark_rejects_a_diff_id_that_disagrees_with_revision(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace("diff-a1b2c3d-1", "diff-bbbbbbb-1")
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="does not agree with revision"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_two_diff_tasks_with_the_same_revision(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    with manifest.open("a", encoding="utf-8") as stream:
        stream.write(
            """  - id: diff-a1b2c3d-2
    kind: diff
    revision:
      base_commit: 0123456789ABCDEF0123456789ABCDEF01234567
      commit: A1B2C3D456789ABCDEF0123456789ABCDEF01234
    expectation: clean
"""
        )
    key = root / "answer-key.yaml"
    key.write_text(
        key.read_text(encoding="utf-8").replace(
            "applies_to: [diff-a1b2c3d-1]", "applies_to: [diff-a1b2c3d-1, diff-a1b2c3d-2]"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="repeats the revision of diff task diff-a1b2c3d-1"):
        validate_benchmark(root)


@pytest.mark.parametrize("source_path", ["foo//bar", "foo/./bar", "foo/", "./foo"])
def test_validate_benchmark_rejects_a_noncanonical_source_path(tmp_path, source_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace("  path: .\n", f"  path: {source_path}\n")
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="normalized repository-relative scope"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_unknown_manifest_fields(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("tasks:\n", "unknown: value\ntasks:\n"), encoding="utf-8"
    )
    with pytest.raises(ValueError, match=r"benchmark-v2\.schema"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_overlapping_check_ids(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    with key.open("a", encoding="utf-8") as stream:
        stream.write(
            """  - id: record-owner-check
    applies_to: [diff-a1b2c3d-1]
    expectation: clean
    locations: [{file: models/records.py, line: 1}]
    changes: [{file: models/records.py, line: 1, side: new}]
"""
        )
    with pytest.raises(ValueError, match="overlapping task scope"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_duplicate_check_scopes(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    text = key.read_text(encoding="utf-8").replace(
        "applies_to: [diff-a1b2c3d-1]",
        "applies_to: [diff-a1b2c3d-1, diff-a1b2c3d-1]",
    )
    key.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_diff_changes_on_repository_tasks(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    with key.open("a", encoding="utf-8") as stream:
        stream.write(
            "  - id: repository-only\n"
            "    applies_to: [repository-0123456]\n"
            "    expectation: findings\n"
            "    changes: [{file: models/records.py, line: 12, side: new}]\n"
            "    locations: [{file: models/records.py, line: 12}]\n"
        )

    with pytest.raises(ValueError, match="changes require exactly one diff task"):
        validate_benchmark(root)
