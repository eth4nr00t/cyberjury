"""Tests for the versioned benchmark validation contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.benchmarks.validate import validate_benchmark


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
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="location does not exist"):
        validate_benchmark(root, source_root=source)


def test_validate_benchmark_rejects_a_diff_id_that_disagrees_with_revision(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace("diff-a1b2c3d-1", "diff-bbbbbbb-1")
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="does not agree with revision"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_removed_review_rationale(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "    review:\n      context: repository\n      mode: standard\n",
        "    review:\n      rationale: no\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_a_task_path_outside_source(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "  - id: diff-a1b2c3d-1\n", "  - id: diff-a1b2c3d-1\n    path: .\n"
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
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


def test_validate_benchmark_rejects_check_knowledge_outside_task_scope(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    text = key.read_text(encoding="utf-8").replace("guides: [languages/python]", "guides: [frameworks/python/fastapi]")
    key.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="knowledge outside its task scope"):
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
    locations:
      files: [models/records.py]
    knowledge:
      vulnerabilities: [insecure-direct-object-reference]
      guides: [languages/python]
"""
        )
    with pytest.raises(ValueError, match="overlapping task scope"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_unknown_preparation_fields(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "  path: .\n",
        "  path: .\n  prepare:\n    shell: make setup\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
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


def test_validate_benchmark_rejects_duplicate_locations(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    text = key.read_text(encoding="utf-8").replace(
        "files: [models/records.py]",
        "files: [models/records.py, models/records.py]",
    )
    key.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_a_guide_absent_from_the_stack(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace(
        "guides: [languages/python]",
        "guides: [languages/python, protocols/graphql]",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"absent from stack\.protocols"):
        validate_benchmark(root)


def test_validate_benchmark_rejects_an_unknown_profile(tmp_path):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    text = manifest.read_text(encoding="utf-8").replace("profile: web", "profile: unknown")
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="unknown or unavailable review profile"):
        validate_benchmark(root)


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        (
            "vulnerabilities: [insecure-direct-object-reference]",
            "vulnerabilities: [unknown-vulnerability]",
            r"knowledge\.vulnerabilities has unknown id",
        ),
        (
            "guides: [languages/python]",
            "guides: [languages/unknown]",
            r"knowledge\.guides has unknown id",
        ),
    ],
)
def test_validate_benchmark_rejects_unknown_profile_knowledge(tmp_path, old, new, match):
    root = tmp_path / "example"
    _write_benchmark(root)
    manifest = root / "benchmark.yaml"
    manifest.write_text(manifest.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    key = root / "answer-key.yaml"
    key.write_text(key.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        validate_benchmark(root)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("    applies_to: [diff-a1b2c3d-1]\n", "    applies_to: []\n"),
        (
            "    knowledge:\n"
            "      vulnerabilities: [insecure-direct-object-reference]\n"
            "      guides: [languages/python]\n",
            "",
        ),
        (
            "      vulnerabilities: [insecure-direct-object-reference]\n",
            "      vulnerabilities: [insecure-direct-object-reference, missing-authorization]\n",
        ),
    ],
)
def test_load_answer_key_enforces_the_versioned_schema(tmp_path, old, new):
    root = tmp_path / "example"
    _write_benchmark(root)
    key = root / "answer-key.yaml"
    key.write_text(key.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(key)
