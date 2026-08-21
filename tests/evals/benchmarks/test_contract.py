"""Answer key loading enforces the version 1 document shape."""

from pathlib import Path

import pytest

from evals.benchmarks.contract import load_answer_key


def _write(tmp_path: Path, document: str) -> Path:
    path = tmp_path / "answer-key.yaml"
    path.write_text(document, encoding="utf-8")
    return path


def _finding(check_id: str, tasks: str, file: str, *, vulnerability: str = "idor") -> str:
    return (
        f"  - id: {check_id}\n"
        f"    applies_to: [{tasks}]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        f"    locations: {{files: [{file}]}}\n"
        f"    knowledge: {{vulnerabilities: [{vulnerability}], guides: []}}\n"
    )


def _clean(check_id: str, tasks: str, file: str) -> str:
    return (
        f"  - id: {check_id}\n"
        f"    applies_to: [{tasks}]\n"
        "    expectation: clean\n"
        f"    locations: {{files: [{file}]}}\n"
        "    knowledge: {vulnerabilities: [idor], guides: []}\n"
    )


def test_load_answer_key_fails_loud_without_schema_version(tmp_path):
    path = _write(tmp_path, "benchmark_id: demo\nchecks:\n" + _finding("finding", "repository-vulnerable", "x.py"))

    with pytest.raises(ValueError, match="schema_version"):
        load_answer_key(path)


@pytest.mark.parametrize("removed", ["target: demo", "planted: []", "safe: []"])
def test_load_answer_key_rejects_removed_fields(tmp_path, removed):
    document = (
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        + _finding("finding", "repository-vulnerable", "x.py")
        + removed
        + "\n"
    )

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_rejects_scalar_location_files(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        "  - id: finding\n"
        "    applies_to: [repository-vulnerable]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations: {files: x.py}\n"
        "    knowledge: {vulnerabilities: [idor], guides: []}\n"
    )

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_fails_loud_without_checks(tmp_path):
    document = "schema_version: 1\nbenchmark_id: demo\nchecks: []\n"

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_rejects_invalid_expectation(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        "  - id: finding\n"
        "    applies_to: [repository-vulnerable]\n"
        "    expectation: unknown\n"
        "    locations: {files: [x.py]}\n"
        "    knowledge: {vulnerabilities: [idor], guides: []}\n"
    )

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_requires_finding_severity(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        "  - id: finding\n"
        "    applies_to: [repository-vulnerable]\n"
        "    expectation: findings\n"
        "    locations: {files: [x.py]}\n"
        "    knowledge: {vulnerabilities: [idor], guides: []}\n"
    )

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_requires_location_files(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: demo\nchecks:\n"
        "  - id: finding\n"
        "    applies_to: [repository-vulnerable]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations: {}\n"
        "    knowledge: {vulnerabilities: [idor], guides: []}\n"
    )

    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_filters_checks_by_task(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: project\nchecks:\n"
        + _finding("global", "repository-vulnerable-v1, diff-introduce-command", "shared.py")
        + _finding("repo-only", "repository-vulnerable-v1", "repo.py")
        + _finding("diff-only", "diff-introduce-command", "diff.py", vulnerability="command-injection")
        + _clean("safe-repo", "repository-vulnerable-v1", "repo-safe.py")
    )

    key = load_answer_key(_write(tmp_path, document), task_id="repository-vulnerable-v1")

    assert [entry.id for entry in key.findings] == ["global", "repo-only"]
    assert [entry.id for entry in key.clean] == ["safe-repo"]


def test_load_answer_key_allows_one_finding_to_move_between_disjoint_tasks(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: project\nchecks:\n"
        + _finding("moved-finding", "diff-introduce-finding", "old.py")
        + _finding("moved-finding", "repository-vulnerable", "new.py")
    )
    path = _write(tmp_path, document)

    diff_key = load_answer_key(path, task_id="diff-introduce-finding")
    repository_key = load_answer_key(path, task_id="repository-vulnerable")

    assert [entry.files for entry in diff_key.findings] == [("old.py",)]
    assert [entry.files for entry in repository_key.findings] == [("new.py",)]


def test_load_answer_key_rejects_duplicate_ids_with_overlapping_task_scopes(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: project\nchecks:\n"
        + _finding("duplicate", "repository-vulnerable", "one.py")
        + _finding("duplicate", "repository-vulnerable, diff-introduce-finding", "two.py")
    )

    with pytest.raises(ValueError, match="overlapping task scopes"):
        load_answer_key(_write(tmp_path, document))


def test_load_answer_key_rejects_conflicting_expectations_for_one_task(tmp_path):
    document = (
        "schema_version: 1\nbenchmark_id: project\nchecks:\n"
        + _finding("conflicting", "repository-vulnerable", "one.py")
        + _clean("conflicting", "repository-vulnerable", "one.py")
    )

    with pytest.raises(ValueError, match="overlapping task scopes"):
        load_answer_key(_write(tmp_path, document))
