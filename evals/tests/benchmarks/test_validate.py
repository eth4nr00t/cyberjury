"""Benchmark validation enforces the versioned contract and its semantic checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.benchmarks.validate import validate_benchmark

_DIFF_CASE = """  - id: diff-a1b2c3d
    kind: diff
    base: 0123456789abcdef0123456789abcdef01234567
    commit: a1b2c3d456789abcdef0123456789abcdef01234
    checks:
      - id: record-owner-missing-permission
        root_cause: Record.save does not check the record owner
        locations:
          - {file: models/records.py, symbol: Record.owner}
        change_anchors:
          - {file: producers/input.py, line: 12, side: new}
"""


def _write_benchmark(root: Path) -> Path:
    root.mkdir()
    path = root / "benchmark.yaml"
    path.write_text(
        """id: example-project
repository:
  url: https://github.com/example/example-project.git
  commit: 0123456789abcdef0123456789abcdef01234567
cases:
  - id: repository-0123456
    kind: repository
    checks:
      - id: record-owner-missing-permission
        root_cause: Record.save does not check the record owner
        locations:
          - {file: models/records.py, line: 1}
"""
        + _DIFF_CASE,
        encoding="utf-8",
    )
    return path


def _replace(path: Path, old: str, new: str, count: int = -1) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, count), encoding="utf-8")


def test_validate_benchmark_accepts_the_versioned_contract(tmp_path):
    """A file with one repository case and one diff case validates and keeps both case ids in order."""
    root = tmp_path / "example-project"
    _write_benchmark(root)
    benchmark = validate_benchmark(root)

    assert [case["id"] for case in benchmark["cases"]] == ["repository-0123456", "diff-a1b2c3d"]


def test_validate_benchmark_accepts_a_local_repository(tmp_path):
    """Replacing the repository url with a local_path still passes validation."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "url: https://github.com/example/example-project.git", f"local_path: {tmp_path / 'repo'}")

    validate_benchmark(path)


def test_validate_benchmark_rejects_a_repository_with_url_and_local_path(tmp_path):
    """A repository block carrying both url and local_path fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "  commit: 0123", "  local_path: /srv/repo\n  commit: 0123", 1)

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_a_case_without_checks(tmp_path):
    """A diff case whose checks list is empty fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    text = path.read_text(encoding="utf-8")
    path.write_text(text[: text.index("    checks:\n", text.index("diff-a1b2c3d"))] + "    checks: []\n")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_checks_repository_case_locations_when_source_is_given(tmp_path):
    """With an empty source root, the repository case location models/records.py is reported missing."""
    path = _write_benchmark(tmp_path / "example-project")
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(ValueError, match=r"location does not exist: models/records\.py"):
        validate_benchmark(path, source_root=source)


def test_validate_benchmark_does_not_apply_repository_source_to_diff_case_locations(tmp_path):
    """A diff case naming models/absent.py passes even though the source root lacks that file."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "{file: models/records.py, symbol: Record.owner}", "{file: models/absent.py, symbol: Record}")
    source = tmp_path / "source"
    (source / "models").mkdir(parents=True)
    (source / "models" / "records.py").write_text("owner = None\n", encoding="utf-8")

    validate_benchmark(path, source_root=source)


@pytest.mark.parametrize(
    ("old", "new"),
    [("id: diff-a1b2c3d", "id: diff-bbbbbbb"), ("id: repository-0123456", "id: repository-aaaaaaa")],
)
def test_validate_benchmark_rejects_a_case_id_that_disagrees_with_its_commit(tmp_path, old, new):
    """Diff and repository case ids whose hash suffix differs from the commit are rejected."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, old, new)

    with pytest.raises(ValueError, match="id does not agree with its commit"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_a_diff_id_with_an_ordinal(tmp_path):
    """A diff case id with a trailing ordinal, diff-a1b2c3d-1, fails the schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "id: diff-a1b2c3d", "id: diff-a1b2c3d-1")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_duplicate_case_ids(tmp_path):
    """Appending a second diff-a1b2c3d case with a different base raises a duplicate case ids error."""
    path = _write_benchmark(tmp_path / "example-project")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(_DIFF_CASE.replace("base: 0123456789abcdef", "base: 1123456789abcdef"))

    with pytest.raises(ValueError, match="duplicate case ids"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_duplicate_check_ids_in_one_case(tmp_path):
    """A second record-owner-missing-permission check in diff-a1b2c3d raises a duplicate check ids error."""
    path = _write_benchmark(tmp_path / "example-project")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            """      - id: record-owner-missing-permission
        root_cause: Record.save does not check the record owner
        locations: [{file: models/records.py, line: 1}]
        change_anchors: [{file: models/records.py, line: 1, side: new}]
"""
        )

    with pytest.raises(ValueError, match="case diff-a1b2c3d has duplicate check ids"):
        validate_benchmark(path)


@pytest.mark.parametrize(
    "root_cause",
    ['""', "Record.save does not check the record owner.", '"Record.save does not check the record owner\\n"'],
)
def test_validate_benchmark_requires_a_root_cause_sentence_without_a_trailing_period(tmp_path, root_cause):
    """Empty, period-terminated, and newline-terminated root causes all fail the schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "root_cause: Record.save does not check the record owner\n", f"root_cause: {root_cause}\n", 1)

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_requires_a_root_cause_for_every_check(tmp_path):
    """Removing root_cause from the first check fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "        root_cause: Record.save does not check the record owner\n", "", 1)

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


@pytest.mark.parametrize("check_id", ["record-owner", "record-owner-unknown-weakness", "Record-owner-idor"])
def test_validate_benchmark_rejects_a_check_id_outside_the_weakness_vocabulary(tmp_path, check_id):
    """Check ids without a known weakness suffix or with uppercase letters fail the schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "id: record-owner-missing-permission", f"id: {check_id}", 1)

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_reports_the_field_path_of_a_bad_check_id(tmp_path):
    """A bad check id error names cases.0.checks.0.id and stays under 2000 characters."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "id: record-owner-missing-permission", "id: record-owner-bad")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema") as raised:
        validate_benchmark(path)

    message = str(raised.value)
    assert "cases.0.checks.0.id" in message
    assert len(message) < 2000


def test_validate_benchmark_accepts_a_location_path_with_spaces(tmp_path):
    """A quoted location file "models/my records.py" passes validation."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "{file: models/records.py, line: 1}", '{file: "models/my records.py", line: 1}')

    validate_benchmark(path)


@pytest.mark.parametrize(
    "file",
    [
        "./models/records.py",
        "/models/records.py",
        '"models\\\\records.py"',
        "models//records.py",
        "models/./records.py",
        "models/../records.py",
        "models/",
    ],
)
def test_validate_benchmark_rejects_a_location_that_is_not_a_normalized_relative_path(tmp_path, file):
    """A ./ or / prefix, a backslash, an empty, . or .. segment, or a trailing slash fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "{file: models/records.py, line: 1}", f"{{file: {file}, line: 1}}")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


@pytest.mark.parametrize("symbol", ["Record.owner()", "Record.owner:12", "records.py:Record"])
def test_validate_benchmark_rejects_a_symbol_that_is_not_a_qualified_name(tmp_path, symbol):
    """Symbols with call parentheses, a :line suffix, or a file: prefix fail the schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "symbol: Record.owner}", f'symbol: "{symbol}"}}')

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_unknown_fields(tmp_path):
    """An extra top-level unknown: value key fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "cases:\n", "unknown: value\ncases:\n")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_requires_change_anchors_on_diff_checks(tmp_path):
    """Removing change_anchors from the diff case check fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(path, "        change_anchors:\n          - {file: producers/input.py, line: 12, side: new}\n", "")

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)


def test_validate_benchmark_rejects_change_anchors_on_repository_checks(tmp_path):
    """Adding change_anchors to the repository case check fails the benchmark-v1 schema."""
    path = _write_benchmark(tmp_path / "example-project")
    _replace(
        path,
        "          - {file: models/records.py, line: 1}\n",
        "          - {file: models/records.py, line: 1}\n"
        "        change_anchors:\n          - {file: models/records.py, line: 1, side: new}\n",
    )

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        validate_benchmark(path)
