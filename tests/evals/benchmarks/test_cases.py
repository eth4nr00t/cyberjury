"""Benchmark cases materialize repository and diff tasks from one project contract."""

from __future__ import annotations

import subprocess
from dataclasses import replace

import pytest

from cyberjury.sources.git import canonical_patch
from evals.benchmarks import cases
from evals.benchmarks.cases import find_case, load_cases, validate_change_anchors
from evals.benchmarks.contract import ExpectedChange


def test_public_projects_load_every_task_with_pinned_git_targets():
    loaded = load_cases()

    assert {case.kind for case in loaded.values()} == {"repository", "diff"}
    assert {case.expectation for case in loaded.values() if case.kind == "diff"} == {"clean", "findings"}
    for case in loaded.values():
        assert len(case.target["ref"]) == 40
        assert case.checks
        if case.kind == "diff":
            assert len(case.target["base"]) == 40


def test_cases_carry_task_scoped_checks_and_targets(benchmark_project):
    repository = find_case(benchmark_project.repository_case, [benchmark_project.manifest])
    diff = find_case(benchmark_project.diff_case, [benchmark_project.manifest])

    assert repository.target == {"ref": benchmark_project.ref, "path": ".", "root": str(benchmark_project.repo)}
    assert repository.expectation == "findings"
    assert [check.locations[0].line for check in repository.findings] == [2]
    assert diff.target["base"] == benchmark_project.base
    assert [check.changes[0].line for check in diff.findings] == [2]


def test_one_case_name_cannot_come_from_two_manifests(benchmark_project):
    with pytest.raises(ValueError, match="two manifests define"):
        load_cases([benchmark_project.manifest, benchmark_project.manifest.parent])


@pytest.mark.parametrize("side", ["old", "new"])
def test_change_anchors_inside_the_reviewed_patch_are_accepted(benchmark_project, side):
    case = find_case(benchmark_project.diff_case, [benchmark_project.manifest])
    check = replace(case.checks[0], changes=(ExpectedChange(file="views.py", line=2, side=side),))
    patch = canonical_patch(benchmark_project.repo, benchmark_project.base, benchmark_project.ref)

    validate_change_anchors(replace(case, checks=(check,)), patch)


def test_change_anchors_absent_from_the_reviewed_patch_are_rejected(benchmark_project):
    case = find_case(benchmark_project.diff_case, [benchmark_project.manifest])
    check = replace(case.checks[0], changes=(ExpectedChange(file="views.py", line=9, side="new"),))
    patch = canonical_patch(benchmark_project.repo, benchmark_project.base, benchmark_project.ref)

    with pytest.raises(ValueError, match=r"change anchor .* is absent from the reviewed patch"):
        validate_change_anchors(replace(case, checks=(check,)), patch)


def test_git_url_targets_fetch_exact_commits(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if cmd[3] == "cat-file" else 0)

    monkeypatch.setattr(cases.subprocess, "run", fake_run)
    target = {"url": "https://example.com/repo.git", "path": ".", "base": "abc123", "ref": "def456"}

    cases.ensure_git_target_refs(target, tmp_path)

    assert ["git", "-C", str(tmp_path), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(tmp_path), "fetch", "origin", "def456"] in calls
