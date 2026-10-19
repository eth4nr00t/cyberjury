"""Benchmark cases materialize the repository and diff cases of one project definition."""

from __future__ import annotations

from dataclasses import replace

import pytest

from cyberjury.sources.git import canonical_patch
from evals.benchmarks.cases import checks_sha256, find_case, load_cases, validate_change_anchors
from evals.benchmarks.contract import ChangeAnchor, Check, Location


def test_public_projects_load_every_case_with_pinned_git_targets():
    """Every bundled case has checks and a 40-char commit, and diff cases also have a 40-char base."""
    loaded = load_cases()

    assert {case.kind for case in loaded.values()} == {"repository", "diff"}
    for case in loaded.values():
        assert len(case.target["commit"]) == 40
        assert case.checks
        if case.kind == "diff":
            assert len(case.target["base"]) == 40


def test_cases_carry_their_nested_checks_and_targets(benchmark_project):
    """Repository and diff cases carry commit, base, and local_path targets with checks at line 2."""
    repository = find_case(benchmark_project.repository_case, [benchmark_project.benchmark])
    diff = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])

    assert repository.target == {"commit": benchmark_project.commit, "local_path": str(benchmark_project.repo)}
    assert [check.locations[0].line for check in repository.checks] == [2]
    assert diff.target == {
        "commit": benchmark_project.commit,
        "base": benchmark_project.base,
        "local_path": str(benchmark_project.repo),
    }
    assert [check.change_anchors[0].line for check in diff.checks] == [2]
    assert not repository.checks[0].change_anchors


def test_checks_digest_ignores_check_and_location_order():
    """Reversing the checks and their locations keeps the digest, and editing a location changes it."""
    case = next(case for case in load_cases().values() if len(case.checks) > 1)
    checks = tuple(replace(check, locations=check.locations[::-1]) for check in case.checks[::-1])
    moved = Check(id=checks[0].id, root_cause=checks[0].root_cause, locations=(Location(file="moved.py", line=1),))

    assert checks_sha256(replace(case, checks=checks)) == checks_sha256(case)
    assert checks_sha256(replace(case, checks=(moved, *checks[1:]))) != checks_sha256(case)


def test_one_case_name_cannot_come_from_two_benchmarks(benchmark_project):
    """Loading one benchmark directory alongside its parent raises "two benchmark definitions define"."""
    with pytest.raises(ValueError, match="two benchmark definitions define"):
        load_cases([benchmark_project.benchmark, benchmark_project.benchmark.parent])


@pytest.mark.parametrize("side", ["old", "new"])
def test_change_anchors_inside_the_reviewed_patch_are_accepted(benchmark_project, side):
    """An anchor at views.py line 2 on either the old or new side validates against the base..commit patch."""
    case = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])
    check = replace(case.checks[0], change_anchors=(ChangeAnchor(file="views.py", line=2, side=side),))
    patch = canonical_patch(benchmark_project.repo, benchmark_project.base, benchmark_project.commit)

    validate_change_anchors(replace(case, checks=(check,)), patch)


def test_change_anchors_absent_from_the_reviewed_patch_are_rejected(benchmark_project):
    """An anchor at views.py line 9, outside the patch hunks, raises "absent from the reviewed patch"."""
    case = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])
    check = replace(case.checks[0], change_anchors=(ChangeAnchor(file="views.py", line=9, side="new"),))
    patch = canonical_patch(benchmark_project.repo, benchmark_project.base, benchmark_project.commit)

    with pytest.raises(ValueError, match=r"change anchor .* is absent from the reviewed patch"):
        validate_change_anchors(replace(case, checks=(check,)), patch)
