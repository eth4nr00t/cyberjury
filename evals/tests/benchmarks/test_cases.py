"""Benchmark cases materialize the repository and diff cases of one project definition."""

from __future__ import annotations

from dataclasses import replace

import pytest

from cyberjury.sources.git import canonical_patch
from evals.benchmarks.cases import checks_sha256, find_case, load_cases, validate_change_anchors
from evals.benchmarks.contract import ChangeAnchor, Check, Location


def test_public_benchmarks_validate():
    """Every bundled project benchmark passes the benchmark-v1 schema and the semantic checks."""
    assert load_cases()


def test_cases_carry_their_nested_checks_and_targets(benchmark_project):
    """Repository and diff cases carry their commit, base, and local_path targets and their checks."""
    repository = find_case(benchmark_project.repository_case, [benchmark_project.benchmark])
    diff = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])

    assert repository.target == {"commit": benchmark_project.commit, "local_path": str(benchmark_project.repo)}
    assert diff.target == {
        "commit": benchmark_project.commit,
        "base": benchmark_project.base,
        "local_path": str(benchmark_project.repo),
    }
    assert (len(repository.checks), len(diff.checks)) == (1, 1)


def test_checks_digest_ignores_check_and_location_order(benchmark_project):
    """Reversing two checks and their two locations keeps the digest, and editing a location changes it."""
    case = find_case(benchmark_project.repository_case, [benchmark_project.benchmark])
    first = Check(
        id="first",
        root_cause="first root cause",
        locations=(Location(file="a.py", line=1), Location(file="b.py", line=2)),
    )
    second = Check(id="second", root_cause="second root cause", locations=(Location(file="c.py", line=3),))
    original = replace(case, checks=(first, second))
    reordered = replace(case, checks=(second, replace(first, locations=first.locations[::-1])))
    moved = replace(case, checks=(replace(first, locations=(Location(file="moved.py", line=1),)), second))

    assert checks_sha256(reordered) == checks_sha256(original)
    assert checks_sha256(moved) != checks_sha256(original)


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


def test_a_change_anchor_on_a_skipped_noise_file_is_rejected(benchmark_project):
    """An anchor on a changed README.md line is rejected because the review skips that file as noise."""
    case = find_case(benchmark_project.diff_case, [benchmark_project.benchmark])
    check = replace(case.checks[0], change_anchors=(ChangeAnchor(file="README.md", line=1, side="new"),))
    patch = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -0,0 +1 @@\n+# Title\n"

    with pytest.raises(ValueError, match=r"README\.md:1:new is absent from the reviewed patch"):
        validate_change_anchors(replace(case, checks=(check,)), patch)
