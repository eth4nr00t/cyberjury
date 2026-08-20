"""Evaluation review modes keep the same adapter boundaries."""

from pathlib import Path


def test_review_mode_packages_have_matching_stage_modules():
    root = Path("evals/review")
    expected = {"execution.py", "progress.py", "results.py", "targets.py"}

    assert {path.name for path in (root / "diff").glob("*.py") if path.name != "__init__.py"} == expected
    assert {path.name for path in (root / "repository").glob("*.py") if path.name != "__init__.py"} == expected
