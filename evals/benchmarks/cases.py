"""Load the cases of benchmark definitions as review cases.

A case of a project's `benchmark.yaml` is named `<project id>:<case id>` and carries its nested
checks. Public projects live under `evals/projects/<project-id>`. This module is engine-free so
listing and adjudication do not import the review runner.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from evals.benchmarks.contract import Check, case_checks
from evals.benchmarks.validate import benchmark_path, validate_benchmark

PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"


@dataclass(frozen=True, kw_only=True)
class BenchmarkCase:
    """One benchmark case with its pinned git target and its checks."""

    name: str
    kind: str
    target: dict[str, str]
    checks: tuple[Check, ...]


def expected_checks(case: BenchmarkCase) -> list[dict]:
    """Return the case checks in their benchmark.yaml form."""
    return [check.to_dict() for check in case.checks]


def checks_sha256(case: BenchmarkCase) -> str:
    """Return the digest of the case checks that a ledger is adjudicated against."""
    return sha256(json.dumps(expected_checks(case), sort_keys=True).encode()).hexdigest()


def public_benchmarks() -> list[Path]:
    """Return every public project benchmark definition."""
    return sorted(PROJECTS_DIR.glob("*/benchmark.yaml"))


def load_cases(benchmarks: Sequence[str | Path] | None = None) -> dict[str, BenchmarkCase]:
    """Load every case of the given benchmark definitions, defaulting to the public projects."""
    cases: dict[str, BenchmarkCase] = {}
    for path in benchmarks or public_benchmarks():
        benchmark = validate_benchmark(benchmark_path(path))
        for case in benchmark["cases"]:
            name = f"{benchmark['id']}:{case['id']}"
            if name in cases:
                raise ValueError(f"two benchmark definitions define case {name!r}")
            cases[name] = BenchmarkCase(
                name=name,
                kind=case["kind"],
                target=case_target(benchmark["repository"], case),
                checks=case_checks(case["checks"]),
            )
    return cases


def find_case(name: str, benchmarks: Sequence[str | Path] | None = None) -> BenchmarkCase:
    """Resolve one case and fail loud with the known names."""
    cases = load_cases(benchmarks)
    if name not in cases:
        raise ValueError(f"unknown benchmark case {name!r}. Known: {', '.join(cases) or 'none'}")
    return cases[name]


def case_target(repository: Mapping, case: Mapping) -> dict[str, str]:
    """Translate a validated repository and case into the pinned whole-repository review target."""
    target = {"commit": case["commit"] if case["kind"] == "diff" else repository["commit"]}
    if repository.get("url"):
        target["url"] = repository["url"]
    else:
        target["local_path"] = repository["local_path"]
    if case["kind"] == "diff":
        target["base"] = case["base"]
    return target


def validate_change_anchors(case: BenchmarkCase, diff: str) -> None:
    """Reject change anchors absent from the patch the review reads."""
    if not any(check.change_anchors for check in case.checks):
        return
    from cyberjury.review.detection import load_detection
    from cyberjury.review.diff.model import diff_line_ranges

    ranges = diff_line_ranges(diff, load_detection())
    sides = {"old": ranges.old, "new": ranges.new}
    for check in case.checks:
        for anchor in check.change_anchors:
            line_ranges = sides[anchor.side].get(anchor.file, ())
            if any(start <= anchor.line <= end for start, end in line_ranges):
                continue
            raise ValueError(
                f"diff case {case.name!r} check {check.id!r} change anchor "
                f"{anchor.file}:{anchor.line}:{anchor.side} is absent from the reviewed patch"
            )
