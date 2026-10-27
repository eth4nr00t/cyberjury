"""Benchmark definition validation against the versioned contract."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
BENCHMARK_SCHEMA = "benchmark-v1.schema.json"


def validate_document(data: object, schema_name: str, where: object) -> None:
    """Reject a document that its closed versioned schema does not accept."""
    schema = json.loads((_SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.absolute_path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"{where} violates {schema_name}: {detail}")


def _validate_project_id(benchmark: dict, directory: str) -> None:
    project = benchmark["id"]
    if project != directory:
        raise ValueError(f"benchmark id {project} does not match its directory {directory}")
    url = benchmark["repository"].get("url")
    if url:
        name = PurePosixPath(urlparse(url).path).name.removesuffix(".git")
        if project != re.sub(r"[._]+", "-", name.lower()):
            raise ValueError(f"benchmark id {project} does not match its repository name {name}")


def _validate_semantics(benchmark: dict, *, source_root: Path | None = None) -> None:
    cases = benchmark["cases"]
    commit = str(benchmark["repository"]["commit"])
    for case in cases:
        _validate_case_id(case, commit if case["kind"] == "repository" else str(case["commit"]))
        _validate_checks(case)
    case_ids = [str(case["id"]) for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("benchmark.yaml has duplicate case ids")
    if source_root is not None:
        _validate_source_locations(cases, source_root)


def _validate_case_id(case: dict, commit: str) -> None:
    if case["id"] != f"{case['kind']}-{commit[:7]}":
        raise ValueError(f"{case['kind']} case {case['id']} id does not agree with its commit")


def _validate_checks(case: dict) -> None:
    check_ids = [str(check["id"]) for check in case["checks"]]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError(f"case {case['id']} has duplicate check ids")


def _validate_source_locations(cases: list[dict], source_root: Path) -> None:
    resolved_root = source_root.resolve()
    for case in cases:
        if case["kind"] != "repository":
            continue
        for check in case["checks"]:
            for rel in (entry["file"] for entry in check["locations"]):
                path = (source_root / rel).resolve()
                if not path.is_file() or not path.is_relative_to(resolved_root):
                    raise ValueError(f"case {case['id']} check {check['id']} location does not exist: {rel}")


def benchmark_path(path: str | Path) -> Path:
    """Resolve a benchmark project directory or definition path to its benchmark.yaml."""
    target = Path(path)
    if target.is_dir():
        return target / "benchmark.yaml"
    if target.name == "benchmark.yaml":
        return target
    raise ValueError(f"{target} must be a benchmark directory or benchmark.yaml")


def validate_benchmark(path: str | Path, *, source_root: str | Path | None = None) -> dict:
    """Validate one benchmark definition and return it."""
    benchmark_file = benchmark_path(path)
    benchmark = yaml.safe_load(benchmark_file.read_text(encoding="utf-8"))
    validate_document(benchmark, BENCHMARK_SCHEMA, benchmark_file)
    _validate_project_id(benchmark, benchmark_file.parent.name)
    _validate_semantics(benchmark, source_root=Path(source_root) if source_root else None)
    return benchmark
