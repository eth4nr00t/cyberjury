"""Validate benchmark manifests and answer keys against their versioned contract."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator, FormatChecker

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_SCHEMA_FILES = {
    "benchmark.yaml": "benchmark-v2.schema.json",
    "answer-key.yaml": "answer-key-v1.schema.json",
}
_REPOSITORY_ID = re.compile(r"^repository-[0-9a-f]{7}$")
_DIFF_ID = re.compile(r"^diff-[0-9a-f]{7}-[0-9]+$")


def validate_document(data: object, schema_name: str, where: object) -> None:
    """Reject a document that its closed versioned schema does not accept."""
    schema = json.loads((_SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.absolute_path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"{where} violates {schema_name}: {detail}")


def _load_validated_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    validate_document(data, _SCHEMA_FILES[path.name], path)
    return data


def _validate_semantics(manifest: dict, answer_key: dict, *, source_root: Path | None = None) -> None:
    if manifest["benchmark_id"] != answer_key["benchmark_id"]:
        raise ValueError("benchmark_id differs between benchmark.yaml and answer-key.yaml")
    source = manifest["source"]
    _scope_parts(source["path"], "source.path")
    known_tasks = _validate_tasks(source, manifest["tasks"])
    _validate_checks(known_tasks, answer_key["checks"])
    _validate_expectation_coverage(manifest["tasks"], answer_key["checks"])
    if source_root is not None:
        _validate_source_locations(answer_key["checks"], known_tasks, source_root)


def _validate_tasks(source: dict, tasks: list[dict]) -> dict[str, str]:
    task_ids = [str(task["id"]) for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("benchmark.yaml has duplicate task ids")
    for task_index, task in enumerate(tasks):
        if task["kind"] == "repository":
            _validate_repository_task(source, task)
        else:
            _validate_diff_task(task, tasks[:task_index])
    return {str(task["id"]): str(task["kind"]) for task in tasks}


def _validate_repository_task(source: dict, task: dict) -> None:
    task_id = str(task["id"])
    source_token = str(source["identity"]["commit"])
    effective_commit = str((task.get("revision") or {}).get("commit") or source_token)
    expected_id = f"repository-{effective_commit[:7].lower()}"
    if not _REPOSITORY_ID.fullmatch(task_id) or task_id != expected_id:
        raise ValueError(f"repository task {task_id} id does not agree with its effective commit")


def _validate_diff_task(task: dict, preceding_tasks: list[dict]) -> None:
    task_id = str(task["id"])
    if not _DIFF_ID.fullmatch(task_id):
        raise ValueError(f"diff task {task_id} has an invalid id")
    commit = str(task["revision"]["commit"])
    sequence = int(task_id.rsplit("-", 1)[-1])
    prior_sequence = max(
        (int(str(prior["id"]).rsplit("-", 1)[-1]) for prior in preceding_tasks if prior["kind"] == "diff"),
        default=0,
    )
    if sequence <= prior_sequence or not task_id.startswith(f"diff-{commit[:7].lower()}-"):
        raise ValueError(f"diff task {task_id} id does not agree with revision.commit or task order")
    revision = _revision(task)
    for prior in preceding_tasks:
        if prior["kind"] == "diff" and _revision(prior) == revision:
            raise ValueError(f"diff task {task_id} repeats the revision of diff task {prior['id']}")


def _revision(task: dict) -> tuple[str, str]:
    return (str(task["revision"]["base_commit"]).lower(), str(task["revision"]["commit"]).lower())


def _validate_checks(known_tasks: dict[str, str], checks: list[dict]) -> None:
    by_id: dict[str, list[dict]] = {}
    for check in checks:
        check_id = str(check["id"])
        _check_unique(check["applies_to"], f"answer-key check {check_id}.applies_to")
        unknown = sorted(set(check["applies_to"]) - known_tasks.keys())
        if unknown:
            raise ValueError(f"answer-key check {check['id']} references unknown task id(s): {', '.join(unknown)}")
        for index, location in enumerate(check["locations"]):
            _scope_parts(location["file"], f"answer-key check {check_id}.locations[{index}].file")
        _validate_change_anchor_scope(check_id, check, known_tasks)
        _validate_disjoint_check_scope(check, by_id.setdefault(check["id"], []))
        by_id[check["id"]].append(check)


def _validate_change_anchor_scope(check_id: str, check: dict, known_tasks: dict[str, str]) -> None:
    changes = check.get("changes")
    scoped_tasks = check["applies_to"]
    diff_tasks = [task for task in scoped_tasks if known_tasks[task] == "diff"]
    if diff_tasks and not changes:
        raise ValueError(f"answer-key check {check_id} changes are required for a diff task")
    if not changes:
        return
    if len(scoped_tasks) != 1 or known_tasks[scoped_tasks[0]] != "diff":
        raise ValueError(f"answer-key check {check_id} changes require exactly one diff task")
    for change in changes:
        _scope_parts(change["file"], f"answer-key check {check_id}.changes.file")


def _validate_disjoint_check_scope(check: dict, prior_checks: list[dict]) -> None:
    for prior in prior_checks:
        overlap = set(prior["applies_to"]).intersection(check["applies_to"])
        if overlap:
            joined = ", ".join(sorted(overlap))
            raise ValueError(f"answer-key check {check['id']} has overlapping task scope(s): {joined}")


def _validate_expectation_coverage(tasks: list[dict], checks: list[dict]) -> None:
    for task in tasks:
        if task["kind"] != "diff":
            continue
        expectation = task["expectation"]
        if not any(task["id"] in check["applies_to"] and check["expectation"] == expectation for check in checks):
            raise ValueError(f"{expectation} task {task['id']} has no {expectation} answer-key check")


def _validate_source_locations(checks: list[dict], known_tasks: dict[str, str], source_root: Path) -> None:
    """Validate locations owned by the manifest source revision."""
    resolved_root = source_root.resolve()
    for check in checks:
        if not any(known_tasks[task_id] == "repository" for task_id in check["applies_to"]):
            continue
        for rel in (entry["file"] for entry in check["locations"]):
            path = (source_root / rel).resolve()
            if not path.is_file() or not path.is_relative_to(resolved_root):
                raise ValueError(f"answer-key check {check['id']} location does not exist: {rel}")


def _scope_parts(scope: str, where: str) -> tuple[str, ...]:
    path = PurePosixPath(scope)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != scope:
        raise ValueError(f"{where} is not a normalized repository-relative scope")
    return () if path.as_posix() == "." else path.parts


def _check_unique(values: list[str], where: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{where} contains duplicates")


def manifest_path(path: str | Path) -> Path:
    """Resolve a benchmark directory or manifest path to its benchmark.yaml."""
    target = Path(path)
    if target.is_dir():
        return target / "benchmark.yaml"
    if target.name == "benchmark.yaml":
        return target
    raise ValueError(f"{target} must be a benchmark directory or benchmark.yaml")


def validate_benchmark(path: str | Path, *, source_root: str | Path | None = None) -> tuple[dict, dict]:
    """Validate one benchmark manifest and its sibling answer key, and return both documents."""
    manifest_file = manifest_path(path)
    answer_key_file = manifest_file.with_name("answer-key.yaml")
    if not answer_key_file.is_file():
        raise ValueError(f"{path} has no answer-key.yaml")
    manifest = _load_validated_yaml(manifest_file)
    answer_key = _load_validated_yaml(answer_key_file)
    _validate_semantics(manifest, answer_key, source_root=Path(source_root) if source_root else None)
    return manifest, answer_key
