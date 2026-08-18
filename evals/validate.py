"""Validate benchmark manifests and answer keys against the versioned contract."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator, FormatChecker

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_SCHEMA_FILES = {
    "benchmark.yaml": _SCHEMA_DIR / "benchmark-schema-1.0.0.json",
    "answer-key.yaml": _SCHEMA_DIR / "answer-key-schema-1.0.0.json",
}
_REPOSITORY_ID = re.compile(r"^repository-[0-9a-f]{7}$")
_DIFF_ID = re.compile(r"^diff-[0-9a-f]{7}-[0-9]+$")


def _load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return data


def _validate_document(path: Path) -> dict:
    data = _load_yaml(path)
    schema_path = _SCHEMA_FILES.get(path.name)
    if schema_path is None:
        raise ValueError(f"{path} must be named benchmark.yaml or answer-key.yaml")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.absolute_path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"{path} violates {schema_path.name}: {detail}")
    return data


def _validate_semantics(manifest: dict, answer_key: dict, *, source_root: Path | None = None) -> None:
    if manifest["benchmark_id"] != answer_key["benchmark_id"]:
        raise ValueError("benchmark_id differs between benchmark.yaml and answer-key.yaml")
    source = manifest["source"]
    _scope_parts(source["path"], "source.path")
    merged_knowledge = manifest["knowledge"]
    for block_name in ("languages", "frameworks", "protocols"):
        _check_sorted_unique(manifest["stack"][block_name], f"stack.{block_name}")
    for block_name in ("vulnerabilities", "guides"):
        _check_sorted_unique(merged_knowledge[block_name], f"knowledge.{block_name}")
    task_ids = [str(task["id"]) for task in manifest["tasks"]]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("benchmark.yaml has duplicate task ids")
    known_tasks = set(task_ids)
    by_id: dict[str, list[dict]] = {}
    task_by_id = {str(task["id"]): task for task in manifest["tasks"]}
    for task_index, task in enumerate(manifest["tasks"]):
        task_id = str(task["id"])
        if source["kind"] == "explorer" and task["kind"] == "diff":
            raise ValueError(f"explorer diff task {task_id} is not supported")
        if source["kind"] == "explorer" and "revision" in task:
            raise ValueError(f"explorer task {task_id} contains a git revision")
        if task["kind"] == "repository":
            if source["kind"] == "git":
                source_token = str(source["identity"].get("commit") or "")
            else:
                source_token = str(source["identity"]["address"]).lower().removeprefix("0x")
            effective_commit = str((task.get("revision") or {}).get("commit") or source_token)
            expected_id = f"repository-{effective_commit[:7].lower()}"
            if not _REPOSITORY_ID.fullmatch(task_id) or task_id != expected_id:
                raise ValueError(f"repository task {task_id} id does not agree with its effective commit")
            if "review" in task and (task["review"].get("context") == "diff"):
                raise ValueError(f"repository task {task_id} cannot use diff review context")
        else:
            if not _DIFF_ID.fullmatch(task_id):
                raise ValueError(f"diff task {task_id} has an invalid id")
            commit = str(task["revision"]["commit"])
            sequence = int(task_id.rsplit("-", 1)[-1])
            expected_sequence = sum(1 for prior in manifest["tasks"][: task_index + 1] if prior["kind"] == "diff")
            if sequence != expected_sequence or not task_id.startswith(f"diff-{commit[:7].lower()}-"):
                raise ValueError(f"diff task {task_id} id does not agree with revision.commit or task order")
    for check in answer_key["checks"]:
        unknown = sorted(set(check["applies_to"]) - known_tasks)
        if unknown:
            raise ValueError(f"answer-key check {check['id']} references unknown task id(s): {', '.join(unknown)}")
        merged = merged_knowledge
        for task_id in check["applies_to"]:
            merged = _merge_knowledge(merged, task_by_id[task_id].get("knowledge"))
        for block_name in ("vulnerabilities", "guides"):
            unknown_refs = sorted(set(check["knowledge"][block_name]) - set(merged[block_name]))
            if unknown_refs:
                joined = ", ".join(unknown_refs)
                raise ValueError(f"answer-key check {check['id']} has knowledge outside its task scope: {joined}")
        for prior in by_id.setdefault(check["id"], []):
            overlap = set(prior["applies_to"]).intersection(check["applies_to"])
            if overlap:
                joined = ", ".join(sorted(overlap))
                raise ValueError(f"answer-key check {check['id']} has overlapping task scope(s): {joined}")
        by_id[check["id"]].append(check)
    for task in manifest["tasks"]:
        if task["kind"] != "diff" or task["expectation"] != "clean":
            continue
        if not any(
            task["id"] in check["applies_to"] and check["expectation"] == "clean" for check in answer_key["checks"]
        ):
            raise ValueError(f"clean task {task['id']} has no clean answer-key check")
    for task in manifest["tasks"]:
        if (
            task["kind"] == "diff"
            and task["expectation"] == "findings"
            and not any(
                task["id"] in check["applies_to"] and check["expectation"] == "findings"
                for check in answer_key["checks"]
            )
        ):
            raise ValueError(f"findings task {task['id']} has no findings answer-key check")
    if source_root is None:
        return
    for check in answer_key["checks"]:
        for rel in check["locations"].get("files", []):
            path = (source_root / rel).resolve()
            if not path.is_file() or not path.is_relative_to(source_root.resolve()):
                raise ValueError(f"answer-key check {check['id']} location does not exist: {rel}")


def _scope_parts(scope: str, where: str) -> tuple[str, ...]:
    path = PurePosixPath(scope)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{where} is not a normalized repository-relative scope")
    return () if path.as_posix() == "." else path.parts


def _check_sorted_unique(values: list[str], where: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{where} contains duplicates")
    if list(values) != sorted(values):
        raise ValueError(f"{where} is not sorted")


def _merge_knowledge(base: dict, overlay: dict | None) -> dict:
    overlay = overlay or {}
    return {
        key: [*base.get(key, []), *[value for value in overlay.get(key, []) if value not in base.get(key, [])]]
        for key in ("vulnerabilities", "guides")
    }


def validate_benchmark(path: str | Path, *, source_root: str | Path | None = None) -> None:
    """Validate one benchmark directory or one manifest and its answer key."""
    target = Path(path)
    if target.is_dir():
        manifest_path = target / "benchmark.yaml"
        answer_key_path = target / "answer-key.yaml"
    elif target.name == "benchmark.yaml":
        manifest_path = target
        answer_key_path = target.with_name("answer-key.yaml")
    else:
        raise ValueError(f"{target} must be a benchmark directory or benchmark.yaml")
    if not answer_key_path.is_file():
        raise ValueError(f"{target} has no answer-key.yaml")
    manifest = _validate_document(manifest_path)
    answer_key = _validate_document(answer_key_path)
    _validate_semantics(manifest, answer_key, source_root=Path(source_root) if source_root else None)


def validate_answer_key(path: str | Path, *, benchmark_path: str | Path | None = None) -> None:
    """Validate an answer key and optionally its sibling benchmark manifest."""
    answer_key_path = Path(path)
    answer_key = _validate_document(answer_key_path)
    if benchmark_path is None:
        benchmark_path = answer_key_path.with_name("benchmark.yaml")
    manifest = _validate_document(Path(benchmark_path))
    _validate_semantics(manifest, answer_key)
