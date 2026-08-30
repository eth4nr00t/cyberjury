"""Validate benchmark manifests and answer keys against their versioned contract."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from cyberjury.profiles.registry import get_profile
from evals.benchmarks.contract import ExpectedLocation

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_SCHEMA_FILES = {
    "benchmark.yaml": _SCHEMA_DIR / "benchmark-v1.schema.json",
    "answer-key.yaml": _SCHEMA_DIR / "answer-key-v1.schema.json",
}
_REPOSITORY_ID = re.compile(r"^repository-[0-9a-f]{7}$")
_DIFF_ID = re.compile(r"^diff-[0-9a-f]{7}-[0-9]+$")


def _load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    return data


def load_validated_document(path: Path) -> dict[str, object]:
    """Load one versioned document only after its closed schema accepts it."""
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
    _validate_manifest_taxonomy(manifest)
    known_tasks = _validate_tasks(source, manifest["tasks"])
    _validate_checks(manifest["knowledge"], known_tasks, answer_key["checks"])
    _validate_expectation_coverage(manifest["tasks"], answer_key["checks"])
    if source_root is not None:
        _validate_source_locations(answer_key["checks"], known_tasks, source_root)


def _validate_manifest_taxonomy(manifest: dict) -> None:
    knowledge = manifest["knowledge"]
    for block_name in ("languages", "frameworks", "protocols"):
        _check_sorted_unique(manifest["stack"][block_name], f"stack.{block_name}")
    for block_name in ("vulnerabilities", "guides"):
        _check_sorted_unique(knowledge[block_name], f"knowledge.{block_name}")
    _validate_knowledge_ids(str(manifest["profile"]), knowledge)
    _validate_stack_guides(manifest["stack"], knowledge["guides"])


def _validate_knowledge_ids(profile_name: str, knowledge: dict[str, list[str]]) -> None:
    profile = get_profile(profile_name)
    vulnerability_ids = {path.stem for path in profile.paths.vulnerabilities_dir.glob("*.md")}
    guides_root = profile.paths.knowledge / "guides"
    guide_ids = {path.relative_to(guides_root).with_suffix("").as_posix() for path in guides_root.rglob("*.md")}
    for block_name, known_ids in (("vulnerabilities", vulnerability_ids), ("guides", guide_ids)):
        unknown = sorted(set(knowledge[block_name]) - known_ids)
        if unknown:
            joined = ", ".join(unknown)
            raise ValueError(f"knowledge.{block_name} has unknown id(s) for profile {profile_name}: {joined}")


def _validate_tasks(source: dict, tasks: list[dict]) -> dict[str, str]:
    task_ids = [str(task["id"]) for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("benchmark.yaml has duplicate task ids")
    for task_index, task in enumerate(tasks):
        task_id = str(task["id"])
        if source["kind"] == "explorer" and task["kind"] == "diff":
            raise ValueError(f"explorer diff task {task_id} is not supported")
        if source["kind"] == "explorer" and "revision" in task:
            raise ValueError(f"explorer task {task_id} contains a git revision")
        if task["kind"] == "repository":
            _validate_repository_task(source, task)
        else:
            _validate_diff_task(task, tasks[: task_index + 1])
    return {str(task["id"]): str(task["kind"]) for task in tasks}


def _validate_repository_task(source: dict, task: dict) -> None:
    task_id = str(task["id"])
    if source["kind"] == "git":
        source_token = str(source["identity"].get("commit") or "")
    else:
        source_token = str(source["identity"]["address"]).lower().removeprefix("0x")
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
    expected_sequence = sum(1 for prior in preceding_tasks if prior["kind"] == "diff")
    if sequence != expected_sequence or not task_id.startswith(f"diff-{commit[:7].lower()}-"):
        raise ValueError(f"diff task {task_id} id does not agree with revision.commit or task order")


def _validate_checks(knowledge: dict, known_tasks: dict[str, str], checks: list[dict]) -> None:
    by_id: dict[str, list[dict]] = {}
    for check in checks:
        check_id = str(check["id"])
        _check_unique(check["applies_to"], f"answer-key check {check_id}.applies_to")
        unknown = sorted(set(check["applies_to"]) - known_tasks.keys())
        if unknown:
            raise ValueError(f"answer-key check {check['id']} references unknown task id(s): {', '.join(unknown)}")
        _validate_check_locations(check_id, check)
        _validate_check_knowledge(check_id, check, knowledge)
        _validate_change_anchor_scope(check_id, check, known_tasks)
        _validate_disjoint_check_scope(check, by_id.setdefault(check["id"], []))
        by_id[check["id"]].append(check)
    _validate_structured_scoring_identities(checks)


def _validate_check_locations(check_id: str, check: dict) -> None:
    if isinstance(check["locations"], list):
        for index, location in enumerate(check["locations"]):
            _scope_parts(location["file"], f"answer-key check {check_id}.locations[{index}].file")
        return
    for block_name in ("files", "endpoints", "symbols"):
        values = check["locations"].get(block_name)
        if values:
            _check_unique(values, f"answer-key check {check_id}.locations.{block_name}")


def _validate_check_knowledge(check_id: str, check: dict, knowledge: dict) -> None:
    for block_name in ("vulnerabilities", "guides"):
        values = check["knowledge"][block_name]
        _check_unique(values, f"answer-key check {check_id}.knowledge.{block_name}")
        unknown_refs = sorted(set(values) - set(knowledge[block_name]))
        if unknown_refs:
            joined = ", ".join(unknown_refs)
            raise ValueError(f"answer-key check {check_id} has knowledge outside its task scope: {joined}")


def _validate_change_anchor_scope(check_id: str, check: dict, known_tasks: dict[str, str]) -> None:
    changes = check.get("changes") or check.get("change_anchors")
    structured = isinstance(check["locations"], list)
    scoped_tasks = check["applies_to"]
    diff_tasks = [task for task in scoped_tasks if known_tasks[task] == "diff"]
    if structured and diff_tasks and not changes:
        raise ValueError(f"answer-key check {check_id} changes are required for a diff task")
    if not changes:
        return
    if len(scoped_tasks) != 1 or known_tasks[scoped_tasks[0]] != "diff":
        label = "changes" if check.get("changes") else "change anchors"
        raise ValueError(f"answer-key check {check_id} {label} require exactly one diff task")
    for change in changes:
        _scope_parts(change["file"], f"answer-key check {check_id}.changes.file")


def _validate_structured_scoring_identities(checks: list[dict]) -> None:
    """Reject structured diff checks that deterministic evidence cannot distinguish."""
    by_task: dict[str, list[dict]] = {}
    for check in checks:
        if not isinstance(check["locations"], list) or not _check_changes(check):
            continue
        for task_id in check["applies_to"]:
            by_task.setdefault(task_id, []).append(check)
    for task_id, task_checks in by_task.items():
        for index, check in enumerate(task_checks):
            for other in task_checks[index + 1 :]:
                if _anchored_checks_overlap(check, other):
                    raise ValueError(
                        f"answer-key checks {check['id']} and {other['id']} have ambiguous scoring identity "
                        f"for task {task_id}"
                    )


def _anchored_checks_overlap(check: dict, other: dict) -> bool:
    category = check["knowledge"]["vulnerabilities"][0]
    other_category = other["knowledge"]["vulnerabilities"][0]
    if category != other_category:
        return False
    locations = _structured_locations(check)
    other_locations = _structured_locations(other)
    if locations.isdisjoint(other_locations):
        return False
    changes = {(entry["file"], entry["line"], entry["side"]) for entry in _check_changes(check)}
    other_changes = {(entry["file"], entry["line"], entry["side"]) for entry in _check_changes(other)}
    return not changes.isdisjoint(other_changes)


def _check_changes(check: dict) -> list[dict]:
    return check.get("changes") or check.get("change_anchors") or []


def _structured_locations(check: dict) -> set[ExpectedLocation]:
    return {
        ExpectedLocation(
            file=entry["file"],
            line=entry.get("line"),
            symbol=entry.get("symbol", ""),
        )
        for entry in check["locations"]
    }


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
        locations = check["locations"]
        files = [entry["file"] for entry in locations] if isinstance(locations, list) else locations.get("files", [])
        for rel in files:
            path = (source_root / rel).resolve()
            if not path.is_file() or not path.is_relative_to(resolved_root):
                raise ValueError(f"answer-key check {check['id']} location does not exist: {rel}")


def _scope_parts(scope: str, where: str) -> tuple[str, ...]:
    path = PurePosixPath(scope)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != scope:
        raise ValueError(f"{where} is not a normalized repository-relative scope")
    return () if path.as_posix() == "." else path.parts


def _check_sorted_unique(values: list[str], where: str) -> None:
    _check_unique(values, where)
    if list(values) != sorted(values):
        raise ValueError(f"{where} is not sorted")


def _check_unique(values: list[str], where: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{where} contains duplicates")


def _validate_stack_guides(stack: dict[str, list[str]], guides: list[str]) -> None:
    """Require guide taxonomy values to appear on the matching stack axis."""
    for guide in guides:
        parts = PurePosixPath(guide).parts
        if len(parts) == 2 and parts[0] == "languages" and parts[1] not in stack["languages"]:
            raise ValueError(f"knowledge guide {guide} is absent from stack.languages")
        if len(parts) == 3 and parts[0] == "frameworks":
            if parts[1] not in stack["languages"]:
                raise ValueError(f"knowledge guide {guide} language is absent from stack.languages")
            if parts[2] not in stack["frameworks"]:
                raise ValueError(f"knowledge guide {guide} is absent from stack.frameworks")
        if len(parts) == 2 and parts[0] == "protocols" and parts[1] not in stack["protocols"]:
            raise ValueError(f"knowledge guide {guide} is absent from stack.protocols")


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
    manifest = load_validated_document(manifest_path)
    answer_key = load_validated_document(answer_key_path)
    _validate_semantics(manifest, answer_key, source_root=Path(source_root) if source_root else None)


def validate_answer_key(path: str | Path, *, benchmark_path: str | Path | None = None) -> None:
    """Validate an answer key and optionally its sibling benchmark manifest."""
    answer_key_path = Path(path)
    answer_key = load_validated_document(answer_key_path)
    if benchmark_path is None:
        benchmark_path = answer_key_path.with_name("benchmark.yaml")
    manifest = load_validated_document(Path(benchmark_path))
    _validate_semantics(manifest, answer_key)
