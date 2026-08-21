"""Factories shared by benchmark tests."""

from __future__ import annotations

from pathlib import Path

import yaml

from evals.benchmarks import registry


def public_only(tmp_path, monkeypatch):
    config = tmp_path / "empty.yaml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(config))


def public_diff_tasks() -> list[dict]:
    return [task for _manifest, task in public_diff_task_rows()]


def public_diff_task_count() -> int:
    root = Path(registry.__file__).resolve().parent
    total = 0
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        total += sum(1 for task in data.get("tasks") or [] if task.get("kind") == "diff")
    return total


def write_contract_project(root: Path, *, outcome: str = "findings") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "benchmark.yaml"
    task_id = "diff-bbbbbbb-1"
    manifest.write_text(
        "schema_version: 1\nbenchmark_id: contract-project\nprofile: web\n"
        "source:\n  kind: git\n  identity:\n    url: https://example.com/demo.git\n"
        "    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  path: .\n"
        "stack:\n  languages: [python]\n  frameworks: []\n  protocols: []\n"
        "knowledge:\n  vulnerabilities: [command-injection]\n  guides: [languages/python]\n"
        "tasks:\n"
        "  - id: repository-aaaaaaa\n    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        f"  - id: {task_id}\n    kind: diff\n"
        "    revision:\n      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        f"    expectation: {outcome}\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (root / "answer-key.yaml").write_text(
        "schema_version: 1\nbenchmark_id: contract-project\nchecks:\n"
        "  - id: demo-entry\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [run.py]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n"
        "      guides: [languages/python]\n"
        f"    applies_to: [{task_id}]\n",
        encoding="utf-8",
    )
    return manifest


def public_diff_task_rows() -> list[tuple[Path, dict]]:
    root = Path(registry.__file__).resolve().parent
    tasks = []
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            if task.get("kind") == "diff":
                tasks.append((manifest, task))
    return tasks
