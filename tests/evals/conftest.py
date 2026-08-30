"""Evaluation fixtures expose shared public benchmark builders."""

from pathlib import Path

import pytest
import yaml

from evals.benchmarks import registry


@pytest.fixture(autouse=True)
def _hermetic_eval_config(monkeypatch, tmp_path):
    config = tmp_path / "eval-config.yaml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(config))


@pytest.fixture
def public_only():
    def configure(tmp_path, monkeypatch):
        config = tmp_path / "empty.yaml"
        config.write_text("", encoding="utf-8")
        monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(config))

    return configure


@pytest.fixture
def public_diff_task_rows():
    def load() -> list[tuple[Path, dict]]:
        root = Path(registry.__file__).resolve().parent
        tasks = []
        for manifest in root.rglob("benchmark.yaml"):
            data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
            for task in data.get("tasks") or []:
                if task.get("kind") == "diff":
                    tasks.append((manifest, task))
        return tasks

    return load


@pytest.fixture
def public_diff_tasks(public_diff_task_rows):
    return lambda: [task for _manifest, task in public_diff_task_rows()]


@pytest.fixture
def public_diff_task_count(public_diff_task_rows):
    return lambda: len(public_diff_task_rows())


@pytest.fixture
def write_contract_project():
    def write(root: Path, *, outcome: str = "findings") -> Path:
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
            "    review:\n      mode: standard\n"
            f"  - id: {task_id}\n    kind: diff\n"
            "    revision:\n      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
            f"    expectation: {outcome}\n"
            "    review:\n      mode: standard\n",
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

    return write
