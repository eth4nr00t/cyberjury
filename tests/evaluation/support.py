"""Shared factories for evaluation tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import yaml

from evals.benchmarks import registry


def _public_only(tmp_path, monkeypatch):
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))


def _run(target, found, missed, fps, n_findings, n_reports=0, errors=0, file_found=(), file_missed=(), extra=()):
    from evals.score.result import Result

    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        extra=list(extra),
        file_found=list(file_found),
        file_missed=list(file_missed),
        n_findings=n_findings,
        n_file_findings=len(file_found) + len(file_missed),
        n_reports=n_reports,
        errors=errors,
    )


def _public_diff_tasks() -> list[dict]:
    return [task for _manifest, task in _public_diff_task_rows()]


def _diff_result(findings=None, *, degraded=False, failures=None, errors=0, incomplete=None, failure_reason=""):
    """Build the complete diff result contract used by eval runner tests."""
    outcome = SimpleNamespace(
        findings=list(findings or []),
        failures=list(failures or []),
        degraded=degraded,
        errors=errors,
        incomplete=list(incomplete or []),
        pending=[],
        failure_reason=failure_reason,
        requires_convergence=False,
        converged=False,
    )
    return SimpleNamespace(outcome=outcome)


def _key(tmp_path, body: str) -> Path:
    p = tmp_path / "answer-key.yaml"
    if not body.startswith("schema_version:"):
        body = "schema_version: 1\n" + body
    data = yaml.safe_load(body) or {}
    if isinstance(data, dict) and "target" in data and "issues" not in data:
        task_ids = sorted(
            {
                task_id
                for row in (*(data.get("planted") or []), *(data.get("safe") or []))
                for task_id in row.get("applies_to") or []
            }
        ) or ["repository-vulnerable"]
        entries = []
        for legacy_section, expectation in (("planted", "findings"), ("safe", "clean")):
            for row in data.get(legacy_section) or []:
                locations = {}
                for key in ("files", "symbols"):
                    if key in row:
                        locations[key] = row[key]
                if "entry" in row:
                    locations["endpoints"] = [row["entry"]]
                if "files" not in locations:
                    locations["files"] = ["__anchor__.py"]
                entry = {
                    "id": row.get("id", f"{legacy_section}-entry"),
                    "applies_to": row.get("applies_to") or task_ids,
                    "expectation": expectation,
                    "locations": locations,
                    "knowledge": {
                        "vulnerabilities": [row.get("category", "business-logic")],
                        "guides": (row.get("knowledge") or {}).get("guides", []),
                    },
                }
                if expectation == "findings":
                    entry["severity"] = row.get("severity") or "HIGH"
                entries.append(entry)
        data = {"schema_version": 1, "benchmark_id": data["target"], "checks": entries}
        body = yaml.safe_dump(data, sort_keys=False)
    p.write_text(body, encoding="utf-8")
    return p


def _public_diff_task_count() -> int:
    root = Path(registry.__file__).resolve().parent
    total = 0
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        total += sum(1 for task in data.get("tasks") or [] if task.get("kind") == "diff")
    return total


def _write_contract_project(root: Path, *, outcome: str = "findings") -> Path:
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


def _public_diff_task_rows() -> list[tuple[Path, dict]]:
    root = Path(registry.__file__).resolve().parent
    tasks = []
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            if task.get("kind") == "diff":
                tasks.append((manifest, task))
    return tasks


def _arm(
    ws,
    *,
    errors=0,
    verify_errors=0,
    incomplete=0,
    unlocatable=0,
    complete=True,
    requests=100,
    seconds=60.0,
):
    leaf = ws / "leaf"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": errors,
                "verify_errors": verify_errors,
                "incomplete": incomplete,
                "unlocatable": unlocatable,
                "complete": complete,
                "timing": {"total_seconds": seconds},
                "usage": {
                    "model_requests": requests,
                    "total_input_tokens": requests * 100,
                    "output_tokens": requests * 10,
                    "unit_review_calls": 20,
                },
            }
        ),
        encoding="utf-8",
    )
    return ws


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()
