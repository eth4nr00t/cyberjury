"""Diff benchmark target and manifest tests."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

from evals.benchmarks import registry

from .support import (
    _git,
    _public_diff_task_count,
    _public_diff_task_rows,
    _public_diff_tasks,
    _public_only,
    _write_contract_project,
)


def test_default_diff_cases_load_project_diff_tasks(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()
    names = {c.name for c in cases}
    assert any(name.startswith("github-mcp-server:diff-1c4cb29-") for name in names)
    assert len(names) == _public_diff_task_count()
    assert {c.outcome for c in cases} == {"clean", "findings"}
    assert all(c.answer_key is not None for c in cases)
    assert all(c.diff.startswith("diff --git") or c.target.get("url") for c in cases)


def test_default_diff_cases_use_real_git_commit_targets(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()

    assert all(c.target.get("type") == "git" for c in cases)
    assert all(c.target.get("base") and c.target.get("ref") for c in cases)
    assert all(len(str(c.target.get("base") or "")) == 40 and len(str(c.target.get("ref") or "")) == 40 for c in cases)


def test_project_diff_task_loads_from_shared_manifest(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "add exec")
    ref = _git(repo, "rev-parse", "HEAD")
    diff_task_id = f"diff-{ref[:7]}-1"
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-diff-project\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        f"    repository_path: {repo}\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [typescript]\n  frameworks: []\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: repository-{ref[:7]}\n"
        "    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-diff-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        f"    applies_to: [repository-{ref[:7]}]\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n"
        "  - id: diff-command\n"
        f"    applies_to: [{diff_task_id}]\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.cases import diff_cases, diff_text

    case = next(c for c in diff_cases() if c.name == f"demo-diff-project:{diff_task_id}")

    assert case.category == "command-injection"
    assert "exec(input)" in diff_text(case)
    assert set(case.knowledge) == {
        "guide:languages/typescript",
        "guide:protocols/mcp",
        "vuln:command-injection",
    }
    assert "knowledge" not in case.target
    assert case.provenance == "private"
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.findings] == ["diff-command"]


def test_private_diff_benchmark_can_load_git_target(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "private-context-safe"
    project.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = home / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "server.py").write_text("def get_client():\n    return current_user_client()\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "server.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "add tool")
    ref = _git(repo, "rev-parse", "HEAD")
    diff_task_id = f"diff-{ref[:7]}-1"
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: private-context-safe\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        "    repository_path: ~/repo\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [python]\n  frameworks: [fastapi]\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [insecure-direct-object-reference]\n"
        "  guides: [frameworks/python/fastapi, languages/python, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: clean\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: private-context-safe\n"
        "checks:\n"
        "  - id: per-user-client\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: clean\n"
        "    locations:\n      files: [server.py]\n"
        "    knowledge:\n"
        "      vulnerabilities: [insecure-direct-object-reference]\n"
        "      guides: [frameworks/python/fastapi, languages/python, protocols/mcp]\n"
        "",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.cases import diff_cases, diff_text

    case = next(c for c in diff_cases() if c.name == f"private-context-safe:{diff_task_id}")
    assert "tool()" in diff_text(case)
    assert case.context == ""
    assert case.target["root"] == "~/repo"
    assert case.target["path"] == "."
    assert case.provenance == "private"
    assert case.expectation == "clean"
    assert not case.is_positive
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.clean] == ["per-user-client"]
    from evals.benchmarks.coverage import coverage_matrix

    cov = coverage_matrix()
    assert cov["vuln:insecure-direct-object-reference"].private >= 1


def test_diff_benchmark_can_load_git_url_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "add exec")
    ref = _git(repo, "rev-parse", "HEAD")
    diff_task_id = f"diff-{ref[:7]}-1"
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: public-real-diff\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        f"    repository_path: {repo}\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [typescript]\n  frameworks: []\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: public-real-diff\n"
        "checks:\n"
        "  - id: exec-command\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n      symbols: [exec]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n"
        "      guides: [languages/typescript, protocols/mcp]\n"
        "",
        encoding="utf-8",
    )
    from evals.benchmarks.cases import diff_text, load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert case.diff == ""
    assert "exec(input)" in diff_text(case)
    assert case.name == f"public-real-diff:{diff_task_id}"
    assert case.target["root"] == str(repo)
    assert case.provenance == "public"


def test_git_url_diff_fetches_exact_commit_targets(tmp_path, monkeypatch):
    """Git URL diff fetches concrete SHAs before diffing."""
    from evals.benchmarks import cases
    from evals.benchmarks.cases import DiffCase, diff_text

    root = tmp_path / "repo"
    root.mkdir()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[3] == "cat-file":
            return subprocess.CompletedProcess(cmd, 1)
        if cmd[3] == "diff":
            return subprocess.CompletedProcess(cmd, 0, stdout="diff --git a/app.py b/app.py\n+sink()\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(cases, "git_target_root", lambda target: root)
    monkeypatch.setattr(cases.subprocess, "run", fake_run)

    diff = diff_text(
        DiffCase(
            name="needs-fetch",
            diff="",
            target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
        )
    )

    assert "sink()" in diff
    assert ["git", "-C", str(root), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(root), "fetch", "origin", "def456"] in calls


def test_project_diff_task_uses_manifest_profile(tmp_path):
    """Project profile supplies the profile for every task."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir)
    for path in (manifest, case_dir / "answer-key.yaml"):
        path.write_text(
            path.read_text(encoding="utf-8")
            .replace("contract-project", "solidity-real-diff")
            .replace("command-injection", "reentrancy")
            .replace("languages/python", "languages/solidity"),
            encoding="utf-8",
        )
    manifest.write_text(
        manifest.read_text(encoding="utf-8")
        .replace("profile: web", "profile: evm")
        .replace("languages: [python]", "languages: [solidity]"),
        encoding="utf-8",
    )
    from evals.benchmarks.cases import load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert case.profile == "evm"


def test_project_diff_task_profile_overrides_manifest_profile(tmp_path):
    """Task metadata cannot override the manifest profile."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n", "    expectation: findings\n    profile: evm\n"
    )
    manifest.write_text(text, encoding="utf-8")
    from evals.benchmarks.cases import load_project_diff_cases

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        load_project_diff_cases(manifest)


def test_clean_diff_task_scores_the_fixed_issue_as_clean(tmp_path):
    """Clean diff tasks treat the repaired issue anchor as clean."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir, outcome="clean")
    key = case_dir / "answer-key.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("contract-project", "fixed-real-diff"),
        encoding="utf-8",
    )
    key_data = yaml.safe_load(key.read_text(encoding="utf-8"))
    entry = key_data["checks"][0]
    key_data["benchmark_id"] = "fixed-real-diff"
    entry["id"] = "shell-command"
    entry["expectation"] = "clean"
    entry.pop("severity", None)
    key.write_text(yaml.safe_dump(key_data, sort_keys=False), encoding="utf-8")
    from evals.benchmarks.cases import load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert not case.is_positive
    assert case.outcome == "clean"
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.findings] == []
    assert [entry.id for entry in case.answer_key.clean] == ["shell-command"]


def test_solidity_diff_benchmarks_declare_evm_profile():
    """Explicit benchmark routing keeps runs independent of checkout file heuristics."""
    root = Path("evals/benchmarks/languages/solidity")
    for manifest in sorted(root.glob("*/benchmark.yaml")):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        diff_tasks = [task for task in data.get("tasks") or [] if task.get("kind") == "diff"]
        if diff_tasks:
            assert data.get("profile") == "evm", f"{manifest} should declare profile: evm"


def test_shipped_diff_tasks_declare_expectation():
    tasks = _public_diff_tasks()

    assert tasks
    assert {task.get("expectation") for task in tasks} <= {"clean", "findings"}
    assert all(task.get("expectation") for task in tasks)


def test_shipped_task_ids_follow_the_benchmark_naming_contract():
    """Shipped task ids contain the commit prefix and task sequence."""
    root = Path(registry.__file__).resolve().parent
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            task_id = str(task.get("id") or "")
            if task.get("kind") == "repository":
                source = data["source"]
                if source["kind"] == "git":
                    token = str((task.get("revision") or {}).get("commit") or source["identity"]["commit"])
                else:
                    token = str(source["identity"]["address"]).lower().removeprefix("0x")
                assert task_id == f"repository-{token[:7].lower()}", f"{manifest}: {task_id}"
                continue
            match = re.fullmatch(r"diff-([0-9a-f]{7})-([0-9]+)", task_id)
            assert match, f"{manifest}: {task_id}"
            assert match.group(1) == str(task["revision"]["commit"])[:7].lower(), f"{manifest}: {task_id}"


def test_shipped_diff_tasks_review_the_whole_commit():
    """File scope hints would disclose the expected answer to the reviewer."""
    scoped = [
        f"{manifest}: {task.get('id')}"
        for manifest, task in _public_diff_task_rows()
        if "diff_path" in task or "diff_paths" in task
    ]

    assert scoped == []


def test_shipped_answer_key_applies_to_references_existing_tasks():
    """Shipped answer key task references point at existing manifest tasks."""
    root = Path(registry.__file__).resolve().parent
    for manifest in sorted(root.rglob("benchmark.yaml")):
        key_file = manifest.parent / "answer-key.yaml"
        if not key_file.is_file():
            continue
        benchmark = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        known = {str(task.get("id")) for task in benchmark.get("tasks") or [] if task.get("id")}
        key = yaml.safe_load(key_file.read_text(encoding="utf-8")) or {}
        for entry in key.get("entries") or []:
            for task_id in entry.get("task_ids") or []:
                assert task_id in known, f"{key_file} references unknown task {task_id!r}"


def test_diff_source_root_fetches_exact_commit_targets(monkeypatch, tmp_path):
    """Diff source checkout fetches concrete SHAs before adding the worktree."""
    from contextlib import contextmanager

    from evals.benchmarks.cases import DiffCase
    from evals.review import diff as diffmod

    root = tmp_path / "repo"
    root.mkdir()
    calls = []

    @contextmanager
    def fake_target_tree(root, ref):
        yield tmp_path / "checkout"

    def fake_ensure(target, root=None):
        calls.append((target, root))

    monkeypatch.setattr(diffmod, "git_target_root", lambda target: root)
    monkeypatch.setattr(diffmod, "ensure_git_target_refs", fake_ensure)
    monkeypatch.setattr(diffmod, "_target_tree", fake_target_tree)

    case = DiffCase(
        name="needs-fetch",
        diff="diff --git a/app.py b/app.py\n+sink()\n",
        target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
    )
    with diffmod._source_root(case) as checkout:
        assert checkout == tmp_path / "checkout"

    assert calls == [(case.target, root)]


def test_diff_review_root_uses_the_git_url_target_path(tmp_path):
    from evals.review import diff as diffmod

    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)

    target = {"type": "git", "url": "https://example.com/repo.git", "path": "contracts"}
    assert diffmod._review_root(root, target) == scope


def test_diff_review_root_rejects_escaping_target_paths(tmp_path):
    from evals.review import diff as diffmod

    root = tmp_path / "repo"
    root.mkdir()

    with pytest.raises(ValueError, match="inside the repository"):
        diffmod._review_root(root, {"type": "git", "url": "https://example.com/repo.git", "path": "../outside"})


def test_git_url_diff_uses_the_target_path_as_a_pathspec(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "scope").mkdir()
    (repo / "outside").mkdir()
    (repo / "scope" / "app.py").write_text("value = 'base'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'base'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "scope" / "app.py").write_text("value = 'ref'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'ref'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "ref")
    ref = _git(repo, "rev-parse", "HEAD")
    from evals.benchmarks.cases import DiffCase, diff_text

    diff = diff_text(
        DiffCase(
            name="scoped",
            diff="",
            target={"type": "git", "url": repo.as_uri(), "path": "scope", "base": base, "ref": ref},
        )
    )

    assert "scope/app.py" in diff
    assert "outside/noise.py" not in diff


def test_shipped_diff_library_uses_real_project_tasks(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()
    by_name = {c.name: c for c in cases}
    case = next(case for name, case in by_name.items() if name.startswith("github-mcp-server:diff-1c4cb29-"))
    assert len(by_name) == _public_diff_task_count()
    assert case.answer_key is not None
    assert len(case.answer_key.findings) == 1
