"""Benchmark cases materialize repository and diff tasks from one project contract."""

from __future__ import annotations

import re
import subprocess

import pytest
import yaml

from evals.benchmarks import cases, registry
from evals.benchmarks.cases import DiffCase, diff_text, find_repository_case
from evals.benchmarks.contract import AnswerKey, ExpectedChange, ExpectedLocation, KeyCheck, load_answer_key


def test_registry_finds_the_public_paperless_benchmark(tmp_path, monkeypatch, public_only):
    public_only(tmp_path, monkeypatch)
    bench = find_repository_case("paperless-ngx")
    assert bench.provenance == "public"
    key = load_answer_key(bench.answer_key)
    assert key.benchmark_id == "paperless-ngx"
    assert key.findings


def test_registry_exposes_repository_task_from_project_source(tmp_path, monkeypatch):
    src = tmp_path / "private"
    project = src / "demo-project"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        "    url: https://example.com/demo.git\n"
        "    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "  path: src/tools\n"
        "tasks:\n"
        "  - id: repository-aaaaaaa\n"
        "    kind: repository\n"
        "  - id: diff-bbbbbbb-1\n"
        "    kind: diff\n"
        "    revision:\n"
        "      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "    expectation: findings\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        "    applies_to: [repository-aaaaaaa]\n"
        "    expectation: findings\n"
        "    locations:\n"
        "      - {file: src/tools/run.ts, line: 1}\n"
        "  - id: diff-command\n"
        "    applies_to: [diff-bbbbbbb-1]\n"
        "    expectation: findings\n"
        "    locations:\n"
        "      - {file: src/tools/run.ts, line: 1}\n"
        "    changes:\n"
        "      - {file: src/tools/run.ts, line: 1, side: new}\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    bench = find_repository_case("demo-project")
    key = load_answer_key(bench.answer_key, task_id=bench.task_id)

    assert bench.project_id == "demo-project"
    assert bench.task_id == "repository-aaaaaaa"
    assert bench.target == {
        "type": "git",
        "url": "https://example.com/demo.git",
        "ref": "a" * 40,
        "path": "src/tools",
    }
    assert [entry.id for entry in key.findings] == ["repo-command"]


_PATCH = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,5 +1,5 @@\n"
    " import requests\n"
    " \n"
    " def fetch(url):\n"
    "-    return requests.get(ALLOWED + url)\n"
    "+    return requests.get(url)\n"
    " \n"
)


def _anchored_case(anchor: ExpectedChange, monkeypatch) -> DiffCase:
    monkeypatch.setattr(cases, "_target_diff", lambda target: _PATCH)
    key = AnswerKey(
        benchmark_id="demo",
        checks=(
            KeyCheck(
                id="changed-line",
                expectation="findings",
                applies_to=("diff-abcdef0-1",),
                locations=(ExpectedLocation(file="app.py", line=4),),
                changes=(anchor,),
            ),
        ),
    )
    return DiffCase(name="demo:diff-abcdef0-1", answer_key=key)


@pytest.mark.parametrize(
    "anchor",
    [
        ExpectedChange(file="app.py", line=4, side="old"),
        ExpectedChange(file="app.py", line=4, side="new"),
    ],
)
def test_diff_text_accepts_an_exact_materialized_change_anchor(anchor, monkeypatch):
    assert diff_text(_anchored_case(anchor, monkeypatch)) == _PATCH


def test_diff_text_rejects_a_change_anchor_absent_from_the_materialized_patch(monkeypatch):
    case = _anchored_case(ExpectedChange(file="does-not-exist.py", line=999999, side="old"), monkeypatch)

    with pytest.raises(ValueError, match=r"change anchor .* is absent from the materialized patch"):
        diff_text(case)


def test_default_diff_cases_load_project_diff_tasks(tmp_path, monkeypatch, public_diff_task_count, public_only):
    public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()
    names = {c.name for c in cases}
    assert any(name.startswith("paperless-ngx:diff-") for name in names)
    assert len(names) == public_diff_task_count()
    assert {c.expectation for c in cases} == {"clean", "findings"}


def test_default_diff_cases_use_real_git_commit_targets(tmp_path, monkeypatch, public_only):
    public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()

    assert all(c.target.get("type") == "git" for c in cases)
    assert all(c.target.get("base") and c.target.get("ref") for c in cases)
    assert all(len(str(c.target.get("base") or "")) == 40 and len(str(c.target.get("ref") or "")) == 40 for c in cases)


def test_project_diff_task_loads_from_shared_manifest(tmp_path, monkeypatch, git_runner):
    repo = tmp_path / "repo"
    repo.mkdir()
    git_runner(repo, "init")
    git_runner(repo, "config", "user.email", "test@example.com")
    git_runner(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    git_runner(repo, "add", "tool.ts")
    git_runner(repo, "commit", "-m", "base")
    base = git_runner(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    git_runner(repo, "add", "tool.ts")
    git_runner(repo, "commit", "-m", "add exec")
    ref = git_runner(repo, "rev-parse", "HEAD")
    diff_task_id = f"diff-{ref[:7]}-1"
    src = tmp_path / "private"
    project = src / "demo-diff-project"
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
        "tasks:\n"
        f"  - id: repository-{ref[:7]}\n"
        "    kind: repository\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-diff-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        f"    applies_to: [repository-{ref[:7]}]\n    expectation: findings\n"
        "    locations:\n      - {file: tool.ts, line: 2}\n"
        "  - id: diff-command\n"
        f"    applies_to: [{diff_task_id}]\n    expectation: findings\n"
        "    locations:\n      - {file: tool.ts, line: 2}\n"
        "    changes:\n      - {file: tool.ts, line: 2, side: new}\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.cases import diff_cases, diff_text

    case = next(c for c in diff_cases() if c.name == f"demo-diff-project:{diff_task_id}")

    assert "exec(input)" in diff_text(case)
    assert case.provenance == "private"
    assert [entry.id for entry in case.answer_key.findings] == ["diff-command"]


def test_private_diff_benchmark_can_load_git_target(tmp_path, monkeypatch, git_runner):
    src = tmp_path / "private"
    project = src / "private-context-safe"
    project.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = home / "repo"
    repo.mkdir()
    git_runner(repo, "init")
    git_runner(repo, "config", "user.email", "test@example.com")
    git_runner(repo, "config", "user.name", "Test User")
    (repo / "server.py").write_text("def get_client():\n    return current_user_client()\n", encoding="utf-8")
    git_runner(repo, "add", "server.py")
    git_runner(repo, "commit", "-m", "base")
    base = git_runner(repo, "rev-parse", "HEAD")
    (repo / "server.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    git_runner(repo, "add", "server.py")
    git_runner(repo, "commit", "-m", "add tool")
    ref = git_runner(repo, "rev-parse", "HEAD")
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
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: clean\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: private-context-safe\n"
        "checks:\n"
        "  - id: per-user-client\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: clean\n"
        "    locations:\n      - {file: server.py, symbol: tool}\n"
        "    changes:\n      - {file: server.py, line: 4, side: new}\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.benchmarks.cases import diff_cases, diff_text

    case = next(c for c in diff_cases() if c.name == f"private-context-safe:{diff_task_id}")
    assert "tool()" in diff_text(case)
    assert case.target["root"] == "~/repo"
    assert case.target["path"] == "."
    assert case.provenance == "private"
    assert case.expectation == "clean"
    assert not case.is_positive
    assert [entry.id for entry in case.answer_key.clean] == ["per-user-client"]


def test_diff_benchmark_can_load_git_url_target(tmp_path, monkeypatch, git_runner):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    git_runner(repo, "init")
    git_runner(repo, "config", "user.email", "test@example.com")
    git_runner(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    git_runner(repo, "add", "tool.ts")
    git_runner(repo, "commit", "-m", "base")
    base = git_runner(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    git_runner(repo, "add", "tool.ts")
    git_runner(repo, "commit", "-m", "add exec")
    ref = git_runner(repo, "rev-parse", "HEAD")
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
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: public-real-diff\n"
        "checks:\n"
        "  - id: exec-command\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: findings\n"
        "    locations:\n      - {file: tool.ts, symbol: run}\n"
        "    changes:\n      - {file: tool.ts, line: 2, side: new}\n",
        encoding="utf-8",
    )
    from evals.benchmarks.cases import diff_text, load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert "exec(input)" in diff_text(case)
    assert case.name == f"public-real-diff:{diff_task_id}"
    assert case.target["root"] == str(repo)
    assert case.provenance == "public"


def test_git_url_diff_fetches_exact_commit_targets(tmp_path, monkeypatch):
    from evals.benchmarks import cases
    from evals.benchmarks.cases import DiffCase, diff_text
    from evals.benchmarks.contract import AnswerKey

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
            answer_key=AnswerKey(benchmark_id="t", checks=()),
            target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
        )
    )

    assert "sink()" in diff
    assert ["git", "-C", str(root), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(root), "fetch", "origin", "def456"] in calls


def test_project_diff_task_rejects_a_task_profile(tmp_path, write_contract_project):
    case_dir = tmp_path / "case"
    manifest = write_contract_project(case_dir)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n", "    expectation: findings\n    profile: web\n"
    )
    manifest.write_text(text, encoding="utf-8")
    from evals.benchmarks.cases import load_project_diff_cases

    with pytest.raises(ValueError, match=r"benchmark-v1\.schema"):
        load_project_diff_cases(manifest)


def test_clean_diff_task_scores_the_fixed_issue_as_clean(tmp_path, write_contract_project):
    case_dir = tmp_path / "case"
    manifest = write_contract_project(case_dir, outcome="clean")
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
    key.write_text(yaml.safe_dump(key_data, sort_keys=False), encoding="utf-8")
    from evals.benchmarks.cases import load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert not case.is_positive
    assert case.expectation == "clean"
    assert [entry.id for entry in case.answer_key.findings] == []
    assert [entry.id for entry in case.answer_key.clean] == ["shell-command"]


def test_git_url_diff_uses_the_target_path_as_a_pathspec(tmp_path, git_runner):
    repo = tmp_path / "repo"
    repo.mkdir()
    git_runner(repo, "init")
    git_runner(repo, "config", "user.email", "test@example.com")
    git_runner(repo, "config", "user.name", "Test User")
    (repo / "scope").mkdir()
    (repo / "outside").mkdir()
    (repo / "scope" / "app.py").write_text("value = 'base'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'base'\n", encoding="utf-8")
    git_runner(repo, "add", ".")
    git_runner(repo, "commit", "-m", "base")
    base = git_runner(repo, "rev-parse", "HEAD")
    (repo / "scope" / "app.py").write_text("value = 'ref'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'ref'\n", encoding="utf-8")
    git_runner(repo, "add", ".")
    git_runner(repo, "commit", "-m", "ref")
    ref = git_runner(repo, "rev-parse", "HEAD")
    from evals.benchmarks.cases import DiffCase, diff_text
    from evals.benchmarks.contract import AnswerKey

    diff = diff_text(
        DiffCase(
            name="scoped",
            answer_key=AnswerKey(benchmark_id="t", checks=()),
            target={"type": "git", "url": repo.as_uri(), "path": "scope", "base": base, "ref": ref},
        )
    )

    assert "scope/app.py" in diff
    assert "outside/noise.py" not in diff


def test_shipped_diff_library_uses_real_project_tasks(tmp_path, monkeypatch, public_diff_task_count, public_only):
    public_only(tmp_path, monkeypatch)
    from evals.benchmarks.cases import diff_cases

    cases = diff_cases()
    by_name = {c.name: c for c in cases}
    case = by_name["paperless-ngx:diff-11af74b-3"]
    assert len(by_name) == public_diff_task_count()
    assert len(case.answer_key.findings) == 1


def test_shipped_diff_tasks_declare_expectation(public_diff_tasks):
    tasks = public_diff_tasks()

    assert tasks
    assert {task.get("expectation") for task in tasks} <= {"clean", "findings"}
    assert all(task.get("expectation") for task in tasks)


def test_shipped_task_ids_follow_the_benchmark_naming_contract():
    root = registry.PUBLIC_PROJECTS_DIR
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            task_id = str(task.get("id") or "")
            if task.get("kind") == "repository":
                token = str((task.get("revision") or {}).get("commit") or data["source"]["identity"]["commit"])
                assert task_id == f"repository-{token[:7].lower()}", f"{manifest}: {task_id}"
                continue
            match = re.fullmatch(r"diff-([0-9a-f]{7})-([0-9]+)", task_id)
            assert match, f"{manifest}: {task_id}"
            assert match.group(1) == str(task["revision"]["commit"])[:7].lower(), f"{manifest}: {task_id}"


def test_shipped_answer_key_applies_to_references_existing_tasks():
    root = registry.PUBLIC_PROJECTS_DIR
    for manifest in sorted(root.rglob("benchmark.yaml")):
        key_file = manifest.parent / "answer-key.yaml"
        if not key_file.is_file():
            continue
        benchmark = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        known = {str(task.get("id")) for task in benchmark.get("tasks") or [] if task.get("id")}
        key = yaml.safe_load(key_file.read_text(encoding="utf-8")) or {}
        for check in key.get("checks") or []:
            for task_id in check.get("applies_to") or []:
                assert task_id in known, f"{key_file} references unknown task {task_id!r}"
