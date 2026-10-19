"""Benchmark git targets fetch the exact commits their cases pin."""

from __future__ import annotations

import subprocess

from evals.benchmarks import targets


def test_git_url_targets_fetch_exact_commits(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if cmd[3] == "cat-file" else 0)

    monkeypatch.setattr(targets.subprocess, "run", fake_run)
    target = {"url": "https://example.com/repo.git", "base": "abc123", "commit": "def456"}

    targets.ensure_git_target_refs(target, tmp_path)

    assert ["git", "-C", str(tmp_path), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(tmp_path), "fetch", "origin", "def456"] in calls


def test_url_targets_are_cached_under_a_target_neutral_directory():
    path = targets.target_repository({"url": "https://example.com/org/repo.git", "commit": "def456"})

    assert path.parent.name == "benchmark-targets"
    assert path.name.startswith("repo-")
