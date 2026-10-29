"""Benchmark Git targets fetch the exact commits their cases pin and report git's own errors."""

from __future__ import annotations

import subprocess

import pytest

from evals.benchmarks import targets
from tests.support import git


def test_git_url_targets_fetch_exact_commits(tmp_path, monkeypatch):
    """When cat-file misses after the clone, base abc123 and commit def456 are each fetched from origin by hash."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if cmd[3] == "cat-file" else 0)

    monkeypatch.setattr(targets.subprocess, "run", fake_run)
    monkeypatch.setattr(targets.Path, "home", lambda: tmp_path)
    target = {"url": "https://example.com/repo.git", "base": "abc123", "commit": "def456"}

    root = targets.git_target_root(target)

    assert ["git", "-C", str(root), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(root), "fetch", "origin", "def456"] in calls


def test_a_failed_checkout_reports_the_git_error(tmp_path):
    """Checking out a commit the repository lacks raises with git's own invalid reference message."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet")

    with (
        pytest.raises(RuntimeError, match="invalid reference"),
        targets.source_root({"local_path": str(repo), "commit": "0" * 40}),
    ):
        pass


def test_git_url_targets_skip_fetching_commits_the_clone_already_has(tmp_path, monkeypatch):
    """When cat-file finds both pinned commits, no fetch by hash is issued."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(targets.subprocess, "run", fake_run)
    monkeypatch.setattr(targets.Path, "home", lambda: tmp_path)

    targets.git_target_root({"url": "https://example.com/repo.git", "base": "abc123", "commit": "def456"})

    assert not any(cmd[3:5] == ["fetch", "origin"] for cmd in calls)


def test_a_local_target_resolves_to_its_path_without_running_git(tmp_path, monkeypatch):
    """A local_path target returns that path and never calls git."""
    monkeypatch.setattr(targets.subprocess, "run", lambda *args, **kwargs: pytest.fail("git was called"))

    assert targets.git_target_root({"local_path": str(tmp_path), "commit": "def456"}) == tmp_path
