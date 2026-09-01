"""Resolved targets bind canonical Git comparisons to exact source roots."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import cyberjury.sources.git as gitmod
from cyberjury.review.paths import repository_files
from cyberjury.review.target import (
    ResolvedTarget,
    TargetResolutionError,
    materialize_diff_target,
    resolve_diff_target,
    resolve_repository_target,
)


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()


def _repository(root: Path) -> tuple[Path, str, str]:
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / "app.py").write_text("base\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "--quiet", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("head\n", encoding="utf-8")
    _git(root, "commit", "--quiet", "-am", "head")
    head = _git(root, "rev-parse", "HEAD")
    return root, base, head


def test_two_dot_target_round_trips_and_materializes_resolved_head(tmp_path):
    repository, base, head = _repository(tmp_path / "repo")

    target = resolve_diff_target(repository, f"{base}..{head}")
    restored = ResolvedTarget.from_dict(target.to_dict())

    assert restored == target
    assert target.git is not None
    assert target.git.range_kind == "two-dot"
    assert target.git.left_revision == base
    assert target.git.patch_base_revision == base
    assert target.git.right_revision == head
    assert target.patch is not None
    assert "+head" in target.patch.text
    with materialize_diff_target(target) as source_root:
        assert (source_root / "app.py").read_text(encoding="utf-8") == "head\n"
        assert ".git" not in repository_files(source_root)


def test_three_dot_target_keeps_left_endpoint_and_unique_merge_base(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / "base.txt").write_text("base\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "checkout", "--quiet", "-b", "left")
    (repository / "left.txt").write_text("left\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "left")
    left = _git(repository, "rev-parse", "HEAD")
    _git(repository, "checkout", "--quiet", "-b", "right", base)
    (repository / "right.txt").write_text("right\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "right")
    right = _git(repository, "rev-parse", "HEAD")

    target = resolve_diff_target(repository, "left...right")

    assert target.git is not None
    assert target.git.range_kind == "three-dot"
    assert target.git.left_revision == left
    assert target.git.right_revision == right
    assert target.git.patch_base_revision == base
    assert target.patch is not None
    assert "+right" in target.patch.text
    assert "left.txt" not in target.patch.text


def test_resolved_target_is_immune_to_later_symbolic_ref_movement(tmp_path):
    repository, base, head = _repository(tmp_path / "repo")
    target = resolve_diff_target(repository, f"{base}..HEAD")
    (repository / "app.py").write_text("later\n", encoding="utf-8")
    _git(repository, "commit", "--quiet", "-am", "later")

    assert target.git is not None
    assert target.git.right_revision == head
    assert target.patch is not None
    assert "+head" in target.patch.text
    assert "+later" not in target.patch.text
    with materialize_diff_target(target) as source_root:
        assert (source_root / "app.py").read_text(encoding="utf-8") == "head\n"


def test_diff_target_uses_git_top_level_for_subdirectory_input(tmp_path):
    repository, base, head = _repository(tmp_path / "repo")
    subdirectory = repository / "src"
    subdirectory.mkdir()

    target = resolve_diff_target(subdirectory, f"{base}..{head}")

    assert target.repository_root == str(repository.resolve())


@pytest.mark.parametrize(
    "git_range",
    ["HEAD", "..HEAD", "HEAD..", "HEAD..HEAD..HEAD", "HEAD HEAD"],
)
def test_diff_target_rejects_noncommitted_or_option_like_ranges(tmp_path, git_range):
    repository, _base, _head = _repository(tmp_path / "repo")

    with pytest.raises(TargetResolutionError):
        resolve_diff_target(repository, git_range)


def test_option_like_git_range_cannot_write_an_output_file(tmp_path):
    repository, _base, _head = _repository(tmp_path / "repo")
    unexpected = tmp_path / "unexpected.patch"

    with pytest.raises(TargetResolutionError, match="Git option"):
        resolve_diff_target(repository, f"--output={unexpected}")

    assert not unexpected.exists()


def test_operator_git_diff_configuration_does_not_change_patch(tmp_path):
    repository, base, head = _repository(tmp_path / "repo")
    first = resolve_diff_target(repository, f"{base}..{head}")
    _git(repository, "config", "diff.renames", "true")
    _git(repository, "config", "diff.external", "/bin/false")
    _git(repository, "config", "color.ui", "always")
    _git(repository, "config", "core.abbrev", "4")
    _git(repository, "config", "diff.indentHeuristic", "true")
    _git(repository, "config", "diff.interHunkContext", "20")

    second = resolve_diff_target(repository, f"{base}..{head}")

    assert second.patch == first.patch
    assert second.target_sha256 == first.target_sha256


def test_git_materialization_uses_exact_blobs_without_smudge_filter(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / ".gitattributes").write_text("*.txt filter=demo\n")
    (repository / "value.txt").write_text("blob-base\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "value.txt").write_text("blob-head\n")
    _git(repository, "commit", "--quiet", "-am", "head")
    _git(repository, "config", "filter.demo.smudge", "sed s/blob/worktree/")
    target = resolve_diff_target(repository, f"{base}..HEAD")

    with materialize_diff_target(target) as source_root:
        assert (source_root / "value.txt").read_bytes() == b"blob-head\n"


def test_canonical_patch_keeps_the_default_rename_representation(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / "before.py").write_text("value = 1\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "mv", "before.py", "after.py")
    _git(repository, "commit", "--quiet", "-m", "rename")
    _git(repository, "config", "diff.renames", "false")

    target = resolve_diff_target(repository, f"{base}..HEAD")

    assert target.patch is not None
    assert "rename from before.py" in target.patch.text
    assert "rename to after.py" in target.patch.text


def test_diff_target_fails_loud_when_head_contains_unacquired_submodule(tmp_path):
    repository, base, _head = _repository(tmp_path / "repo")
    _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dependency")
    _git(repository, "commit", "--quiet", "-m", "gitlink")

    with pytest.raises(TargetResolutionError, match="submodules"):
        resolve_diff_target(repository, f"{base}..HEAD")


def test_repository_target_requires_a_real_nonsymlink_directory(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    link = tmp_path / "link"
    link.symlink_to(repository, target_is_directory=True)

    assert resolve_repository_target(repository).repository_root == str(repository.resolve())
    with pytest.raises(TargetResolutionError, match="symlink"):
        resolve_repository_target(link)


def test_diff_target_fails_loud_before_returning_an_oversized_patch(monkeypatch, tmp_path):
    repository, base, _head = _repository(tmp_path / "repo")
    monkeypatch.setattr(gitmod, "_MAX_PATCH_BYTES", 1)

    with pytest.raises(TargetResolutionError, match="patch exceeds the byte limit"):
        resolve_diff_target(repository, f"{base}..HEAD")
