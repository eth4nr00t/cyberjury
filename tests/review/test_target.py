"""Resolved targets bind canonical Git comparisons to exact source roots."""

from __future__ import annotations

from pathlib import Path

import pytest

import cyberjury.sources.git as gitmod
from cyberjury.review.target import (
    TargetResolutionError,
    materialize_diff_target,
    resolve_diff_target,
    resolve_repository_target,
)
from tests.support import git


def _repository(root: Path) -> tuple[Path, str, str]:
    root.mkdir()
    git(root, "init", "--quiet")
    (root / "app.py").write_text("base\n", encoding="utf-8")
    git(root, "add", "app.py")
    git(root, "commit", "--quiet", "-m", "base")
    base = git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("head\n", encoding="utf-8")
    git(root, "commit", "--quiet", "-am", "head")
    head = git(root, "rev-parse", "HEAD")
    return root, base, head


def test_two_dot_target_materializes_resolved_head(tmp_path):
    """A base..head range patches from base, and the materialized root holds app.py as head without .git."""
    repository, base, head = _repository(tmp_path / "repo")

    target = resolve_diff_target(repository, f"{base}..{head}")
    assert target.git is not None
    assert target.git.range_kind == "two-dot"
    assert target.git.left_revision == base
    assert target.git.patch_base_revision == base
    assert target.git.right_revision == head
    assert target.patch is not None
    assert "+head" in target.patch.text
    with materialize_diff_target(target) as source_root:
        assert (source_root / "app.py").read_text(encoding="utf-8") == "head\n"
        assert not (source_root / ".git").exists()


def test_three_dot_target_keeps_left_endpoint_and_unique_merge_base(tmp_path):
    """A left...right range patches from the merge base, so right.txt appears and left.txt does not."""
    repository = tmp_path / "repo"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / "base.txt").write_text("base\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "base")
    base = git(repository, "rev-parse", "HEAD")
    git(repository, "checkout", "--quiet", "-b", "left")
    (repository / "left.txt").write_text("left\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "left")
    left = git(repository, "rev-parse", "HEAD")
    git(repository, "checkout", "--quiet", "-b", "right", base)
    (repository / "right.txt").write_text("right\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "right")
    right = git(repository, "rev-parse", "HEAD")

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
    """A base..HEAD target keeps the original head commit after a later commit moves HEAD."""
    repository, base, head = _repository(tmp_path / "repo")
    target = resolve_diff_target(repository, f"{base}..HEAD")
    (repository / "app.py").write_text("later\n", encoding="utf-8")
    git(repository, "commit", "--quiet", "-am", "later")

    assert target.git is not None
    assert target.git.right_revision == head
    assert target.patch is not None
    assert "+head" in target.patch.text
    assert "+later" not in target.patch.text
    with materialize_diff_target(target) as source_root:
        assert (source_root / "app.py").read_text(encoding="utf-8") == "head\n"


def test_diff_target_uses_git_top_level_for_subdirectory_input(tmp_path):
    """Resolving from the src subdirectory reports the repository top level as repository_root."""
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
    """HEAD, ..HEAD, HEAD.., HEAD..HEAD..HEAD, and HEAD HEAD all raise TargetResolutionError."""
    repository, _base, _head = _repository(tmp_path / "repo")

    with pytest.raises(TargetResolutionError):
        resolve_diff_target(repository, git_range)


def test_option_like_git_range_cannot_write_an_output_file(tmp_path):
    """A --output=<path> range is rejected as a Git option and no patch file is created."""
    repository, _base, _head = _repository(tmp_path / "repo")
    unexpected = tmp_path / "unexpected.patch"

    with pytest.raises(TargetResolutionError, match="Git option"):
        resolve_diff_target(repository, f"--output={unexpected}")

    assert not unexpected.exists()


def test_operator_git_diff_configuration_does_not_change_patch(tmp_path):
    """Setting diff.renames, diff.external, color.ui, core.abbrev and similar leaves patch and hash unchanged."""
    repository, base, head = _repository(tmp_path / "repo")
    first = resolve_diff_target(repository, f"{base}..{head}")
    git(repository, "config", "diff.renames", "true")
    git(repository, "config", "diff.external", "/bin/false")
    git(repository, "config", "color.ui", "always")
    git(repository, "config", "core.abbrev", "4")
    git(repository, "config", "diff.indentHeuristic", "true")
    git(repository, "config", "diff.interHunkContext", "20")

    second = resolve_diff_target(repository, f"{base}..{head}")

    assert second.patch == first.patch
    assert second.target_sha256 == first.target_sha256


def test_git_materialization_uses_exact_blobs_without_smudge_filter(tmp_path):
    """A configured smudge filter on *.txt is skipped, so value.txt materializes as blob-head."""
    repository = tmp_path / "repo"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / ".gitattributes").write_text("*.txt filter=demo\n")
    (repository / "value.txt").write_text("blob-base\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "base")
    base = git(repository, "rev-parse", "HEAD")
    (repository / "value.txt").write_text("blob-head\n")
    git(repository, "commit", "--quiet", "-am", "head")
    git(repository, "config", "filter.demo.smudge", "sed s/blob/worktree/")
    target = resolve_diff_target(repository, f"{base}..HEAD")

    with materialize_diff_target(target) as source_root:
        assert (source_root / "value.txt").read_bytes() == b"blob-head\n"


def test_canonical_patch_keeps_the_default_rename_representation(tmp_path):
    """With diff.renames=false configured, the patch still shows rename from before.py to after.py."""
    repository = tmp_path / "repo"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / "before.py").write_text("value = 1\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "base")
    base = git(repository, "rev-parse", "HEAD")
    git(repository, "mv", "before.py", "after.py")
    git(repository, "commit", "--quiet", "-m", "rename")
    git(repository, "config", "diff.renames", "false")

    target = resolve_diff_target(repository, f"{base}..HEAD")

    assert target.patch is not None
    assert "rename from before.py" in target.patch.text
    assert "rename to after.py" in target.patch.text


def test_diff_target_with_a_submodule_materializes_without_it(tmp_path):
    """A head commit holding a gitlink at lib/dependency resolves and materializes app.py without lib/dependency."""
    repository, base, _head = _repository(tmp_path / "repo")
    git(repository, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dependency")
    git(repository, "commit", "--quiet", "-m", "gitlink")

    target = resolve_diff_target(repository, f"{base}..HEAD")

    with materialize_diff_target(target) as source_root:
        assert (source_root / "app.py").read_text(encoding="utf-8") == "head\n"
        assert not (source_root / "lib" / "dependency").exists()


def test_diff_target_patch_ignores_a_repository_submodule_diff_setting(tmp_path):
    """With diff.submodule=log in the repository config, the gitlink still appears as a 160000 patch section."""
    repository, base, _head = _repository(tmp_path / "repo")
    git(repository, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dependency")
    git(repository, "commit", "--quiet", "-m", "gitlink")
    git(repository, "config", "diff.submodule", "log")

    target = resolve_diff_target(repository, f"{base}..HEAD")

    assert "diff --git a/lib/dependency b/lib/dependency\nnew file mode 160000" in target.patch.text


def test_repository_target_with_a_submodule_resolves(tmp_path):
    """A work tree whose index holds a gitlink at lib/dependency resolves as a repository target."""
    repository, base, _head = _repository(tmp_path / "repo")
    git(repository, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dependency")

    assert resolve_repository_target(repository).repository_root == str(repository.resolve())


def test_repository_target_requires_a_real_nonsymlink_directory(tmp_path):
    """A real directory resolves, while a symlink to it raises TargetResolutionError."""
    repository = tmp_path / "repo"
    repository.mkdir()
    link = tmp_path / "link"
    link.symlink_to(repository, target_is_directory=True)

    assert resolve_repository_target(repository).repository_root == str(repository.resolve())
    with pytest.raises(TargetResolutionError, match="symlink"):
        resolve_repository_target(link)


def test_diff_target_fails_loud_before_returning_an_oversized_patch(monkeypatch, tmp_path):
    """With the patch byte limit set to 1, resolving raises patch exceeds the byte limit."""
    repository, base, _head = _repository(tmp_path / "repo")
    monkeypatch.setattr(gitmod, "_MAX_PATCH_BYTES", 1)

    with pytest.raises(TargetResolutionError, match="patch exceeds the byte limit"):
        resolve_diff_target(repository, f"{base}..HEAD")
