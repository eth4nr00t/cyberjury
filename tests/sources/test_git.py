"""Git acquisition lists work trees, builds config-independent patches, and materializes exact committed blobs."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import cyberjury.sources.git as gitmod
from cyberjury.sources.git import GitSourceError, canonical_patch, materialize_revision, worktree_files
from tests.support import git


def _commit_symlink(repo: Path, target: bytes) -> str:
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    git(repo, "add", "app.py")
    blob = (
        subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
            input=target,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},link.py")
    git(repo, "commit", "--quiet", "-m", "link")
    return git(repo, "rev-parse", "HEAD")


def _two_commits(repo: Path) -> tuple[str, str]:
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / "app.py").write_text("base\n", encoding="utf-8")
    git(repo, "add", "app.py")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("head\n", encoding="utf-8")
    git(repo, "commit", "--quiet", "-am", "head")
    return base, git(repo, "rev-parse", "HEAD")


def test_worktree_files_leaves_out_a_checked_out_submodule(tmp_path):
    """A gitlink at lib/dep whose directory is checked out is left out, and app.py is listed."""
    git(tmp_path, "init", "--quiet")
    (tmp_path / "app.py").write_text("app\n", encoding="utf-8")
    git(tmp_path, "add", "app.py")
    git(tmp_path, "commit", "--quiet", "-m", "base")
    git(tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{git(tmp_path, 'rev-parse', 'HEAD')},lib/dep")
    (tmp_path / "lib" / "dep").mkdir(parents=True)
    (tmp_path / "lib" / "dep" / "Dep.sol").write_text("contract Dep {}\n", encoding="utf-8")

    assert worktree_files(tmp_path) == ("app.py",)


def test_operator_git_diff_configuration_does_not_change_the_patch(tmp_path):
    """Setting diff.renames, diff.external, color.ui, core.abbrev, and similar leaves the patch text unchanged."""
    repo = tmp_path / "repo"
    base, head = _two_commits(repo)
    first = canonical_patch(repo, base, head)
    git(repo, "config", "diff.renames", "true")
    git(repo, "config", "diff.external", "/bin/false")
    git(repo, "config", "color.ui", "always")
    git(repo, "config", "core.abbrev", "4")
    git(repo, "config", "diff.indentHeuristic", "true")
    git(repo, "config", "diff.interHunkContext", "20")

    assert canonical_patch(repo, base, head) == first


def test_canonical_patch_keeps_the_default_rename_representation(tmp_path):
    """With diff.renames=false configured, the patch still shows rename from before.py to after.py."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / "before.py").write_text("value = 1\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "mv", "before.py", "after.py")
    git(repo, "commit", "--quiet", "-m", "rename")
    git(repo, "config", "diff.renames", "false")

    patch = canonical_patch(repo, base, git(repo, "rev-parse", "HEAD"))

    assert "rename from before.py" in patch
    assert "rename to after.py" in patch


def test_canonical_patch_ignores_a_repository_submodule_diff_setting(tmp_path):
    """With diff.submodule=log in the repository config, the gitlink still appears as a 160000 patch section."""
    repo = tmp_path / "repo"
    base, _head = _two_commits(repo)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dependency")
    git(repo, "commit", "--quiet", "-m", "gitlink")
    git(repo, "config", "diff.submodule", "log")

    patch = canonical_patch(repo, base, git(repo, "rev-parse", "HEAD"))

    assert "diff --git a/lib/dependency b/lib/dependency\nnew file mode 160000" in patch


def test_canonical_patch_fails_loud_above_the_patch_byte_limit(monkeypatch, tmp_path):
    """With the patch byte limit set to 1, canonical_patch raises Git patch exceeds the byte limit."""
    repo = tmp_path / "repo"
    base, head = _two_commits(repo)
    monkeypatch.setattr(gitmod, "_MAX_PATCH_BYTES", 1)

    with pytest.raises(GitSourceError, match="patch exceeds the byte limit"):
        canonical_patch(repo, base, head)


def test_materialization_writes_exact_blobs_without_a_smudge_filter(tmp_path):
    """A configured smudge filter on *.txt is skipped, so value.txt materializes as blob-head."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / ".gitattributes").write_text("*.txt filter=demo\n")
    (repo / "value.txt").write_text("blob-head\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "head")
    git(repo, "config", "filter.demo.smudge", "sed s/blob/worktree/")

    with materialize_revision(repo, git(repo, "rev-parse", "HEAD")) as root:
        assert (root / "value.txt").read_bytes() == b"blob-head\n"


def test_a_relative_internal_symlink_is_materialized(tmp_path):
    """A committed link.py pointing at app.py is recreated as a symlink that reads "value = 1"."""
    repo = tmp_path / "repo"
    revision = _commit_symlink(repo, b"app.py")

    with materialize_revision(repo, revision) as root:
        link = root / "link.py"
        assert link.is_symlink()
        assert os.readlink(link) == "app.py"
        assert link.read_text(encoding="utf-8") == "value = 1\n"


@pytest.mark.parametrize(
    ("target", "message"),
    [
        pytest.param(b"/etc/passwd", "must be relative", id="absolute"),
        pytest.param(b"../outside.py", "escapes or is broken", id="escaping"),
        pytest.param(b"missing.py", "escapes or is broken", id="dangling"),
        pytest.param(b"\xff.py", "not UTF-8", id="not-utf8"),
        pytest.param(b"a" * 5000, "exceeds the byte limit", id="oversized"),
    ],
)
def test_an_unsafe_symlink_fails_materialization_and_leaves_nothing_behind(monkeypatch, tmp_path, target, message):
    """Absolute, escaping, dangling, non-UTF-8, or oversized targets raise and remove the temporary root."""
    repo = tmp_path / "repo"
    revision = _commit_symlink(repo, target)
    created = []
    make_temporary = gitmod.tempfile.mkdtemp

    def recorded(**kwargs):
        created.append(Path(make_temporary(**kwargs)))
        return str(created[-1])

    monkeypatch.setattr(gitmod.tempfile, "mkdtemp", recorded)
    yielded = []

    with pytest.raises(GitSourceError, match=message), materialize_revision(repo, revision) as root:
        yielded.append(root)

    assert yielded == []
    assert len(created) == 1
    assert not created[0].exists()
