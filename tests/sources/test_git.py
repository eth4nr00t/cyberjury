"""Git materialization writes exact committed blobs and rejects symlinks that leave the tree."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import cyberjury.sources.git as gitmod
from cyberjury.sources.git import GitSourceError, materialize_revision
from tests.support import git


def _commit_symlink(repo: Path, target: bytes) -> str:
    """Commit `app.py` and a `link.py` symlink whose stored target is exactly `target`."""
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


def test_a_relative_internal_symlink_is_materialized(tmp_path):
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
