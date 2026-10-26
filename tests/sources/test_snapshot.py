"""Source snapshots expose stable manifests and detect every supported drift type."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cyberjury.sources.paths import SourceSnapshotError
from cyberjury.sources.snapshot import SourceSnapshot, source_snapshot_files
from tests.support import git


def _scope(root: Path) -> tuple[str, ...]:
    return tuple(sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()))


def test_snapshot_id_is_stable(tmp_path):
    """Three captures of an unchanged a.py and b.ts tree produce one identical snapshot_id."""
    (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("export const b = 2\n", encoding="utf-8")

    snapshots = [SourceSnapshot.capture(tmp_path, _scope(tmp_path)) for _ in range(3)]
    assert len({snapshot.snapshot_id for snapshot in snapshots}) == 1


@pytest.mark.parametrize("change", ["modify", "delete", "add", "rename", "executable"])
def test_snapshot_detects_file_and_scope_drift(tmp_path, change):
    """Modifying, deleting, adding, renaming, or chmod +x on app.py makes matches() return False."""
    source = tmp_path / "app.py"
    source.write_text("before\n", encoding="utf-8")
    snapshot = SourceSnapshot.capture(tmp_path, _scope(tmp_path), scope_provider=lambda: _scope(tmp_path))

    if change == "modify":
        source.write_text("after\n", encoding="utf-8")
    elif change == "delete":
        source.unlink()
    elif change == "add":
        (tmp_path / "new.py").write_text("new\n", encoding="utf-8")
    elif change == "rename":
        source.rename(tmp_path / "renamed.py")
    else:
        source.chmod(source.stat().st_mode | 0o111)

    assert snapshot.matches() is False


def test_snapshot_counts_a_repointed_internal_symlink_as_drift(tmp_path):
    """Re-pointing current.py from first.py to second.py with the same content makes matches() return False."""
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("same\n")
    second.write_text("same\n")
    link = tmp_path / "current.py"
    link.symlink_to(first.name)
    snapshot = SourceSnapshot.capture(tmp_path, ("current.py",))
    link.unlink()
    link.symlink_to(second.name)

    assert snapshot.matches() is False


def test_snapshot_capture_rejects_a_symlink_to_a_file_outside_the_root(tmp_path):
    """A current.py link to a file beside the root raises SourceSnapshotError at capture."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("same\n")
    (tmp_path / "current.py").symlink_to(outside)

    with pytest.raises(SourceSnapshotError):
        SourceSnapshot.capture(tmp_path, ("current.py",))


def test_snapshot_accepts_names_that_are_only_unportable_to_other_filesystems(tmp_path):
    """Windows-reserved names like aux.c, case twins README/readme, "notes.", and "a:b.txt" are all captured."""
    names = ("drivers/aux.c", "include/con.h", "README", "readme", "notes.", "a:b.txt")
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")

    snapshot = SourceSnapshot.capture(tmp_path, source_snapshot_files(tmp_path))

    assert snapshot.files == tuple(sorted(names))


def test_git_work_tree_snapshot_lists_tracked_and_unignored_files_without_walking_ignored_trees(tmp_path):
    """Listing yields .gitignore, app.py, new.py, skipping ignored .venv, build.log, and deleted files."""
    git(tmp_path, "init", "--quiet")
    (tmp_path / ".gitignore").write_text(".venv/\nbuild.log\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("tracked\n", encoding="utf-8")
    (tmp_path / "deleted.py").write_text("deleted\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    (tmp_path / "deleted.py").unlink()
    (tmp_path / "new.py").write_text("untracked\n", encoding="utf-8")
    (tmp_path / "build.log").write_text("ignored\n", encoding="utf-8")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (tmp_path / ".venv" / "lib64").symlink_to("lib", target_is_directory=True)
    (venv / "site.py").write_text("ignored\n", encoding="utf-8")

    files = source_snapshot_files(tmp_path)
    snapshot = SourceSnapshot.capture(tmp_path, files, scope_provider=lambda: source_snapshot_files(tmp_path))

    assert files == (".gitignore", "app.py", "new.py")
    assert snapshot.matches()
    (tmp_path / "later.py").write_text("added\n", encoding="utf-8")
    assert not snapshot.matches()


def test_listing_skips_symlinks_that_do_not_resolve_to_a_contained_file(tmp_path):
    """Directory, dangling, and outside links are left out of a plain tree, and link.py to app.py stays."""
    (tmp_path / "app.py").write_text("app\n", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("mod\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to("app.py")
    (tmp_path / "pkg-link").symlink_to("pkg", target_is_directory=True)
    (tmp_path / "dangling.py").symlink_to("missing.py")
    (tmp_path / "outside.py").symlink_to(outside)

    files = source_snapshot_files(tmp_path)

    assert files == ("app.py", "link.py", "pkg/mod.py")
    assert SourceSnapshot.capture(tmp_path, files).files == files


def test_git_listing_skips_a_tracked_directory_symlink(tmp_path):
    """A tracked fixtures/dir-link symlink to a directory is left out, and its target file is still listed."""
    git(tmp_path, "init", "--quiet")
    (tmp_path / "fixtures" / "dir").mkdir(parents=True)
    (tmp_path / "fixtures" / "dir" / "data.py").write_text("data\n", encoding="utf-8")
    (tmp_path / "fixtures" / "dir-link").symlink_to("dir", target_is_directory=True)
    git(tmp_path, "add", ".")

    files = source_snapshot_files(tmp_path)

    assert files == ("fixtures/dir/data.py",)
    assert SourceSnapshot.capture(tmp_path, files).files == files


def test_snapshot_rejects_unsupported_file_type(tmp_path):
    """Capturing a FIFO named events.pipe raises SourceSnapshotError mentioning "regular file"."""
    fifo = tmp_path / "events.pipe"
    os.mkfifo(fifo)

    with pytest.raises(SourceSnapshotError, match="regular file"):
        SourceSnapshot.capture(tmp_path, ("events.pipe",))


def test_snapshot_includes_dependency_and_vendored_source_inputs(tmp_path):
    """Files under lib/, dependencies/, and node_modules/ are captured, and editing lib/dependency.py changes the id."""
    (tmp_path / "src").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "dependencies").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "src" / "vault.py").write_text("class Vault: ...\n")
    (tmp_path / "lib" / "dependency.py").write_text("class Dependency: ...\n")
    (tmp_path / "dependencies" / "math.py").write_text("class Math: ...\n")
    (tmp_path / "node_modules" / "noise.js").write_text("generated\n")
    files = source_snapshot_files(tmp_path)
    snapshot = SourceSnapshot.capture(tmp_path, files)
    (tmp_path / "lib" / "dependency.py").write_text("class Dependency:\n    changed = 1\n")
    changed = SourceSnapshot.capture(tmp_path, source_snapshot_files(tmp_path))

    assert "lib/dependency.py" in files
    assert "dependencies/math.py" in files
    assert "node_modules/noise.js" in files
    assert changed.snapshot_id != snapshot.snapshot_id


def test_snapshot_fails_with_the_unreadable_source_path(monkeypatch, tmp_path):
    """A PermissionError opening app.py surfaces as SourceSnapshotError naming app.py and "access denied"."""
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    original_open = Path.open

    def deny_read(path: Path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise PermissionError("access denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_read)

    with pytest.raises(SourceSnapshotError, match=r"app\.py.*access denied"):
        SourceSnapshot.capture(tmp_path, ("app.py",))


def test_materialize_copies_exact_bytes_modes_and_relative_symlinks(tmp_path):
    """A materialized copy keeps CRLF bytes, the executable run.sh, and link.py -> app.py, and the same id."""
    root = tmp_path / "source"
    (root / "bin").mkdir(parents=True)
    (root / "app.py").write_bytes(b"value = 1\r\n" * 200_000)
    (root / "bin" / "run.sh").write_text("#!/bin/sh\n")
    (root / "bin" / "run.sh").chmod(0o755)
    (root / "link.py").symlink_to("app.py")
    snapshot = SourceSnapshot.capture(root, ("app.py", "bin/run.sh", "link.py"))

    with snapshot.materialize() as materialized:
        assert (materialized / "app.py").read_bytes() == (root / "app.py").read_bytes()
        assert os.access(materialized / "bin" / "run.sh", os.X_OK)
        assert os.readlink(materialized / "link.py") == "app.py"
        assert SourceSnapshot.capture(materialized, snapshot.files).snapshot_id == snapshot.snapshot_id
