"""Source snapshots expose stable manifests and detect every supported drift type."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cyberjury.review.storage import facts_cache_key_from_snapshot
from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError, source_snapshot_files


def _scope(root: Path) -> tuple[str, ...]:
    return tuple(sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()))


def test_snapshot_id_is_stable_and_round_trips(tmp_path):
    (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("export const b = 2\n", encoding="utf-8")

    snapshots = [SourceSnapshot.capture(tmp_path, _scope(tmp_path)) for _ in range(3)]
    restored = SourceSnapshot.from_dict(snapshots[0].to_dict(), root=tmp_path)

    assert len({snapshot.snapshot_id for snapshot in snapshots}) == 1
    assert restored.to_dict() == snapshots[0].to_dict()


@pytest.mark.parametrize("change", ["modify", "delete", "add", "rename", "executable"])
def test_snapshot_detects_file_and_scope_drift(tmp_path, change):
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


def test_snapshot_records_internal_symlink_identity_and_rejects_external_target(tmp_path):
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

    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("same\n")
    link.unlink()
    link.symlink_to(outside)
    with pytest.raises(SourceSnapshotError):
        SourceSnapshot.capture(tmp_path, ("current.py",))


@pytest.mark.parametrize(
    "files",
    [
        ("../outside.py",),
        ("/absolute.py",),
        ("a.py", "a.py"),
        ("A.py", "a.py"),
        ("dir/./a.py",),
        ("dir\\a.py",),
        ("CON.py",),
        ("dir/a:b.py",),
        ("trailing.",),
        ("Parent", "parent/child.py"),
    ],
)
def test_snapshot_rejects_unsafe_duplicate_or_nonportable_paths(tmp_path, files):
    with pytest.raises(SourceSnapshotError):
        SourceSnapshot.capture(tmp_path, files)


def test_snapshot_rejects_unsupported_file_type(tmp_path):
    fifo = tmp_path / "events.pipe"
    os.mkfifo(fifo)

    with pytest.raises(SourceSnapshotError, match="regular file"):
        SourceSnapshot.capture(tmp_path, ("events.pipe",))


def test_profile_and_backend_change_facts_key_but_not_snapshot_id(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n")
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",))

    first = facts_cache_key_from_snapshot(
        snapshot.snapshot_id,
        "web",
        profile_content_snapshot_id="1" * 64,
        backend_identity="backend-one",
    )
    second = facts_cache_key_from_snapshot(
        snapshot.snapshot_id,
        "other",
        profile_content_snapshot_id="2" * 64,
        backend_identity="backend-two",
    )

    assert first != second
    assert SourceSnapshot.capture(tmp_path, ("app.py",)).snapshot_id == snapshot.snapshot_id


def test_snapshot_policy_is_profile_independent_and_includes_all_source_inputs(tmp_path):
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
    before = facts_cache_key_from_snapshot(
        snapshot.snapshot_id,
        "other",
        profile_content_snapshot_id="1" * 64,
        backend_identity="backend-two",
    )
    (tmp_path / "lib" / "dependency.py").write_text("class Dependency:\n    changed = 1\n")
    changed = SourceSnapshot.capture(tmp_path, source_snapshot_files(tmp_path))
    after = facts_cache_key_from_snapshot(
        changed.snapshot_id,
        "other",
        profile_content_snapshot_id="1" * 64,
        backend_identity="backend-two",
    )

    assert "lib/dependency.py" in files
    assert "dependencies/math.py" in files
    assert "node_modules/noise.js" in files
    assert changed.snapshot_id != snapshot.snapshot_id
    assert after != before


def test_snapshot_fails_with_the_unreadable_source_path(monkeypatch, tmp_path):
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
