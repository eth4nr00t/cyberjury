"""Canonical source path rules reject unsafe paths and symlinks that leave their root."""

from __future__ import annotations

import pytest

from cyberjury.sources.paths import SourceSnapshotError, portable_paths, require_contained_symlinks


@pytest.mark.parametrize(
    "files",
    [
        ("../outside.py",),
        ("/absolute.py",),
        ("a.py", "a.py"),
        ("dir/./a.py",),
        ("dir\\a.py",),
    ],
)
def test_portable_paths_rejects_unsafe_or_duplicate_paths(files):
    """Parent-escaping, absolute, duplicated, dot-segment, or backslash paths raise SourceSnapshotError."""
    with pytest.raises(SourceSnapshotError):
        portable_paths(files)


def test_require_contained_symlinks_rejects_a_link_resolving_outside_the_root(tmp_path):
    """A root/link.py symlink to a file beside the root raises SourceSnapshotError naming link.py."""
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.py").write_text("outside\n", encoding="utf-8")
    (root / "link.py").symlink_to("../outside.py")

    with pytest.raises(SourceSnapshotError, match=r"link\.py"):
        require_contained_symlinks(root, ("link.py",))
