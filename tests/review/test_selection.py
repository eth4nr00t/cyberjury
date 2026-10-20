"""File selection decides which files are reviewed, navigable, or skipped."""

from cyberjury.review.detection import load_detection
from cyberjury.review.result import SkippedFile
from cyberjury.review.selection import select_files


def _select(root, files: dict[str, bytes]):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return select_files(root, sorted(files), load_detection())


def test_binary_undecodable_and_empty_files_are_skipped_with_reasons(tmp_path):
    """Binary, Latin-1, and empty files are skipped, and a form feed or escape byte does not skip a file."""
    selection = _select(
        tmp_path,
        {
            "binary.dat": b"\0binary",
            "legacy.py": "name = 'caf\xe9'\n".encode("latin-1"),
            "empty.py": b"",
            "pager.py": b"def page():\n    pass\n\x0c\nCOLOR = '\x1b[0m'\n",
        },
    )

    assert selection.review_files == ("pager.py",)
    assert set(selection.skipped_files) == {
        SkippedFile(path="binary.dat", reason="binary"),
        SkippedFile(path="legacy.py", reason="not_utf8"),
        SkippedFile(path="empty.py", reason="empty_file"),
    }


def test_documentation_is_navigable_but_not_reviewed(tmp_path):
    """README.md is offered to navigation and kept out of review."""
    selection = _select(tmp_path, {"app.py": b"value = 1\n", "README.md": b"documentation\n"})

    assert selection.review_files == ("app.py",)
    assert selection.documentation_files == ("README.md",)
    assert "README.md" in selection.navigation_files
