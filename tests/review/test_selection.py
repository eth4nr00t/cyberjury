"""File selection decides which files are reviewed, navigable, or skipped."""

from cyberjury.review.detection import detection_for, load_detection
from cyberjury.review.result import SkippedFile
from cyberjury.review.selection import select_files
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


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


def test_image_font_and_pdf_assets_are_excluded_without_being_listed_as_skipped(tmp_path):
    """A PNG logo, a WOFF2 font, and a PDF guide are neither reviewed nor reported as skipped binaries."""
    selection = _select(
        tmp_path,
        {
            "app.py": b"value = 1\n",
            "static/logo.png": b"\x89PNG\r\n\x1a\n\0image",
            "static/font.woff2": b"wOF2\0font",
            "docs/guide.pdf": b"%PDF-1.7\n\0document",
        },
    )

    assert selection.review_files == ("app.py",)
    assert selection.skipped_files == ()


def test_documentation_is_navigable_but_not_reviewed(tmp_path):
    """README.md is offered to navigation and kept out of review."""
    selection = _select(tmp_path, {"app.py": b"value = 1\n", "README.md": b"documentation\n"})

    assert selection.review_files == ("app.py",)
    assert selection.documentation_files == ("README.md",)
    assert "README.md" in selection.navigation_files


def test_vendored_files_are_navigable_but_not_reviewed(tmp_path):
    """A linguist-vendored public/plugins/lib.js is a navigable dependency file, while app.py is reviewed."""
    files = {
        ".gitattributes": b"public/plugins/** linguist-vendored\n",
        "app.py": b"def handler(value):\n    return value\n",
        "public/plugins/lib.js": b"function helper(value) { return value }\n",
    }
    _select(tmp_path, files)

    selection = select_files(tmp_path, sorted(files), detection_for(tmp_path, sorted(files)))

    assert selection.review_files == (".gitattributes", "app.py")
    assert selection.dependency_files == ("public/plugins/lib.js",)
    assert "public/plugins/lib.js" in selection.navigation_files


def test_files_over_the_size_limit_are_skipped_as_too_large(tmp_path):
    """A bindata.go over the size limit is skipped as too_large and offered neither to review nor navigation."""
    limit = DEFAULT_REVIEW_SETTINGS.execution.max_reviewed_source_bytes
    files = {
        "app.py": b"def handler(value):\n    return value\n",
        "bindata.go": b"package bindata\n\nvar data = `" + b"a" * limit + b"`\n",
    }
    _select(tmp_path, files)

    selection = select_files(tmp_path, sorted(files), detection_for(tmp_path, sorted(files)))

    assert selection.review_files == ("app.py",)
    assert selection.skipped_files == (SkippedFile(path="bindata.go", reason="too_large"),)
    assert "bindata.go" not in selection.navigation_files
