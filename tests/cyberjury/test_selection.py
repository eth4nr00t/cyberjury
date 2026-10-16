"""Every readable production source can enter review regardless of language."""

from cyberjury.detection import load_detection
from cyberjury.review.result import SkippedFile
from cyberjury.selection import select_files


def test_source_selection_accepts_unlisted_languages_and_records_unreadable_files(tmp_path):
    for name in ("service.rs", "contract.sol", "handler.rb", "worker.ex", "Makefile"):
        (tmp_path / name).write_text("operation(input)\n", encoding="utf-8")
    (tmp_path / "binary.dat").write_bytes(b"\0binary")
    (tmp_path / "legacy.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    (tmp_path / "pager.py").write_bytes(b"def page():\n    pass\n\x0c\nCOLOR = '\x1b[0m'\n")
    (tmp_path / "README.md").write_text("documentation\n", encoding="utf-8")
    (tmp_path / "messages.xlf").write_text("<unit/>\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "service.rs").write_text("test\n", encoding="utf-8")
    files = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file())

    selection = select_files(tmp_path, files, load_detection())

    assert set(selection.review_files) == {
        "service.rs",
        "contract.sol",
        "handler.rb",
        "worker.ex",
        "Makefile",
        "pager.py",
    }
    assert set(selection.skipped_files) == {
        SkippedFile(path="binary.dat", reason="binary"),
        SkippedFile(path="legacy.py", reason="not_utf8"),
        SkippedFile(path="empty.py", reason="empty_file"),
    }
    assert set(selection.navigation_files) == {*selection.review_files, "empty.py", "README.md"}
