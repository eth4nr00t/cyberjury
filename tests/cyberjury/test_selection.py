"""Every readable production source can enter review regardless of language."""

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import default_profile
from cyberjury.selection import source_files


def test_source_selection_accepts_unlisted_languages(tmp_path):
    for name in ("service.rs", "contract.sol", "handler.rb", "worker.ex", "Makefile"):
        (tmp_path / name).write_text("operation(input)\n", encoding="utf-8")
    (tmp_path / "binary.dat").write_bytes(b"\0binary")
    (tmp_path / "control.dat").write_bytes(b"\x01binary")
    (tmp_path / "README.md").write_text("documentation\n", encoding="utf-8")
    (tmp_path / "messages.xlf").write_text("<unit/>\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "service.rs").write_text("test\n", encoding="utf-8")

    assert set(source_files(tmp_path, load_detection(default_profile().paths.detection_file))) == {
        "service.rs",
        "contract.sol",
        "handler.rb",
        "worker.ex",
        "Makefile",
    }
