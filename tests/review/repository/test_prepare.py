"""The repository prepare stage plans and grounds units without running model review."""

from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.result import SkippedFile, SkippedFiles
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.support import bound_artifacts, recorder

APP = """
from flask import Flask
app = Flask(__name__)

@app.route("/users", methods=["GET"])
def list_users():
    return "ok"

@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    return "", 204
"""


def prepare_target(target):
    """Prepare a repository review of the target's current source."""
    return prepare_repository_review(capture_source_snapshot(target), recorder=recorder())


def _target(tmp_path):
    root = tmp_path / "myservice"
    root.mkdir(exist_ok=True)
    (root / "app.py").write_text(APP, encoding="utf-8")
    return root


def test_prepare_plans_source_files_and_leaves_out_test_directories(tmp_path):
    """The file app/managers/auth_manager.py gets its own unit while files under app/tests get none."""
    root = tmp_path / "dj"
    (root / "app" / "managers").mkdir(parents=True)
    (root / "app" / "tests").mkdir()
    (root / "manage.py").write_text("import django\n", encoding="utf-8")
    (root / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n", encoding="utf-8")
    (root / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n", encoding="utf-8")
    (root / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    (root / "requirements.txt").write_text("Django==4.2\n", encoding="utf-8")
    prepared = prepare_target(root)
    assert "app/managers/auth_manager.py" in [unit.file for unit in prepared.units]
    assert not any("test" in unit.file for unit in prepared.units)


def test_prepare_records_binary_undecodable_and_empty_files_as_skipped(tmp_path):
    """A SQLite cache.db, a Latin-1 legacy.py, and an empty.py are skipped with reasons, and only app.py is planned."""
    target = _target(tmp_path)
    (target / "cache.db").write_bytes(b"SQLite format 3\0binary")

    (target / "legacy.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
    (target / "empty.py").write_text("", encoding="utf-8")

    stages = recorder()
    artifacts = bound_artifacts(stages)

    prepared = prepare_repository_review(capture_source_snapshot(target), recorder=stages)

    assert [unit.file for unit in prepared.units] == ["app.py"]
    assert artifacts[SkippedFiles].files == (
        SkippedFile(path="cache.db", reason="binary"),
        SkippedFile(path="empty.py", reason="empty_file"),
        SkippedFile(path="legacy.py", reason="not_utf8"),
    )


def test_a_repository_without_source_prepares_no_units(tmp_path):
    """A directory holding only notes.md prepares no units."""
    root = tmp_path / "plain"
    root.mkdir()
    (root / "notes.md").write_text("hi", encoding="utf-8")
    prepared = prepare_target(root)
    assert prepared.units == ()
