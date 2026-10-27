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
    """Prepare a Repository Review of the target's current source."""
    return prepare_repository_review(capture_source_snapshot(target), recorder=recorder())


def _target(tmp_path):
    d = tmp_path / "myservice"
    d.mkdir(exist_ok=True)
    (d / "app.py").write_text(APP)
    return d


GO_LIB = """
package matcher

func Match(a, b string) bool {
    return a == b
}
"""


def _go_lib(tmp_path):
    d = tmp_path / "matcher"
    d.mkdir(exist_ok=True)
    (d / "matcher.go").write_text(GO_LIB)
    return d


def test_prepare_reviews_library_source_without_export_rules(tmp_path):
    """A Go library with only matcher.go plans matcher.go as its single unit."""
    res = prepare_target(_go_lib(tmp_path))
    assert [unit.name for unit in res.units] == ["matcher.go"]


def test_prepare_plans_a_django_url_module_for_review(tmp_path):
    """A Django project with manage.py and app/urls.py plans a unit for app/urls.py."""
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = prepare_target(d)
    assert "app/urls.py" in [unit.file for unit in res.units]


def test_prepare_assigns_downstream_logic_to_review_units(tmp_path):
    """The file app/managers/auth_manager.py gets its own unit while files under app/tests get none."""
    d = tmp_path / "dj"
    (d / "app" / "managers").mkdir(parents=True)
    (d / "app" / "tests").mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n")
    (d / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = prepare_target(d)
    assert "app/managers/auth_manager.py" in [unit.file for unit in res.units]
    assert not any("test" in unit.file for unit in res.units)


def test_prepare_records_binary_undecodable_and_empty_files_as_skipped(tmp_path):
    """A PNG, a Latin-1 legacy.py, and an empty.py are skipped with reasons, and only app.py is planned."""
    target = _target(tmp_path)
    (target / "banner.png").write_bytes(b"\x89PNG\r\n\x1a\n\0binary")

    (target / "legacy.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
    (target / "empty.py").write_text("")

    stages = recorder()
    artifacts = bound_artifacts(stages)

    res = prepare_repository_review(capture_source_snapshot(target), recorder=stages)

    assert [unit.file for unit in res.units] == ["app.py"]
    assert artifacts[SkippedFiles].files == (
        SkippedFile(path="banner.png", reason="binary"),
        SkippedFile(path="empty.py", reason="empty_file"),
        SkippedFile(path="legacy.py", reason="not_utf8"),
    )


def test_a_repository_without_source_prepares_no_units(tmp_path):
    """A directory holding only notes.md prepares no units."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.md").write_text("hi")
    res = prepare_target(d)
    assert res.units == ()
