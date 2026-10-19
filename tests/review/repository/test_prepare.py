"""The repository prepare stage plans and grounds units without running model review."""

import pytest

from cyberjury.review import prepare
from cyberjury.review.facts import Facts
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.result import SkippedFile
from cyberjury.sources.paths import SourceSnapshotError
from cyberjury.sources.snapshot import capture_source_snapshot

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
    return prepare_repository_review(capture_source_snapshot(target))


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
    """A Go library with only matcher.go plans matcher.go as its single owned path and unit."""
    res = prepare_target(_go_lib(tmp_path))
    assert res.unit_plan.expected_owned_paths == ("matcher.go",)
    assert [unit.name for unit in res.units] == ["matcher.go"]


def test_prepare_plans_a_django_url_module_for_review(tmp_path):
    """A Django project with manage.py and app/urls.py lists app/urls.py among owned paths."""
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = prepare_target(d)
    assert "app/urls.py" in res.unit_plan.expected_owned_paths


def test_prepare_assigns_downstream_logic_to_review_units(tmp_path):
    """The file app/managers/auth_manager.py gets its own unit while files under app/tests are never owned."""
    d = tmp_path / "dj"
    (d / "app" / "managers").mkdir(parents=True)
    (d / "app" / "tests").mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n")
    (d / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = prepare_target(d)
    assert "app/managers/auth_manager.py" in res.unit_plan.expected_owned_paths
    assert not any("test" in t for t in res.unit_plan.expected_owned_paths)
    assert any(unit.file == "app/managers/auth_manager.py" for unit in res.units)


def test_prepare_splits_a_large_candidate_into_slice_units(tmp_path):
    """A views.py of 200 padded routes becomes views.py#1, views.py#2, ..., the first starting at offset 0."""
    d = tmp_path / "big"
    d.mkdir()
    header = "from flask import Flask\napp = Flask(__name__)\n\n"
    block = '@app.route("/r%d")\ndef h%d():\n    x = "%s"\n    return x\n\n'
    body = "".join(block % (i, i, "p" * 200) for i in range(200))
    (d / "views.py").write_text(header + body)
    (d / "requirements.txt").write_text("Flask==3.0\n")
    res = prepare_target(d)
    names = [unit.name for unit in res.units]
    assert "views.py" not in names
    assert {"views.py#1", "views.py#2"} <= set(names)
    first = next(unit for unit in res.units if unit.name == "views.py#1")
    assert first.file == "views.py"
    assert first.span[0] == 0


def _block_facts(monkeypatch):
    calls = []

    def extract(root, files, navigation_files):
        calls.append(root)
        return Facts(by_file={"app.py": "def f():\n    return 1"})

    monkeypatch.setattr(prepare, "extract_syntax_facts", extract)
    return calls


def test_prepare_grounds_units_with_the_extracted_facts(tmp_path, monkeypatch):
    """Stubbed facts for app.py become the unit's fenced syntax hints and the grounding receipt matches."""
    calls = _block_facts(monkeypatch)
    res = prepare_target(_target(tmp_path))

    assert len(calls) == 1
    assert [unit.grounding.syntax_hints for unit in res.units] == [
        "app.py: syntax hints (unverified, cite only delivered source):\n```\ndef f():\n    return 1\n```"
    ]
    assert [record.unit_id for record in res.grounding.contexts] == [unit.id for unit in res.units]
    assert res.grounding.unit_plan_receipt_sha256 == res.unit_plan.receipt_sha256


def test_prepare_fails_loud_when_facts_extraction_cannot_run(tmp_path, monkeypatch):
    """A RuntimeError from syntax facts extraction raises BackendUnavailable "no grounding"."""

    def unavailable(*_args):
        raise RuntimeError("facts toolchain is unavailable")

    monkeypatch.setattr(prepare, "extract_syntax_facts", unavailable)

    with pytest.raises(BackendUnavailable, match="no grounding"):
        prepare_target(_target(tmp_path))


def test_prepare_fails_loud_on_an_unreadable_source(monkeypatch, tmp_path):
    """A PermissionError opening app.py raises SourceSnapshotError naming app.py and "access denied"."""
    target = _target(tmp_path)
    source = target / "app.py"
    original_open = type(source).open

    def deny_source(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise PermissionError("access denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(source), "open", deny_source)

    with pytest.raises(SourceSnapshotError, match=r"app\.py.*access denied"):
        prepare_target(target)


def test_prepare_records_binary_undecodable_and_empty_files_as_skipped(tmp_path):
    """A PNG, a Latin-1 legacy.py, and an empty.py are skipped with reasons, and only app.py is planned."""
    target = _target(tmp_path)
    (target / "banner.png").write_bytes(b"\x89PNG\r\n\x1a\n\0binary")

    (target / "legacy.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
    (target / "empty.py").write_text("")

    res = prepare_target(target)

    assert [unit.file for unit in res.units] == ["app.py"]
    assert res.unit_plan.expected_owned_paths == ("app.py",)
    assert res.skipped_files == (
        SkippedFile(path="banner.png", reason="binary"),
        SkippedFile(path="empty.py", reason="empty_file"),
        SkippedFile(path="legacy.py", reason="not_utf8"),
    )


def test_plain_repository_still_prepares(tmp_path):
    """A directory holding only notes.txt prepares with no owned paths and no units."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = prepare_target(d)
    assert res.unit_plan.expected_owned_paths == ()
    assert res.units == ()
