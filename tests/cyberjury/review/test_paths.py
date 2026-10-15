"""Repository path guards keep unsafe locations outside source reads."""

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import get_profile
from cyberjury.review.paths import is_unsafe_rel, resolve_source_path, safe_repository_path, source_navigation_files


def test_navigation_indexes_documentation_without_treating_it_as_source(tmp_path):
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "usage.md").write_text("Development only\n", encoding="utf-8")
    (tmp_path / "binary.txt").write_bytes(b"\xe4\xff")
    detection = load_detection(get_profile("web").paths.detection_file)

    assert source_navigation_files(tmp_path, detection) == ("app.py", "usage.md")


def test_is_unsafe_rel_flags_empty_absolute_and_traversal():
    assert is_unsafe_rel("")
    assert is_unsafe_rel("/etc/passwd")
    assert is_unsafe_rel("../secrets")
    assert is_unsafe_rel("a/../../b")


def test_is_unsafe_rel_allows_a_plain_relative_path():
    assert not is_unsafe_rel("app/api/routes.py")
    assert not is_unsafe_rel("main.go")


def test_safe_repository_path_resolves_a_relative_path_under_root(tmp_path):
    target = tmp_path / "app" / "routes.py"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    resolved = safe_repository_path(tmp_path, "app/routes.py")
    assert resolved == target.resolve()


def test_safe_repository_path_refuses_empty_absolute_and_traversal(tmp_path):
    assert safe_repository_path(tmp_path, "") is None
    assert safe_repository_path(tmp_path, "/etc/passwd") is None
    assert safe_repository_path(tmp_path, "../outside") is None


def test_safe_repository_path_refuses_a_symlink_escaping_root(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "link").symlink_to(outside)
    assert safe_repository_path(root, "link") is None


def test_resolve_source_path_never_falls_back_to_a_basename(tmp_path):
    (tmp_path / "internal" / "controller").mkdir(parents=True)
    real = tmp_path / "internal" / "controller" / "activity_controller.go"
    real.write_text("package controller\n")
    assert resolve_source_path(tmp_path, "activity_controller.go") is None
    assert resolve_source_path(tmp_path, "internal/controller/activity_controller.go") == real.resolve()


def test_resolve_source_path_refuses_a_traversal_path(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n")
    (tmp_path / "outside.py").write_text("x = 1\n")
    assert resolve_source_path(tmp_path / "app", "../outside.py") is None
