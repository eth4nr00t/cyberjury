"""Repository path guards keep unsafe locations outside source reads."""

from cyberjury.review.paths import is_unsafe_rel, resolve_source_path, safe_repository_path


def test_is_unsafe_rel_flags_empty_absolute_and_traversal():
    """Empty, /etc/passwd, ../secrets, and a/../../b are all reported unsafe."""
    assert is_unsafe_rel("")
    assert is_unsafe_rel("/etc/passwd")
    assert is_unsafe_rel("../secrets")
    assert is_unsafe_rel("a/../../b")


def test_is_unsafe_rel_allows_a_plain_relative_path():
    """The paths app/api/routes.py and main.go are not reported unsafe."""
    assert not is_unsafe_rel("app/api/routes.py")
    assert not is_unsafe_rel("main.go")


def test_safe_repository_path_resolves_a_relative_path_under_root(tmp_path):
    """The path app/routes.py resolves to the existing file under the repository root."""
    target = tmp_path / "app" / "routes.py"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    resolved = safe_repository_path(tmp_path, "app/routes.py")
    assert resolved == target.resolve()


def test_safe_repository_path_refuses_empty_absolute_and_traversal(tmp_path):
    """Empty, /etc/passwd, and ../outside all resolve to None."""
    assert safe_repository_path(tmp_path, "") is None
    assert safe_repository_path(tmp_path, "/etc/passwd") is None
    assert safe_repository_path(tmp_path, "../outside") is None


def test_safe_repository_path_refuses_a_symlink_escaping_root(tmp_path):
    """A link inside the root pointing to a file outside it resolves to None."""
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "link").symlink_to(outside)
    assert safe_repository_path(root, "link") is None


def test_resolve_source_path_never_falls_back_to_a_basename(tmp_path):
    """A bare activity_controller.go gives None, and only internal/controller/activity_controller.go resolves."""
    (tmp_path / "internal" / "controller").mkdir(parents=True)
    real = tmp_path / "internal" / "controller" / "activity_controller.go"
    real.write_text("package controller\n")
    assert resolve_source_path(tmp_path, "activity_controller.go") is None
    assert resolve_source_path(tmp_path, "internal/controller/activity_controller.go") == real.resolve()


def test_resolve_source_path_refuses_a_traversal_path(tmp_path):
    """The path ../outside.py from an app root gives None even though the file exists one level up."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n")
    (tmp_path / "outside.py").write_text("x = 1\n")
    assert resolve_source_path(tmp_path / "app", "../outside.py") is None
