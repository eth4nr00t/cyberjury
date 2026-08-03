"""The path boundary that keeps a tampered or hallucinated location from reading a file
outside the reviewed repository. is_unsafe_rel drops it before it becomes a finding, safe_repository_path
refuses it before a workspace-to-source read."""

from cyberjury.review.repository.paths import is_unsafe_rel, resolve_source_path, safe_repository_path


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


def test_resolve_source_path_finds_a_bare_filename_recorded_one_directory_down(tmp_path):
    (tmp_path / "internal" / "controller").mkdir(parents=True)
    real = tmp_path / "internal" / "controller" / "activity_controller.go"
    real.write_text("package controller\n")
    assert resolve_source_path(tmp_path, "activity_controller.go") == real


def test_resolve_source_path_refuses_an_ambiguous_basename(tmp_path):
    root = tmp_path / "backend"
    for d in ("core", "schemas", "routes"):
        (root / "app" / d).mkdir(parents=True)
        (root / "app" / d / "auth.py").write_text("x = 1\n")
    # the recorded path is rooted one level above the reviewed root, so it matches nothing exactly
    assert resolve_source_path(root, "backend/app/core/auth.py") is None


def test_resolve_source_path_prefers_the_exact_path_over_the_basename(tmp_path):
    (tmp_path / "app").mkdir()
    exact = tmp_path / "app" / "views.py"
    exact.write_text("exact\n")
    (tmp_path / "views.py").write_text("shadow\n")
    assert resolve_source_path(tmp_path, "app/views.py") == exact


def test_resolve_source_path_ignores_a_vendored_copy(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("vendored\n")
    assert resolve_source_path(tmp_path, "index.js") is None


def test_resolve_source_path_refuses_a_traversal_path(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n")
    assert resolve_source_path(tmp_path / "app", "../outside.py") is None
