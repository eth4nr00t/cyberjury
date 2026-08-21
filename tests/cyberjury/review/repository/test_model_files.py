"""RepositoryModel builds a language agnostic file map from data driven signals."""

from cyberjury.review.repository.model import (
    build_repository_model,
    build_repository_model_from_dir,
    candidate_entrypoint_files,
    files_with_exported_symbols,
)


def test_build_lists_files_sorted():
    """Build lists files sorted."""
    m = build_repository_model("/repository", ["b/x.py", "a.py", "a/y.js"])
    assert m.root == "/repository"
    assert m.files == ("a.py", "a/y.js", "b/x.py")


def test_candidate_entrypoint_files_by_glob():
    """Candidate entrypoint files by glob."""
    files = ["app/urls.py", "app/views.py", "manage.py", "README.md"]
    assert candidate_entrypoint_files(files, globs=["*urls.py"]) == ["app/urls.py"]
    assert candidate_entrypoint_files(files, globs=["*urls.py", "manage.py"]) == ["app/urls.py", "manage.py"]
    assert candidate_entrypoint_files(files, globs=[]) == []


def test_candidate_entrypoint_files_by_content_markers(tmp_path):
    """Candidate entrypoint files by content markers."""
    (tmp_path / "handlers.py").write_text("class TokenViewSet(ViewSet):\n    pass\n")
    (tmp_path / "notes.md").write_text("ViewSet mentioned in prose, not code\n")
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    got = candidate_entrypoint_files(["handlers.py", "notes.md", "util.py"], root=tmp_path, markers=["ViewSet"])
    assert got == ["handlers.py"]


def test_candidate_entrypoint_files_sorted_and_deduped(tmp_path):
    """Candidate entrypoint files sorted and deduped."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "urls.py").write_text("class ViewSet:\n    pass\n")
    (tmp_path / "b" / "urls.py").write_text("x = 1\n")
    files = ["b/urls.py", "a/urls.py", "a/urls.py"]
    got = candidate_entrypoint_files(files, root=tmp_path, globs=["*urls.py"], markers=["ViewSet"])
    assert got == ["a/urls.py", "b/urls.py"]


def test_files_with_exported_symbols_selects_exports_and_skips_private_only(tmp_path):
    (tmp_path / "exported.go").write_text("package p\nfunc Handle(r *R) error {\n return nil\n}\n")
    (tmp_path / "private.go").write_text("package p\nfunc helper() int {\n return 1\n}\n")
    files = ["exported.go", "private.go"]
    got = files_with_exported_symbols(files, root=tmp_path, patterns=["^func [A-Z]"])
    assert got == ["exported.go"]


def test_files_with_exported_symbols_skips_tests_and_needs_patterns(tmp_path):
    (tmp_path / "api.go").write_text("package p\nfunc Do() {}\n")
    (tmp_path / "api_test.go").write_text("package p\nfunc TestDo() {}\n")
    files = ["api.go", "api_test.go"]
    assert files_with_exported_symbols(files, root=tmp_path, patterns=["^func [A-Z]"]) == ["api.go"]
    assert files_with_exported_symbols(files, root=tmp_path, patterns=[]) == []
    assert files_with_exported_symbols(files, patterns=["^func [A-Z]"]) == []


def test_build_from_dir_walks_tree_and_skips_noise(tmp_path):
    """Build from dir walks tree and skips noise."""
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "urls.py").write_text("x = 1")
    (tmp_path / "go.mod").write_text("module x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1")
    (tmp_path / "build" / "lib" / "pkg").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "pkg" / "urls.py").write_text("x = 1")

    m = build_repository_model_from_dir(tmp_path)
    assert {"app.py", "pkg/urls.py", "go.mod"} <= set(m.files)
    assert all("__pycache__" not in f for f in m.files)
    assert all(not f.startswith("build/") for f in m.files)


def test_build_is_deterministic():
    """Build is deterministic."""
    assert build_repository_model("/r", ["b.py", "a.py"]) == build_repository_model("/r", ["a.py", "b.py"])
