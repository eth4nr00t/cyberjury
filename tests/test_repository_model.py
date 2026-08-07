"""RepositoryModel is a language-agnostic file map.

Candidate entrypoint files are flagged by guide-declared globs, not by parsing code.
"""

from cyberjury.review.repository.model import (
    build_repository_model,
    build_repository_model_from_dir,
    candidate_entrypoint_files,
    public_api_files,
)


def test_build_lists_files_sorted():
    """Exercise the build lists files sorted case."""
    m = build_repository_model("/repository", ["b/x.py", "a.py", "a/y.js"])
    assert m.root == "/repository"
    assert m.files == ("a.py", "a/y.js", "b/x.py")


def test_candidate_entrypoint_files_by_glob():
    """Exercise the candidate entrypoint files by glob case."""
    files = ["app/urls.py", "app/views.py", "manage.py", "README.md"]
    assert candidate_entrypoint_files(files, globs=["*urls.py"]) == ["app/urls.py"]
    assert candidate_entrypoint_files(files, globs=["*urls.py", "manage.py"]) == ["app/urls.py", "manage.py"]
    assert candidate_entrypoint_files(files, globs=[]) == []


def test_candidate_entrypoint_files_by_content_markers(tmp_path):
    """Exercise the candidate entrypoint files by content markers case."""
    (tmp_path / "handlers.py").write_text("class TokenViewSet(ViewSet):\n    pass\n")
    (tmp_path / "notes.md").write_text("ViewSet mentioned in prose, not code\n")
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    got = candidate_entrypoint_files(["handlers.py", "notes.md", "util.py"], root=tmp_path, markers=["ViewSet"])
    assert got == ["handlers.py"]


def test_candidate_entrypoint_files_sorted_and_deduped(tmp_path):
    """Exercise the candidate entrypoint files sorted and deduped case."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "urls.py").write_text("class ViewSet:\n    pass\n")
    (tmp_path / "b" / "urls.py").write_text("x = 1\n")
    files = ["b/urls.py", "a/urls.py", "a/urls.py"]
    got = candidate_entrypoint_files(files, root=tmp_path, globs=["*urls.py"], markers=["ViewSet"])
    assert got == ["a/urls.py", "b/urls.py"]


def test_public_api_files_selects_exported_and_skips_private_only(tmp_path):
    """Exercise the public api files selects exported and skips private only case."""
    (tmp_path / "exported.go").write_text("package p\nfunc Handle(r *R) error {\n return nil\n}\n")
    (tmp_path / "private.go").write_text("package p\nfunc helper() int {\n return 1\n}\n")
    files = ["exported.go", "private.go"]
    got = public_api_files(files, root=tmp_path, patterns=["^func [A-Z]"])
    assert got == ["exported.go"]


def test_public_api_files_skips_tests_and_needs_patterns(tmp_path):
    """Exercise the public api files skips tests and needs patterns case."""
    (tmp_path / "api.go").write_text("package p\nfunc Do() {}\n")
    (tmp_path / "api_test.go").write_text("package p\nfunc TestDo() {}\n")
    files = ["api.go", "api_test.go"]
    assert public_api_files(files, root=tmp_path, patterns=["^func [A-Z]"]) == ["api.go"]
    assert public_api_files(files, root=tmp_path, patterns=[]) == []
    assert public_api_files(files, patterns=["^func [A-Z]"]) == []


def test_build_from_dir_walks_tree_and_skips_noise(tmp_path):
    """Exercise the build from dir walks tree and skips noise case."""
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
    """Exercise the build is deterministic case."""
    assert build_repository_model("/r", ["b.py", "a.py"]) == build_repository_model("/r", ["a.py", "b.py"])
