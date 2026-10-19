"""Navigation source collection publishes repository evidence without language binding rules."""

from pathlib import Path

from cyberjury.review.detection import load_detection
from cyberjury.review.syntax.analyzer import AnalyzedRepository, load_specs
from cyberjury.review.syntax.sources import (
    collect_navigation_evidence,
    reviewable_sources,
)


def _analyzed(*paths: str) -> AnalyzedRepository:
    return AnalyzedRepository(
        definitions=(),
        imports={},
        namespaces={},
        qualified_uses={},
        structural_relationships={},
        sources=dict.fromkeys(paths, "parsed"),
    )


def test_navigation_sources_publishes_manifests_without_interpreting_targets(tmp_path):
    """The package.json, tsconfig.json, and jsconfig.json manifests are published verbatim with no limitations."""
    (tmp_path / "package.json").write_text('{"workspaces":["packages/*"]}\n')
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"@/*":["src/*"]}}}\n')
    (tmp_path / "jsconfig.json").write_text('{"compilerOptions":{"baseUrl":"src"}}\n')
    (tmp_path / "route.ts").write_text("export function route() { return true; }\n")

    resolved = collect_navigation_evidence(
        tmp_path, _analyzed("route.ts"), ("package.json", "tsconfig.json", "jsconfig.json", "route.ts")
    )

    assert resolved.navigation_sources == {
        "package.json": '{"workspaces":["packages/*"]}\n',
        "tsconfig.json": '{"compilerOptions":{"paths":{"@/*":["src/*"]}}}\n',
        "jsconfig.json": '{"compilerOptions":{"baseUrl":"src"}}\n',
    }
    assert resolved.limitations == ()


def test_navigation_sources_does_not_duplicate_sources_already_parsed_by_tree_sitter(tmp_path):
    """A route.ts already parsed by the analyzer is not repeated as a navigation source."""
    (tmp_path / "route.ts").write_text("export function route() { return true; }\n")

    resolved = collect_navigation_evidence(tmp_path, _analyzed("route.ts"), ("route.ts",))

    assert "route.ts" not in resolved.navigation_sources


def test_navigation_sources_records_an_unreadable_declaration_as_a_limitation(monkeypatch, tmp_path):
    """An OSError reading package.json drops it from navigation sources and records a limitation for it."""
    manifest = tmp_path / "package.json"
    manifest.write_text("{}\n")
    read_text = Path.read_text

    def fail_manifest(path, *args, **kwargs):
        if path == manifest:
            raise OSError("permission denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_manifest)

    resolved = collect_navigation_evidence(tmp_path, _analyzed(), ("package.json",))

    assert resolved.navigation_sources == {}
    assert [limitation.source for limitation in resolved.limitations] == ["package.json"]


def test_reviewable_sources_are_selected_by_query_extensions_outside_tests(tmp_path):
    """Only keep.py is selected, and notes.md, tests/test_keep.py, and node_modules/lib.js are excluded."""
    files = ("keep.py", "notes.md", "tests/test_keep.py", "node_modules/lib.js")

    sources = reviewable_sources(tmp_path, files, load_detection(), load_specs())

    assert [(rel, spec.name) for _path, rel, spec in sources] == [("keep.py", "python")]
