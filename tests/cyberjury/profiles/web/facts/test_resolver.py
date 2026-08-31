"""Web resolution publishes repository evidence without language binding rules."""

from pathlib import Path

from cyberjury.profiles.web.facts.analyzer import AnalyzedRepository, load_specs
from cyberjury.profiles.web.facts.resolver import (
    RepositoryNavigationEvidence,
    collect_navigation_evidence,
    load_profile_detection,
    reviewable_sources,
)


def _analyzed(*paths: str) -> AnalyzedRepository:
    return AnalyzedRepository(
        definitions=(),
        imports={},
        namespaces={},
        qualified_uses={},
        sources=dict.fromkeys(paths, "parsed"),
    )


def test_resolver_contract_contains_only_navigation_evidence_and_limitations():
    assert set(RepositoryNavigationEvidence.__dataclass_fields__) == {"navigation_sources", "limitations"}


def test_resolver_publishes_manifests_without_interpreting_targets(tmp_path):
    (tmp_path / "package.json").write_text('{"workspaces":["packages/*"]}\n')
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"@/*":["src/*"]}}}\n')
    (tmp_path / "jsconfig.json").write_text('{"compilerOptions":{"baseUrl":"src"}}\n')
    (tmp_path / "route.ts").write_text("export function route() { return true; }\n")

    resolved = collect_navigation_evidence(tmp_path, _analyzed("route.ts"), load_profile_detection())

    assert resolved.navigation_sources == {
        "package.json": '{"workspaces":["packages/*"]}\n',
        "tsconfig.json": '{"compilerOptions":{"paths":{"@/*":["src/*"]}}}\n',
        "jsconfig.json": '{"compilerOptions":{"baseUrl":"src"}}\n',
    }
    assert resolved.limitations == ()


def test_resolver_does_not_duplicate_sources_already_parsed_by_tree_sitter(tmp_path):
    (tmp_path / "route.ts").write_text("export function route() { return true; }\n")

    resolved = collect_navigation_evidence(tmp_path, _analyzed("route.ts"), load_profile_detection())

    assert "route.ts" not in resolved.navigation_sources


def test_resolver_records_an_unreadable_declaration_as_a_limitation(monkeypatch, tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}\n")
    read_text = Path.read_text

    def fail_manifest(path, *args, **kwargs):
        if path == manifest:
            raise OSError("permission denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_manifest)

    resolved = collect_navigation_evidence(tmp_path, _analyzed(), load_profile_detection())

    assert resolved.navigation_sources == {}
    assert [(item.source, item.analyzer, item.reason) for item in resolved.limitations] == [
        ("package.json", "web-resolver", "could not read repository navigation evidence")
    ]


def test_reviewable_sources_are_selected_by_query_extensions_without_following_external_symlinks(tmp_path):
    specs = load_specs()
    (tmp_path / "keep.py").write_text("def keep():\n    return 1\n")
    (tmp_path / "notes.md").write_text("not source\n")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("def outside():\n    return 1\n")
    (tmp_path / "linked.py").symlink_to(outside)

    sources = reviewable_sources(tmp_path, load_profile_detection(), specs)

    assert [(rel, spec.name) for _path, rel, spec in sources] == [("keep.py", "python")]
