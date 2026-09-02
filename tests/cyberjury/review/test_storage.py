"""Facts storage preserves cache identity and loud failure behavior."""

from pathlib import Path

import pytest

from cyberjury.review.facts import FactLimitation, Facts
from cyberjury.review.storage import FactsStore, facts_cache_key
from cyberjury.sources.snapshot import SourceSnapshotError


def test_facts_cache_key_fails_with_the_unreadable_source_path(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")

    def deny_read(path: Path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise PermissionError("access denied")
        return original_open(path, *args, **kwargs)

    original_open = Path.open
    monkeypatch.setattr(Path, "open", deny_read)

    with pytest.raises(SourceSnapshotError, match=r"app\.py.*access denied"):
        facts_cache_key(tmp_path, ("app.py",), "web")


def test_facts_cache_key_changes_with_profile_content_identity(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    first = facts_cache_key(tmp_path, ("app.py",), "web", profile_content_snapshot_id="1" * 64)
    second = facts_cache_key(tmp_path, ("app.py",), "web", profile_content_snapshot_id="2" * 64)

    assert first != second


def test_facts_cache_key_changes_with_backend_identity(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    first = facts_cache_key(tmp_path, ("app.py",), "web", backend_identity="backend-one")
    second = facts_cache_key(tmp_path, ("app.py",), "web", backend_identity="backend-two")

    assert first != second


def test_facts_summary_does_not_broadcast_source_limitations(tmp_path):
    workspace = tmp_path / "workspace"
    cache = tmp_path / "cache"
    workspace.mkdir()
    limitation = FactLimitation(
        source="broken.ts",
        analyzer="typescript",
        reason="unparsable",
        line=3,
        column=2,
    )

    FactsStore(workspace=workspace, cache_root=cache).persist(
        Facts(summary="Call graph", limitations=(limitation,)),
        "key",
        is_test_path=lambda _path: False,
    )

    assert (workspace / "_facts.md").read_text(encoding="utf-8") == "Call graph"
    assert "broken.ts" in (workspace / "_facts_limitations.json").read_text(encoding="utf-8")


def test_optional_cache_failure_keeps_committed_workspace_facts(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    cache = tmp_path / "cache"
    workspace.mkdir()
    store = FactsStore(workspace=workspace, cache_root=cache)
    original = FactsStore._write_manifest

    def fail_cache_manifest(path, artifacts):
        if path.parent == cache:
            raise OSError("cache unavailable")
        return original(path, artifacts)

    monkeypatch.setattr(FactsStore, "_write_manifest", staticmethod(fail_cache_manifest))

    store.persist(Facts(summary="facts"), "key", is_test_path=lambda _path: False)

    assert store.complete()
    assert "cache unavailable" in (workspace / "_facts_cache_error.txt").read_text()
    assert not (cache / "key.manifest.json").exists()


def test_relationship_evidence_persists_and_restores_with_facts_cache(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relationships import relationship_evidence_from_data
    from cyberjury.review.repository.context import load_relationship_evidence

    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    restored = tmp_path / "restored"
    cache = tmp_path / "cache"
    source.mkdir()
    workspace.mkdir()
    restored.mkdir()
    (source / "app.py").write_text("def route(x):\n    return load(x)\n", encoding="utf-8")
    facts = TreeSitterFacts().extract(source)
    expected = relationship_evidence_from_data(facts.data["relationship_evidence"])
    store = FactsStore(workspace=workspace, cache_root=cache)

    store.persist(facts, "key", is_test_path=lambda _path: False)

    assert load_relationship_evidence(workspace) == expected
    assert FactsStore(workspace=restored, cache_root=cache).restore("key")
    assert load_relationship_evidence(restored) == expected
