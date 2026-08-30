"""Facts storage preserves cache identity and loud failure behavior."""

from pathlib import Path

import pytest

from cyberjury.review.facts import FactLimitation, Facts
from cyberjury.review.storage import FactsStore, facts_cache_key


def test_facts_cache_key_fails_with_the_unreadable_source_path(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")

    def deny_read(path: Path) -> bytes:
        if path == source:
            raise PermissionError("access denied")
        return original_read(path)

    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", deny_read)

    with pytest.raises(OSError, match=r"app\.py.*access denied"):
        facts_cache_key(tmp_path, ("app.py",), "web")


def test_facts_cache_key_changes_with_profile_content_identity(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    first = facts_cache_key(tmp_path, ("app.py",), "web", profile_fingerprint="one")
    second = facts_cache_key(tmp_path, ("app.py",), "web", profile_fingerprint="two")

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
