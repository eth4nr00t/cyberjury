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
