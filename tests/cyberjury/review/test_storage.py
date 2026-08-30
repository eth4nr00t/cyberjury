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


def test_relationship_results_restore_only_for_the_same_evidence_and_resolver(tmp_path):
    import json

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.providers.mock import MockProvider
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data
    from cyberjury.review.storage import RelationshipStore

    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    source.mkdir()
    workspace.mkdir()
    (source / "service.py").write_text("def load(x):\n    return x\n")
    (source / "route.py").write_text("from service import load\n\ndef route(x):\n    return load(x)\n")
    bundle = relationship_evidence_from_data(TreeSitterFacts().extract(source).data["relationship_evidence"])

    def response(_system, messages):
        packet = json.loads(messages[0].content)
        target = packet["published_candidates"][0]
        if "structural_subject" in packet:
            return json.dumps(
                {
                    "subject_id": packet["subject_id"],
                    "supported_relations": [
                        {
                            "target_definition_id": target["id"],
                            "evidence_ids": target["required_evidence_ids"],
                        }
                    ],
                    "candidate_target_ids": [],
                    "excluded_candidates": [],
                    "target_coverage": "complete",
                    "coverage_limitation_ids": [],
                    "reason": "exact structural source",
                }
            )
        evidence = [
            *packet["source_evidence"],
            *(item["id"] for item in packet["producer_observations"]),
        ]
        argument = packet["callsite"]["arguments"][0]
        parameter = target["parameters"][0]
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [
                    {
                        "target_definition_id": target["id"],
                        "evidence_ids": evidence,
                        "argument_relations": [
                            {
                                "argument_position": 0,
                                "parameter_id": parameter["id"],
                                "evidence_ids": [argument["source"]["id"], parameter["source"]["id"]],
                            }
                        ],
                        "data_coverage": "complete",
                        "unmapped_argument_positions": [],
                    }
                ],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "exact source",
            }
        )

    provider = MockProvider(responder=response)
    resolver = ModelRelationshipResolver(provider=provider, model="model")
    store = RelationshipStore(workspace=workspace)

    first = store.resolve(source, bundle, resolver)
    restored = store.resolve(source, bundle, resolver)

    assert first.calls == 2
    assert restored.calls == first.calls
    assert restored.restored is True
    assert restored.call_results == first.call_results
    assert restored.structural_results == first.structural_results
    assert len(provider.calls) == 2
    changed = ModelRelationshipResolver(provider=provider, model="other-model")
    with pytest.raises(ValueError, match=r"resolver changed.*--fresh"):
        store.resolve(source, bundle, changed)
