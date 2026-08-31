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
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import RelationshipResolution, RelationshipResolver
    from cyberjury.review.relationships import (
        ArgumentToParameterRelation,
        CallsiteRelationshipResult,
        NavigationReceipt,
        StructuralRelationshipResult,
        SupportedCallRelation,
        SupportedStructuralRelation,
        relationship_evidence_from_data,
    )
    from cyberjury.review.storage import RelationshipStore

    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    source.mkdir()
    workspace.mkdir()
    (source / "service.py").write_text("def load(x):\n    return x\n")
    (source / "route.py").write_text("from service import load\n\ndef route(x):\n    return load(x)\n")
    bundle = relationship_evidence_from_data(TreeSitterFacts().extract(source).data["relationship_evidence"])

    class StaticResolver(RelationshipResolver):
        def __init__(self, identity):
            self.identity = identity

        def cache_identity(self):
            return self.identity

        def resolve(self, _root, current):
            callsite = current.callsites[0]
            caller = next(item for item in current.definitions if item.id == callsite.caller_definition_id)
            target = next(item for item in current.definitions if item.name == "load")
            observation = next(item for item in current.observations if callsite.id in item.subject_ids)
            parameter = target.parameters[0]
            argument = callsite.arguments[0]
            call_receipt = NavigationReceipt.create(
                kind="symbol",
                purpose="target_candidate",
                query="load",
                path_prefix="",
                cursor=0,
                returned_definition_ids=(target.id,),
                returned_source_ids=(target.source.id,),
                next_cursor=None,
            )
            call_evidence = tuple(
                dict.fromkeys(
                    (
                        caller.source.id,
                        callsite.source.id,
                        target.source.id,
                        observation.id,
                        *observation.provenance_source_ids,
                        call_receipt.id,
                    )
                )
            )
            subject = current.structural_subjects[0]
            structural_receipt = NavigationReceipt.create(
                kind="symbol",
                purpose="target_candidate",
                query=subject.reference,
                path_prefix="",
                cursor=0,
                returned_definition_ids=(target.id,),
                returned_source_ids=(target.source.id,),
                next_cursor=None,
            )
            return RelationshipResolution(
                call_results=(
                    CallsiteRelationshipResult(
                        callsite_id=callsite.id,
                        supported_relations=(
                            SupportedCallRelation(
                                target_definition_id=target.id,
                                evidence_ids=call_evidence,
                                argument_relations=(
                                    ArgumentToParameterRelation(
                                        argument_position=0,
                                        parameter_id=parameter.id,
                                        evidence_ids=(argument.source.id, parameter.source.id),
                                    ),
                                ),
                            ),
                        ),
                        candidate_target_ids=(),
                        target_coverage="complete",
                        coverage_limitation_ids=(),
                        reason="static test relationship",
                        navigation_receipts=(call_receipt,),
                    ),
                ),
                structural_results=(
                    StructuralRelationshipResult(
                        subject_id=subject.id,
                        supported_relations=(
                            SupportedStructuralRelation(
                                target_definition_id=target.id,
                                evidence_ids=(structural_receipt.id, subject.source.id, target.source.id),
                            ),
                        ),
                        candidate_target_ids=(),
                        target_coverage="complete",
                        coverage_limitation_ids=(),
                        reason="static test relationship",
                        navigation_receipts=(structural_receipt,),
                    ),
                ),
                calls=2,
                initial_packet_characters=0,
            )

    resolver = StaticResolver("resolver-one")
    store = RelationshipStore(workspace=workspace)

    first = store.resolve(source, bundle, resolver)
    restored = store.resolve(source, bundle, resolver)

    assert first.calls == 2
    assert restored.calls == first.calls
    assert restored.restored is True
    assert restored.call_results == first.call_results
    assert restored.structural_results == first.structural_results
    changed = StaticResolver("resolver-two")
    with pytest.raises(ValueError, match=r"resolver changed.*--fresh"):
        store.resolve(source, bundle, changed)
