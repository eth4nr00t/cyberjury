"""Models establish callsite relationships only from published exact source."""

import json
import re

import pytest

from cyberjury.providers.mock import MockProvider


def _navigation_deliveries(messages):
    deliveries = []
    for message in messages:
        if not message.content.startswith("Deterministic navigation results:"):
            continue
        encoded = message.content.split("Deterministic navigation results:\n", 1)[1].split("\n\nRequest", 1)[0]
        deliveries.extend(json.loads(encoded))
    return deliveries


def _target_navigation_request(query):
    return json.dumps(
        {
            "navigation_requests": [
                {
                    "kind": "symbol",
                    "purpose": "target_candidate",
                    "query": query,
                    "path_prefix": "",
                    "cursor": 0,
                }
            ]
        }
    )


def _web_bundle(tmp_path, *, dynamic=False):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "service.py").write_text(
        "class A:\n"
        "    def load(self, value):\n"
        "        return value\n\n"
        "class B:\n"
        "    def load(self, value):\n"
        "        return value\n\n"
        "def direct(value):\n"
        "    return value\n",
        encoding="utf-8",
    )
    route = (
        "def route(service, value):\n    return service.load(value)\n"
        if dynamic
        else "from service import direct\n\ndef route(value):\n    return direct(value)\n"
    )
    (tmp_path / "route.py").write_text(route, encoding="utf-8")
    data = TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]
    return replace(relationship_evidence_from_data(data), structural_subjects=())


def _supported_response(_system, messages):
    packet = json.loads(messages[0].content)
    if "structural_subject" in packet:
        target = packet["published_candidates"][0]
        return json.dumps(
            {
                "subject_id": packet["subject_id"],
                "supported_relations": [_supported_entry(packet, target, target["required_evidence_ids"])],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "reason": "exact structural source",
            }
        )
    deliveries = _navigation_deliveries(messages)
    if not deliveries:
        return _target_navigation_request(packet["callsite"]["callee_spelling"])
    target = deliveries[-1]["published_candidates"][0]
    delivered = {source_id for source_id, evidence in packet["source_evidence"].items() if "text" in evidence}
    delivered.update(
        source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
    )
    required_sources = {source_id for source_id in target["required_evidence_ids"] if source_id.startswith("src-")}
    required_sources.update(parameter["source"]["id"] for parameter in target["parameters"])
    missing = sorted(required_sources.difference(delivered))
    if missing:
        return json.dumps({"evidence_requests": missing})
    evidence_ids = list(
        dict.fromkeys(
            (
                *packet["source_evidence"],
                *(item["id"] for item in packet["producer_observations"]),
                *target["required_evidence_ids"],
            )
        )
    )
    return json.dumps(
        {
            "callsite_id": packet["callsite_id"],
            "supported_relations": [_supported_entry(packet, target, evidence_ids)],
            "candidate_target_ids": [],
            "excluded_candidates": [],
            "target_coverage": "complete",
            "coverage_limitation_ids": [],
            "related_contexts": [],
            "reason": "exact import, caller, callsite, and target source",
        }
    )


def _supported_entry(packet, target, evidence_ids):
    callsite = packet.get("callsite")
    if callsite is None:
        return {
            "target_definition_id": target["id"],
            "evidence_ids": evidence_ids,
        }
    mapped = [
        {
            "argument_position": argument["position"],
            "parameter_id": target["parameters"][argument["position"]]["id"],
            "evidence_ids": [
                argument["source"]["id"],
                target["parameters"][argument["position"]]["source"]["id"],
            ],
        }
        for argument in callsite["arguments"]
        if argument["source"] is not None and argument["position"] < len(target["parameters"])
    ]
    unmapped = [
        argument["position"]
        for argument in callsite["arguments"]
        if argument["source"] is None or argument["position"] >= len(target["parameters"])
    ]
    return {
        "target_definition_id": target["id"],
        "evidence_ids": evidence_ids,
        "argument_relations": mapped,
        "data_coverage": "incomplete" if unmapped else "complete",
        "unmapped_argument_positions": unmapped,
    }


def test_model_relationship_resolver_reads_import_and_target_source(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.definitions import definition_dependencies
    from cyberjury.review.relations import ModelRelationshipResolver, graph_with_model_relationships

    provider = MockProvider(responder=_supported_response)
    bundle = _web_bundle(tmp_path)

    resolution = ModelRelationshipResolver(provider=provider, model="model").resolve(tmp_path, bundle)

    assert resolution.calls == 3
    assert resolution.call_results[0].target_coverage == "complete"
    assert len(resolution.call_results[0].supported_relations) == 1
    packet = json.loads(provider.calls[0]["messages"][0].content)
    assert any(item["text"] == "from service import direct" for item in packet["source_evidence"].values())
    assert any("def direct" in message.content for message in provider.calls[-1]["messages"])
    coded_graph = TreeSitterFacts().extract(tmp_path).data["graph"]
    model_graph = graph_with_model_relationships(coded_graph, bundle, resolution.call_results)
    calls = [dependency for dependency in definition_dependencies(model_graph) if dependency.kind == "call"]
    assert [(dependency.source.name, dependency.target.name) for dependency in calls] == [("route", "direct")]
    assert calls[0].resolution == "supported"


def test_model_relationship_resolver_rejects_supported_target_without_target_source_receipt(tmp_path):
    from cyberjury.review.relations import ModelRelationshipResolver, RelationshipResolutionError

    def incomplete(_system, messages):
        packet = json.loads(messages[0].content)
        deliveries = _navigation_deliveries(messages)
        if not deliveries:
            return _target_navigation_request(packet["callsite"]["callee_spelling"])
        target = deliveries[-1]["published_candidates"][0]
        callsite_source = packet["callsite"]["source"]["id"]
        navigation_receipt = deliveries[-1]["receipt"]["id"]
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [
                    {
                        **_supported_entry(packet, target, [callsite_source, navigation_receipt]),
                    }
                ],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "unsupported promotion",
            }
        )

    with pytest.raises(RelationshipResolutionError, match="omits controlling evidence"):
        ModelRelationshipResolver(provider=MockProvider(responder=incomplete), model="model").resolve(
            tmp_path,
            _web_bundle(tmp_path),
        )


def test_argument_relation_requires_both_exact_endpoint_sources(tmp_path):
    from cyberjury.review.relationship_protocol import RelationshipResolutionError, validate_controlling_evidence
    from cyberjury.review.relationships import (
        ArgumentToParameterRelation,
        CallsiteRelationshipResult,
        NavigationReceipt,
        SupportedCallRelation,
    )

    bundle = _web_bundle(tmp_path)
    callsite = bundle.callsites[0]
    target = next(definition for definition in bundle.definitions if definition.name == "direct")
    observation = bundle.observations[0]
    argument = callsite.arguments[0]
    parameter = target.parameters[0]
    receipt = NavigationReceipt.create(
        kind="symbol",
        purpose="target_candidate",
        query="direct",
        path_prefix="",
        cursor=0,
        returned_definition_ids=(target.id,),
        returned_source_ids=(target.source.id,),
        next_cursor=None,
    )
    result = CallsiteRelationshipResult(
        callsite_id=callsite.id,
        supported_relations=(
            SupportedCallRelation(
                target_definition_id=target.id,
                evidence_ids=tuple(
                    dict.fromkeys(
                        (
                            callsite.source.id,
                            target.source.id,
                            receipt.id,
                            observation.id,
                            *observation.provenance_source_ids,
                        )
                    )
                ),
                argument_relations=(
                    ArgumentToParameterRelation(
                        argument_position=0,
                        parameter_id=parameter.id,
                        evidence_ids=(argument.source.id,),
                    ),
                ),
            ),
        ),
        candidate_target_ids=(),
        target_coverage="complete",
        coverage_limitation_ids=(),
        reason="missing parameter endpoint source",
        navigation_receipts=(receipt,),
    )

    with pytest.raises(RelationshipResolutionError, match="omits exact endpoint evidence"):
        validate_controlling_evidence(
            result,
            callsite=callsite,
            definitions={definition.id: definition for definition in bundle.definitions},
            observations=(observation,),
        )


def test_unresolved_dynamic_call_remains_incomplete_without_inventing_candidates(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.definitions import unresolved_dependencies
    from cyberjury.review.relations import ModelRelationshipResolver, graph_with_model_relationships

    def unresolved(_system, messages):
        packet = json.loads(messages[-1].content)
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [item["id"] for item in packet["published_candidates"]],
                "excluded_candidates": [],
                "target_coverage": "incomplete",
                "coverage_limitation_ids": packet["available_coverage_limitation_ids"],
                "related_contexts": [],
                "reason": "the untyped receiver can name targets outside the repository",
            }
        )

    bundle = _web_bundle(tmp_path, dynamic=True)
    resolution = ModelRelationshipResolver(provider=MockProvider(responder=unresolved), model="model").resolve(
        tmp_path,
        bundle,
    )
    result = resolution.call_results[0]

    assert result.target_coverage == "incomplete"
    assert result.candidate_target_ids == ()
    assert result.navigation_receipts == ()
    model_graph = graph_with_model_relationships(
        TreeSitterFacts().extract(tmp_path).data["graph"],
        bundle,
        resolution.call_results,
    )
    assert [(item.source.name, item.reference) for item in unresolved_dependencies(model_graph)] == [("route", "load")]


def test_model_relationship_resolver_fails_loud_on_malformed_reply(tmp_path):
    from cyberjury.review.relations import ModelRelationshipResolver, RelationshipResolutionError

    with pytest.raises(RelationshipResolutionError, match="must contain exactly"):
        ModelRelationshipResolver(provider=MockProvider(default="{}"), model="model").resolve(
            tmp_path,
            _web_bundle(tmp_path),
        )


def test_model_relationship_resolver_allows_one_validated_correction(tmp_path):
    from cyberjury.review.relations import ModelRelationshipResolver

    result_attempts = 0

    def responder(_system, messages):
        nonlocal result_attempts
        packet = json.loads(messages[0].content)
        deliveries = _navigation_deliveries(messages)
        if not deliveries:
            return _target_navigation_request(packet["callsite"]["callee_spelling"])
        target = deliveries[-1]["published_candidates"][0]
        delivered = {source_id for source_id, item in packet["source_evidence"].items() if "text" in item}
        delivered.update(
            source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        required_sources = {source_id for source_id in target["required_evidence_ids"] if source_id.startswith("src-")}
        required_sources.update(parameter["source"]["id"] for parameter in target["parameters"])
        missing = sorted(required_sources.difference(delivered))
        if missing:
            return json.dumps({"evidence_requests": missing})
        result_attempts += 1
        evidence = list(
            dict.fromkeys(
                (
                    *packet["source_evidence"],
                    *(item["id"] for item in packet["producer_observations"]),
                    *target["required_evidence_ids"],
                )
            )
        )
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [_supported_entry(packet, target, evidence)],
                "candidate_target_ids": [target["id"]] if result_attempts == 1 else [],
                "excluded_candidates": [],
                "target_coverage": "incomplete" if result_attempts == 1 else "complete",
                "coverage_limitation_ids": (
                    packet["available_coverage_limitation_ids"] if result_attempts == 1 else []
                ),
                "related_contexts": [],
                "reason": "corrected relationship",
            }
        )

    result = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
    ).resolve(tmp_path, _web_bundle(tmp_path))

    assert result.calls == 4
    assert result.call_results[0].target_coverage == "complete"


def test_large_relationship_source_is_read_by_id_before_a_final_result(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "service.py").write_text(f"def direct(value):\n    payload = {'x' * 12_000!r}\n    return value\n")
    (tmp_path / "route.py").write_text("from service import direct\n\ndef route(value):\n    return direct(value)\n")
    from dataclasses import replace

    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )
    required: list[str] = []
    observations: list[str] = []
    callsite_id = ""
    target_id = ""

    def responder(_system, messages):
        nonlocal required, observations, callsite_id, target_id
        packet = json.loads(messages[0].content)
        deliveries = _navigation_deliveries(messages)
        if not deliveries:
            return _target_navigation_request(packet["callsite"]["callee_spelling"])
        candidate = deliveries[-1]["published_candidates"][0]
        if not required:
            required = candidate["required_evidence_ids"]
            observations = [item["id"] for item in packet["producer_observations"]]
            callsite_id = packet["callsite_id"]
            target_id = candidate["id"]
            assert candidate["source"]["id"] not in packet["source_evidence"]
        delivered = {source_id for source_id, item in packet["source_evidence"].items() if "text" in item}
        delivered.update(
            source_id
            for message in messages[1:]
            for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        source_ids = {
            *packet["source_evidence"],
            *(source_id for source_id in required if source_id.startswith("src-")),
            *(parameter["source"]["id"] for parameter in candidate["parameters"]),
        }
        remaining = sorted(source_ids.difference(delivered))
        if remaining:
            return json.dumps({"evidence_requests": remaining})
        return json.dumps(
            {
                "callsite_id": callsite_id,
                "supported_relations": [
                    _supported_entry(
                        packet,
                        candidate,
                        list(dict.fromkeys((*required, *observations))),
                    )
                ],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "requested exact source before supporting the target",
            }
        )

    provider = MockProvider(responder=responder)
    resolution = ModelRelationshipResolver(
        provider=provider,
        model="model",
        max_packet_chars=7_000,
        concurrency=1,
    ).resolve(tmp_path, bundle)

    assert resolution.call_results[0].target_coverage == "complete"
    assert resolution.calls >= 2


def test_large_navigation_catalog_reads_every_page_without_dropping_targets(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data

    classes = "\n\n".join(f"class C{index}:\n    def load(self, value):\n        return value" for index in range(20))
    (tmp_path / "service.py").write_text(classes + "\n")
    (tmp_path / "route.py").write_text("def route(client, value):\n    return client.load(value)\n")
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        deliveries = _navigation_deliveries(messages)
        if not deliveries:
            return _target_navigation_request("load")
        receipt = deliveries[-1]["receipt"]
        if receipt["next_cursor"] is not None:
            return json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": receipt["kind"],
                            "purpose": "target_candidate",
                            "query": receipt["query"],
                            "path_prefix": receipt["path_prefix"],
                            "cursor": receipt["next_cursor"],
                        }
                    ]
                }
            )
        candidates = list(
            {
                candidate["id"]: candidate for delivery in deliveries for candidate in delivery["published_candidates"]
            }.values()
        )
        delivered = {source_id for source_id, item in packet["source_evidence"].items() if "text" in item}
        delivered.update(
            source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        required_sources = {
            source_id
            for candidate in candidates
            for source_id in candidate["required_evidence_ids"]
            if source_id.startswith("src-")
        }
        remaining = sorted(required_sources.difference(delivered))
        if remaining:
            return json.dumps({"evidence_requests": remaining})
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [
                    {
                        "target_definition_id": candidate["id"],
                        "evidence_ids": candidate["required_evidence_ids"],
                        "reason": "the untyped receiver does not prove this target",
                    }
                    for candidate in candidates
                ],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "candidate checked",
            }
        )

    resolution = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
        concurrency=1,
        navigation_page_size=5,
    ).resolve(tmp_path, bundle)

    assert len(resolution.call_results) == 1
    assert len(resolution.call_results[0].excluded_candidates) == 20
    assert resolution.call_results[0].navigation_receipts[-1].next_cursor is None


def _navigation_delivery(messages):
    content = next(
        message.content
        for message in reversed(messages)
        if message.role == "user" and message.content.startswith("Deterministic navigation results:")
    )
    encoded = content.split("Deterministic navigation results:\n", 1)[1].split("\n\nRequest", 1)[0]
    return json.loads(encoded)[0]


def test_model_can_find_a_missing_target_through_attributable_navigation(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "app.py").write_text(
        "def actual(value):\n    return value\n\ndef route(value):\n    invoke = actual\n    return invoke(value)\n"
    )
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        if not any(message.content.startswith("Deterministic navigation results:") for message in messages):
            return json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": "symbol",
                            "purpose": "target_candidate",
                            "query": "actual",
                            "path_prefix": "",
                            "cursor": 0,
                        }
                    ]
                }
            )
        delivery = _navigation_delivery(messages)
        candidate = delivery["published_candidates"][0]
        required = candidate["required_evidence_ids"]
        supported = _supported_entry(packet, candidate, required)
        delivered = {source_id for source_id, evidence in packet["source_evidence"].items() if "text" in evidence}
        delivered.update(
            source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        required_sources = {
            *(item for item in required if item.startswith("src-")),
            *(
                item
                for relation in supported["argument_relations"]
                for item in relation["evidence_ids"]
                if item.startswith("src-")
            ),
        }
        missing = sorted(required_sources.difference(delivered))
        if missing:
            return json.dumps({"evidence_requests": missing})
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [supported],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "the local assignment binds invoke to actual",
            }
        )

    resolution = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
        concurrency=1,
    ).resolve(tmp_path, bundle)

    relation = resolution.call_results[0].supported_relations[0]
    assert next(item for item in bundle.definitions if item.id == relation.target_definition_id).name == "actual"
    assert resolution.call_results[0].navigation_receipts[0].purpose == "target_candidate"


def test_zero_candidate_call_cannot_complete_without_target_navigation(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver, RelationshipResolutionError
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "app.py").write_text(
        "def actual(value):\n    return value\n\ndef route(value):\n    invoke = actual\n    return invoke(value)\n"
    )
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "no target",
            }
        )

    with pytest.raises(RelationshipResolutionError, match="requires target navigation"):
        ModelRelationshipResolver(
            provider=MockProvider(responder=responder),
            model="model",
            correction_attempts=0,
        ).resolve(tmp_path, bundle)


def test_web_same_name_definitions_are_not_prepublished_as_targets(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "service.py").write_text("def target(value):\n    return value\n")
    (tmp_path / "route.py").write_text("def route(value):\n    return target(value)\n")
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        assert packet["published_candidates"] == []
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "incomplete",
                "coverage_limitation_ids": packet["available_coverage_limitation_ids"],
                "related_contexts": [],
                "reason": "no target search was attempted",
            }
        )

    resolution = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
        correction_attempts=0,
    ).resolve(tmp_path, bundle)

    assert resolution.call_results[0].target_coverage == "incomplete"


def test_zero_candidate_structural_subject_cannot_complete_without_target_navigation(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver, RelationshipResolutionError
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "service.py").write_text("def target(value):\n    return value\n")
    (tmp_path / "barrel.py").write_text("from service import target\n")
    original = relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"])
    bundle = replace(original, callsites=(), observations=())

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        return json.dumps(
            {
                "subject_id": packet["subject_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "reason": "no target",
            }
        )

    with pytest.raises(RelationshipResolutionError, match="requires target navigation"):
        ModelRelationshipResolver(
            provider=MockProvider(responder=responder),
            model="model",
            correction_attempts=0,
        ).resolve(tmp_path, bundle)


def test_completed_no_hit_navigation_can_prove_zero_targets(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "app.py").write_text("def route(handler, value):\n    return handler(value)\n")
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        if not any(message.content.startswith("Deterministic navigation results:") for message in messages):
            return json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": "symbol",
                            "purpose": "target_candidate",
                            "query": "missing_handler",
                            "path_prefix": "",
                            "cursor": 0,
                        }
                    ]
                }
            )
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "completed repository search found no target",
            }
        )

    resolution = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
        correction_attempts=0,
    ).resolve(tmp_path, bundle)

    assert resolution.call_results[0].target_coverage == "complete"
    assert resolution.call_results[0].navigation_receipts[0].next_cursor is None


def test_incomplete_target_navigation_page_cannot_claim_complete_coverage(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relations import ModelRelationshipResolver, RelationshipResolutionError
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "target_a.py").write_text("def target(value):\n    return value\n")
    (tmp_path / "target_b.py").write_text("def target(value):\n    return value\n")
    (tmp_path / "app.py").write_text("def route(handler, value):\n    return handler(value)\n")
    bundle = replace(
        relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"]),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        deliveries = [
            _navigation_delivery(messages)
            for message in messages
            if message.content.startswith("Deterministic navigation results:")
        ]
        if not deliveries:
            return json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": "symbol",
                            "purpose": "target_candidate",
                            "query": "target",
                            "path_prefix": "",
                            "cursor": 0,
                        }
                    ]
                }
            )
        candidate = deliveries[-1]["published_candidates"][0]
        required_sources = [item for item in candidate["required_evidence_ids"] if item.startswith("src-")]
        delivered = {source_id for source_id, evidence in packet["source_evidence"].items() if "text" in evidence}
        delivered.update(
            source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        missing = sorted(set(required_sources).difference(delivered))
        if missing:
            return json.dumps({"evidence_requests": missing})
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [],
                "candidate_target_ids": [],
                "excluded_candidates": [
                    {
                        "target_definition_id": candidate["id"],
                        "evidence_ids": candidate["required_evidence_ids"],
                        "reason": "first page candidate excluded",
                    }
                ],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [],
                "reason": "incorrectly stopped after one page",
            }
        )

    with pytest.raises(RelationshipResolutionError, match="requires every target navigation page"):
        ModelRelationshipResolver(
            provider=MockProvider(responder=responder),
            model="model",
            correction_attempts=0,
            navigation_page_size=1,
        ).resolve(tmp_path, bundle)


def test_model_can_add_non_callee_data_context_without_promoting_it_to_a_target(tmp_path):
    from dataclasses import replace

    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.definitions import definition_dependencies
    from cyberjury.review.relations import ModelRelationshipResolver, graph_with_model_relationships
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "app.py").write_text(
        "def normalize(value):\n"
        "    return value.strip()\n\n"
        "def target(value):\n"
        "    return value\n\n"
        "def route(value):\n"
        "    transform = normalize\n"
        "    return target(value)\n"
    )
    extracted = TreeSitterFacts().extract(tmp_path)
    original = relationship_evidence_from_data(extracted.data["relationship_evidence"])
    callsite = next(item for item in original.callsites if item.callee_spelling == "target")
    bundle = replace(
        original,
        callsites=(callsite,),
        observations=tuple(item for item in original.observations if callsite.id in item.subject_ids),
        structural_subjects=(),
    )

    def responder(_system, messages):
        packet = json.loads(messages[0].content)
        deliveries = _navigation_deliveries(messages)
        target_delivery = next(
            (item for item in deliveries if item["receipt"]["purpose"] == "target_candidate"),
            None,
        )
        if target_delivery is None:
            return _target_navigation_request("target")
        context_delivery = next(
            (item for item in deliveries if item["receipt"]["purpose"] == "context_evidence"),
            None,
        )
        if context_delivery is None:
            return json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": "symbol",
                            "purpose": "context_evidence",
                            "query": "normalize",
                            "path_prefix": "",
                            "cursor": 0,
                        }
                    ]
                }
            )
        target = target_delivery["published_candidates"][0]
        context = context_delivery["published_context_definitions"][0]
        call_evidence = list(
            dict.fromkeys(
                (
                    *packet["source_evidence"],
                    *(item["id"] for item in packet["producer_observations"]),
                    *target["required_evidence_ids"],
                )
            )
        )
        context_evidence = [
            context_delivery["receipt"]["id"],
            packet["caller"]["source"]["id"],
            packet["callsite"]["source"]["id"],
            context["source"]["id"],
        ]
        required_sources = {
            *(item for item in call_evidence if item.startswith("src-")),
            *(item for item in context_evidence if item.startswith("src-")),
            *(parameter["source"]["id"] for parameter in target["parameters"]),
        }
        delivered = {source_id for source_id, evidence in packet["source_evidence"].items() if "text" in evidence}
        delivered.update(
            source_id for message in messages for source_id in re.findall(r"Source `(src-[0-9a-f]+)`", message.content)
        )
        missing = sorted(required_sources.difference(delivered))
        if missing:
            return json.dumps({"evidence_requests": missing})
        return json.dumps(
            {
                "callsite_id": packet["callsite_id"],
                "supported_relations": [_supported_entry(packet, target, call_evidence)],
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "related_contexts": [
                    {
                        "definition_id": context["id"],
                        "kind": "data",
                        "evidence_ids": context_evidence,
                        "reason": "the caller assigns normalize as its transform",
                    }
                ],
                "reason": "target and supporting data context are established separately",
            }
        )

    resolution = ModelRelationshipResolver(
        provider=MockProvider(responder=responder),
        model="model",
        concurrency=1,
    ).resolve(tmp_path, bundle)
    result = resolution.call_results[0]

    assert [item.kind for item in result.related_contexts] == ["data"]
    assert result.related_contexts[0].definition_id not in {
        relation.target_definition_id for relation in result.supported_relations
    }
    graph = graph_with_model_relationships(
        extracted.data["graph"],
        bundle,
        resolution.call_results,
        resolution.structural_results,
    )
    data_edges = [item for item in definition_dependencies(graph) if item.kind == "data"]
    assert any(item.target.name == "normalize" for item in data_edges)
