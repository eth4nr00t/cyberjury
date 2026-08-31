"""Provide the deterministic relationship responder used by dry runs."""

from __future__ import annotations

import json
import re

from cyberjury.providers.base import Message


def relationship_dry_run_response(messages: list[Message]) -> str:
    """Return a complete evidence attributed relationship receipt for dry runs."""
    packet = json.loads(messages[0].content)
    navigation_deliveries = [
        item
        for message in messages
        if message.role == "user" and message.content.startswith("Deterministic navigation results:")
        for item in json.loads(
            message.content.split("Deterministic navigation results:\n", 1)[1].split("\n\nRequest", 1)[0]
        )
    ]
    target_deliveries = [item for item in navigation_deliveries if item["receipt"]["purpose"] == "target_candidate"]
    subject = packet.get("structural_subject")
    producer_targets = {
        target
        for observation in packet.get("producer_observations", ())
        for target in observation["candidate_target_ids"]
    }
    target_navigation_required = not packet["published_candidates"] if subject else not producer_targets
    if target_navigation_required and not target_deliveries:
        raw_query = subject["reference"] if subject else packet["callsite"]["callee_spelling"]
        query = raw_query.split(" from ", 1)[0].rsplit(".", 1)[-1]
        source_file = subject["source_file"] if subject else packet["callsite"]["source"]["path"]
        return json.dumps(
            {
                "navigation_requests": [
                    {
                        "kind": "symbol",
                        "purpose": "target_candidate",
                        "query": query,
                        "path_prefix": source_file.rsplit("/", 1)[0] if "/" in source_file else "",
                        "cursor": 0,
                    }
                ]
            }
        )
    unfinished = next(
        (item["receipt"] for item in reversed(target_deliveries) if item["receipt"]["next_cursor"] is not None),
        None,
    )
    if unfinished is not None and not any(
        item["receipt"]["kind"] == unfinished["kind"]
        and item["receipt"]["query"] == unfinished["query"]
        and item["receipt"]["path_prefix"] == unfinished["path_prefix"]
        and item["receipt"]["cursor"] == unfinished["next_cursor"]
        for item in target_deliveries
    ):
        return json.dumps(
            {
                "navigation_requests": [
                    {
                        "kind": unfinished["kind"],
                        "purpose": "target_candidate",
                        "query": unfinished["query"],
                        "path_prefix": unfinished["path_prefix"],
                        "cursor": unfinished["next_cursor"],
                    }
                ]
            }
        )
    source_evidence = packet["source_evidence"]
    delivered_source_ids = {source_id for source_id, evidence in source_evidence.items() if "text" in evidence}
    delivered_source_ids.update(
        source_id for message in messages[1:] for source_id in re.findall(r"Source `(src-[0-9a-f]+)`:", message.content)
    )
    missing_source_ids = [source_id for source_id in source_evidence if source_id not in delivered_source_ids]
    if missing_source_ids:
        return json.dumps({"evidence_requests": missing_source_ids})
    candidates = list(packet["published_candidates"])
    candidates.extend(candidate for delivery in target_deliveries for candidate in delivery["published_candidates"])
    candidates = list({candidate["id"]: candidate for candidate in candidates}.values())
    candidate_source_ids = {
        evidence_id
        for candidate in candidates
        for evidence_id in candidate["required_evidence_ids"]
        if evidence_id.startswith("src-")
    }
    unread_candidate_sources = sorted(candidate_source_ids.difference(delivered_source_ids))
    if unread_candidate_sources:
        return json.dumps({"evidence_requests": unread_candidate_sources})
    if "structural_subject" in packet:
        supported = [
            {
                "target_definition_id": candidate["id"],
                "evidence_ids": candidate["required_evidence_ids"],
            }
            for candidate in candidates
        ]
        return json.dumps(
            {
                "subject_id": packet["subject_id"],
                "supported_relations": supported,
                "candidate_target_ids": [],
                "excluded_candidates": [],
                "target_coverage": "complete",
                "coverage_limitation_ids": [],
                "reason": (
                    "mock structural relationship resolution"
                    if candidates
                    else "mock found no repository target for the structural syntax"
                ),
            }
        )
    evidence_ids = [
        *source_evidence,
        *(item["id"] for item in packet["producer_observations"]),
    ]
    observed = {
        target for observation in packet["producer_observations"] for target in observation["candidate_target_ids"]
    }
    supported = [
        {
            "target_definition_id": candidate["id"],
            "evidence_ids": evidence_ids,
            "argument_relations": [
                {
                    "argument_position": argument["position"],
                    "parameter_id": candidate["parameters"][argument["position"]]["id"],
                    "evidence_ids": [
                        argument["source"]["id"],
                        candidate["parameters"][argument["position"]]["source"]["id"],
                    ],
                }
                for argument in packet["callsite"]["arguments"]
                if argument["source"] is not None and argument["position"] < len(candidate["parameters"])
            ],
            "data_coverage": (
                "complete" if len(candidate["parameters"]) >= len(packet["callsite"]["arguments"]) else "incomplete"
            ),
            "unmapped_argument_positions": [
                argument["position"]
                for argument in packet["callsite"]["arguments"]
                if argument["source"] is None or argument["position"] >= len(candidate["parameters"])
            ],
        }
        for candidate in candidates
        if candidate["id"] in observed
    ]
    excluded = [
        {
            "target_definition_id": candidate["id"],
            "evidence_ids": list(dict.fromkeys((*evidence_ids, *candidate["required_evidence_ids"]))),
            "reason": "mock candidate exclusion",
        }
        for candidate in candidates
        if candidate["id"] not in observed
    ]
    return json.dumps(
        {
            "callsite_id": packet["callsite_id"],
            "supported_relations": supported,
            "candidate_target_ids": [],
            "excluded_candidates": excluded,
            "target_coverage": "complete",
            "coverage_limitation_ids": [],
            "related_contexts": [],
            "reason": "mock relationship resolution",
        }
    )


__all__ = ["relationship_dry_run_response"]
