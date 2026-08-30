"""Relationship navigation stays bounded, attributable, and purpose aware."""

import json

import pytest


def _bundle(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts
    from cyberjury.review.relationships import relationship_evidence_from_data

    (tmp_path / "service.py").write_text(
        "def target(value):\n    return value\n\ndef target_other(value):\n    return value\n"
    )
    (tmp_path / "route.py").write_text("def route(value):\n    invoke = target\n    return invoke(value)\n")
    return relationship_evidence_from_data(TreeSitterFacts().extract(tmp_path).data["relationship_evidence"])


def _source_catalog(bundle):
    sources = {item.id: item for item in bundle.sources}
    for definition in bundle.definitions:
        sources[definition.source.id] = definition.source
        for parameter in definition.parameters:
            sources[parameter.source.id] = parameter.source
    for callsite in bundle.callsites:
        sources[callsite.source.id] = callsite.source
        for argument in callsite.arguments:
            if argument.source is not None:
                sources[argument.source.id] = argument.source
    return sources


def test_symbol_navigation_pages_without_changing_query_purpose(tmp_path):
    from cyberjury.review.relationship_navigation import (
        execute_navigation,
        parse_navigation_requests,
    )

    bundle = _bundle(tmp_path)
    request = parse_navigation_requests(
        json.dumps(
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
    )[0]
    catalog = _source_catalog(bundle)

    receipt = execute_navigation(
        bundle,
        catalog,
        request,
        page_size=1,
        read_source=lambda reference: (tmp_path / reference.path).read_text()[reference.start : reference.end],
    )

    assert receipt.purpose == "target_candidate"
    assert len(receipt.returned_definition_ids) == 1
    assert receipt.next_cursor == 1


def test_navigation_rejects_a_path_that_can_leave_the_repository():
    from cyberjury.review.relationship_navigation import NavigationError, parse_navigation_requests

    with pytest.raises(NavigationError, match="stay within"):
        parse_navigation_requests(
            json.dumps(
                {
                    "navigation_requests": [
                        {
                            "kind": "text",
                            "purpose": "context_evidence",
                            "query": "target",
                            "path_prefix": "../outside",
                            "cursor": 0,
                        }
                    ]
                }
            )
        )
