"""Test definition graph validation, traversal, and unit planning."""

import pytest

from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    definition_dependencies,
    definition_fragments,
    dependencies_data,
    dependency_closure,
    dependency_paths,
    plan_definition_units,
    unresolved_dependencies,
)
from cyberjury.review.failures import BackendUnavailable


def test_dependency_closure_keeps_a_complete_two_hop_chain():
    handle = DefinitionFragment("route.py", "handle", 0, 20)
    load = DefinitionFragment("service.py", "load", 20, 50)
    read = DefinitionFragment("store.py", "read", 50, 90)
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 20], "calls": ["load"]}]},
            "service.py": {"load": [{"range": [20, 50], "calls": ["read"]}]},
            "store.py": {"read": [{"range": [50, 90], "calls": []}]},
        },
        "dependencies": dependencies_data(
            (
                DefinitionDependency("route.py", load, handle),
                DefinitionDependency("service.py", read, load),
            )
        ),
    }

    edges = dependency_closure((handle,), graph, depth=2)

    assert [(edge.source_file, edge.target.file, edge.target.name) for edge in edges] == [
        ("route.py", "service.py", "load"),
        ("service.py", "store.py", "read"),
    ]
    assert all(edge.source is not None for edge in definition_dependencies(graph))


def test_dependency_paths_do_not_follow_unrelated_definitions_in_a_reached_file():
    handle = DefinitionFragment("route.py", "handle", 0, 20)
    load = DefinitionFragment("service.py", "load", 20, 50)
    admin = DefinitionFragment("service.py", "admin", 60, 90)
    read = DefinitionFragment("store.py", "read", 0, 30)
    wipe = DefinitionFragment("store.py", "wipe", 40, 70)
    graph = {
        "dependencies": dependencies_data(
            (
                DefinitionDependency("route.py", load, handle),
                DefinitionDependency("service.py", read, load),
                DefinitionDependency("service.py", wipe, admin),
            )
        )
    }

    paths = dependency_paths((handle,), graph, depth=2)

    assert paths == (
        (
            DefinitionDependency("route.py", load, handle),
            DefinitionDependency("service.py", read, load),
        ),
    )


def test_definition_dependencies_fail_loud_without_resolved_edges():
    graph = {"callgraph": {"route.py": {"handle": [{"range": [0, 20], "calls": ["load"]}]}}}

    with pytest.raises(BackendUnavailable, match="no resolved dependency edges"):
        definition_dependencies(graph)


@pytest.mark.parametrize(
    ("callgraph", "message"),
    [
        (["not", "a", "mapping"], "callgraph must be an object"),
        ({"route.py": []}, "definitions for route.py must be an object"),
        ({"route.py": {"handle": []}}, "must be a nonempty list"),
        ({"route.py": {"handle": [None]}}, "entry 1 must be an object"),
        ({"route.py": {"handle": [{"range": [20, 10]}]}}, "entry 1 has an invalid range"),
    ],
)
def test_definition_fragments_fail_loud_on_malformed_nonempty_entries(callgraph, message):
    with pytest.raises(BackendUnavailable, match=message):
        definition_fragments({"callgraph": callgraph})


def test_definition_dependencies_validate_definitions_before_using_edges():
    graph = {
        "callgraph": {"route.py": {"handle": [{"range": None}]}},
        "dependencies": [],
    }

    with pytest.raises(BackendUnavailable, match=r"route\.py:handle entry 1"):
        definition_dependencies(graph)


@pytest.mark.parametrize("span", [[False, 10], [0, True]])
def test_definition_dependencies_reject_boolean_endpoint_offsets(span):
    graph = {
        "dependencies": [
            {
                "source_file": "route.py",
                "target": {"file": "service.py", "name": "load", "range": span},
            }
        ]
    }

    with pytest.raises(BackendUnavailable, match="malformed dependency endpoint"):
        definition_dependencies(graph)


@pytest.mark.parametrize(
    "source",
    [
        {},
        {"file": "route.py", "name": "handle", "range": [False, 10]},
        {"file": "route.py", "name": "handle", "range": [0, 0]},
    ],
)
def test_unresolved_dependencies_reject_a_malformed_supplied_source(source):
    graph = {
        "unresolved_dependencies": [
            {
                "source_file": "route.py",
                "source": source,
                "reference": "missing",
                "kind": "call",
            }
        ]
    }

    with pytest.raises(BackendUnavailable, match="malformed unresolved dependency endpoint"):
        unresolved_dependencies(graph)


def test_definition_unit_planner_preserves_edges_when_source_exceeds_budget():
    entry = DefinitionFragment("entry.py", "handle", 0, 20)
    service = DefinitionFragment("service.py", "load", 20, 60)
    sink = DefinitionFragment("store.py", "read", 60, 100)
    graph = {
        "dependencies": dependencies_data(
            (
                DefinitionDependency("entry.py", service, entry),
                DefinitionDependency("service.py", sink, service),
            )
        )
    }

    plans = plan_definition_units((entry,), graph, depth=2, max_chars=1)

    assert len(plans) == 1
    assert plans[0].seeds == (entry,)
    assert plans[0].fragments == (entry,)
    assert plans[0].dependencies == (
        DefinitionDependency("entry.py", service, entry),
        DefinitionDependency("service.py", sink, service),
    )


def test_definition_unit_planner_counts_nested_ranges_once():
    owner = DefinitionFragment("views.py", "View", 0, 100)
    method = DefinitionFragment("views.py", "get", 20, 60)
    other = DefinitionFragment("other.py", "post", 0, 80)
    graph = {"dependencies": []}

    plans = plan_definition_units((owner, method, other), graph, depth=2, max_chars=180)

    assert len(plans) == 1
    assert plans[0].fragments == (owner, method, other)
