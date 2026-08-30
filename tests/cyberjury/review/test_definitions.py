"""Test definition graph validation, traversal, and unit planning."""

import pytest

from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    UnresolvedDependency,
    definition_dependencies,
    definition_fragments,
    definition_references,
    dependencies_data,
    dependency_closure,
    dependency_paths,
    plan_definition_units,
    unresolved_dependencies,
    unresolved_dependencies_data,
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


def test_candidate_clues_are_separate_from_supported_dependencies():
    from cyberjury.review.definitions import (
        CallCandidate,
        DefinitionFragment,
        StructuralCandidate,
        StructuralGap,
        call_candidates_data,
        definition_call_candidates,
        definition_structural_candidates,
        definition_structural_gaps,
        structural_candidates_data,
        structural_gaps_data,
    )

    caller = DefinitionFragment("route.py", "route", 0, 30)
    target = DefinitionFragment("service.py", "load", 0, 20)
    graph = {
        "callgraph": {
            "route.py": {"route": [{"range": [0, 30], "calls": ["load"]}]},
            "service.py": {"load": [{"range": [0, 20], "calls": []}]},
        },
        "call_candidates": call_candidates_data((CallCandidate(source=caller, target=target, reference="load"),)),
        "structural_candidates": structural_candidates_data(
            (
                StructuralCandidate(
                    source_file="route.py",
                    target=target,
                    kind="import",
                    reference="load",
                ),
            )
        ),
        "structural_gaps": structural_gaps_data(
            (StructuralGap(source_file="route.py", kind="import", reference="missing"),)
        ),
        "dependencies": [],
        "unresolved_dependencies": [],
    }

    assert definition_call_candidates(graph) == (CallCandidate(source=caller, target=target, reference="load"),)
    assert definition_structural_candidates(graph)[0].target == target
    assert definition_structural_gaps(graph)[0].reference == "missing"
    assert definition_dependencies(graph) == ()


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


def test_definition_fragments_reject_malformed_calls():
    graph = {"callgraph": {"route.py": {"handle": [{"range": [0, 20], "calls": "load"}]}}}

    with pytest.raises(BackendUnavailable, match="invalid calls"):
        definition_fragments(graph)


def test_definition_dependencies_require_endpoints_from_the_callgraph():
    graph = {
        "callgraph": {"route.py": {"handle": [{"range": [0, 20], "calls": ["ghost"]}]}},
        "dependencies": [
            {
                "source_file": "route.py",
                "source": {"file": "route.py", "name": "handle", "range": [0, 20]},
                "target": {"file": "other.py", "name": "ghost", "range": [0, 10]},
            }
        ],
    }

    with pytest.raises(BackendUnavailable, match="not present in the callgraph"):
        definition_dependencies(graph)


def test_definition_dependencies_require_a_consistent_source_file():
    graph = {
        "dependencies": [
            {
                "source_file": "wrong.py",
                "source": {"file": "route.py", "name": "handle", "range": [0, 20]},
                "target": {"file": "other.py", "name": "load", "range": [0, 10]},
            }
        ]
    }

    with pytest.raises(BackendUnavailable, match="does not match"):
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


@pytest.mark.parametrize("extension", [".go", ".sol"])
def test_definition_unit_planner_keeps_each_direct_caller_with_a_changed_callee(extension):
    changed = DefinitionFragment(f"helper{extension}", "check", 0, 20)
    sink = DefinitionFragment(f"sink{extension}", "read", 0, 30)
    first = DefinitionFragment(f"first{extension}", "authorize", 0, 40)
    second = DefinitionFragment(f"second{extension}", "validate", 0, 50)
    dependencies = (
        DefinitionDependency(first.file, changed, first),
        DefinitionDependency(second.file, changed, second),
        DefinitionDependency(changed.file, sink, changed),
    )

    plans = plan_definition_units(
        (changed,),
        {"dependencies": dependencies_data(dependencies)},
        depth=2,
        max_chars=200,
        pack_surfaces=False,
    )

    assert len(plans) == 2
    assert {plan.fragments[1] for plan in plans} == {first, second}
    assert all(plan.seeds == (changed,) for plan in plans)
    assert all(changed in plan.fragments and sink in plan.fragments for plan in plans)


def test_definition_unit_planner_does_not_split_one_caller_from_its_changed_callee():
    changed = DefinitionFragment("helper.go", "check", 0, 200)
    caller = DefinitionFragment("authorize.go", "authorize", 0, 300)
    dependency = DefinitionDependency(caller.file, changed, caller)

    plan = plan_definition_units(
        (changed,),
        {"dependencies": dependencies_data((dependency,))},
        depth=2,
        max_chars=1,
        include_seed_chars=False,
        pack_surfaces=False,
    )[0]

    assert plan.fragments == (changed, caller)
    assert plan.dependencies == (dependency,)


def test_definition_unit_planner_counts_nested_ranges_once():
    owner = DefinitionFragment("views.py", "View", 0, 100)
    method = DefinitionFragment("views.py", "get", 20, 60)
    other = DefinitionFragment("other.py", "post", 0, 80)
    graph = {"dependencies": []}

    plans = plan_definition_units((owner, method, other), graph, depth=2, max_chars=180)

    assert len(plans) == 1
    assert plans[0].fragments == (owner, method, other)


def test_definition_unit_planner_keeps_reachable_unresolved_dependencies():
    source = DefinitionFragment("a.py", "a", 0, 10)
    target = DefinitionFragment("b.py", "b", 0, 10)
    graph = {
        "dependencies": dependencies_data((DefinitionDependency("a.py", target, source),)),
        "unresolved_dependencies": unresolved_dependencies_data(
            (UnresolvedDependency("b.py", "missing", "call", target),)
        ),
    }

    plan = plan_definition_units((source,), graph, depth=2, max_chars=100)[0]

    assert [item.reference for item in plan.unresolved] == ["missing"]


def test_definition_unit_planner_matches_file_edges_by_alias_and_unicode_reference():
    seed = DefinitionFragment("route.py", "handle", 0, 20)
    alias_target = DefinitionFragment("base.py", "Original", 0, 10)
    unicode_target = DefinitionFragment("unicode.py", "策略", 0, 10)
    dependencies = (
        DefinitionDependency("route.py", alias_target, None, "import", "supported", "Alias"),
        DefinitionDependency("route.py", unicode_target, None, "import", "supported", "策略"),
    )

    plan = plan_definition_units(
        (seed,),
        {"dependencies": dependencies_data(dependencies)},
        depth=1,
        max_chars=100,
        references_by_seed={seed: frozenset({"Alias", "策略"})},
    )[0]

    assert plan.dependencies == dependencies


def test_definition_references_reads_each_source_file_once():
    seeds = (
        DefinitionFragment("same.py", "first", 0, 5),
        DefinitionFragment("same.py", "second", 6, 12),
    )
    calls = []

    references = definition_references(seeds, lambda path: calls.append(path) or "first second")

    assert calls == ["same.py"]
    assert references[seeds[0]] == frozenset({"first"})


@pytest.mark.parametrize("depth", [0, -1])
def test_definition_traversal_rejects_nonpositive_depth(depth):
    with pytest.raises(ValueError, match="depth must be positive"):
        dependency_paths((), {"dependencies": []}, depth=depth)
    with pytest.raises(ValueError, match="depth must be positive"):
        plan_definition_units((), {"dependencies": []}, depth=depth, max_chars=10)


def test_definition_unit_planner_fails_loud_on_oversized_relationship_metadata():
    seed = DefinitionFragment("a.py", "a", 0, 10)
    target = DefinitionFragment("b.py", "long_target_name", 0, 10)
    graph = {"dependencies": dependencies_data((DefinitionDependency("a.py", target, seed),))}

    with pytest.raises(BackendUnavailable, match="definition relationships require"):
        plan_definition_units((seed,), graph, depth=1, max_chars=100, max_relationship_chars=1)
