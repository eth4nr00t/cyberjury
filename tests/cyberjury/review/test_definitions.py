"""Definition graph validation and seed planning."""

import pytest

from cyberjury.review.definitions import (
    DefinitionFragment,
    definition_fragments,
    definition_union_size,
    plan_definition_units,
)
from cyberjury.review.failures import BackendUnavailable


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


def test_definition_fragments_reject_malformed_calls():
    graph = {"callgraph": {"route.py": {"handle": [{"range": [0, 20], "calls": "load"}]}}}

    with pytest.raises(BackendUnavailable, match="invalid calls"):
        definition_fragments(graph)


def test_definition_unit_planner_groups_seeds_by_file_in_seed_order():
    view = DefinitionFragment("views.py", "View", 0, 100)
    method = DefinitionFragment("views.py", "get", 20, 60)
    other = DefinitionFragment("other.py", "post", 0, 80)

    plans = plan_definition_units((view, other, method), seed_files=("views.py",))

    assert [plan.seeds for plan in plans] == [(view, method), (other,)]
    assert [plan.seed_files for plan in plans] == [("views.py",), ()]
    assert [plan.fragments for plan in plans] == [(view, method), (other,)]


def test_definition_union_size_counts_nested_ranges_once():
    owner = DefinitionFragment("views.py", "View", 0, 100)
    method = DefinitionFragment("views.py", "get", 20, 60)
    other = DefinitionFragment("other.py", "post", 0, 80)

    assert definition_union_size((owner, method, other)) == 180
