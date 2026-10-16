"""Definition ordering and seed planning."""

from cyberjury.review.definitions import definitions_by_name
from cyberjury.review.diff.model import plan_definition_units
from tests.cyberjury.review.support import definition


def test_definitions_group_by_first_seen_name_in_source_order():
    file_scope = definition("a.py", "<file>", 0, 200)
    load = definition("a.py", "load", 10, 50)
    route = definition("a.py", "route", 60, 90)
    other_load = definition("b.py", "load", 0, 40)

    ordered = definitions_by_name((other_load, route, file_scope, load))

    assert ordered == (load, other_load, route, file_scope)


def test_definition_unit_planner_groups_seeds_by_file_in_seed_order():
    view = definition("views.py", "View", 0, 100)
    method = definition("views.py", "get", 20, 60)
    other = definition("other.py", "post", 0, 80)

    plans = plan_definition_units((view, other, method), seed_files=("views.py",))

    assert [plan.seeds for plan in plans] == [(view, method), (other,)]
    assert [plan.seed_files for plan in plans] == [("views.py",), ()]
