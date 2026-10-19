"""Definition ordering by first seen name in source order."""

from cyberjury.review.definitions import definitions_by_name
from tests.review.support import definition


def test_definitions_group_by_first_seen_name_in_source_order():
    """Both load definitions group ahead of route in source position order, with the <file> scope last."""
    file_scope = definition("a.py", "<file>", 0, 200)
    load = definition("a.py", "load", 10, 50)
    route = definition("a.py", "route", 60, 90)
    other_load = definition("b.py", "load", 0, 40)

    ordered = definitions_by_name((other_load, route, file_scope, load))

    assert ordered == (load, other_load, route, file_scope)
