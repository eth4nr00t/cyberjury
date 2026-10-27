"""Diff planning maps changed lines to definitions and packs them into bounded units."""

from dataclasses import replace

import pytest

from cyberjury.review.detection import load_detection
from cyberjury.review.diff import planning
from cyberjury.review.diff.model import changed_line_ranges
from cyberjury.review.diff.planning import build_diff_units, changed_definitions, plan_definition_units
from cyberjury.review.failures import BackendUnavailable
from tests.review.support import definition

_DETECTION = load_detection()


def test_diff_unit_planners_return_an_empty_worklist_for_empty_input(tmp_path):
    """An empty diff string with no definitions plans no units."""
    assert build_diff_units("", root=tmp_path, definitions=()) == []


def test_changed_definition_mapping_keeps_deletion_and_enclosing_definitions(tmp_path):
    """A deleted require_admin line inside View.handle marks both View and handle as changed."""
    source = "class View(Base):\n    def handle(self):\n        require_admin(self)\n        return sensitive()\n"
    (tmp_path / "view.py").write_text(source)
    method_start = source.index("    def")
    definitions = (
        definition("view.py", "View", 0, len(source), source=source),
        definition("view.py", "handle", method_start, len(source), source=source),
    )
    diff = (
        "diff --git a/view.py b/view.py\n--- a/view.py\n+++ b/view.py\n"
        "@@ -2,3 +2,2 @@ class View(Base):\n"
        "     def handle(self):\n"
        "-        require_admin(self)\n"
        "         return sensitive()\n"
    )

    changed = changed_definitions(tmp_path, ("view.py",), changed_line_ranges(diff), definitions)

    assert [item.name for item in changed] == ["View", "handle"]


def test_adjacent_definition_end_does_not_claim_the_next_line(tmp_path):
    """Changing the first line of b(), directly after a() ends, marks only b as changed."""
    first = "def a():\n    return 1\n"
    second = "def b():\n    return 2\n"
    (tmp_path / "app.py").write_text(first + second)
    definitions = (
        definition("app.py", "a", 0, len(first), source=first + second),
        definition("app.py", "b", len(first), len(first + second), source=first + second),
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n-def b():\n+def b(x):\n"

    changed = changed_definitions(tmp_path, ("app.py",), changed_line_ranges(diff), definitions)

    assert [item.name for item in changed] == ["b"]


def test_definition_unit_planner_groups_seeds_by_file_in_seed_order():
    """Seeds View, post, get yield a views.py plan (View, get) then an other.py plan (post)."""
    view = definition("views.py", "View", 0, 100)
    method = definition("views.py", "get", 20, 60)
    other = definition("other.py", "post", 0, 80)

    plans = plan_definition_units((view, other, method))

    assert [plan.seeds for plan in plans] == [(view, method), (other,)]
    assert [plan.seed_files for plan in plans] == [("views.py",), ("other.py",)]


def _two_changed_files(tmp_path, body_chars):
    definitions = []
    diff = ""
    for name in ("first", "second"):
        source = f"def {name}():\n" + "    value = 1\n" * (body_chars // 14)
        (tmp_path / f"{name}.py").write_text(source, encoding="utf-8")
        definitions.append(definition(f"{name}.py", name, 0, len(source), source=source))
        diff += f"diff --git a/{name}.py b/{name}.py\n+++ b/{name}.py\n@@ -1 +1 @@\n-def old():\n+def {name}():\n"
    return diff, tuple(definitions)


def test_diff_surface_packing_does_not_charge_lazy_seed_definitions_to_context_budget(tmp_path, monkeypatch):
    """Two 100k-char definitions stay in one unit under a 1k-char patch target."""
    diff, definitions = _two_changed_files(tmp_path, 100_000)
    monkeypatch.setattr(planning, "_SETTINGS", replace(planning._SETTINGS, target_patch_chars_per_unit=1_000))

    units = build_diff_units(diff, root=tmp_path, definitions=definitions)

    assert [unit.definition_plan.seeds for unit in units] == [definitions]


def test_diff_surface_packing_bounds_the_lazy_definition_catalog(tmp_path, monkeypatch):
    """With max_definition_evidence_items_per_unit=1, two changed definitions split into two units."""
    diff, definitions = _two_changed_files(tmp_path, 100)
    monkeypatch.setattr(planning, "_SETTINGS", replace(planning._SETTINGS, max_definition_evidence_items_per_unit=1))

    units = build_diff_units(diff, root=tmp_path, definitions=definitions)

    assert [unit.definition_plan.seeds for unit in units] == [(definitions[0],), (definitions[1],)]


def test_an_unreadable_changed_source_fails_planning_instead_of_hiding_its_definitions(tmp_path):
    """A non-UTF-8 app.py raises BackendUnavailable "diff planning could not read source app.py"."""
    (tmp_path / "app.py").write_bytes(b"def app():\n    return '\xff'\n")
    definitions = (definition("app.py", "app", 0, 10),)
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-def old():\n+def app():\n"

    with pytest.raises(BackendUnavailable, match=r"diff planning could not read source app\.py"):
        changed_definitions(tmp_path, ("app.py",), changed_line_ranges(diff), definitions)


def test_a_deleted_changed_source_has_no_changed_definitions(tmp_path):
    """A diff deleting gone.py to /dev/null maps to no changed definitions."""
    definitions = (definition("gone.py", "gone", 0, 10),)
    diff = "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def gone():\n"

    assert changed_definitions(tmp_path, ("gone.py",), changed_line_ranges(diff), definitions) == ()
