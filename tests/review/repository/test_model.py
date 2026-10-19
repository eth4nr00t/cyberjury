"""Repository model tests cover file mapping and review unit construction."""

from dataclasses import replace

from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.repository import model as repository_model
from cyberjury.review.repository.context import gather_context
from cyberjury.review.repository.model import (
    build_units,
    char_spans,
    repository_unit_plan_record,
)
from cyberjury.review.unit_plans import UnitPlanReceipt
from tests.review.support import definition

_FACTS = FactsReceipt.create(backend_id="test", facts=Facts())


def test_build_units_binds_candidate_definitions_to_their_source_window(tmp_path):
    """A single route definition yields one route.py unit over the whole file seeded with that definition."""
    source = "def route(value):\n    return value\n"
    (tmp_path / "route.py").write_text(source)
    route = definition("route.py", "route", 0, len(source), source=source)

    units = build_units(tmp_path, ["route.py"], (route,))

    assert [(unit.name, unit.file, unit.span) for unit in units] == [("route.py", "route.py", (0, len(source)))]
    receipt = UnitPlanReceipt.create(
        facts=_FACTS,
        units=tuple(repository_unit_plan_record(unit) for unit in units),
        expected_owned_paths=("route.py",),
    )
    assert [(unit.kind, unit.owned_paths) for unit in receipt.units] == [("source", ("route.py",))]
    assert units[0].definition_plan == DefinitionUnitPlan(seeds=(route,), seed_files=("route.py",))


def test_oversized_source_keeps_bounded_windows(tmp_path, monkeypatch):
    """A 40-character unit limit splits one large class into several units of at most 40 characters."""
    monkeypatch.setattr(
        repository_model,
        "_SETTINGS",
        replace(repository_model._SETTINGS, max_source_chars_per_unit=40, hard_split_overlap_chars=10),
    )
    source = "class PublicViewSet:\n" + "    value = 1\n" * 10
    (tmp_path / "views.py").write_text(source)
    units = build_units(tmp_path, ["views.py"], (definition("views.py", "PublicViewSet", 0, len(source)),))

    assert len(units) > 1
    assert all(unit.span[1] - unit.span[0] <= 40 for unit in units)


def test_repository_unit_plan_records_intentional_hard_split_overlap(tmp_path):
    """A 30,000-space file splits into slices where consecutive windows overlap by 2,000 characters."""
    (tmp_path / "large.py").write_text(" " * 30_000)
    units = build_units(tmp_path, ["large.py"], ())

    receipt = UnitPlanReceipt.create(
        facts=_FACTS,
        units=tuple(repository_unit_plan_record(unit) for unit in units),
        expected_owned_paths=("large.py",),
    )

    slices = [unit.source_slices[0] for unit in receipt.units]
    assert slices[0].end - slices[1].start == 2_000


def test_build_units_keeps_root_level_sources_separate(tmp_path):
    """Root files app.py and services.py each get their own whole-file unit."""
    (tmp_path / "app.py").write_text("entry")
    (tmp_path / "services.py").write_text("service")

    units = build_units(tmp_path, ["app.py", "services.py"], ())

    assert [(unit.name, unit.file, unit.span) for unit in units] == [
        ("app.py", "app.py", (0, 5)),
        ("services.py", "services.py", (0, 7)),
    ]


def test_build_units_covers_each_source_once(tmp_path):
    """An entry file plus 25 pkg services of 24 KB yield 26 units, each with complete gathered coverage."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "entry.py").write_text("entry")
    targets = []
    for index in range(25):
        rel = f"pkg/service_{index:02d}.py"
        (tmp_path / rel).write_text("x" * 24_000)
        targets.append(rel)

    units = build_units(tmp_path, ["pkg/entry.py", *targets], ())
    covered = {unit.file for unit in units if unit.name != "pkg/entry.py"}

    assert covered == set(targets)
    assert len(units) == 26
    assert all(gather_context(unit).coverage.complete for unit in units)


def test_build_units_splits_a_large_file_into_overlapping_windows(tmp_path):
    """A 60,000-character views.py yields views.py#1 to #3, with overlap and full coverage to the end."""
    (tmp_path / "views.py").write_text("x" * 60_000)
    units = build_units(str(tmp_path), ["views.py"], ())
    assert [u.name for u in units] == ["views.py#1", "views.py#2", "views.py#3"]
    assert units[0].span[0] == 0
    assert units[1].span[0] < units[0].span[1]
    assert units[-1].span[1] == 60_000


def test_spans_snaps_a_window_to_a_top_level_construct_boundary():
    """A file with two long functions splits so the second window begins at 'def g'."""
    a = "def f():\n" + "    x = 1\n" * 2000
    text = a + "def g():\n" + "    y = 2\n" * 2000
    spans = char_spans(text)
    assert spans[0][0] == 0
    assert text[spans[0][1] :].startswith("def g")


def test_spans_keep_a_decorator_with_its_definition():
    """A window boundary near a decorated function starts at '@require_admin', not at its def line."""
    prefix = "x = 1\n" * 3_300
    text = prefix + "@require_admin\ndef sensitive():\n" + "    x = 1\n" * 500

    spans = char_spans(text)
    second = text[spans[1][0] : spans[1][1]]

    assert second.startswith("@require_admin\ndef sensitive")
