"""Repository model tests cover file mapping and review unit construction."""

from dataclasses import replace

import pytest

from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository import model as repository_model
from cyberjury.review.repository.context import gather_context
from cyberjury.review.repository.model import (
    build_units,
    char_spans,
    repository_unit_plan_receipt,
)


def _facts_resolution() -> FactsResolutionReceipt:
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    return FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def test_build_units_binds_candidate_definitions_to_their_source_window(tmp_path):
    source = "def route(value):\n    return value\n"
    (tmp_path / "route.py").write_text(source)
    graph = {
        "callgraph": {
            "route.py": {"route": [{"range": [0, len(source)], "calls": []}]},
        },
    }

    units = build_units(tmp_path, ["route.py"], facts_graph=graph)

    assert [(unit.name, unit.files, unit.span) for unit in units] == [
        ("route.py", ("route.py",), None),
    ]
    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("route.py",),
    )
    assert receipt.expected_seed_ids == ("source:route.py",)
    assert receipt.unowned_seed_ids == ()
    assert receipt.multi_unit_seed_ids == ()
    assert receipt.units[0].kind == "source"
    assert units[0].definition_plan == DefinitionUnitPlan(
        seeds=(DefinitionFragment("route.py", "route", 0, len(source)),),
        seed_files=("route.py",),
    )


def test_oversized_source_keeps_bounded_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(
        repository_model,
        "_SETTINGS",
        replace(repository_model._SETTINGS, max_source_chars_per_unit=40, hard_split_overlap_chars=10),
    )
    source = "class PublicViewSet:\n" + "    value = 1\n" * 10
    (tmp_path / "views.py").write_text(source)
    graph = {
        "callgraph": {
            "views.py": {
                "PublicViewSet": [{"range": [0, len(source)], "calls": []}],
            }
        },
    }

    units = build_units(
        tmp_path,
        ["views.py"],
        facts_graph=graph,
    )

    assert len(units) > 1
    assert all(unit.span is not None and unit.span[1] - unit.span[0] <= 40 for unit in units)


def test_repository_unit_plan_excludes_empty_sources_without_creating_work(tmp_path):
    (tmp_path / "empty.py").write_text("")

    units = build_units(tmp_path, ["empty.py"])
    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("empty.py",),
    )

    assert units == []
    assert receipt.excluded_empty_paths == ("empty.py",)
    assert receipt.unowned_paths == ()
    assert receipt.expected_seed_ids == ()


def test_repository_unit_plan_rejects_an_uncovered_source_range(tmp_path):
    (tmp_path / "large.py").write_text("x" * 30_000)
    units = build_units(tmp_path, ["large.py"])

    with pytest.raises(ValueError, match="left source range"):
        repository_unit_plan_receipt(
            tmp_path,
            units[:1],
            _facts_resolution(),
            expected_owned_paths=("large.py",),
        )


def test_repository_unit_plan_records_intentional_hard_split_overlap(tmp_path):
    (tmp_path / "large.py").write_text(" " * 30_000)
    units = build_units(tmp_path, ["large.py"])

    receipt = repository_unit_plan_receipt(
        tmp_path,
        units,
        _facts_resolution(),
        expected_owned_paths=("large.py",),
    )

    assert receipt.overlapping_source_chars == 2_000
    assert receipt.multi_unit_seed_ids == ("source:large.py",)


def test_load_facts_graph_reads_the_graph_empty_and_fails_loud_on_corrupt(tmp_path):
    from cyberjury.review.repository.context import load_facts_graph

    assert load_facts_graph(tmp_path) == {}
    (tmp_path / "_facts_graph.json").write_text('{"callgraph": {"a.py": {}}}')
    assert load_facts_graph(tmp_path)["callgraph"] == {"a.py": {}}
    (tmp_path / "_facts_graph.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_graph(tmp_path)


def test_build_units_keeps_each_source_independently_owned(tmp_path):
    paths = (
        "accounts/views/api.py",
        "authorization/views/web.py",
        "accounts/managers/m.py",
        "authorization/dao/d.py",
    )
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("source")
    units = build_units(
        tmp_path,
        list(paths),
    )
    units_by_name = {u.name: u for u in units}
    assert units_by_name["accounts/views/api.py"].files == ("accounts/views/api.py",)
    assert units_by_name["accounts/managers/m.py"].files == ("accounts/managers/m.py",)
    assert units_by_name["authorization/dao/d.py"].files == ("authorization/dao/d.py",)


def test_build_units_keeps_root_level_sources_separate(tmp_path):
    (tmp_path / "app.py").write_text("entry")
    (tmp_path / "services.py").write_text("service")

    units = build_units(tmp_path, ["app.py", "services.py"])

    assert [(unit.name, unit.files) for unit in units] == [
        ("app.py", ("app.py",)),
        ("services.py", ("services.py",)),
    ]


def test_build_units_covers_each_source_once(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "entry.py").write_text("entry")
    targets = []
    for index in range(25):
        rel = f"pkg/service_{index:02d}.py"
        (tmp_path / rel).write_text("x" * 24_000)
        targets.append(rel)

    units = build_units(tmp_path, ["pkg/entry.py", *targets])
    covered = {unit.files[0] for unit in units if unit.name != "pkg/entry.py"}

    assert covered == set(targets)
    assert len(units) == 26
    assert all(gather_context(unit).coverage.complete for unit in units)


def test_build_units_splits_a_large_file_into_overlapping_windows(tmp_path):
    (tmp_path / "views.py").write_text("x" * 60_000)
    units = build_units(str(tmp_path), ["views.py"])
    assert [u.name for u in units] == ["views.py#1", "views.py#2", "views.py#3"]
    assert units[0].span[0] == 0
    assert units[1].span[0] < units[0].span[1]
    assert units[-1].span[1] == 60_000


def test_spans_snaps_a_window_to_a_top_level_construct_boundary():
    a = "def f():\n" + "    x = 1\n" * 2000
    text = a + "def g():\n" + "    y = 2\n" * 2000
    spans = char_spans(text)
    assert spans[0][0] == 0
    assert text[spans[0][1] :].startswith("def g")


def test_spans_keep_a_decorator_with_its_definition():
    prefix = "x = 1\n" * 3_300
    text = prefix + "@require_admin\ndef sensitive():\n" + "    x = 1\n" * 500

    spans = char_spans(text)
    second = text[spans[1][0] : spans[1][1]]

    assert second.startswith("@require_admin\ndef sensitive")


def test_build_units_keeps_a_small_file_whole(tmp_path):
    (tmp_path / "v.py").write_text("x" * 1_000)
    units = build_units(str(tmp_path), ["v.py"])
    assert [u.name for u in units] == ["v.py"]
    assert units[0].span is None
