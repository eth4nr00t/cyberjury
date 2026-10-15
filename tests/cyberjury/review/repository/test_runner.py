"""The unit runner reviews every unit once and records each failure."""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository.context import Unit, ground_units
from cyberjury.review.repository.reviewer import ModelReviewer
from cyberjury.review.repository.runner import run_units
from cyberjury.review.repository.union import Accumulator, Candidate
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.cyberjury.review.repository.support import EMPTY_REPLY, finding, prompt_unit, unit_provider


def _reviewer(provider):
    return ModelReviewer(provider=provider, model="mock")


def _grounded(units, *, limitations=(), navigator=None):
    return list(
        ground_units(
            tuple(units),
            facts_by_file={},
            limitations=limitations,
            navigator=navigator,
            source_snapshot=capture_source_snapshot(units[0].root),
        )
    )


def _units(root, names):
    for name in names:
        (root / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
    return _grounded([Unit(name=name, root=str(root), files=(f"{name}.py",)) for name in names])


def test_concurrency_yields_same_union_as_serial(tmp_path):
    units = _units(tmp_path, [f"u{i}" for i in range(6)])

    def provider():
        return unit_provider(lambda name: [finding(f"{name}.py", 1, title=name)])

    serial = run_units(units, _reviewer(provider()), concurrency=1)
    parallel = run_units(units, _reviewer(provider()), concurrency=4)
    assert {c.key() for c in serial.findings} == {c.key() for c in parallel.findings}
    assert len(parallel.findings) == 6
    assert serial.outcome is not None
    assert parallel.outcome is not None
    assert serial.outcome.scheduling is not None
    assert parallel.outcome.scheduling is not None
    serial_receipt = serial.outcome.scheduling.semantic_dict()
    parallel_receipt = parallel.outcome.scheduling.semantic_dict()
    serial_receipt.pop("duration_seconds")
    parallel_receipt.pop("duration_seconds")
    assert serial_receipt == parallel_receipt


def test_unit_failures_are_counted_not_silent(tmp_path):
    units = _units(tmp_path, ["ok1", "bad", "ok2"])
    provider = unit_provider(
        lambda name: RuntimeError("rate limited") if name == "bad" else [finding(f"{name}.py", 1, title=name)]
    )

    acc = run_units(units, _reviewer(provider), concurrency=2)

    assert acc.errors >= 1
    assert len(acc.unit_failures) == 1
    assert acc.unit_failures[0].paths == ("bad.py",)
    assert "rate limited" in acc.unit_failures[0].reason
    assert {c.title for c in acc.findings} == {"ok1", "ok2"}


def test_repository_runner_materializes_prompt_grounding_once(tmp_path, monkeypatch):
    from cyberjury.review.repository import context as context_module

    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    reads = 0
    original = context_module._read_unit_text

    def counted(unit, rel):
        nonlocal reads
        reads += 1
        return original(unit, rel)

    monkeypatch.setattr(context_module, "_read_unit_text", counted)
    provider = MockProvider(default=EMPTY_REPLY)

    run_units(_grounded([Unit(name="unit", root=str(tmp_path), files=("unit.py",))]), _reviewer(provider))

    assert "value = 1" in provider.calls[0]["messages"][0].content
    assert reads == 1


def test_repository_runner_attaches_a_limitation_to_its_rendered_source(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)

    acc = run_units(
        _grounded(
            [Unit(name="broken.py", root=str(tmp_path), files=("broken.py",))],
            limitations=(
                FactLimitation(source="broken.py", analyzer="python", reason="unparsable", line=1, column=11),
            ),
        ),
        _reviewer(provider),
    )

    assert "broken.py at 1:11" in provider.calls[0]["messages"][0].content
    assert acc.outcome is not None
    assert acc.outcome.grounding.limitations == ("facts:broken.py:1:11",)
    assert acc.outcome.complete is False


def test_repository_runner_attaches_a_limitation_to_a_published_evidence_source(tmp_path):
    app_source = "def route():\n    return load()\n"
    service_source = "def load():\n    return 1\n"
    (tmp_path / "app.py").write_text(app_source, encoding="utf-8")
    (tmp_path / "service.py").write_text(service_source, encoding="utf-8")
    source = DefinitionFragment("app.py", "route", 0, len(app_source))
    target = DefinitionFragment("service.py", "load", 0, len(service_source))
    plan = DefinitionUnitPlan(seeds=(source,), evidence=(source, target))
    provider = MockProvider(default=EMPTY_REPLY)

    acc = run_units(
        _grounded(
            [Unit(name="route", root=str(tmp_path), files=("app.py",), definition_plan=plan)],
            limitations=(
                FactLimitation(source="service.py", analyzer="python", reason="unparsable", line=1, column=1),
            ),
        ),
        _reviewer(provider),
    )

    assert provider.calls
    assert acc.outcome is not None
    assert acc.outcome.grounding.limitations == ("facts:service.py:1:1",)
    assert acc.outcome.complete is False


def test_failed_unit_identity_does_not_collapse_units_that_share_files(tmp_path):
    (tmp_path / "same.py").write_text("value = 1\n")
    units = _grounded(
        [
            Unit(name="one", root=str(tmp_path), files=("same.py",)),
            Unit(name="two", root=str(tmp_path), files=("same.py",)),
        ]
    )
    provider = unit_provider(lambda name: RuntimeError("failed") if name == "one" else [])

    acc = run_units(units, _reviewer(provider), concurrency=1)

    assert acc.failed_units == {"one"}


def test_repository_runner_binds_source_operations_before_cross_unit_union(tmp_path):
    class OperationNavigator:
        relationship_evidence = RelationshipEvidenceBundle()

        def session(self):
            return self

        def source_operation_id(self, file, line):
            return "call-shared" if file == "matching.py" and line in {63, 64} else ""

    (tmp_path / "matching.py").write_text("value = 1\n" * 70, encoding="utf-8")
    provider = unit_provider(
        lambda _name: [finding("matching.py", line, title=f"regex operation {line}") for line in (63, 64)]
    )

    acc = run_units(
        _grounded([Unit(name="matching", root=str(tmp_path), files=("matching.py",))], navigator=OperationNavigator()),
        _reviewer(provider),
    )

    assert len(acc.findings) == 1
    assert acc.findings[0].source_operation_id == "call-shared"


def test_units_receive_only_the_carried_findings_they_own(tmp_path):
    units = _units(tmp_path, ["a", "b"])
    accumulator = Accumulator()
    accumulator.finding_accumulator.add([Candidate(title="carried finding", file="a.py", line=1)])
    prompts: dict[str, str] = {}

    def respond(_system, messages):
        prompts[prompt_unit(messages)] = messages[-1].content
        return EMPTY_REPLY

    run_units(units, _reviewer(MockProvider(responder=respond)), accumulator=accumulator, concurrency=1)

    assert "carried finding" in prompts["a"]
    assert "carried finding" not in prompts["b"]


def test_run_units_rejects_ungrounded_units_before_review(tmp_path):
    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)

    with pytest.raises(ValueError, match="lack initial grounding: unit"):
        run_units([Unit(name="unit", root=str(tmp_path), files=("unit.py",))], _reviewer(provider))
    assert provider.calls == []
