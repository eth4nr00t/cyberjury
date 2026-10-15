"""Strict location score allocation and result classification tests."""

import pytest

from evals.benchmarks.contract import AnswerKey, ExpectedChange, ExpectedLocation, KeyCheck
from evals.score.engine import score
from evals.score.location import SymbolLocationError
from evals.score.report import Report, ReportChangeAnchor, ReportLocation


def _check(check_id, *locations, expectation="findings", changes=()):
    return KeyCheck(
        id=check_id,
        expectation=expectation,
        applies_to=("task",),
        locations=tuple(ExpectedLocation(file=file, **position) for file, position in locations),
        changes=tuple(ExpectedChange(file=file, line=line, side=side) for file, line, side in changes),
    )


def _key(*checks):
    return AnswerKey(benchmark_id="t", checks=checks)


def _report(name, *locations, anchor=None):
    return Report(
        name=name,
        locations=tuple(ReportLocation(file, line) for file, line in locations),
        change_anchor=ReportChangeAnchor(*anchor) if anchor else None,
    )


def test_score_counts_found_missed_fp_and_extra():
    key = _key(
        _check("hit", ("app/x.py", {"line": 4})),
        _check("miss", ("app/t.py", {"line": 9})),
        _check("lookalike", ("app/safe.py", {"line": 2}), expectation="clean"),
    )
    reports = [
        _report("r-hit", ("app/x.py", 4)),
        _report("r-fp", ("app/safe.py", 2)),
        _report("r-extra", ("app/other.py", 1)),
    ]

    result = score(key, reports)

    assert result.found == ["hit"]
    assert result.missed == ["miss"]
    assert result.false_positives == ["lookalike"]
    assert result.extra == ["r-extra"]
    assert result.recall == 0.5
    assert result.precision_known == 0.5


def test_one_report_on_several_clean_anchors_counts_as_one_false_positive():
    key = _key(
        _check("safe-a", ("app/a.py", {"line": 1}), expectation="clean"),
        _check("safe-b", ("app/a.py", {"line": 1}), expectation="clean"),
    )

    result = score(key, [_report("r", ("app/a.py", 1))])

    assert result.false_positives == ["safe-a"]
    assert result.extra == []


def test_a_duplicate_report_of_a_findings_bug_is_not_a_false_positive():
    key = _key(
        _check("bug", ("app/a.py", {"line": 5})),
        _check("lookalike", ("app/a.py", {"line": 5}), expectation="clean"),
    )

    result = score(key, [_report("first", ("app/a.py", 5)), _report("second", ("app/a.py", 5))])

    assert result.found == ["bug"]
    assert result.false_positives == []
    assert result.extra == ["second"]


def test_one_report_cannot_satisfy_two_findings_checks():
    key = _key(_check("p1", ("svc/a.py", {"line": 1})), _check("p2", ("svc/a.py", {"line": 1})))

    result = score(key, [_report("r-one", ("svc/a.py", 1))])

    assert len(result.found) == 1
    assert len(result.missed) == 1


def test_diff_change_anchor_selects_the_causal_report_and_keeps_a_sibling_extra():
    key = _key(_check("causal", ("app.py", {"line": 12}), changes=[("app.py", 12, "new")]))
    sibling = _report("sibling", ("app.py", 12), anchor=("settings.py", 4, "new"))
    causal = _report("causal", ("app.py", 12), anchor=("app.py", 12, "new"))

    result = score(key, [sibling, causal])

    assert result.found == ["causal"]
    assert result.extra == ["sibling"]


def test_clean_diff_change_anchor_attributes_only_the_repaired_behavior():
    key = _key(_check("repaired", ("app.py", {"line": 20}), expectation="clean", changes=[("app.py", 20, "new")]))
    unrelated = _report("unrelated", ("app.py", 20), anchor=("app.py", 30, "new"))
    repaired = _report("repaired", ("app.py", 20), anchor=("app.py", 20, "new"))

    result = score(key, [unrelated, repaired])

    assert result.false_positives == ["repaired"]
    assert result.extra == ["unrelated"]


def test_change_anchor_inside_a_declared_symbol_matches_on_the_same_side(tmp_path):
    (tmp_path / "views.py").write_text(
        "class TargetView:\n    def post(self):\n        return create()\n\nclass SiblingView:\n"
        "    def post(self):\n        return download()\n"
    )
    key = _key(
        _check(
            "target-access",
            ("views.py", {"symbol": "TargetView.post"}),
            changes=[("views.py", 3, "new")],
        )
    )

    def report(line, side):
        return _report("r", ("views.py", line), anchor=("views.py", line, side))

    assert score(key, [report(2, "new")], source_root=str(tmp_path)).found == ["target-access"]
    assert score(key, [report(2, "old")], source_root=str(tmp_path)).missed == ["target-access"]
    assert score(key, [report(6, "new")], source_root=str(tmp_path)).missed == ["target-access"]


def test_change_anchor_still_requires_an_accepted_location():
    key = _key(
        _check(
            "rendered-input",
            ("templates/dialog.html", {"line": 8}),
            changes=[("producers/message.ts", 20, "new")],
        )
    )
    anchor = ("producers/message.ts", 20, "new")

    assert score(key, [_report("f", ("other.html", 8), anchor=anchor)]).missed
    assert score(key, [_report("ok", ("templates/dialog.html", 8), anchor=anchor)]).found


def test_finding_assignment_maximizes_recall_independent_of_key_and_report_order():
    broad = _check("broad", ("app.py", {"line": 1}))
    specific = _check("specific", ("app.py", {"line": 2}))
    versatile = _report("a-versatile", ("app.py", 1), ("app.py", 2))
    broad_only = _report("b-broad", ("app.py", 1))
    traces: list[dict] = []

    first = score(_key(broad, specific), [versatile, broad_only], trace=traces.append)
    second = score(_key(specific, broad), [broad_only, versatile])

    assert set(first.found) == set(second.found) == {"broad", "specific"}
    assignments = {
        event["key"]: event["report"]
        for event in traces
        if event.get("event") == "score_match" and event.get("kind") == "findings"
    }
    assert assignments == {"broad": "b-broad", "specific": "a-versatile"}


def test_structured_locations_match_exact_lines_or_symbol_spans(tmp_path):
    (tmp_path / "views.py").write_text(
        "class ActionView:\n    permission = 'user'\n\n    def post(self):\n        return save()\n"
    )
    key = _key(
        _check(
            "guarded-action",
            ("views.py", {"line": 2}),
            ("views.py", {"symbol": "ActionView.post"}),
        )
    )

    for line in (2, 5):
        report = _report("r", ("views.py", line))
        assert score(key, [report], source_root=str(tmp_path)).found == ["guarded-action"]
    outside = _report("r", ("views.py", 1))
    assert score(key, [outside], source_root=str(tmp_path)).missed == ["guarded-action"]


def test_structured_locations_do_not_match_basenames(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/views.py").write_text("def guarded():\n    return safe()\n")
    key = _key(_check("guarded-action", ("src/views.py", {"symbol": "guarded"})))

    basename = _report("basename", ("views.py", 2))

    assert score(key, [basename], source_root=str(tmp_path)).missed == ["guarded-action"]


def test_structured_locations_fail_loud_when_a_symbol_cannot_be_resolved(tmp_path):
    (tmp_path / "views.py").write_text("def sibling():\n    return safe()\n")
    key = _key(_check("guarded-action", ("views.py", {"symbol": "missing"})))
    report = _report("report", ("views.py", 1))

    with pytest.raises(SymbolLocationError, match=r"cannot resolve 'missing' in views\.py"):
        score(key, [report], source_root=str(tmp_path))
    with pytest.raises(SymbolLocationError, match="without benchmark source"):
        score(key, [report])
