"""Stored finding report parsing tests."""

import json

import pytest

from evals.score.report import ReportChangeAnchor, ReportLocation, reports_from_json


def test_reports_from_json_reads_diff_finding_body_fields(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "file": "app.py",
                        "line": 12,
                        "category": "missing-authorization",
                        "description": "call_tool reaches a sink",
                        "exploit_scenario": "the path ignores _denied_if_not_declared",
                        "recommendation": "check allowed before routing",
                        "change_anchor": {"file": "routes.py", "line": 7, "side": "new"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = reports_from_json(path)[0]

    assert report.lines_for("app.py") == (12,)
    assert report.change_anchor == ReportChangeAnchor(file="routes.py", line=7, side="new")


def test_reports_from_json_binds_body_citations_to_the_reported_file(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "file": "src/my handler.py",
                        "category": "missing-authorization",
                        "description": "The check is missing at `src/my handler.py`:12 and my_handler.py:30.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = reports_from_json(path)[0]

    assert report.lines_for("src/my handler.py") == (12,)
    assert ReportLocation("src/my handler.py", 12) in report.locations


@pytest.mark.parametrize("line", [True, False, 0, -1, 1.5, "12"])
def test_reports_from_json_rejects_an_invalid_line(tmp_path, line):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": [{"file": "app.py", "line": line}]}), encoding="utf-8")

    with pytest.raises(ValueError, match=r"findings\[0\]\.line must be null or a positive integer"):
        reports_from_json(path)


@pytest.mark.parametrize(
    "anchor",
    [
        {},
        {"file": "app.py", "line": 0, "side": "new"},
        {"file": "app.py", "line": 12, "side": "context"},
        {"file": "app.py", "line": 12, "side": "new", "extra": True},
    ],
)
def test_reports_from_json_rejects_a_malformed_change_anchor(tmp_path, anchor):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": [{"file": "app.py", "change_anchor": anchor}]}), encoding="utf-8")

    with pytest.raises(ValueError, match=r"findings\[0\]\.change_anchor is malformed"):
        reports_from_json(path)
