"""Render Findings as text, markdown, JSON, and SARIF."""

import json
from pathlib import Path

import jsonschema

from cyberjury.finding import Finding
from cyberjury.report import render, severity_breakdown, to_json, to_markdown, to_sarif, to_text
from cyberjury.sources.metadata import SourceMeta

_TARGET = SourceMeta(
    chain="bsc",
    chain_id=56,
    address="0x" + "ab" * 20,
    source_url="https://bscscan.com/address/x#code",
    contract_name="Token",
)

_SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())

_FINDINGS = [
    Finding(
        file="app/payment.py",
        line=42,
        severity="CRITICAL",
        category="sql_injection",
        description="string-concatenated query",
        exploit_scenario="send ' OR 1=1 --",
        confidence=0.95,
    ),
    Finding(
        file="app/views.py",
        line=10,
        severity="MEDIUM",
        category="idor",
        description="missing ownership check",
        confidence=0.6,
    ),
]


def test_breakdown_counts_findings_by_severity():
    """Breakdown counts findings by severity."""
    assert severity_breakdown(_FINDINGS) == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0}


def test_text_lists_severity_and_location():
    """Text lists severity and location."""
    out = render("text", _FINDINGS)
    assert "[CRITICAL] sql_injection app/payment.py:42" in out
    assert "exploit:" in out


def test_markdown_has_summary_and_sections():
    """Markdown has summary and sections."""
    out = render("markdown", _FINDINGS)
    assert "1 critical, 0 high, 1 medium" in out
    assert "`app/payment.py:42`" in out


def test_json_has_findings_and_summary_keys():
    """JSON has findings and summary keys."""
    doc = json.loads(to_json(_FINDINGS))
    assert set(doc) == {"findings", "summary"}
    assert doc["findings"][0]["severity"] == "CRITICAL"


def test_sarif_validates_against_schema():
    """SARIF validates against schema."""
    doc = json.loads(to_sarif(_FINDINGS))
    jsonschema.validate(doc, _SCHEMA)
    res = doc["runs"][0]["results"]
    assert res[0]["ruleId"] == "sql_injection"
    assert res[0]["level"] == "error"
    assert res[0]["properties"]["confidence"] == 0.95


def test_empty_findings_render_to_no_findings_text():
    """Empty findings render to no findings text."""
    assert render("text", []) == "no findings"
    jsonschema.validate(json.loads(to_sarif([])), _SCHEMA)


def test_target_absent_leaves_every_format_unchanged():
    """Target absent leaves every format unchanged."""
    assert to_text(_FINDINGS) == to_text(_FINDINGS, None)
    assert to_markdown(_FINDINGS) == to_markdown(_FINDINGS, None)
    assert to_json(_FINDINGS) == to_json(_FINDINGS, None)
    assert to_sarif(_FINDINGS) == to_sarif(_FINDINGS, None)
    assert "target" not in json.loads(to_json(_FINDINGS))


def test_target_shows_in_text_and_markdown():
    """Target shows in text and markdown."""
    text = render("text", _FINDINGS, _TARGET)
    assert text.startswith("Target:")
    assert "Chain: bsc" in text
    md = render("markdown", _FINDINGS, _TARGET)
    assert "## Target" in md
    assert md.index("## Target") < md.index("## Security review")
    assert "- Address: 0x" in md


def test_target_shows_in_json_and_sarif():
    """Target shows in JSON and SARIF."""
    doc = json.loads(render("json", _FINDINGS, _TARGET))
    assert doc["target"]["chain"] == "bsc"
    assert doc["target"]["chain_id"] == 56
    sarif = json.loads(render("sarif", _FINDINGS, _TARGET))
    jsonschema.validate(sarif, _SCHEMA)
    assert sarif["runs"][0]["properties"]["target"]["address"].startswith("0x")


def test_target_renders_with_no_findings():
    """Target renders with no findings."""
    md = to_markdown([], _TARGET)
    assert "## Target" in md
    assert "No findings." in md
    assert to_text([], _TARGET).startswith("Target:")
