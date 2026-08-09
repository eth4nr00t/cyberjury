"""Render a list of Findings as text, markdown, JSON, or SARIF."""

from __future__ import annotations

import json

from cyberjury.finding import Finding
from cyberjury.severity import SARIF_LEVEL, SEVERITIES, index
from cyberjury.sources.metadata import SourceMeta


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def _target_lines(target: SourceMeta | None) -> list[str]:
    """The Target block for a text or markdown report, empty when no provenance was supplied.

    so a plain diff review renders exactly as before.
    """
    if target is None:
        return []
    return [f"- {label}: {value}" for label, value in target.display_rows()]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (index(f.severity), f.file, f.line or 0))


def severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity for text and gate summaries."""
    out = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def to_text(findings: list[Finding], target: SourceMeta | None = None) -> str:
    """Render findings as the plain text report format."""
    head = _target_lines(target)
    if head:
        head = ["Target:", *head, ""]
    if not findings:
        return "\n".join([*head, "no findings"]) if head else "no findings"
    lines = list(head)
    for f in _sorted(findings):
        cat = f" {f.category}" if f.category else ""
        lines.append(f"[{f.severity}]{cat} {_loc(f)}  (confidence {f.confidence:.2f})")
        if f.description:
            lines.append(f"  {f.description}")
        if f.exploit_scenario:
            lines.append(f"  exploit: {f.exploit_scenario}")
    return "\n".join(lines)


def to_markdown(findings: list[Finding], target: SourceMeta | None = None) -> str:
    """Render findings as Markdown for humans and review workspaces."""
    head = _target_lines(target)
    preamble = ["## Target", "", *head, ""] if head else []
    if not findings:
        return "\n".join([*preamble, "## Security review", "", "No findings.", ""])
    b = severity_breakdown(findings)
    out = [
        *preamble,
        "## Security review",
        "",
        f"{b['CRITICAL']} critical, {b['HIGH']} high, {b['MEDIUM']} medium, {b['LOW']} low.",
        "",
    ]
    for f in _sorted(findings):
        cat = f" {f.category}" if f.category else ""
        out.append(f"### {f.severity}{cat} `{_loc(f)}`")
        if f.description:
            out.append(f"\n{f.description}")
        if f.exploit_scenario:
            out.append(f"\n**Exploit:** {f.exploit_scenario}")
        if f.recommendation:
            out.append(f"\n**Fix:** {f.recommendation}")
        out.append("")
    return "\n".join(out)


def to_json(findings: list[Finding], target: SourceMeta | None = None) -> str:
    """Render findings as stable JSON for automation."""
    report: dict = {"findings": [f.to_dict() for f in _sorted(findings)], "summary": severity_breakdown(findings)}
    if target is not None:
        report["target"] = target.to_dict()
    return json.dumps(report, indent=2, ensure_ascii=False)


def to_sarif(findings: list[Finding], target: SourceMeta | None = None) -> str:
    """Render findings as SARIF for code scanning integrations."""
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results = []
    for f in _sorted(findings):
        if not f.file:
            continue
        rule_id = f.category or "security"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({"id": rule_id, "name": rule_id, "shortDescription": {"text": f"Cyberjury: {rule_id}"}})
        region: dict = {}
        if f.line:
            region = {"startLine": f.line}
        physical = {"artifactLocation": {"uri": f.file}}
        if region:
            physical["region"] = region
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.description or f.category or "security finding"},
                "locations": [{"physicalLocation": physical}],
                "properties": {
                    "severity": f.severity,
                    "category": f.category,
                    "confidence": f.confidence,
                    "exploitScenario": f.exploit_scenario,
                },
            }
        )
    run: dict = {
        "tool": {
            "driver": {"name": "Cyberjury", "informationUri": "https://github.com/eth4nr00t/cyberjury", "rules": rules}
        },
        "results": results,
    }
    if target is not None:
        run["properties"] = {"target": target.to_dict()}
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)


def render(fmt: str, findings: list[Finding], target: SourceMeta | None = None) -> str:
    """Render the result."""
    return {"text": to_text, "markdown": to_markdown, "json": to_json, "sarif": to_sarif}[fmt](findings, target)
