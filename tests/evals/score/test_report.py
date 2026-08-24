"""Stored finding report parsing and discovery tests."""

import json

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.review.repository.results import _workspace_reports
from evals.score.engine import score
from evals.score.report import ReportChangeAnchor, parse_finding_md, reports_from_findings_dir, reports_from_json


def test_workspace_reports_prefers_the_review_scope_leaf(tmp_path):
    workspace = tmp_path / "ws"
    leaf = workspace / "webui"
    leaf.mkdir(parents=True)
    (leaf / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    kind, path = _workspace_reports(workspace, "open-webui", {"path": "backend/apps/webui"})

    assert kind == "json"
    assert path == leaf / "findings.json"


def test_workspace_reports_refuses_to_guess_an_unrelated_output(tmp_path):
    out = tmp_path / "ws" / "other-benchmark"
    out.mkdir(parents=True)
    (out / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    with pytest.raises(FileNotFoundError, match=r"no findings\.json"):
        _workspace_reports(tmp_path / "ws", "target", {})


def test_parse_finding_md_and_score_repository(tmp_path, answer_key_file):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "f1.md").write_text(
        "# wallet idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /wallets/<id>`\n"
        "## Analysis\napp/services/wallet.py:11 no owner check\n"
    )
    rep = parse_finding_md((findings / "f1.md").read_text(), "f1")
    assert rep.endpoint == "get /wallets/*"
    assert rep.category == "idor"
    assert "app/services/wallet.py" in rep.files

    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: w\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /wallets/<id>\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    res = score(key, reports_from_findings_dir(findings))
    assert res.found == ["w"]


def test_parse_finding_md_ignores_line_range_tail_paths():
    rep = parse_finding_md(
        "# cors\n"
        "- Risk: HIGH\n"
        "- Type: cors-misconfiguration\n"
        "- Source: `main.py`\n"
        "## Analysis\n"
        "The issue spans main.py:100-main.py:114 and main.py:61/main.py:93.\n",
        "cors",
    )

    assert rep.files == ("main.py",)
    assert 114 not in rep.lines


def test_parse_finding_md_treats_solidity_source_as_file_citation():
    rep = parse_finding_md(
        "# unchecked payout\n"
        "- Risk: MEDIUM\n"
        "- Type: unchecked-low-level-call\n"
        "- Source: `V3Proxy.sol`\n"
        "## Analysis\n"
        "V3Proxy.sol:192 calls payable(msg.sender).call and ignores success.\n",
        "unchecked",
    )

    assert rep.endpoint == "v3proxy.sol"
    assert rep.files == ("V3Proxy.sol",)
    assert rep.lines == (192,)


def test_solidity_file_keyed_report_scores_from_markdown_source(tmp_path, answer_key_file):
    report = parse_finding_md(
        "# unchecked payout\n"
        "- Risk: MEDIUM\n"
        "- Type: unchecked-low-level-call\n"
        "- Source: `V3Proxy.sol`\n"
        "## Analysis\n"
        "V3Proxy.sol:156, V3Proxy.sol:174, and V3Proxy.sol:192 send ETH with call and ignore success.\n",
        "v3proxy-unchecked",
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: unchecked-eth\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - contracts/helper/V3Proxy.sol\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - unchecked-low-level-call\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )

    res = score(key, [report])

    assert res.found == ["unchecked-eth"]
    assert res.file_found == []


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

    assert "call_tool reaches a sink" in report.text
    assert "_denied_if_not_declared" in report.text
    assert report.lines == (12,)
    assert report.change_anchor == ReportChangeAnchor(file="routes.py", line=7, side="new")


def test_parse_finding_md_preserves_a_quoted_source_path_with_spaces():
    report = parse_finding_md(
        "# missing authorization\n"
        "- Type: missing-authorization\n"
        "- Source: `src/my handler.py`\n"
        "## Analysis\n"
        "The missing check is at src/my handler.py:12.\n",
        "missing-auth",
    )

    assert report.files == ("src/my handler.py",)
    assert report.lines == (12,)


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
