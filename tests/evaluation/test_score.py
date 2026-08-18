"""Scoring, matching, and report parsing tests."""

from __future__ import annotations

import json

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.review.repository import _workspace_reports
from evals.score.engine import score
from evals.score.match import endpoint_match
from evals.score.report import Report, parse_finding_md, reports_from_findings_dir, reports_from_json

from .support import (
    _key,
)


def test_endpoint_match_tolerates_mount_prefix_and_params():
    assert endpoint_match("GET /api/v1/memories/123/update", "POST /memories/<id>/update") is False
    assert endpoint_match("POST /api/v1/memories/123/update", "POST /memories/<id>/update") is True
    assert endpoint_match("GET /files/abc/content", "GET /files/<id>/content") is True


def test_endpoint_match_does_not_conflate_item_with_collection():
    assert endpoint_match("GET /wallets/<id>", "GET /wallets") is False
    assert endpoint_match("GET /wallets/123", "GET /wallets") is False
    assert endpoint_match("GET /wallets", "GET /wallets") is True


def test_endpoint_match_ignores_a_trailing_handler_annotation():
    assert endpoint_match("POST /v1/user/upsert` (tRPC `user.upsertUser`)`", "POST /v1/user/upsert") is True
    assert endpoint_match("`GET` `/v1/user/detail`", "GET /v1/user/detail") is True
    assert endpoint_match("translate batch handler", "translate batch handler") is True


def test_workspace_reports_prefers_the_review_scope_leaf(tmp_path):
    workspace = tmp_path / "ws"
    leaf = workspace / "webui"
    leaf.mkdir(parents=True)
    (leaf / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    kind, path = _workspace_reports(workspace, "open-webui", {"path": "backend/apps/webui"})

    assert kind == "json"
    assert path == leaf / "findings.json"


def test_workspace_reports_refuses_to_guess_between_multiple_outputs(tmp_path):
    for leaf in ("api", "web"):
        out = tmp_path / "ws" / leaf
        out.mkdir(parents=True)
        (out / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="multiple findings outputs"):
        _workspace_reports(tmp_path / "ws", "target", {})


def test_endpoint_match_ignores_a_query_string():
    assert endpoint_match("GET /api/search/?query=<name>", "GET /api/search/") is True
    assert endpoint_match("GET /api/search/", "GET /api/search/?query=x") is True


def test_endpoint_match_credits_a_report_that_lists_several_routes():
    blob = "GET /files/<id>/content, GET /files/<id>/content/<name>, GET /files/<id>"
    assert endpoint_match(blob, "GET /files/<id>/content") is True
    assert endpoint_match(blob, "DELETE /files/<id>") is False
    assert endpoint_match("GET /a/content POST /a/write", "POST /a/write") is True


def test_category_of_unifies_spaces_and_hyphens():
    from evals.score.match import category_match, category_of

    assert category_of("server-side request forgery") == category_of("server-side-request-forgery")
    assert category_match(category_of("server-side request forgery"), category_of("server-side-request-forgery"))
    assert not category_match(category_of("server-side request forgery"), category_of("cross-site-request-forgery"))


def test_category_of_folds_an_abbreviation_onto_its_class():
    from evals.score.match import category_of

    assert category_of("xxe") == category_of("xml-external-entity")
    assert category_of("csrf") == category_of("cross-site-request-forgery")
    assert category_of("xxe") != category_of("ssrf")


def test_load_answer_key_fails_loud_without_schema_version(tmp_path):
    p = tmp_path / "answer-key.yaml"
    p.write_text("target: t\nplanted:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        load_answer_key(p)


def test_load_answer_key_rejects_removed_fields(tmp_path):
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_key(tmp_path, "target: t\nissues:\n  - id: a\n"))
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nplanted:\n  - id: a\n    category: idor\n    files: [x.py]\n"))
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nsafe:\n  - id: a\n    category: idor\n    files: [x.py]\n"))


def test_load_answer_key_rejects_scalar_list_fields(tmp_path):
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(
            _key(
                tmp_path,
                "benchmark_id: t\nchecks:\n"
                "  - id: a\n    expectation: findings\n    severity: HIGH\n"
                "    applies_to: [repository-vulnerable]\n    locations:\n      files: x.py\n"
                "    knowledge: {vulnerabilities: [idor], guides: []}\n",
            )
        )


def test_load_answer_key_fails_loud_without_findings(tmp_path):
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nchecks: []\n"))


def test_load_answer_key_rejects_invalid_expectation_and_severity(tmp_path):
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(
            _key(
                tmp_path,
                "benchmark_id: t\nchecks:\n"
                "  - id: a\n    expectation: unknown\n    applies_to: [repository-vulnerable]\n"
                "    locations: {files: [x.py]}\n"
                "    knowledge: {vulnerabilities: [idor], guides: []}\n",
            )
        )
    missing_severity = tmp_path / "missing-severity"
    missing_severity.mkdir()
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(
            _key(
                missing_severity,
                "benchmark_id: t\nchecks:\n"
                "  - id: a\n    expectation: findings\n    applies_to: [repository-vulnerable]\n"
                "    locations: {files: [x.py]}\n"
                "    knowledge: {vulnerabilities: [idor], guides: []}\n",
            )
        )


def test_load_answer_key_rejects_unlocatable_check(tmp_path):
    with pytest.raises(ValueError, match=r"answer-key-v1\.schema"):
        load_answer_key(
            _key(
                tmp_path,
                "benchmark_id: t\nchecks:\n"
                "  - id: a\n    expectation: findings\n    severity: HIGH\n"
                "    applies_to: [repository-vulnerable]\n    locations: {}\n"
                "    knowledge: {vulnerabilities: [idor], guides: []}\n",
            )
        )


def test_load_answer_key_filters_checks_by_task(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: project\n"
            "planted:\n"
            "  - id: global\n"
            "    category: idor\n"
            "    files: [shared.py]\n"
            "  - id: repo-only\n"
            "    category: idor\n"
            "    files: [repo.py]\n"
            "    applies_to: [repository-vulnerable-v1]\n"
            "  - id: diff-only\n"
            "    category: command-injection\n"
            "    files: [diff.py]\n"
            "    applies_to: [diff-introduce-command]\n"
            "safe:\n"
            "  - id: safe-repo\n"
            "    category: idor\n"
            "    files: [repo_safe.py]\n"
            "    applies_to: [repository-vulnerable-v1]\n",
        ),
        task_id="repository-vulnerable-v1",
    )

    assert [entry.id for entry in key.findings] == ["global", "repo-only"]
    assert [entry.id for entry in key.clean] == ["safe-repo"]


def test_load_answer_key_allows_one_finding_to_move_between_disjoint_tasks(tmp_path):
    """One finding id may carry task specific anchors after a code move."""
    path = _key(
        tmp_path,
        "target: project\n"
        "planted:\n"
        "  - id: moved-finding\n"
        "    category: idor\n"
        "    files: [old.py]\n"
        "    applies_to: [diff-introduce-finding]\n"
        "  - id: moved-finding\n"
        "    category: idor\n"
        "    files: [new.py]\n"
        "    applies_to: [repository-vulnerable]\n",
    )

    diff_key = load_answer_key(path, task_id="diff-introduce-finding")
    repository_key = load_answer_key(path, task_id="repository-vulnerable")

    assert [entry.files for entry in diff_key.findings] == [("old.py",)]
    assert [entry.files for entry in repository_key.findings] == [("new.py",)]


def test_load_answer_key_rejects_duplicate_ids_with_overlapping_task_scopes(tmp_path):
    """A task cannot count two checks under one finding id."""
    path = _key(
        tmp_path,
        "target: project\n"
        "planted:\n"
        "  - id: duplicate\n"
        "    category: idor\n"
        "    files: [one.py]\n"
        "    applies_to: [repository-vulnerable]\n"
        "  - id: duplicate\n"
        "    category: idor\n"
        "    files: [two.py]\n"
        "    applies_to: [repository-vulnerable, diff-introduce-finding]\n",
    )

    with pytest.raises(ValueError, match="overlapping task scopes"):
        load_answer_key(path)


def test_load_answer_key_rejects_one_id_as_findings_and_clean_for_the_same_task(tmp_path):
    """One task cannot expect a finding id to be both present and absent."""
    path = _key(
        tmp_path,
        "target: project\n"
        "planted:\n"
        "  - id: conflicting\n"
        "    category: idor\n"
        "    files: [one.py]\n"
        "    applies_to: [repository-vulnerable]\n"
        "safe:\n"
        "  - id: conflicting\n"
        "    category: idor\n"
        "    files: [one.py]\n"
        "    applies_to: [repository-vulnerable]\n",
    )

    with pytest.raises(ValueError, match="overlapping task scopes"):
        load_answer_key(path)


def test_category_match_credits_a_broader_label_but_not_a_sibling():
    from evals.score.match import category_match, category_of

    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")
    assert not category_match("access-control", "missing-authorization")
    assert not category_match("", "code-injection")
    assert category_of("access control") == "access-control"
    assert category_of("missing access control") == "missing-authorization"


def test_score_counts_found_missed_fp_and_extra(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: hit\n    category: idor\n    entry: GET /x/<id>\n"
            "  - id: miss\n    category: replay\n    entry: POST /t\n"
            "safe:\n"
            "  - id: lookalike\n    category: idor\n    entry: GET /safe/<id>\n",
        )
    )
    reports = [
        Report.make("r-hit", "GET /x/9", "idor", []),
        Report.make("r-fp", "GET /safe/9", "idor", []),
        Report.make("r-extra", "GET /unknown/thing", "xss", []),
    ]
    res = score(key, reports)
    assert res.found == ["hit"]
    assert res.missed == ["miss"]
    assert res.false_positives == ["r-fp"]
    assert res.extra == ["r-extra"]
    assert res.recall == 0.5
    assert res.to_dict()["precision_known"] == 0.5


def test_one_report_on_several_clean_anchors_counts_as_one_false_positive(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: real\n    category: idor\n    entry: GET /x/<id>\n"
            "safe:\n"
            "  - id: look1\n    category: idor\n    files: [svc/a.py]\n"
            "  - id: look2\n    category: idor\n    files: [svc/a.py]\n",
        )
    )
    reports = [
        Report.make("r-hit", "GET /x/9", "idor", []),
        Report.make("r-dup", "", "idor", ["svc/a.py"]),
    ]
    res = score(key, reports)
    assert res.found == ["real"]
    assert res.false_positives == ["r-dup"]
    assert res.to_dict()["precision_known"] == 0.5


def test_clean_anchor_on_an_endpoint_requires_the_class_it_certifies(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: real\n    category: idor\n    entry: GET /x/<id>\n"
            "safe:\n"
            "  - id: authz-ok\n    category: business-logic\n    entry: GET /users/list\n",
        )
    )
    reports = [
        Report.make("r-hit", "GET /x/9", "missing authorization", []),
        Report.make("r-adjacent", "GET /users/list", "information exposure", []),
    ]
    res = score(key, reports)
    assert res.found == ["real"]
    assert res.false_positives == []
    assert "r-adjacent" in res.extra
    res2 = score(key, [Report.make("r-fp", "GET /users/list", "business logic", [])])
    assert res2.false_positives == ["r-fp"]


def test_findings_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: sink\n    category: prototype-pollution\n    entry: POST /api/v2/x/test\n"
            "    files: [utils/dataStore.ts]\n    symbols: [blendData]\n",
        )
    )
    hit = Report.make(
        "r-hit",
        "POST /api/v1/db/x/test",
        "prototype pollution",
        ["utils/dataStore.ts"],
        text="blendData writes attacker keys",
    )
    wrong_symbol = Report.make(
        "r-wrong",
        "POST /api/v1/db/x/test",
        "prototype pollution",
        ["utils/dataStore.ts"],
        text="shallowCopy is fine here",
    )
    assert score(key, [hit]).found == ["sink"]
    assert score(key, [wrong_symbol]).found == []
    assert score(key, [wrong_symbol]).file_found == ["sink"]


def test_diff_score_can_use_file_and_category_without_an_endpoint(tmp_path):
    """Diff scoring does not require an endpoint that the patch cannot establish."""
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: authz\n    category: missing-authorization\n"
            "    entry: POST /answers/accept\n    files: [service.go]\n",
        )
    )
    report = Report.make("r-diff", "", "missing authorization", ["service.go"])

    assert score(key, [report], endpoint_required=False).found == ["authz"]
    assert score(key, [report]).missed == ["authz"]


def test_diff_score_file_fallback_still_requires_the_answered_category(tmp_path):
    """Diff file fallback does not credit a different vulnerability class."""
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: authz\n    category: missing-authorization\n"
            "    entry: POST /answers/accept\n    files: [service.go]\n",
        )
    )
    report = Report.make("r-wrong-class", "", "business logic", ["service.go"])

    result = score(key, [report], endpoint_required=False)

    assert result.found == []
    assert result.missed == ["authz"]
    assert result.extra == ["r-wrong-class"]


def test_score_reports_file_localization_without_changing_endpoint_recall(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: file-read\n    category: idor\n    entry: GET /files/<id>/content\n"
            "    files: [models/files.py]\n    symbols: [get_file_by_id]\n",
        )
    )
    endpoint_only = Report.make(
        "r-endpoint",
        "GET /files/123/content",
        "idor",
        ["routers/files.py"],
        text="get_file_by_id is reached here",
    )
    localized = Report.make(
        "r-localized",
        "",
        "idor",
        ["models/files.py"],
        text="get_file_by_id reads without an owner predicate",
    )

    endpoint_res = score(key, [endpoint_only])
    both_res = score(key, [endpoint_only, localized])

    assert endpoint_res.found == ["file-read"]
    assert endpoint_res.file_found == []
    assert endpoint_res.file_missed == ["file-read"]
    assert endpoint_res.file_recall == 0
    assert both_res.found == ["file-read"]
    assert both_res.file_found == ["file-read"]
    assert both_res.file_missed == []
    assert both_res.to_dict()["file_recall"] == 1


def test_score_prefers_exact_file_match_over_endpoint_only_match(tmp_path):
    """An exact file anchor wins over an endpoint only match when both are valid."""
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: sink\n    category: prototype-pollution\n    entry: POST /api/v2/x/test\n"
            "    files: [controllers/request.controller.ts, utils/dataStore.ts]\n"
            "    symbols: [blendData]\n",
        )
    )
    weak = Report.make(
        "r-weak",
        "POST /api/v2/x/test",
        "prototype-pollution",
        ["routers/request.ts"],
        text="the endpoint permits prototype keys",
    )
    strong = Report.make(
        "r-strong",
        "",
        "prototype-pollution",
        ["utils/dataStore.ts"],
        text="blendData copies constructor.prototype keys into Object.prototype",
    )

    res = score(key, [weak, strong])

    assert res.found == ["sink"]
    assert res.file_found == ["sink"]
    assert res.extra == ["r-weak"]


def test_symbol_anchor_credits_a_report_that_pins_the_line_without_naming_the_symbol(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.ts").write_text(
        "export function createGen(a, b) {\n"
        "    const x = 1;\n"
        "    const service = new ItemsService(c);\n"
        "    return x;\n"
        "}\n"
        "function other() {\n"
        "    return 2;\n"
        "}\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: gen\n    category: missing-authorization\n"
            "    files: [src/mod.ts]\n    symbols: [createGen]\n",
        )
    )
    inside = Report.make(
        "r-in",
        "",
        "missing authorization",
        ["src/mod.ts"],
        text="new ItemsService built with no accountability",
        lines=[3],
    )
    sibling = Report.make(
        "r-sib", "", "missing authorization", ["src/mod.ts"], text="something in the other function", lines=[7]
    )
    assert score(key, [inside], source_root=str(tmp_path)).found == ["gen"]
    assert score(key, [inside]).found == []
    assert score(key, [sibling], source_root=str(tmp_path)).found == []


def test_clean_symbol_anchor_without_endpoint_requires_the_class_it_certifies(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "body.py").write_text(
        "class LengthReader:\n"
        "    def read(self, n):\n"
        "        return n\n"
        "class Body:\n"
        "    def readline(self):\n"
        "        return 1\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: real\n    category: idor\n    files: [src/other.py]\n"
            "safe:\n"
            "  - id: bounded-reader\n    category: http-request-smuggling\n"
            "    files: [src/body.py]\n    symbols: [LengthReader]\n",
        )
    )
    off_class = Report.make(
        "r-oc", "", "uncontrolled resource consumption", ["src/body.py"], text="reads too much", lines=[3]
    )
    same_class = Report.make("r-sc", "", "http request smuggling", ["src/body.py"], text="framing desync", lines=[3])
    assert score(key, [off_class], source_root=str(tmp_path)).false_positives == []
    assert score(key, [same_class], source_root=str(tmp_path)).false_positives == ["r-sc"]


def test_symbol_anchor_matches_a_whole_word_not_a_substring(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: approve-skips\n    category: access-control\n"
            "    files: [Token.sol]\n    symbols: [approve]\n",
        )
    )
    fee = Report.make(
        "r-fee", "", "accounting-precision", ["Token.sol"], text="the fee is charged beyond the approved allowance"
    )
    real = Report.make("r-real", "", "access control", ["Token.sol"], text="approve skips the blacklist sanity check")
    assert score(key, [fee]).found == []
    assert score(key, [real]).found == ["approve-skips"]


def test_symbol_anchor_does_not_cross_category(tmp_path):
    """A shared helper name cannot credit a report about a different defect class."""
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: predictable-token\n    category: insecure-cryptography\n"
            "    files: [api_app.py]\n    symbols: [build_temporary_credential]\n",
        )
    )
    wrong_class = Report.make(
        "r-wrong",
        "",
        "insecure-direct-object-reference",
        ["api_app.py"],
        text="build_temporary_credential accepts a cross tenant dialog id",
        lines=[45],
    )
    right_class = Report.make(
        "r-right",
        "",
        "insecure-cryptography",
        ["api_app.py"],
        text="build_temporary_credential builds predictable UUIDv1 tokens",
        lines=[45],
    )
    assert score(key, [wrong_class]).found == []
    assert score(key, [wrong_class]).missed == ["predictable-token"]
    assert score(key, [right_class]).found == ["predictable-token"]


def test_a_duplicate_report_of_a_findings_bug_is_not_a_false_positive(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: proxy-takeover\n    category: proxy-delegatecall\n"
            "    files: [VaultProxy.sol]\n    symbols: [initialise, fallback]\n"
            "safe:\n"
            "  - id: safe-guarded-update\n    category: proxy-delegatecall\n"
            "    files: [VaultProxy.sol]\n    symbols: [updateConfig]\n",
        )
    )
    init = Report.make(
        "r-init",
        "",
        "proxy-delegatecall",
        ["VaultProxy.sol"],
        text="initialise is unprotected and installs a malicious updateConfig target",
    )
    fb = Report.make(
        "r-fb",
        "",
        "proxy-delegatecall",
        ["VaultProxy.sol"],
        text="fallback delegatecalls to the config-derived implementation",
    )
    res = score(key, [init, fb])
    assert res.found == ["proxy-takeover"]
    assert res.false_positives == []
    assert len(res.extra) == 1


def test_accounting_shape_folds_to_the_accounting_class():
    from evals.score.match import category_match, category_of

    assert category_match(category_of("accounting flaw, one-sided numeric bound"), category_of("accounting-precision"))


def test_file_keyed_findings_credits_a_report_at_any_accepted_anchor(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: rce\n    category: code-injection\n    files:\n      - lib/sink.js\n      - lib/routes/doc.js\n",
        )
    )
    at_sink = score(key, [Report.make("r", "", "code-injection", ["lib/sink.js"])])
    at_call = score(key, [Report.make("r", "", "code-injection", ["lib/routes/doc.js"])])
    elsewhere = score(key, [Report.make("r", "", "code-injection", ["lib/routes/other.js"])])
    assert at_sink.found == ["rce"]
    assert at_call.found == ["rce"]
    assert elsewhere.missed == ["rce"]


def test_symbols_credit_the_real_framing_not_a_same_class_sibling(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: reent\n    category: reentrancy\n    files: [src/V3Vault.sol]\n"
            "    symbols:\n      - _cleanupLoan\n      - onERC721Received\n",
        )
    )
    real = Report.make(
        "r",
        "",
        "reentrancy",
        ["src/V3Vault.sol"],
        text="_cleanupLoan runs safeTransferFrom, the receiver re-enters via onERC721Received",
    )
    sibling = Report.make(
        "r", "", "reentrancy", ["src/V3Vault.sol"], text="decreaseLiquidityAndCollect lacks a nonReentrant guard"
    )
    assert score(key, [real]).found == ["reent"]
    assert score(key, [sibling]).missed == ["reent"]


def test_symbols_match_the_source_line_too_when_the_body_is_thin(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: ac\n    category: access-control\n    files: [src/V3Utils.sol]\n"
            "    symbols:\n      - execute\n",
        )
    )
    on_source = Report.make("r", "V3Utils.execute", "access-control", ["src/V3Utils.sol"])
    assert score(key, [on_source]).found == ["ac"]


def test_no_symbols_keeps_the_coarse_class_and_file_match(tmp_path):
    key = load_answer_key(
        _key(tmp_path, "target: t\nplanted:\n  - id: rce\n    category: code-injection\n    files: [lib/sink.js]\n")
    )
    bare = Report.make("r", "", "code-injection", ["lib/sink.js"])
    assert score(key, [bare]).found == ["rce"]


def test_endpoint_keyed_findings_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: idor\n    category: idor\n"
            "    entry: GET /tasks/<t>/items/<i>\n    files: [models/item.go]\n",
        )
    )
    sibling = score(key, [Report.make("r", "GET /labels/<id>", "idor", ["models/item.go"])])
    assert sibling.missed == ["idor"]


def test_parse_finding_md_and_score_repository(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "f1.md").write_text(
        "# wallet idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /wallets/<id>`\n"
        "## Analysis\napp/services/wallet.py:11 no owner check\n"
    )
    rep = parse_finding_md((findings / "f1.md").read_text(), "f1")
    assert rep.endpoint == "get /wallets/*"
    assert rep.category == "insecure-direct-object-reference"
    assert "app/services/wallet.py" in rep.files

    key = load_answer_key(
        _key(tmp_path, "target: t\nplanted:\n  - id: w\n    category: idor\n    entry: GET /wallets/<id>\n")
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


def test_solidity_file_keyed_report_scores_from_markdown_source(tmp_path):
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
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: unchecked-eth\n"
            "    category: unchecked-low-level-call\n"
            "    files: [contracts/helper/V3Proxy.sol]\n",
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


def test_one_report_cannot_satisfy_two_findings_checks(tmp_path):
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: p1\n    category: idor\n    files: [svc/a.py]\n"
            "  - id: p2\n    category: idor\n    files: [svc/a.py]\n"
            "safe: []\n",
        )
    )
    reports = [Report.make("r-one", "", "idor", ["svc/a.py"])]
    res = score(key, reports)
    assert len(res.found) == 1
    assert len(res.missed) == 1
    assert res.recall == 0.5
