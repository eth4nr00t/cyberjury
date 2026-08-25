"""Score allocation and result classification tests."""

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.location import SymbolLocationError
from evals.score.report import Report, ReportChangeAnchor


def test_score_counts_found_missed_fp_and_extra(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: hit\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /x/<id>\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: miss\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - POST /t\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - replay\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: lookalike\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /safe/<id>\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
            ),
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
    assert res.false_positives == ["lookalike"]
    assert res.extra == ["r-extra"]
    assert res.recall == 0.5
    assert res.to_dict()["precision_known"] == 0.5


def test_one_report_on_several_clean_anchors_counts_as_one_false_positive(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: real\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /x/<id>\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: look1\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    files:\n"
                "    - svc/a.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "- id: look2\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    files:\n"
                "    - svc/a.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
            ),
        )
    )
    reports = [
        Report.make("r-hit", "GET /x/9", "idor", []),
        Report.make("r-dup", "", "idor", ["svc/a.py"]),
    ]
    res = score(key, reports)
    assert res.found == ["real"]
    assert res.false_positives == ["look1"]
    assert res.to_dict()["precision_known"] == 0.5


def test_clean_anchor_on_an_endpoint_requires_the_class_it_certifies(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: real\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /x/<id>\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: authz-ok\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    endpoints:\n"
                "    - GET /users/list\n"
                "    files:\n"
                "    - __anchor__.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - business-logic\n"
                "    guides: []\n"
            ),
        )
    )
    reports = [
        Report.make("r-hit", "GET /x/9", "idor", []),
        Report.make("r-adjacent", "GET /users/list", "information exposure", []),
    ]
    res = score(key, reports)
    assert res.found == ["real"]
    assert res.false_positives == []
    assert "r-adjacent" in res.extra
    res2 = score(key, [Report.make("r-fp", "GET /users/list", "business logic", [])])
    assert res2.false_positives == ["authz-ok"]


def test_finding_anchor_on_an_endpoint_requires_the_class_it_certifies(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: account-read\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [accounts.py]\n"
                "    endpoints: [GET /accounts/<id>]\n"
                "  knowledge: {vulnerabilities: [idor], guides: []}\n"
            ),
        )
    )
    wrong_class = Report.make("wrong", "GET /accounts/7", "sql-injection", [])

    result = score(key, [wrong_class])

    assert result.missed == ["account-read"]
    assert result.extra == ["wrong"]


def test_finding_matches_any_declared_endpoint_with_the_same_class(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: account-read\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [accounts.py]\n"
                "    endpoints: [GET /accounts/<id>, GET /profiles/<id>]\n"
                "  knowledge: {vulnerabilities: [idor], guides: []}\n"
            ),
        )
    )
    report = Report.make("profile", "GET /profiles/7", "idor", [])

    assert score(key, [report]).found == ["account-read"]


def test_grouped_endpoint_keeps_its_match_semantics_with_a_change_anchor(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: account-read\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [accounts.py]\n"
                "    endpoints: [GET /accounts/<id>]\n"
                "  change_anchors: [{file: routes.py, line: 12, side: new}]\n"
                "  knowledge: {vulnerabilities: [idor], guides: []}\n"
            ),
        )
    )
    report = Report.make(
        "account",
        "GET /accounts/7",
        "idor",
        [],
        change_anchor=ReportChangeAnchor(file="routes.py", line=12, side="new"),
    )

    assert score(key, [report]).found == ["account-read"]


def test_findings_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: sink\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - utils/dataStore.ts\n"
                "    symbols:\n"
                "    - blendData\n"
                "    endpoints:\n"
                "    - POST /api/v2/x/test\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - prototype-pollution\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
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


def test_diff_score_can_use_file_and_category_without_an_endpoint(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: authz\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - service.go\n"
                "    endpoints:\n"
                "    - POST /answers/accept\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    report = Report.make("r-diff", "", "missing authorization", ["service.go"])

    assert score(key, [report], endpoint_required=False).found == ["authz"]
    assert score(key, [report]).missed == ["authz"]


def test_diff_score_file_fallback_still_requires_the_answered_category(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: authz\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - service.go\n"
                "    endpoints:\n"
                "    - POST /answers/accept\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    report = Report.make("r-wrong-class", "", "business logic", ["service.go"])

    result = score(key, [report], endpoint_required=False)

    assert result.found == []
    assert result.missed == ["authz"]
    assert result.extra == ["r-wrong-class"]


def test_score_reports_file_localization_without_changing_endpoint_recall(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: file-read\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - models/files.py\n"
                "    symbols:\n"
                "    - get_file_by_id\n"
                "    endpoints:\n"
                "    - GET /files/<id>/content\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
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


def test_score_prefers_exact_file_match_over_endpoint_only_match(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: sink\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - controllers/request.controller.ts\n"
                "    - utils/dataStore.ts\n"
                "    symbols:\n"
                "    - blendData\n"
                "    endpoints:\n"
                "    - POST /api/v2/x/test\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - prototype-pollution\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
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


def test_symbol_anchor_matches_a_whole_word_not_a_substring(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: approve-skips\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - Token.sol\n"
                "    symbols:\n"
                "    - approve\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - access-control\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    fee = Report.make(
        "r-fee", "", "accounting-precision", ["Token.sol"], text="the fee is charged beyond the approved allowance"
    )
    real = Report.make("r-real", "", "access control", ["Token.sol"], text="approve skips the blacklist sanity check")
    assert score(key, [fee]).found == []
    assert score(key, [real]).found == ["approve-skips"]


def test_symbol_anchor_does_not_cross_category(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: predictable-token\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - api_app.py\n"
                "    symbols:\n"
                "    - build_temporary_credential\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - insecure-cryptography\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
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


def test_a_duplicate_report_of_a_findings_bug_is_not_a_false_positive(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: unbounded-fetch\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - services/cache.py\n"
                "    symbols:\n"
                "    - fetch_page\n"
                "    - drain_results\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - resource-exhaustion\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: bounded-fetch\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    files:\n"
                "    - services/cache.py\n"
                "    symbols:\n"
                "    - fetch_window\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - resource-exhaustion\n"
                "    guides: []\n"
            ),
        )
    )
    fetch = Report.make(
        "r-fetch",
        "",
        "resource-exhaustion",
        ["services/cache.py"],
        text="fetch_page accepts an unbounded page size before drain_results materializes every row",
    )
    drain = Report.make(
        "r-drain",
        "",
        "resource-exhaustion",
        ["services/cache.py"],
        text="drain_results exhausts memory after the unbounded fetch",
    )
    res = score(key, [fetch, drain])
    assert res.found == ["unbounded-fetch"]
    assert res.false_positives == []
    assert len(res.extra) == 1


def test_file_keyed_findings_credits_a_report_at_any_accepted_anchor(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: rce\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - lib/sink.js\n"
                "    - lib/routes/doc.js\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - code-injection\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    at_sink = score(key, [Report.make("r", "", "code-injection", ["lib/sink.js"])])
    at_call = score(key, [Report.make("r", "", "code-injection", ["lib/routes/doc.js"])])
    elsewhere = score(key, [Report.make("r", "", "code-injection", ["lib/routes/other.js"])])
    assert at_sink.found == ["rce"]
    assert at_call.found == ["rce"]
    assert elsewhere.missed == ["rce"]


def test_symbols_credit_the_real_framing_not_a_same_class_sibling(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: archive-access\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - services/archive.py\n"
                "    symbols:\n"
                "    - resolve_owner\n"
                "    - download_archive\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    real = Report.make(
        "r",
        "",
        "missing-authorization",
        ["services/archive.py"],
        text="download_archive trusts resolve_owner without checking the active tenant",
    )
    sibling = Report.make(
        "r", "", "missing-authorization", ["services/archive.py"], text="list_public returns public archive names"
    )
    assert score(key, [real]).found == ["archive-access"]
    assert score(key, [sibling]).missed == ["archive-access"]


def test_symbol_anchor_rejects_an_ambiguous_report_basename(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: transfer-check\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [src/a/Token.sol, src/b/Token.sol]\n"
                "    symbols: [transfer]\n"
                "  knowledge: {vulnerabilities: [access-control], guides: []}\n"
            ),
        )
    )
    ambiguous = Report.make("ambiguous", "", "access-control", ["Token.sol"], text="transfer skips the guard")

    result = score(key, [ambiguous])

    assert result.missed == ["transfer-check"]
    assert result.extra == ["ambiguous"]


def test_symbols_match_the_source_line_too_when_the_body_is_thin(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: credit-access\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - services/ledger.py\n"
                "    symbols:\n"
                "    - apply_credit\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - access-control\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    on_source = Report.make("r", "Ledger.apply_credit", "access-control", ["services/ledger.py"])
    assert score(key, [on_source]).found == ["credit-access"]


def test_no_symbols_keeps_the_coarse_class_and_file_match(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: rce\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - lib/sink.js\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - code-injection\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    bare = Report.make("r", "", "code-injection", ["lib/sink.js"])
    assert score(key, [bare]).found == ["rce"]


def test_endpoint_keyed_findings_ignores_file_so_a_sibling_is_not_credited(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: idor\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - models/item.go\n"
                "    endpoints:\n"
                "    - GET /tasks/<t>/items/<i>\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    sibling = score(key, [Report.make("r", "GET /labels/<id>", "idor", ["models/item.go"])])
    assert sibling.missed == ["idor"]


def test_one_report_cannot_satisfy_two_findings_checks(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: p1\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - svc/a.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: p2\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - svc/a.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    reports = [Report.make("r-one", "", "idor", ["svc/a.py"])]
    res = score(key, reports)
    assert len(res.found) == 1
    assert len(res.missed) == 1
    assert res.recall == 0.5


def test_diff_change_anchor_selects_the_causal_report_and_keeps_a_sibling_extra(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: causal-finding\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  change_anchors: [{file: app.py, line: 12, side: new}]\n"
                "  locations: {files: [app.py]}\n"
                "  knowledge: {vulnerabilities: [idor], guides: []}\n"
            ),
        )
    )
    sibling = Report.make(
        "sibling",
        "",
        "idor",
        ["app.py"],
        change_anchor=ReportChangeAnchor(file="settings.py", line=4, side="new"),
    )
    causal = Report.make(
        "causal",
        "",
        "idor",
        ["app.py"],
        change_anchor=ReportChangeAnchor(file="app.py", line=12, side="new"),
    )

    result = score(key, [sibling, causal])

    assert result.found == ["causal-finding"]
    assert result.extra == ["sibling"]


def test_clean_diff_change_anchor_attributes_only_the_repaired_behavior(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: repaired-finding\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: clean\n"
                "  locations: {files: [app.py]}\n"
                "  change_anchors: [{file: app.py, line: 20, side: new}]\n"
                "  knowledge: {vulnerabilities: [idor], guides: []}\n"
            ),
        )
    )
    unrelated = Report.make(
        "unrelated",
        "",
        "idor",
        ["app.py"],
        change_anchor=ReportChangeAnchor(file="app.py", line=30, side="new"),
    )
    repaired = Report.make(
        "repaired",
        "",
        "idor",
        ["app.py"],
        change_anchor=ReportChangeAnchor(file="app.py", line=20, side="new"),
    )

    result = score(key, [unrelated, repaired])

    assert result.false_positives == ["repaired-finding"]
    assert result.extra == ["unrelated"]


def test_diff_change_anchor_does_not_credit_an_unresolved_grouped_symbol(tmp_path, answer_key_file):
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates/dialog.html").write_text('<div [innerHTML]="message"></div>\n')
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: rendered-input\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [templates/dialog.html, rendering/pipe.ts]\n"
                "    symbols: [TrustedRenderer]\n"
                "  change_anchors: [{file: templates/dialog.html, line: 8, side: new}]\n"
                "  knowledge: {vulnerabilities: [cross-site-scripting], guides: []}\n"
            ),
        )
    )
    report = Report.make(
        "rendered",
        "",
        "cross-site-scripting",
        ["templates/dialog.html"],
        text="untrusted content reaches the raw html binding",
        lines=[8],
        change_anchor=ReportChangeAnchor(file="templates/dialog.html", line=8, side="new"),
    )

    result = score(key, [report], source_root=str(tmp_path))

    assert result.missed == ["rendered-input"]
    assert result.extra == ["rendered"]


def test_diff_change_anchor_does_not_credit_a_same_file_sibling_symbol(tmp_path, answer_key_file):
    source = (
        "class TargetView:\n"
        "    def post(self):\n"
        "        return create()\n"
        "\n"
        "class SiblingView:\n"
        "    def post(self):\n"
        "        return download()\n"
    )
    (tmp_path / "views.py").write_text(source)
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: target-access\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    files: [views.py]\n"
                "    symbols: [TargetView.post]\n"
                "  change_anchors: [{file: policy.py, line: 8, side: new}]\n"
                "  knowledge: {vulnerabilities: [missing-authorization], guides: []}\n"
            ),
        )
    )
    anchor = ReportChangeAnchor(file="policy.py", line=8, side="new")
    target = Report.make(
        "target",
        "",
        "missing-authorization",
        ["views.py"],
        lines=[2],
        change_anchor=anchor,
    )
    sibling = Report.make(
        "sibling",
        "",
        "missing-authorization",
        ["views.py"],
        lines=[6],
        change_anchor=anchor,
    )

    assert score(key, [target], source_root=str(tmp_path)).found == ["target-access"]
    assert score(key, [sibling], source_root=str(tmp_path)).missed == ["target-access"]


def test_diff_change_anchor_still_requires_class_and_accepted_report_file(tmp_path, answer_key_file):
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: rendered-input\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations: {files: [templates/dialog.html]}\n"
                "  change_anchors: [{file: producers/message.ts, line: 20, side: new}]\n"
                "  knowledge: {vulnerabilities: [cross-site-scripting], guides: []}\n"
            ),
        )
    )
    anchor = ReportChangeAnchor(file="producers/message.ts", line=20, side="new")
    wrong_class = Report.make("wrong-class", "", "sql-injection", ["templates/dialog.html"], change_anchor=anchor)
    wrong_file = Report.make("wrong-file", "", "cross-site-scripting", ["other.html"], change_anchor=anchor)

    assert score(key, [wrong_class]).missed == ["rendered-input"]
    assert score(key, [wrong_file]).missed == ["rendered-input"]


def test_finding_assignment_maximizes_recall_independent_of_key_and_report_order(tmp_path, answer_key_file):
    def load(checks: list[tuple[str, str]]):
        rows = "".join(
            f"  - id: {check_id}\n"
            "    applies_to: [repository-vulnerable]\n"
            "    expectation: findings\n"
            "    severity: HIGH\n"
            f"    locations:\n      files: [__anchor__.py]\n      endpoints: [{endpoint}]\n"
            "    knowledge:\n      vulnerabilities: [idor]\n      guides: []\n"
            for check_id, endpoint in checks
        )
        document = f"schema_version: 1\nbenchmark_id: t\nchecks:\n{rows}"
        return load_answer_key(answer_key_file(tmp_path, document))

    broad = ("broad", "GET /broad")
    specific = ("specific", "GET /specific")
    versatile = Report.make("a-versatile", "GET /broad, GET /specific", "idor", [])
    broad_only = Report.make("b-broad", "GET /broad", "idor", [])
    traces: list[dict] = []

    first = score(load([broad, specific]), [versatile, broad_only], trace=traces.append)
    second = score(load([specific, broad]), [broad_only, versatile])

    assert set(first.found) == {"broad", "specific"}
    assert set(second.found) == {"broad", "specific"}
    assert first.missed == second.missed == []
    assignments = {
        event["key"]: event["report"]
        for event in traces
        if event.get("event") == "score_match" and event.get("kind") == "findings"
    }
    assert assignments == {"broad": "b-broad", "specific": "a-versatile"}


def test_structured_locations_match_exact_lines_or_symbol_spans(tmp_path, answer_key_file):
    (tmp_path / "views.py").write_text(
        "class ActionView:\n    permission = 'user'\n\n    def post(self):\n        return save()\n"
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: guarded-action\n"
                "  applies_to: [diff-abcdef0-1]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations:\n"
                "    - {file: views.py, line: 2}\n"
                "    - {file: views.py, symbol: ActionView.post}\n"
                "  changes: [{file: policy.py, line: 8, side: new}]\n"
                "  knowledge: {vulnerabilities: [missing-authorization], guides: []}\n"
            ),
        )
    )
    anchor = ReportChangeAnchor(file="policy.py", line=8, side="new")
    class_control = Report.make("control", "", "missing-authorization", ["views.py"], lines=[2], change_anchor=anchor)
    method = Report.make("method", "", "missing-authorization", ["views.py"], lines=[5], change_anchor=anchor)

    assert score(key, [class_control], source_root=str(tmp_path)).found == ["guarded-action"]
    assert score(key, [method], source_root=str(tmp_path)).found == ["guarded-action"]


def test_structured_locations_do_not_match_symbol_words_or_basenames(tmp_path, answer_key_file):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/views.py").write_text("def guarded():\n    return safe()\n")
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: guarded-action\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations: [{file: src/views.py, symbol: guarded}]\n"
                "  knowledge: {vulnerabilities: [missing-authorization], guides: []}\n"
            ),
        )
    )
    symbol_words = Report.make(
        "words",
        "",
        "missing-authorization",
        ["src/views.py"],
        text="the guarded function is exposed",
        lines=[9],
    )
    basename = Report.make("basename", "", "missing-authorization", ["views.py"], lines=[2])

    assert score(key, [symbol_words], source_root=str(tmp_path)).missed == ["guarded-action"]
    assert score(key, [basename], source_root=str(tmp_path)).missed == ["guarded-action"]


def test_structured_locations_fail_loud_when_a_symbol_cannot_be_resolved(tmp_path, answer_key_file):
    (tmp_path / "views.py").write_text("def sibling():\n    return safe()\n")
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: guarded-action\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  severity: HIGH\n"
                "  locations: [{file: views.py, symbol: missing}]\n"
                "  knowledge: {vulnerabilities: [missing-authorization], guides: []}\n"
            ),
        )
    )
    report = Report.make("report", "", "missing-authorization", ["views.py"], lines=[1])

    with pytest.raises(SymbolLocationError, match=r"cannot resolve 'missing' in views\.py"):
        score(key, [report], source_root=str(tmp_path))
