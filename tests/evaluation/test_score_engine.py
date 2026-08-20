"""Score allocation and result classification tests."""

from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.report import Report

from .support import _key


def test_score_counts_found_missed_fp_and_extra(tmp_path):
    key = load_answer_key(
        _key(
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


def test_one_report_on_several_clean_anchors_counts_as_one_false_positive(tmp_path):
    key = load_answer_key(
        _key(
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


def test_clean_anchor_on_an_endpoint_requires_the_class_it_certifies(tmp_path):
    key = load_answer_key(
        _key(
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
        Report.make("r-hit", "GET /x/9", "missing authorization", []),
        Report.make("r-adjacent", "GET /users/list", "information exposure", []),
    ]
    res = score(key, reports)
    assert res.found == ["real"]
    assert res.false_positives == []
    assert "r-adjacent" in res.extra
    res2 = score(key, [Report.make("r-fp", "GET /users/list", "business logic", [])])
    assert res2.false_positives == ["authz-ok"]


def test_findings_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path):
    key = load_answer_key(
        _key(
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


def test_diff_score_can_use_file_and_category_without_an_endpoint(tmp_path):
    key = load_answer_key(
        _key(
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


def test_diff_score_file_fallback_still_requires_the_answered_category(tmp_path):
    key = load_answer_key(
        _key(
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


def test_score_reports_file_localization_without_changing_endpoint_recall(tmp_path):
    key = load_answer_key(
        _key(
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


def test_score_prefers_exact_file_match_over_endpoint_only_match(tmp_path):
    key = load_answer_key(
        _key(
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


def test_symbol_anchor_matches_a_whole_word_not_a_substring(tmp_path):
    key = load_answer_key(
        _key(
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


def test_symbol_anchor_does_not_cross_category(tmp_path):
    key = load_answer_key(
        _key(
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


def test_a_duplicate_report_of_a_findings_bug_is_not_a_false_positive(tmp_path):
    key = load_answer_key(
        _key(
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


def test_file_keyed_findings_credits_a_report_at_any_accepted_anchor(tmp_path):
    key = load_answer_key(
        _key(
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


def test_symbols_credit_the_real_framing_not_a_same_class_sibling(tmp_path):
    key = load_answer_key(
        _key(
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


def test_symbols_match_the_source_line_too_when_the_body_is_thin(tmp_path):
    key = load_answer_key(
        _key(
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


def test_no_symbols_keeps_the_coarse_class_and_file_match(tmp_path):
    key = load_answer_key(
        _key(
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


def test_endpoint_keyed_findings_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    key = load_answer_key(
        _key(
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


def test_one_report_cannot_satisfy_two_findings_checks(tmp_path):
    key = load_answer_key(
        _key(
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


def test_finding_assignment_maximizes_recall_independent_of_key_and_report_order(tmp_path):
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
        return load_answer_key(_key(tmp_path, document))

    broad = ("broad", "GET /broad")
    specific = ("specific", "GET /specific")
    versatile = Report.make("a-versatile", "GET /broad, GET /specific", "idor", [])
    broad_only = Report.make("b-broad", "GET /broad", "xss", [])
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
