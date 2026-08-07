"""The eval ruler: answer-key loading and the legacy alias, report matching, recall and
precision scoring, private-source discovery, and the compare flips."""

import json
import subprocess
from pathlib import Path

import pytest

from evals import registry
from evals.compare import compare, compare_by
from evals.results import SuiteResult
from evals.runners.repository import reports_from_findings_dir, score_repository
from evals.schema import Report, load_answer_key
from evals.scorers.match import endpoint_match
from evals.scorers.parse import parse_finding_md, reports_from_json
from evals.scorers.score import score


def test_endpoint_match_tolerates_mount_prefix_and_params():
    assert endpoint_match("GET /api/v1/memories/123/update", "POST /memories/<id>/update") is False
    assert endpoint_match("POST /api/v1/memories/123/update", "POST /memories/<id>/update") is True
    assert endpoint_match("GET /files/abc/content", "GET /files/<id>/content") is True


def test_endpoint_match_does_not_conflate_item_with_collection():
    # a report on the item path must not be credited to the collection key, the looseness
    # that turned a real IDOR finding into a false positive on the safe list endpoint
    assert endpoint_match("GET /wallets/<id>", "GET /wallets") is False
    assert endpoint_match("GET /wallets/123", "GET /wallets") is False
    assert endpoint_match("GET /wallets", "GET /wallets") is True


def test_endpoint_match_ignores_a_trailing_handler_annotation():
    # a Source line that names the handler after the endpoint, with stray backticks, still
    # matches the bare endpoint a key entry cites, the brittleness that scored a real
    # account-takeover report as a miss
    assert endpoint_match("POST /v1/user/upsert` (tRPC `user.upsertUser`)`", "POST /v1/user/upsert") is True
    assert endpoint_match("`GET` `/v1/user/detail`", "GET /v1/user/detail") is True
    # a non-HTTP free-text source carries no parenthetical, so it is left intact, not truncated
    assert endpoint_match("translate batch handler", "translate batch handler") is True


def test_endpoint_match_ignores_a_query_string():
    # a report citing the endpoint with a query string names the same endpoint a key entry cites
    # bare, the query is not part of the endpoint identity and its ? must not become a path segment
    assert endpoint_match("GET /api/search/?query=<name>", "GET /api/search/") is True
    assert endpoint_match("GET /api/search/", "GET /api/search/?query=x") is True


def test_endpoint_match_credits_a_report_that_lists_several_routes():
    # one defect hits several sibling routes, so a finding lists them in one Source line. A
    # match on any one credits it, and the last route in the list not matching does not veto it
    blob = "GET /files/<id>/content, GET /files/<id>/content/<name>, GET /files/<id>"
    assert endpoint_match(blob, "GET /files/<id>/content") is True
    # a method that disagrees with every listed route is still a miss, the delete is a different bug
    assert endpoint_match(blob, "DELETE /files/<id>") is False
    # routes run together without a comma also split on the fresh method token
    assert endpoint_match("GET /a/content POST /a/write", "POST /a/write") is True


def test_category_of_unifies_spaces_and_hyphens():
    # a report writing the class with spaces and a key writing it with hyphens reach the
    # scorer on one form, since the pipeline runs category_of on both before matching, so a
    # real server-side request forgery finding is not scored a miss on the separator alone
    from evals.scorers.match import category_match, category_of

    assert category_of("server-side request forgery") == category_of("server-side-request-forgery")
    assert category_match(category_of("server-side request forgery"), category_of("server-side-request-forgery"))
    assert not category_match(category_of("server-side request forgery"), category_of("cross-site-request-forgery"))


def test_category_of_folds_an_abbreviation_onto_its_class():
    # category_of normalizes at load, so a report tagged xxe and a key tagged
    # xml-external-entity reach the scorer as one form and match
    from evals.scorers.match import category_of

    assert category_of("xxe") == category_of("xml-external-entity")
    assert category_of("csrf") == category_of("cross-site-request-forgery")
    # a different class is left on its own form, not folded together
    assert category_of("xxe") != category_of("ssrf")


def _key(tmp_path, body: str) -> Path:
    p = tmp_path / "k.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_answer_key_accepts_legacy_issues_alias(tmp_path):
    new = load_answer_key(
        _key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n")
    )
    legacy = load_answer_key(
        _key(tmp_path, "target: t\nissues:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n")
    )
    assert len(new.planted) == 1
    assert len(legacy.planted) == 1
    assert new.planted[0].id == legacy.planted[0].id == "a"


def test_load_answer_key_fails_loud_without_planted(tmp_path):
    with pytest.raises(ValueError, match="no planted"):
        load_answer_key(_key(tmp_path, "target: t\nsafe: []\n"))


def test_load_answer_key_rejects_unlocatable_entry(tmp_path):
    with pytest.raises(ValueError, match="neither entry nor file"):
        load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n"))


def test_category_match_credits_a_broader_label_but_not_a_sibling():
    from evals.scorers.match import category_match

    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")
    assert not category_match("", "code-injection")


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


def test_one_report_on_several_safe_anchors_counts_as_one_false_positive(tmp_path):
    # counting it several times would understate precision by inflating the denominator
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


def test_safe_anchor_on_an_endpoint_requires_the_class_it_certifies(tmp_path):
    # a safe anchor certifies one endpoint safe for one class, so a report of a different class on
    # that endpoint is an adjacent finding, not the false positive the anchor guards. Planted
    # matching stays class-blind on the endpoint, the finder's label is noisy and the anchor pins
    # the bug, so a class mismatch there must not drop the recall credit.
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
    # a same-class report on the safe endpoint is the false positive the anchor guards
    res2 = score(key, [Report.make("r-fp", "GET /users/list", "business logic", [])])
    assert res2.false_positives == ["r-fp"]


def test_planted_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path):
    # a planted that also pins a file and a symbol is credited by a report that traces that exact
    # sink, even when the report writes the endpoint a little differently, a version prefix or an
    # extra path segment. A report on a sibling function in the same file still does not credit it.
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: sink\n    category: prototype-pollution\n    entry: POST /api/v2/x/test\n"
            "    files: [utils/dataUtils.ts]\n    symbols: [deepMerge]\n",
        )
    )
    hit = Report.make(
        "r-hit",
        "POST /api/v1/db/x/test",
        "prototype pollution",
        ["utils/dataUtils.ts"],
        text="deepMerge writes attacker keys",
    )
    wrong_symbol = Report.make(
        "r-wrong",
        "POST /api/v1/db/x/test",
        "prototype pollution",
        ["utils/dataUtils.ts"],
        text="shallowCopy is fine here",
    )
    assert score(key, [hit]).found == ["sink"]
    assert score(key, [wrong_symbol]).found == []


def test_symbol_anchor_credits_a_report_that_pins_the_line_without_naming_the_symbol(tmp_path):
    # a report can locate the bug inside the right function by line yet never type the function's
    # name. With the source available the symbol anchor reads the function's real span and credits
    # a cited line that falls in it, while a line in a sibling function is still not the bug, and
    # without source the anchor falls back to matching the name only.
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


def test_safe_symbol_anchor_without_endpoint_requires_the_class_it_certifies(tmp_path):
    # a safe anchor that pins a file and symbol but no endpoint must keep the class gate, the same
    # as the endpoint branch. A report of a different class whose cited line only happens to fall in
    # the symbol span is an adjacent finding, not the false positive the anchor guards.
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
    # a symbol like approve must match the function approve, not the word approved in an unrelated
    # allowance finding on the same file, so two distinct bugs are not conflated by a shared prefix
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


def test_a_duplicate_report_of_a_planted_bug_is_not_a_false_positive(tmp_path):
    # a bug spanning two functions is planted with both symbols and written by the finder as two
    # findings. One credits the planted, the other also matches the planted and must not be scored
    # a false positive just because it also matches the safe sibling on the same file
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\n"
            "planted:\n"
            "  - id: proxy-takeover\n    category: proxy-delegatecall\n"
            "    file: VaultProxy.sol\n    symbols: [initialise, fallback]\n"
            "safe:\n"
            "  - id: safe-guarded-update\n    category: proxy-delegatecall\n"
            "    file: VaultProxy.sol\n    symbols: [updateConfig]\n",
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
    # a finding names a specific accounting shape where the key names the class, they must reach
    # the scorer as one form so an unbounded-amount report credits an accounting-precision key
    from evals.scorers.match import category_match, category_of

    assert category_match(category_of("accounting flaw, one-sided numeric bound"), category_of("accounting-precision"))


def test_file_keyed_planted_credits_a_report_at_any_accepted_anchor(tmp_path):
    # a code injection sink with no endpoint, reported at a call site that feeds it, a real
    # detection the scorer used to miss when it pinned only the single sink file
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
    # two findings of one class can live in one file, only the one on the bug's real function
    # path is the planted bug. symbols pin that path, so a report of the same class on a
    # sibling function in the same file is no longer credited, the framing level recall the
    # coarse match by class and file could not measure
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: reent\n    category: reentrancy\n    file: src/V3Vault.sol\n"
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
    # the engine sometimes cites the function only on the Source line, which lands in the
    # report endpoint, so a symbol there counts the same as one in the body
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: ac\n    category: access-control\n    file: src/V3Utils.sol\n"
            "    symbols:\n      - execute\n",
        )
    )
    on_source = Report.make("r", "V3Utils.execute", "access-control", ["src/V3Utils.sol"])
    assert score(key, [on_source]).found == ["ac"]


def test_no_symbols_keeps_the_coarse_class_and_file_match(tmp_path):
    # an entry without symbols must score exactly as before, the behavior every web key and
    # the oracle bundle rely on
    key = load_answer_key(
        _key(tmp_path, "target: t\nplanted:\n  - id: rce\n    category: code-injection\n    file: lib/sink.js\n")
    )
    bare = Report.make("r", "", "code-injection", ["lib/sink.js"])
    assert score(key, [bare]).found == ["rce"]


def test_endpoint_keyed_planted_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    # an entry with an endpoint matches only by endpoint, so a report on another route is not
    # credited even when it cites the same file, the looseness the strict matcher guards
    key = load_answer_key(
        _key(
            tmp_path,
            "target: t\nplanted:\n  - id: idor\n    category: idor\n"
            "    entry: GET /tasks/<t>/items/<i>\n    file: models/item.go\n",
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
    res = score_repository(key, reports_from_findings_dir(findings))
    assert res.found == ["w"]


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


def _public_only(tmp_path, monkeypatch):
    # isolate discovery from the operator's real local config, so a private source on this
    # machine cannot make a public-benchmark test pass or fail
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))


def test_registry_finds_public_openwebui_benchmark(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    bench = registry.find_benchmark("open-webui")
    assert bench.provenance == "public"
    assert bench.stack["frameworks"] == ["fastapi"]
    assert "insecure-direct-object-reference" in bench.knowledge["vulnerabilities"]
    key = load_answer_key(bench.answer_key)
    assert key.target == "open-webui"
    assert any(p.category == "insecure-direct-object-reference" for p in key.planted)


def test_registry_resolves_a_private_path_source_legacy_layout(tmp_path, monkeypatch):
    src = tmp_path / "private"
    (src / "groundtruth").mkdir(parents=True)
    (src / "groundtruth" / "secret.yaml").write_text(
        "target: secret\nissues:\n  - id: s1\n    category: idor\n    entry: GET /s/<id>\n", encoding="utf-8"
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    bench = registry.find_benchmark("secret")
    assert bench.provenance == "private"
    assert bench.manifest is None
    assert bench.answer_key == src / "groundtruth" / "secret.yaml"
    assert load_answer_key(bench.answer_key).planted[0].id == "s1"


def test_registry_unknown_benchmark_fails_loud(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="no benchmark 'nope'"):
        registry.find_benchmark("nope")


def test_registry_duplicate_name_across_roots_fails_loud(tmp_path, monkeypatch):
    # a private source that re-uses a public name must fail loud, not silently shadow it,
    # unless it opts in with override: true
    src = tmp_path / "private"
    (src / "repository" / "open-webui").mkdir(parents=True)
    (src / "repository" / "open-webui" / "answer_key.yaml").write_text(
        "target: open-webui\nplanted:\n  - id: x\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8"
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    with pytest.raises(ValueError, match="defined in two roots"):
        registry.find_benchmark("open-webui")


def test_compare_reports_flips():
    before = {"target": "t", "recall": 0.5, "precision_known": 1.0, "found": ["a"], "false_positives": []}
    after = {"target": "t", "recall": 1.0, "precision_known": 0.5, "found": ["a", "b"], "false_positives": ["fp"]}
    d = compare(before, after)
    assert d["newly_found"] == ["b"]
    assert d["newly_missed"] == []
    assert d["newly_false_positive"] == ["fp"]


def test_compare_reports_subthreshold_catch_rate_move():
    # a planted issue that did not flip the majority verdict but grew flakier should still
    # surface, the value repeated runs add over a single score
    before = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 3}}
    after = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 2}}
    d = compare(before, after)
    assert d["newly_missed"] == []
    assert d["catch_rate_changed"] == [{"id": "a", "before": 1.0, "after": round(2 / 3, 3)}]


def test_compare_by_axis_groups_flips_by_vulnerability():
    # the diff case sqli carries vuln:sql-injection, so a newly found sqli groups under it
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["sqli"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["sql-injection"] == ["sqli"]


def test_gate_passes_clean_and_fails_on_regression():
    from evals.gate import gate

    base = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    good = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    assert gate(good, base, structural=False) == []
    # a planted issue caught at baseline now missing, and a new safe false positive, both block
    bad = {"target": "t", "found": ["a"], "false_positives": ["safe-x"], "precision_known": 0.5, "errors": 0}
    fails = gate(bad, base, precision_floor=0.8, structural=False)
    assert any("newly missed" in f for f in fails)
    assert any("false positive" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    from evals.gate import gate

    # a failed review step is not a clean pass, invariant 4
    assert gate({"target": "t", "errors": 2}, structural=False)
    # an extra unkeyed report alone is not a failure, the key cannot grade it
    assert (
        gate({"target": "t", "found": ["a"], "false_positives": [], "errors": 0, "extra": ["x", "y"]}, structural=False)
        == []
    )


def _run(target, found, missed, fps, n_planted, n_reports=0, errors=0):
    from evals.results import Result

    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        n_planted=n_planted,
        n_reports=n_reports,
        errors=errors,
    )


def test_suite_result_to_markdown_shows_runs_and_flaky():
    sr = SuiteResult.from_runs(
        "diff",
        [
            _run("diff", ["a"], ["b"], [], 2),
            _run("diff", ["a", "b"], [], [], 2),
        ],
    )
    md = sr.to_markdown()
    assert "runs: 2" in md
    assert "flaky: b 1/2" in md


def test_run_diff_cases_handles_the_audit_three_tuple_and_degraded(monkeypatch):
    # a degraded audit counts as a failed step, not a clean zero, invariant 4
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None, **kwargs):
        if "POSITIVE" in d:
            return (["a-finding"], [], False)
        if "DEGRADED" in d:
            return ([], [], True)
        return ([], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    cases = [
        DiffCase(name="p-hit", category="sql-injection", diff="diff --git POSITIVE"),
        DiffCase(name="p-miss", category="sql-injection", diff="diff --git CLEAN"),
        DiffCase(name="s-fp", category="", diff="diff --git POSITIVE"),
        DiffCase(name="s-ok", category="", diff="diff --git CLEAN"),
        DiffCase(name="p-degraded", category="sql-injection", diff="diff --git DEGRADED"),
    ]
    res = diffmod.run_diff_cases(cases, provider=None, model="m")
    assert res.found == ["p-hit"]
    assert res.missed == ["p-miss"]
    assert res.false_positives == ["s-fp"]
    assert res.errors == 1


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch):
    from cyberjury.finding import Finding
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod
    from evals.schema import AnswerKey, KeyEntry

    key = AnswerKey(
        target="real-patch",
        planted=(
            KeyEntry(
                id="paid-auto-publish",
                category="business-logic",
                files=("app.py",),
                symbols=("publish_paid",),
            ),
        ),
        safe=(),
    )

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None, **kwargs):
        finding = Finding(
            file="other.py",
            line=10,
            category="business-logic",
            description="publish_paid is safe here",
        )
        return ([finding], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)

    res = diffmod.run_diff_cases(
        [
            DiffCase(
                name="real-patch",
                category="business-logic",
                diff="diff --git WRONG",
                answer_key=key,
            )
        ],
        provider=None,
        model="m",
    )

    assert res.found == []
    assert res.missed == ["paid-auto-publish"]
    assert res.extra == ["other.py:10:0"]


def test_diff_benchmark_with_source_root_verifies_by_default(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verifier"] = verifier
        seen["verification_root"] = verification_root
        seen["verification_confirmers"] = verification_confirmers
        return ([], [], False)

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)

    res = diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        provider=None,
        model="m",
    )

    assert res.false_positives == []
    assert seen == {
        "verifier": "verifier",
        "verification_root": str(tmp_path),
        "verification_confirmers": [("", "checker")],
    }


def test_diff_benchmark_without_source_root_does_not_verify(monkeypatch):
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    seen = {}

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verifier"] = verifier
        seen["verification_root"] = verification_root
        seen["verification_confirmers"] = verification_confirmers
        return ([], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)

    res = diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        provider=None,
        model="m",
    )

    assert res.false_positives == []
    assert seen == {
        "verifier": None,
        "verification_root": None,
        "verification_confirmers": None,
    }


def test_default_diff_cases_split_positive_and_safe(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.runners.diff import default_cases

    cases = default_cases()
    assert any(c.is_positive for c in cases)
    assert any(not c.is_positive for c in cases)
    assert all(c.diff.startswith("diff --git") for c in cases)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


def test_private_diff_benchmark_can_load_git_target(tmp_path, monkeypatch):
    src = tmp_path / "private"
    case_dir = src / "diff" / "protocols" / "mcp" / "private-context-safe"
    case_dir.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = home / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "server.py").write_text("def get_client():\n    return current_user_client()\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "server.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "add tool")
    ref = _git(repo, "rev-parse", "HEAD")
    (case_dir / "benchmark.yaml").write_text(
        "id: private-context-safe\n"
        "kind: diff\n"
        "target:\n"
        "  type: git\n"
        "  path: ~/repo\n"
        f"  base: {base}\n"
        f"  ref: {ref}\n"
        "knowledge:\n"
        "  vulnerabilities: [insecure-direct-object-reference]\n"
        "  guides: [protocols/mcp, languages/python]\n"
        "tags: [private, diff-context]\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "target: private-context-safe\n"
        "planted: []\n"
        "safe:\n"
        "  - id: per-user-client\n"
        "    category: insecure-direct-object-reference\n"
        "    file: server.py\n"
        "    knowledge:\n"
        "      vulnerabilities: [insecure-direct-object-reference]\n"
        "      guides: [protocols/mcp, languages/python]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.diff_cases import default_cases

    case = next(c for c in default_cases() if c.name == "private-context-safe")
    assert "tool()" in case.diff
    assert case.context == ""
    assert case.target["path"] == "~/repo"
    assert case.provenance == "private"
    from evals.coverage import coverage_matrix

    cov = coverage_matrix()
    assert cov["vuln:insecure-direct-object-reference"].private >= 1


def test_diff_benchmark_can_load_sibling_diff_file(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "change.patch").write_text(
        "diff --git a/server.py b/server.py\n+++ b/server.py\n@@ -1,0 +1,1 @@\n+print(1)\n",
        encoding="utf-8",
    )
    (case_dir / "benchmark.yaml").write_text(
        "id: frozen-diff\n"
        "kind: diff\n"
        "diff_file: change.patch\n"
        "knowledge:\n"
        "  vulnerabilities: [missing-authorization]\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "target: frozen-diff\n"
        "planted: []\n"
        "safe:\n"
        "  - id: safe\n"
        "    category: missing-authorization\n"
        "    files:\n"
        "      - server.py\n",
        encoding="utf-8",
    )
    from evals.diff_cases import load_benchmark_case

    case = load_benchmark_case(case_dir / "benchmark.yaml")

    assert case.name == "frozen-diff"
    assert case.diff.startswith("diff --git")
    assert case.category == ""


def test_diff_benchmark_can_load_multiple_planted_entries(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "change.patch").write_text(
        "diff --git a/server.py b/server.py\n+++ b/server.py\n@@ -1,0 +1,2 @@\n+print(1)\n+print(2)\n",
        encoding="utf-8",
    )
    (case_dir / "benchmark.yaml").write_text(
        "id: multi-finding-diff\n"
        "kind: diff\n"
        "diff_file: change.patch\n"
        "knowledge:\n"
        "  vulnerabilities: [missing-authorization]\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "target: multi-finding-diff\n"
        "planted:\n"
        "  - id: authz-one\n"
        "    category: missing-authorization\n"
        "    files:\n"
        "      - server.py\n"
        "    symbols:\n"
        "      - route_one\n"
        "  - id: authz-two\n"
        "    category: missing-authorization\n"
        "    files:\n"
        "      - server.py\n"
        "    symbols:\n"
        "      - route_two\n",
        encoding="utf-8",
    )
    from evals.diff_cases import load_benchmark_case

    case = load_benchmark_case(case_dir / "benchmark.yaml")

    assert case.name == "multi-finding-diff"
    assert case.answer_key is not None
    assert [item.id for item in case.answer_key.planted] == ["authz-one", "authz-two"]
    assert case.category == "missing-authorization"


def test_coverage_matrix_attributes_repository_entries_to_knowledge(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix

    cov = coverage_matrix()
    # the open-webui benchmark plants three IDORs and guards two safe siblings, so the vuln
    # attributes to its repository entries. Assert a lower bound, another target adding an IDOR,
    # such as vikunja's task attachment IDOR, must not break this
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repository_planted >= 3
    assert idor.repository_safe >= 2
    assert idor.diff_positive >= 1
    # languages/python is exercised by every Python repository target, so assert a lower bound
    # rather than a fixed count that a newly added target would break
    py = cov["guide:languages/python"]
    assert py.repository_planted >= 3
    assert py.public >= 1


def test_coverage_problems_flag_a_vulnerability_missing_a_safe_case(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import Coverage, KnowledgeItem, coverage_problems

    # a class with a positive but no safe case must surface as missing-safe, not missing-positive
    item = KnowledgeItem(ref="vuln:demo", kind="vulnerability", path=Path("demo.md"))
    cov = {"vuln:demo": Coverage(item=item, diff_positive=1)}
    kinds = {(p.kind, p.ref) for p in coverage_problems(cov)}
    assert ("missing-safe", "vuln:demo") in kinds
    assert ("missing-positive", "vuln:demo") not in kinds


def test_shipped_diff_library_covers_every_vulnerability_class(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_problems

    # the case library should leave no vulnerability class without a positive and a safe
    # diff case, the goal of the filled library, so the matrix reports no such gap
    gaps = [(p.kind, p.ref) for p in coverage_problems() if p.kind in {"missing-positive", "missing-safe"}]
    assert gaps == [], f"uncovered vulnerability classes: {gaps}"


def test_suite_result_folds_runs_by_strict_majority():
    from evals.results import SuiteResult

    # three runs, a is found every time, b in two of three, c once, so a and b clear the
    # strict majority and c does not, the anti-noise verdict
    runs = [
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2),
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2),
        _run("diff", ["a", "c"], ["b"], ["safe-x"], 3, n_reports=3, errors=1),
    ]
    sr = SuiteResult.from_runs("diff", runs)
    assert sr.runs == 3
    assert sr.found == ["a", "b"]
    assert sr.missed == ["c"]
    assert sr.false_positives == []
    assert sr.errors == 1
    assert sr.n_reports == 7
    assert sr.found_freq == {"a": 3, "b": 2, "c": 1}
    d = sr.to_dict()
    assert d["recall"] == round(2 / 3, 4)
    assert d["found_freq"]["b"] == 2


def test_suite_result_to_dict_is_compare_compatible():
    from evals.compare import compare
    from evals.results import SuiteResult

    before = SuiteResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = SuiteResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_load_suite_selects_cases_by_tag_and_fails_loud_on_unknown():
    from evals.diff_cases import default_cases
    from evals.suites import load_suite, select_cases

    smoke = load_suite("public-smoke")
    cases = select_cases(smoke, default_cases())
    names = {c.name for c in cases}
    assert "sqli" in names
    assert "safe-param-sql" in names
    assert all("smoke" in c.tags for c in cases)
    # the whole-library suite selects every shipped case
    full = select_cases(load_suite("knowledge-coverage"), default_cases())
    assert len(full) == len(default_cases())
    with pytest.raises(ValueError, match="no suite 'nope'"):
        load_suite("nope")


def test_coverage_problems_flag_unresolved_reference(tmp_path, monkeypatch):
    # a benchmark that names a knowledge file which does not exist is broken data, the gate
    # must see it rather than score against a phantom class
    src = tmp_path / "private"
    (src / "repository" / "ghost").mkdir(parents=True)
    (src / "repository" / "ghost" / "answer_key.yaml").write_text(
        "target: ghost\nplanted:\n  - id: g1\n    category: idor\n    entry: GET /g/<id>\n"
        "    knowledge:\n      vulnerabilities:\n        - no-such-class\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "unresolved-reference" and p.ref == "vuln:no-such-class" for p in problems)


def test_shipped_solidity_cases_run_under_the_evm_domain():
    from evals.runners.diff import default_cases

    sol = [c for c in default_cases() if "solidity" in c.tags]
    assert sol, "no Solidity diff cases shipped"
    assert all(c.domain == "evm" for c in sol)
    # the pairs guard each class against a miss and a false positive
    assert any(c.is_positive for c in sol)
    assert any(not c.is_positive for c in sol)


def test_scan_knowledge_spans_domains(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import scan_knowledge

    items = scan_knowledge()
    # web and evm knowledge resolve under the same flat ref space, the form a case references
    assert items["vuln:sql-injection"].kind == "vulnerability"
    assert items["vuln:reentrancy"].kind == "vulnerability"
    assert "guide:languages/solidity" in items


def test_solidity_cases_resolve_to_evm_knowledge_no_unresolved(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix, coverage_problems

    cov = coverage_matrix()
    # the shipped Solidity pairs attribute to the EVM classes, a positive and a safe each
    assert cov["vuln:reentrancy"].diff_positive >= 1
    assert cov["vuln:reentrancy"].diff_safe >= 1
    # an evm class case must not read as a broken reference, the gate-fatal problem kind
    unresolved = {p.ref for p in coverage_problems(cov) if p.kind == "unresolved-reference"}
    assert "vuln:reentrancy" not in unresolved
    assert "guide:languages/solidity" not in unresolved


def test_run_diff_cases_routes_each_case_to_its_domain(monkeypatch):
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    seen: dict[str, str] = {}
    contexts: dict[str, str] = {}

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None, context="", **kwargs):
        seen[d] = domain.name
        contexts[d] = context
        return ([], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    cases = [
        DiffCase(name="w", category="", diff="web-diff", context="web-context"),
        DiffCase(name="s", category="", diff="sol-diff", domain="evm"),
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert seen == {"web-diff": "web", "sol-diff": "evm"}
    assert contexts["web-diff"] == "web-context"


def test_run_diff_cases_collects_target_context(monkeypatch):
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    contexts: dict[str, str] = {}

    def fake_collector(path, domain):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = f"context from {path} for {domain.name}"

                return Result()

            def text_for_diff(self, diff):
                return f"context from {path} for {domain.name}"

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None, context="", **kwargs):
        contexts[d] = context
        return ([], [], False)

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    cases = [
        DiffCase(
            name="targeted",
            category="",
            diff="diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n",
            target={"type": "git", "path": "/repo"},
        )
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert contexts[cases[0].diff] == "context from /repo for web"


def test_coverage_problems_flag_entry_without_knowledge(tmp_path, monkeypatch):
    src = tmp_path / "private"
    (src / "groundtruth").mkdir(parents=True)
    (src / "groundtruth" / "bare.yaml").write_text(
        "target: bare\nissues:\n  - id: b1\n    category: idor\n    entry: GET /b/<id>\n", encoding="utf-8"
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "entry-without-knowledge" and p.ref == "b1" for p in problems)


def test_one_report_cannot_satisfy_two_planted_entries(tmp_path):
    # two planted entries sharing a loose file and class anchor must not both be credited by a
    # single report, that would inflate recall
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


def test_coverage_splits_diff_and_repository_dimensions():
    from evals.coverage import Coverage, KnowledgeItem

    it = KnowledgeItem(ref="vuln:x", kind="vulnerability", path=Path("x.md"))
    diff_only = Coverage(item=it, diff_positive=1, diff_safe=1)
    assert diff_only.diff_covered
    assert not diff_only.repository_covered
    assert diff_only.covered
    repository_only = Coverage(item=it, repository_planted=1)
    assert repository_only.repository_covered
    assert not repository_only.diff_covered
    assert repository_only.covered
    assert not Coverage(item=it).covered


def test_coverage_problems_flags_a_class_with_no_repository_target():
    # the integration gap, a class a diff case exercises but no whole-repository benchmark plants
    from evals.coverage import Coverage, KnowledgeItem, coverage_problems

    def item(ref):
        return KnowledgeItem(ref=ref, kind="vulnerability", path=Path(f"{ref}.md"))

    cov = {
        "vuln:diffonly": Coverage(item=item("vuln:diffonly"), diff_positive=1, diff_safe=1),
        "vuln:hasrepository": Coverage(
            item=item("vuln:hasrepository"), diff_positive=1, diff_safe=1, repository_planted=1
        ),
    }
    kinds = {(p.ref, p.kind) for p in coverage_problems(cov)}
    assert ("vuln:diffonly", "missing-repository-target") in kinds
    assert ("vuln:hasrepository", "missing-repository-target") not in kinds
    # a diff case present means no missing-positive/safe for either
    assert ("vuln:diffonly", "missing-positive") not in kinds


def _arm(ws, *, errors=0, verify_errors=0, incomplete=0, unlocatable=0, requests=100, seconds=60.0):
    leaf = ws / "leaf"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": errors,
                "verify_errors": verify_errors,
                "incomplete": incomplete,
                "unlocatable": unlocatable,
                "timing": {"total_seconds": seconds},
                "usage": {
                    "model_requests": requests,
                    "total_input_tokens": requests * 100,
                    "output_tokens": requests * 10,
                    "unit_review_calls": 20,
                },
            }
        ),
        encoding="utf-8",
    )
    return ws


def test_with_arms_folds_in_each_arm_cost_and_marks_a_clean_pair_comparable(tmp_path):
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", requests=700))
    assert d["comparable"] is True
    assert d["before_cost"]["model_requests"] == 100
    assert d["after_cost"]["model_requests"] == 700
    assert d["before_cost"]["seconds"] == 60.0


def test_a_failed_review_in_either_arm_disqualifies_the_comparison(tmp_path):
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", errors=2))
    assert d["comparable"] is False
    assert any("after arm records 2 errors" in r for r in d["not_comparable_because"])


def test_a_finding_kept_without_a_completed_verification_disqualifies_too(tmp_path):
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a", incomplete=1), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 incomplete" in r for r in d["not_comparable_because"])


def test_an_arm_that_wrote_no_record_is_not_read_as_a_clean_zero(tmp_path):
    from evals.compare import with_arms

    empty = tmp_path / "empty"
    empty.mkdir()
    d = with_arms({}, _arm(tmp_path / "a"), empty)
    assert d["comparable"] is False
    assert any("wrote no _run.json" in r for r in d["not_comparable_because"])


def test_both_stages_spend_is_summed_rather_than_one_overwriting_the_other(tmp_path):
    from evals.compare import _arm_artifacts

    ws = _arm(tmp_path / "a", requests=100)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 0, "incomplete": 2, "usage": {"model_requests": 40}}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)
    assert got["cost"]["model_requests"] == 140
    assert got["completeness"]["incomplete"] == 2


def test_a_failed_call_counts_once_per_stage_but_a_kept_finding_counts_once(tmp_path):
    from evals.compare import _arm_artifacts

    ws = _arm(tmp_path / "a", verify_errors=2, incomplete=1, unlocatable=1)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 2, "incomplete": 1, "unlocatable": 1}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)["completeness"]
    assert got["verify_errors"] == 4
    assert got["incomplete"] == 1
    assert got["unlocatable"] == 1


def test_the_displayed_cost_components_account_for_the_displayed_total(tmp_path):
    from evals.compare import format_arms, with_arms

    leaf = tmp_path / "a" / "leaf"
    leaf.mkdir(parents=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": 0,
                "usage": {
                    "model_requests": 10,
                    "total_input_tokens": 1000,
                    "uncached_input_tokens": 200,
                    "cache_read_tokens": 750,
                    "cache_write_tokens": 50,
                    "output_tokens": 100,
                },
            }
        ),
        encoding="utf-8",
    )
    rendered = format_arms(with_arms({}, tmp_path / "a", None)).splitlines()
    line = next(row for row in rendered if "total_input_tokens=" in row)
    shown = dict(p.split("=") for p in line.split() if "=" in p)
    components = ("uncached_input_tokens", "cache_read_tokens", "cache_write_tokens")
    assert int(shown["total_input_tokens"]) == sum(int(shown[k]) for k in components)


def test_a_stage_elapsed_falls_back_to_its_own_record_when_no_timeline_exists(tmp_path):
    from evals.compare import format_arms, with_arms

    text = format_arms(with_arms({}, _arm(tmp_path / "a", seconds=60.0), _arm(tmp_path / "b", seconds=90.0)))
    assert "60.0s" in text
    assert "90.0s" in text
    assert "?s" not in text
    assert "seconds x1.50" in text


def test_format_arms_reports_the_cost_ratio_and_the_verdict(tmp_path):
    from evals.compare import format_arms, with_arms

    d = with_arms({}, _arm(tmp_path / "a", requests=100), _arm(tmp_path / "b", requests=800))
    text = format_arms(d)
    assert "model_requests x8.00" in text
    assert "the comparison stands" in text
