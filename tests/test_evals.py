"""The eval ruler: answer-key loading, report matching, recall and precision scoring.

private-source discovery, and the compare flips.
"""

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
    """Endpoint match tolerates mount prefix and params."""
    assert endpoint_match("GET /api/v1/memories/123/update", "POST /memories/<id>/update") is False
    assert endpoint_match("POST /api/v1/memories/123/update", "POST /memories/<id>/update") is True
    assert endpoint_match("GET /files/abc/content", "GET /files/<id>/content") is True


def test_endpoint_match_does_not_conflate_item_with_collection():
    """Endpoint match does not conflate item with collection."""
    assert endpoint_match("GET /wallets/<id>", "GET /wallets") is False
    assert endpoint_match("GET /wallets/123", "GET /wallets") is False
    assert endpoint_match("GET /wallets", "GET /wallets") is True


def test_endpoint_match_ignores_a_trailing_handler_annotation():
    """Endpoint match ignores a trailing handler annotation."""
    assert endpoint_match("POST /v1/user/upsert` (tRPC `user.upsertUser`)`", "POST /v1/user/upsert") is True
    assert endpoint_match("`GET` `/v1/user/detail`", "GET /v1/user/detail") is True
    assert endpoint_match("translate batch handler", "translate batch handler") is True


def test_endpoint_match_ignores_a_query_string():
    """Endpoint match ignores a query string."""
    assert endpoint_match("GET /api/search/?query=<name>", "GET /api/search/") is True
    assert endpoint_match("GET /api/search/", "GET /api/search/?query=x") is True


def test_endpoint_match_credits_a_report_that_lists_several_routes():
    """Endpoint match credits a report that lists several routes."""
    blob = "GET /files/<id>/content, GET /files/<id>/content/<name>, GET /files/<id>"
    assert endpoint_match(blob, "GET /files/<id>/content") is True
    assert endpoint_match(blob, "DELETE /files/<id>") is False
    assert endpoint_match("GET /a/content POST /a/write", "POST /a/write") is True


def test_category_of_unifies_spaces_and_hyphens():
    """Category of unifies spaces and hyphens."""
    from evals.scorers.match import category_match, category_of

    assert category_of("server-side request forgery") == category_of("server-side-request-forgery")
    assert category_match(category_of("server-side request forgery"), category_of("server-side-request-forgery"))
    assert not category_match(category_of("server-side request forgery"), category_of("cross-site-request-forgery"))


def test_category_of_folds_an_abbreviation_onto_its_class():
    """Category of folds an abbreviation onto its class."""
    from evals.scorers.match import category_of

    assert category_of("xxe") == category_of("xml-external-entity")
    assert category_of("csrf") == category_of("cross-site-request-forgery")
    assert category_of("xxe") != category_of("ssrf")


def _key(tmp_path, body: str) -> Path:
    p = tmp_path / "k.yaml"
    if not body.startswith("schema_version:"):
        body = "schema_version: 1\n" + body
    p.write_text(body, encoding="utf-8")
    return p


def test_load_answer_key_fails_loud_without_schema_version(tmp_path):
    """Load answer key fails loud without schema version."""
    p = tmp_path / "k.yaml"
    p.write_text("target: t\nplanted:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        load_answer_key(p)


def test_load_answer_key_rejects_removed_fields(tmp_path):
    """Load answer key rejects removed fields."""
    with pytest.raises(ValueError, match="expected planted"):
        load_answer_key(_key(tmp_path, "target: t\nissues:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n"))
    with pytest.raises(ValueError, match="expected files"):
        load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n    file: x.py\n"))
    with pytest.raises(ValueError, match="expected symbols"):
        load_answer_key(
            _key(
                tmp_path,
                "target: t\nplanted:\n  - id: a\n    category: idor\n    files: [x.py]\n    symbol: handler\n",
            )
        )


def test_load_answer_key_rejects_scalar_list_fields(tmp_path):
    """Load answer key rejects scalar list fields."""
    with pytest.raises(ValueError, match="files is not a list"):
        load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n    files: x.py\n"))


def test_load_answer_key_fails_loud_without_planted(tmp_path):
    """Load answer key fails loud without planted."""
    with pytest.raises(ValueError, match="no planted"):
        load_answer_key(_key(tmp_path, "target: t\nsafe: []\n"))


def test_load_answer_key_rejects_unlocatable_entry(tmp_path):
    """Load answer key rejects unlocatable entry."""
    with pytest.raises(ValueError, match="neither entry nor files"):
        load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n"))


def test_load_answer_key_filters_entries_by_task(tmp_path):
    """Load answer key filters entries by task."""
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

    assert [entry.id for entry in key.planted] == ["global", "repo-only"]
    assert [entry.id for entry in key.safe] == ["safe-repo"]


def test_category_match_credits_a_broader_label_but_not_a_sibling():
    """Category match credits a broader label but not a sibling."""
    from evals.scorers.match import category_match

    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")
    assert not category_match("", "code-injection")


def test_score_counts_found_missed_fp_and_extra(tmp_path):
    """Score counts found missed fp and extra."""
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
    """One report on several safe anchors counts as one false positive."""
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
    """Safe anchor on an endpoint requires the class it certifies."""
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


def test_planted_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path):
    """Planted with endpoint is credited by its exact file and symbol anchor."""
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
    assert score(key, [wrong_symbol]).file_found == ["sink"]


def test_score_reports_file_localization_without_changing_endpoint_recall(tmp_path):
    """Score reports file localization without changing endpoint recall."""
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


def test_symbol_anchor_credits_a_report_that_pins_the_line_without_naming_the_symbol(tmp_path):
    """Symbol anchor credits a report that pins the line without naming the symbol."""
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
    """Safe symbol anchor without endpoint requires the class it certifies."""
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
    """Symbol anchor matches a whole word not a substring."""
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
    """Duplicate report of a planted bug is not a false positive."""
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
    """Accounting shape folds to the accounting class."""
    from evals.scorers.match import category_match, category_of

    assert category_match(category_of("accounting flaw, one-sided numeric bound"), category_of("accounting-precision"))


def test_file_keyed_planted_credits_a_report_at_any_accepted_anchor(tmp_path):
    """File keyed planted credits a report at any accepted anchor."""
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
    """Symbols credit the real framing not a same class sibling."""
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
    """Symbols match the source line too when the body is thin."""
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
    """No symbols keeps the coarse class and file match."""
    key = load_answer_key(
        _key(tmp_path, "target: t\nplanted:\n  - id: rce\n    category: code-injection\n    files: [lib/sink.js]\n")
    )
    bare = Report.make("r", "", "code-injection", ["lib/sink.js"])
    assert score(key, [bare]).found == ["rce"]


def test_endpoint_keyed_planted_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    """Endpoint keyed planted ignores file so a sibling is not credited."""
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
    """Parse finding md and score repository."""
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


def test_parse_finding_md_ignores_line_range_tail_paths():
    """Parse finding md ignores line range tail paths."""
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


def test_reports_from_json_reads_diff_finding_body_fields(tmp_path):
    """Reports from JSON reads diff finding body fields."""
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
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))


def test_registry_finds_public_openwebui_benchmark(tmp_path, monkeypatch):
    """Registry finds public openwebui benchmark."""
    _public_only(tmp_path, monkeypatch)
    bench = registry.find_benchmark("open-webui")
    assert bench.provenance == "public"
    assert bench.stack["frameworks"] == ["fastapi"]
    assert "insecure-direct-object-reference" in bench.knowledge["vulnerabilities"]
    key = load_answer_key(bench.answer_key)
    assert key.target == "open-webui"
    assert any(p.category == "insecure-direct-object-reference" for p in key.planted)


def test_public_real_benchmarks_use_root_taxonomy_layout(tmp_path, monkeypatch):
    """Public real benchmarks use root taxonomy layout."""
    _public_only(tmp_path, monkeypatch)
    public_root = Path(registry.__file__).resolve().parent / "benchmarks"
    manifests = sorted(public_root.rglob("benchmark.yaml"))

    assert manifests
    assert not (public_root / "projects").exists()
    assert not (public_root / "repository").exists()
    assert not list((public_root / "diff").rglob("benchmark.yaml"))
    assert not list((public_root / "diff").rglob("cases.yaml"))
    assert all("kind: project" in path.read_text(encoding="utf-8") for path in manifests)


def test_registry_exposes_repository_task_from_project_source(tmp_path, monkeypatch):
    """Registry exposes repository task from project source."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: demo-project\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/demo.git\n"
        "stack:\n"
        "  languages: [typescript]\n"
        "  protocols: [mcp]\n"
        "knowledge:\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tags: [private, mcp]\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n"
        "    path: src/tools\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n"
        "  - id: diff-introduce-command\n"
        "    kind: diff\n"
        "    base: abc123\n"
        "    ref: def456\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: demo-project\n"
        "planted:\n"
        "  - id: repo-command\n"
        "    category: command-injection\n"
        "    files: [src/tools/run.ts]\n"
        "    applies_to: [repository-vulnerable-v1]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n"
        "  - id: diff-command\n"
        "    category: command-injection\n"
        "    files: [src/tools/run.ts]\n"
        "    applies_to: [diff-introduce-command]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    bench = registry.find_benchmark("demo-project")
    key = load_answer_key(bench.answer_key, task_id=bench.task_id)

    assert bench.project_id == "demo-project"
    assert bench.task_id == "repository-vulnerable-v1"
    assert bench.target == {
        "type": "git",
        "url": "https://example.com/demo.git",
        "ref": "abc123",
        "path": "src/tools",
    }
    assert bench.stack["languages"] == ["typescript"]
    assert bench.knowledge == {
        "guides": ["languages/typescript", "protocols/mcp"],
        "vulnerabilities": ["command-injection"],
    }
    assert bench.tags == ("private", "mcp")
    assert [entry.id for entry in key.planted] == ["repo-command"]


def test_registry_rejects_project_manifest_without_schema_version(tmp_path, monkeypatch):
    """Registry rejects project manifest without schema version."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "missing-version"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "id: missing-version\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/demo.git\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: missing-version\n"
        "planted:\n"
        "  - id: repo-command\n"
        "    category: command-injection\n"
        "    files: [run.ts]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    with pytest.raises(ValueError, match="schema_version"):
        registry.all_benchmarks()


def test_registry_unknown_benchmark_fails_loud(tmp_path, monkeypatch):
    """Registry unknown benchmark fails loud."""
    _public_only(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="no benchmark 'nope'"):
        registry.find_benchmark("nope")


def test_registry_duplicate_name_across_roots_fails_loud(tmp_path, monkeypatch):
    """Registry duplicate name across roots fails loud."""
    src = tmp_path / "private"
    project = src / "frameworks" / "fastapi" / "open-webui-shadow"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: open-webui\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/open-webui.git\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\ntarget: open-webui\nplanted:\n  - id: x\n    category: idor\n    entry: GET /x/<id>\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    with pytest.raises(ValueError, match="defined in two roots"):
        registry.find_benchmark("open-webui")


def test_registry_duplicate_project_task_name_fails_loud(tmp_path, monkeypatch):
    """Registry duplicate project task name fails loud."""
    src = tmp_path / "private"
    for name in ("one", "two"):
        project = src / "protocols" / "mcp" / name
        project.mkdir(parents=True)
        (project / "benchmark.yaml").write_text(
            "schema_version: 1\n"
            "id: duplicate-project\n"
            "kind: project\n"
            "target:\n"
            "  type: git\n"
            "  url: https://example.com/demo.git\n"
            "tasks:\n"
            "  - id: repository-vulnerable-v1\n"
            "    kind: repository\n"
            "    ref: abc123\n",
            encoding="utf-8",
        )
        (project / "answer-key.yaml").write_text(
            "schema_version: 1\n"
            "target: duplicate-project\n"
            "planted:\n"
            "  - id: repo-command\n"
            "    category: command-injection\n"
            "    files: [run.ts]\n",
            encoding="utf-8",
        )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    with pytest.raises(ValueError, match="share the benchmark name 'duplicate-project'"):
        registry.all_benchmarks()


def test_compare_reports_flips():
    """Compare reports flips."""
    before = {"target": "t", "recall": 0.5, "precision_known": 1.0, "found": ["a"], "false_positives": []}
    after = {"target": "t", "recall": 1.0, "precision_known": 0.5, "found": ["a", "b"], "false_positives": ["fp"]}
    d = compare(before, after)
    assert d["newly_found"] == ["b"]
    assert d["newly_missed"] == []
    assert d["newly_false_positive"] == ["fp"]


def test_compare_reports_subthreshold_catch_rate_move():
    """Compare reports subthreshold catch rate move."""
    before = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 3}}
    after = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 2}}
    d = compare(before, after)
    assert d["newly_missed"] == []
    assert d["catch_rate_changed"] == [{"id": "a", "before": 1.0, "after": round(2 / 3, 3)}]


def test_compare_by_attributes_project_diff_answer_key_entries(tmp_path, monkeypatch):
    """Compare by attributes project diff answer key entries."""
    _public_only(tmp_path, monkeypatch)
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["git-init-command-injection-via-exec"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["command-injection"] == ["git-init-command-injection-via-exec"]


def test_gate_passes_clean_and_fails_on_regression():
    """Gate passes clean and fails on regression."""
    from evals.gate import gate

    base = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    good = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    assert gate(good, base, structural=False) == []
    bad = {"target": "t", "found": ["a"], "false_positives": ["safe-x"], "precision_known": 0.5, "errors": 0}
    fails = gate(bad, base, precision_floor=0.8, structural=False)
    assert any("newly missed" in f for f in fails)
    assert any("false positive" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    """Gate fails on errors but not on extra alone."""
    from evals.gate import gate

    assert gate({"target": "t", "errors": 2}, structural=False)
    assert (
        gate({"target": "t", "found": ["a"], "false_positives": [], "errors": 0, "extra": ["x", "y"]}, structural=False)
        == []
    )


def _run(target, found, missed, fps, n_planted, n_reports=0, errors=0, file_found=(), file_missed=()):
    from evals.results import Result

    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        file_found=list(file_found),
        file_missed=list(file_missed),
        n_planted=n_planted,
        n_file_planted=len(file_found) + len(file_missed),
        n_reports=n_reports,
        errors=errors,
    )


def test_suite_result_to_markdown_shows_runs_and_flaky():
    """Suite result to markdown shows runs and flaky."""
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
    """Run diff cases handles the audit three tuple and degraded."""
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
    """Diff benchmark scores findings against answer key."""
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
    """Diff benchmark with source root verifies by default."""
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
    """Diff benchmark without source root does not verify."""
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


def test_default_diff_cases_load_project_diff_tasks(tmp_path, monkeypatch):
    """Default diff cases load project diff tasks."""
    _public_only(tmp_path, monkeypatch)
    from evals.runners.diff import default_cases

    cases = default_cases()
    assert {c.name for c in cases} == {"git-mcp-server:diff-introduce-git-tool-command-injection-cdb8232"}
    assert all(c.is_positive for c in cases)
    assert all(c.answer_key is not None for c in cases)
    assert all(c.diff.startswith("diff --git") or c.target.get("url") for c in cases)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


def test_project_diff_task_loads_from_shared_manifest(tmp_path, monkeypatch):
    """Project diff task loads from shared manifest."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "add exec")
    ref = _git(repo, "rev-parse", "HEAD")
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: demo-diff-project\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        f"  path: {repo}\n"
        "knowledge:\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tags: [private, mcp]\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        f"    ref: {ref}\n"
        "  - id: diff-introduce-command-cafe123\n"
        "    kind: diff\n"
        f"    base: {base}\n"
        f"    ref: {ref}\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n"
        "    tags: [real]\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: demo-diff-project\n"
        "planted:\n"
        "  - id: repo-command\n"
        "    category: command-injection\n"
        "    files: [tool.ts]\n"
        "    applies_to: [repository-vulnerable-v1]\n"
        "  - id: diff-command\n"
        "    category: command-injection\n"
        "    files: [tool.ts]\n"
        "    applies_to: [diff-introduce-command-cafe123]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.diff_cases import default_cases, diff_text

    case = next(c for c in default_cases() if c.name == "demo-diff-project:diff-introduce-command-cafe123")

    assert case.category == "command-injection"
    assert "exec(input)" in diff_text(case)
    assert set(case.knowledge) == {
        "guide:languages/typescript",
        "guide:protocols/mcp",
        "vuln:command-injection",
    }
    assert "knowledge" not in case.target
    assert case.provenance == "private"
    assert case.tags == ("private", "mcp", "real")
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.planted] == ["diff-command"]


def test_private_diff_benchmark_can_load_git_target(tmp_path, monkeypatch):
    """Private diff benchmark can load git target."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "private-context-safe"
    project.mkdir(parents=True)
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
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: private-context-safe\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  path: ~/repo\n"
        "knowledge:\n"
        "  vulnerabilities: [insecure-direct-object-reference]\n"
        "  guides: [protocols/mcp, languages/python]\n"
        "tags: [private, diff-context]\n"
        "tasks:\n"
        "  - id: diff-context-safe\n"
        "    kind: diff\n"
        f"    base: {base}\n"
        f"    ref: {ref}\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: private-context-safe\n"
        "planted: []\n"
        "safe:\n"
        "  - id: per-user-client\n"
        "    category: insecure-direct-object-reference\n"
        "    files: [server.py]\n"
        "    applies_to: [diff-context-safe]\n"
        "    knowledge:\n"
        "      vulnerabilities: [insecure-direct-object-reference]\n"
        "      guides: [protocols/mcp, languages/python]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.diff_cases import default_cases

    case = next(c for c in default_cases() if c.name == "private-context-safe:diff-context-safe")
    assert "tool()" in case.diff
    assert case.context == ""
    assert case.target["path"] == "~/repo"
    assert case.provenance == "private"
    from evals.coverage import coverage_matrix

    cov = coverage_matrix()
    assert cov["vuln:insecure-direct-object-reference"].private >= 1


def test_diff_benchmark_can_load_git_url_target(tmp_path, monkeypatch):
    """Diff benchmark can load git URL target."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "tool.ts").write_text("export function run() {\n  return 'ok';\n}\n", encoding="utf-8")
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tool.ts").write_text(
        "export function run(input: string) {\n  return exec(input);\n}\n",
        encoding="utf-8",
    )
    _git(repo, "add", "tool.ts")
    _git(repo, "commit", "-m", "add exec")
    ref = _git(repo, "rev-parse", "HEAD")
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: public-real-diff\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        f"  url: {repo.as_uri()}\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [protocols/mcp, languages/typescript]\n"
        "tasks:\n"
        "  - id: diff-introduce-exec\n"
        "    kind: diff\n"
        f"    base: {base}\n"
        f"    ref: {ref}\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: public-real-diff\n"
        "planted:\n"
        "  - id: exec-command\n"
        "    category: command-injection\n"
        "    files: [tool.ts]\n"
        "    symbols: [exec]\n",
        encoding="utf-8",
    )
    from evals.diff_cases import diff_text, load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert case.diff == ""
    assert "exec(input)" in diff_text(case)
    assert case.name == "public-real-diff:diff-introduce-exec"
    assert case.target["url"] == repo.as_uri()
    assert case.provenance == "public"


def test_coverage_matrix_attributes_repository_entries_to_knowledge(tmp_path, monkeypatch):
    """Coverage matrix attributes repository entries to knowledge."""
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix

    cov = coverage_matrix()
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repository_planted >= 3
    assert idor.repository_safe >= 2
    py = cov["guide:languages/python"]
    assert py.repository_planted >= 3
    assert py.public >= 1


def test_coverage_problems_flag_a_vulnerability_missing_repository_target(tmp_path, monkeypatch):
    """Coverage problems flag a vulnerability missing repository target."""
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import Coverage, KnowledgeItem, coverage_problems

    item = KnowledgeItem(ref="vuln:demo", kind="vulnerability", path=Path("demo.md"))
    cov = {"vuln:demo": Coverage(item=item, diff_positive=1)}
    kinds = {(p.kind, p.ref) for p in coverage_problems(cov)}
    assert ("missing-repository-target", "vuln:demo") in kinds


def test_shipped_diff_library_uses_real_project_tasks(tmp_path, monkeypatch):
    """Shipped diff library uses real project tasks."""
    _public_only(tmp_path, monkeypatch)
    from evals.diff_cases import default_cases

    cases = default_cases()
    assert [c.name for c in cases] == ["git-mcp-server:diff-introduce-git-tool-command-injection-cdb8232"]
    assert cases[0].answer_key is not None
    assert len(cases[0].answer_key.planted) == 4


def test_suite_result_folds_runs_by_strict_majority():
    """Suite result folds runs by strict majority."""
    from evals.results import SuiteResult

    runs = [
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2, file_found=["a"], file_missed=["b", "c"]),
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2, file_found=["a", "b"], file_missed=["c"]),
        _run("diff", ["a", "c"], ["b"], ["safe-x"], 3, n_reports=3, errors=1, file_found=["a"], file_missed=["b", "c"]),
    ]
    sr = SuiteResult.from_runs("diff", runs)
    assert sr.runs == 3
    assert sr.found == ["a", "b"]
    assert sr.missed == ["c"]
    assert sr.false_positives == []
    assert sr.errors == 1
    assert sr.n_reports == 7
    assert sr.found_freq == {"a": 3, "b": 2, "c": 1}
    assert sr.file_found == ["a"]
    assert sr.file_missed == ["b", "c"]
    assert sr.file_found_freq == {"a": 3, "b": 1, "c": 0}
    d = sr.to_dict()
    assert d["recall"] == round(2 / 3, 4)
    assert d["found_freq"]["b"] == 2
    assert d["file_recall"] == round(1 / 3, 4)


def test_suite_result_to_dict_is_compare_compatible():
    """Suite result to dict is compare compatible."""
    from evals.compare import compare
    from evals.results import SuiteResult

    before = SuiteResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = SuiteResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_load_suite_selects_diff_benchmarks_by_tag_and_fails_loud_on_unknown():
    """Load suite selects diff benchmarks by tag and fails loud on unknown."""
    from evals.diff_cases import default_cases
    from evals.suites import load_suite, select_cases

    smoke = load_suite("public-smoke")
    cases = select_cases(smoke, default_cases())
    names = {c.name for c in cases}
    assert names == {"git-mcp-server:diff-introduce-git-tool-command-injection-cdb8232"}
    assert all("repo-aligned" in c.tags for c in cases)
    full = select_cases(load_suite("knowledge-coverage"), default_cases())
    assert len(full) == len(default_cases())
    with pytest.raises(ValueError, match="no suite 'nope'"):
        load_suite("nope")


def test_coverage_problems_flag_unresolved_reference(tmp_path, monkeypatch):
    """Coverage problems flag unresolved reference."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "ghost"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: ghost\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/ghost.git\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
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


def test_coverage_problems_flag_unresolved_reference_in_diff_only_project(tmp_path, monkeypatch):
    """Coverage problems flag unresolved reference in diff only project."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "ghost-diff"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: ghost-diff\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/ghost.git\n"
        "knowledge:\n"
        "  vulnerabilities: [no-such-class]\n"
        "tasks:\n"
        "  - id: diff-introduce-ghost\n"
        "    kind: diff\n"
        "    base: abc123\n"
        "    ref: def456\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: ghost-diff\n"
        "planted:\n"
        "  - id: g1\n"
        "    category: idor\n"
        "    entry: GET /g/<id>\n"
        "    applies_to: [diff-introduce-ghost]\n"
        "    knowledge:\n"
        "      vulnerabilities: [no-such-class]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "unresolved-reference" and p.ref == "vuln:no-such-class" for p in problems)


def test_scan_knowledge_spans_domains(tmp_path, monkeypatch):
    """Scan knowledge spans domains."""
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import scan_knowledge

    items = scan_knowledge()
    assert items["vuln:sql-injection"].kind == "vulnerability"
    assert items["vuln:reentrancy"].kind == "vulnerability"
    assert "guide:languages/solidity" in items


def test_run_diff_cases_routes_each_case_to_its_domain(monkeypatch):
    """Run diff cases routes each case to its domain."""
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
    """Run diff cases collects target context."""
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


def test_run_diff_cases_collects_context_from_git_url_target(tmp_path, monkeypatch):
    """Run diff cases collects context from git URL target."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "server.py").write_text("value = 'base'\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "base")
    (repo / "server.py").write_text("value = 'ref'\n", encoding="utf-8")
    _git(repo, "add", "server.py")
    _git(repo, "commit", "-m", "ref")
    ref = _git(repo, "rev-parse", "HEAD")
    contexts: dict[str, str] = {}

    def fake_collector(path, domain):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = Path(path, "server.py").read_text(encoding="utf-8").strip()

                return Result()

            def text_for_diff(self, diff):
                return Path(path, "server.py").read_text(encoding="utf-8").strip()

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None, context="", **kwargs):
        contexts[d] = context
        return ([], [], False)

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    case = DiffCase(
        name="targeted-url",
        category="",
        diff="diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n",
        target={"type": "git", "url": repo.as_uri(), "ref": ref},
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert contexts[case.diff] == "value = 'ref'"


def test_coverage_problems_flag_entry_without_knowledge(tmp_path, monkeypatch):
    """Coverage problems flag entry without knowledge."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: bare\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/bare.git\n"
        "tasks:\n"
        "  - id: repository-vulnerable-v1\n"
        "    kind: repository\n"
        "    ref: abc123\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\ntarget: bare\nplanted:\n  - id: b1\n    category: idor\n    entry: GET /b/<id>\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "entry-without-knowledge" and p.ref == "b1" for p in problems)


def test_coverage_problems_flag_diff_only_entry_without_knowledge(tmp_path, monkeypatch):
    """Coverage problems flag diff only entry without knowledge."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare-diff"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "id: bare-diff\n"
        "kind: project\n"
        "target:\n"
        "  type: git\n"
        "  url: https://example.com/bare.git\n"
        "knowledge:\n"
        "  vulnerabilities: [missing-authorization]\n"
        "tasks:\n"
        "  - id: diff-introduce-bare\n"
        "    kind: diff\n"
        "    base: abc123\n"
        "    ref: def456\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "target: bare-diff\n"
        "planted:\n"
        "  - id: b1\n"
        "    category: missing-authorization\n"
        "    entry: GET /b/<id>\n"
        "    applies_to: [diff-introduce-bare]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "entry-without-knowledge" and p.ref == "b1" for p in problems)


def test_one_report_cannot_satisfy_two_planted_entries(tmp_path):
    """One report cannot satisfy two planted entries."""
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
    """Coverage splits diff and repository dimensions."""
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
    """Coverage problems flags a class with no repository target."""
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
    """With arms folds in each arm cost and marks a clean pair comparable."""
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", requests=700))
    assert d["comparable"] is True
    assert d["before_cost"]["model_requests"] == 100
    assert d["after_cost"]["model_requests"] == 700
    assert d["before_cost"]["seconds"] == 60.0


def test_a_failed_review_in_either_arm_disqualifies_the_comparison(tmp_path):
    """Failed review in either arm disqualifies the comparison."""
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", errors=2))
    assert d["comparable"] is False
    assert any("after arm records 2 errors" in r for r in d["not_comparable_because"])


def test_a_finding_kept_without_a_completed_verification_disqualifies_too(tmp_path):
    """Finding kept without a completed verification disqualifies too."""
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a", incomplete=1), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 incomplete" in r for r in d["not_comparable_because"])


def test_an_arm_that_wrote_no_record_is_not_read_as_a_clean_zero(tmp_path):
    """Arm that wrote no record is not read as a clean zero."""
    from evals.compare import with_arms

    empty = tmp_path / "empty"
    empty.mkdir()
    d = with_arms({}, _arm(tmp_path / "a"), empty)
    assert d["comparable"] is False
    assert any("wrote no _run.json" in r for r in d["not_comparable_because"])


def test_both_stages_spend_is_summed_rather_than_one_overwriting_the_other(tmp_path):
    """Both stages spend is summed rather than one overwriting the other."""
    from evals.compare import _arm_artifacts

    ws = _arm(tmp_path / "a", requests=100)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 0, "incomplete": 2, "usage": {"model_requests": 40}}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)
    assert got["cost"]["model_requests"] == 140
    assert got["completeness"]["incomplete"] == 2


def test_a_failed_call_counts_once_per_stage_but_a_kept_finding_counts_once(tmp_path):
    """Failed call counts once per stage but a kept finding counts once."""
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
    """Displayed cost components account for the displayed total."""
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
    """Stage elapsed falls back to its own record when no timeline exists."""
    from evals.compare import format_arms, with_arms

    text = format_arms(with_arms({}, _arm(tmp_path / "a", seconds=60.0), _arm(tmp_path / "b", seconds=90.0)))
    assert "60.0s" in text
    assert "90.0s" in text
    assert "?s" not in text
    assert "seconds x1.50" in text


def test_format_arms_reports_the_cost_ratio_and_the_verdict(tmp_path):
    """Format arms reports the cost ratio and the verdict."""
    from evals.compare import format_arms, with_arms

    d = with_arms({}, _arm(tmp_path / "a", requests=100), _arm(tmp_path / "b", requests=800))
    text = format_arms(d)
    assert "model_requests x8.00" in text
    assert "the comparison stands" in text
