"""The eval ruler covers answer keys, report matching, scoring, discovery, and compare flips."""

import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from evals import registry
from evals.__main__ import _workspace_reports
from evals.compare import compare, compare_by
from evals.models import Report, load_answer_key
from evals.results import RepeatedResult
from evals.runners.repository import reports_from_findings_dir, score_repository
from evals.scorers.match import endpoint_match
from evals.scorers.parse import parse_finding_md, reports_from_json
from evals.scorers.score import score


def _diff_result(findings=None, *, degraded=False, failures=None, errors=0, incomplete=None, failure_reason=""):
    """Build the complete diff result contract used by eval runner tests."""
    outcome = SimpleNamespace(
        findings=list(findings or []),
        failures=list(failures or []),
        degraded=degraded,
        errors=errors,
        incomplete=list(incomplete or []),
        pending=[],
        failure_reason=failure_reason,
        requires_convergence=False,
        converged=False,
    )
    return SimpleNamespace(outcome=outcome)


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


def test_workspace_reports_prefers_the_review_scope_leaf(tmp_path):
    """Workspace reports prefers the review scope leaf."""
    workspace = tmp_path / "ws"
    leaf = workspace / "webui"
    leaf.mkdir(parents=True)
    (leaf / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    kind, path = _workspace_reports(workspace, "open-webui", {"path": "backend/apps/webui"})

    assert kind == "json"
    assert path == leaf / "findings.json"


def test_workspace_reports_refuses_to_guess_between_multiple_outputs(tmp_path):
    """Workspace reports refuses to guess between multiple outputs."""
    for leaf in ("api", "web"):
        out = tmp_path / "ws" / leaf
        out.mkdir(parents=True)
        (out / "findings.json").write_text('{"findings": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="multiple findings outputs"):
        _workspace_reports(tmp_path / "ws", "target", {})


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
    data = yaml.safe_load(body) or {}
    if isinstance(data, dict) and "target" in data and "issues" not in data:
        task_ids = sorted(
            {
                task_id
                for row in (*(data.get("planted") or []), *(data.get("safe") or []))
                for task_id in row.get("applies_to") or []
            }
        ) or ["repository-vulnerable"]
        entries = []
        for legacy_section, expectation in (("planted", "findings"), ("safe", "clean")):
            for row in data.get(legacy_section) or []:
                locations = {}
                for key in ("files", "symbols"):
                    if key in row:
                        locations[key] = row[key]
                if "entry" in row:
                    locations["endpoints"] = [row["entry"]]
                if "files" not in locations:
                    locations["files"] = ["__anchor__.py"]
                entry = {
                    "id": row.get("id", f"{legacy_section}-entry"),
                    "applies_to": row.get("applies_to") or task_ids,
                    "expectation": expectation,
                    "locations": locations,
                    "knowledge": {
                        "vulnerabilities": [row.get("category", "business-logic")],
                        "guides": (row.get("knowledge") or {}).get("guides", []),
                    },
                }
                if expectation == "findings":
                    entry["severity"] = row.get("severity") or "HIGH"
                entries.append(entry)
        data = {"schema_version": 1, "benchmark_id": data["target"], "checks": entries}
        body = yaml.safe_dump(data, sort_keys=False)
    p.write_text(body, encoding="utf-8")
    return p


def _public_diff_task_count() -> int:
    root = Path(registry.__file__).resolve().parent / "benchmarks"
    total = 0
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        total += sum(1 for task in data.get("tasks") or [] if task.get("kind") == "diff")
    return total


def _public_diff_tasks() -> list[dict]:
    return [task for _manifest, task in _public_diff_task_rows()]


def _public_diff_task_rows() -> list[tuple[Path, dict]]:
    root = Path(registry.__file__).resolve().parent / "benchmarks"
    tasks = []
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            if task.get("kind") == "diff":
                tasks.append((manifest, task))
    return tasks


def test_load_answer_key_fails_loud_without_schema_version(tmp_path):
    """Load answer key fails loud without schema version."""
    p = tmp_path / "k.yaml"
    p.write_text("target: t\nplanted:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        load_answer_key(p)


def test_load_answer_key_rejects_removed_fields(tmp_path):
    """Load answer key rejects removed fields."""
    with pytest.raises(ValueError, match="pre-version-1"):
        load_answer_key(_key(tmp_path, "target: t\nissues:\n  - id: a\n"))
    with pytest.raises(ValueError, match="pre-version-1"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nplanted:\n  - id: a\n    category: idor\n    files: [x.py]\n"))
    with pytest.raises(ValueError, match="pre-version-1"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nsafe:\n  - id: a\n    category: idor\n    files: [x.py]\n"))


def test_load_answer_key_rejects_scalar_list_fields(tmp_path):
    """Load answer key rejects scalar list fields."""
    with pytest.raises(ValueError, match="files is not a list"):
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
    """Load answer key fails loud without checks."""
    with pytest.raises(ValueError, match="no checks"):
        load_answer_key(_key(tmp_path, "benchmark_id: t\nchecks: []\n"))


def test_load_answer_key_rejects_invalid_expectation_and_severity(tmp_path):
    """Load answer key rejects invalid expectation and severity combinations."""
    with pytest.raises(ValueError, match="expectation must be findings or clean"):
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
    with pytest.raises(ValueError, match="severity is required"):
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
    """Load answer key rejects an unlocatable check."""
    with pytest.raises(ValueError, match="no matching anchor"):
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
    """Load answer key filters checks by task."""
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
    """Category match credits a broader label but not a sibling."""
    from evals.scorers.match import category_match, category_of

    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")
    assert not category_match("access-control", "missing-authorization")
    assert not category_match("", "code-injection")
    assert category_of("access control") == "access-control"
    assert category_of("missing access control") == "missing-authorization"


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


def test_one_report_on_several_clean_anchors_counts_as_one_false_positive(tmp_path):
    """One report on several clean anchors counts as one false positive."""
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


def test_findings_with_endpoint_is_credited_by_its_exact_file_and_symbol_anchor(tmp_path):
    """Planted with endpoint is credited by its exact file and symbol anchor."""
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


def test_clean_symbol_anchor_without_endpoint_requires_the_class_it_certifies(tmp_path):
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
    """Duplicate report of a findings bug is not a false positive."""
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


def test_file_keyed_findings_credits_a_report_at_any_accepted_anchor(tmp_path):
    """A file-keyed findings check credits a report at any accepted anchor."""
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


def test_endpoint_keyed_findings_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    """An endpoint-keyed findings check ignores file siblings."""
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


def test_parse_finding_md_treats_solidity_source_as_file_citation():
    """Parse finding md treats Solidity source as file citation."""
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
    """Solidity file keyed report scores from Markdown source."""
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
    assert key.benchmark_id == "open-webui"
    assert any(p.category == "insecure-direct-object-reference" for p in key.findings)


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
    assert all("schema_version: 1" in path.read_text(encoding="utf-8") for path in manifests)


def test_registry_exposes_repository_task_from_project_source(tmp_path, monkeypatch):
    """Registry exposes repository task from project source."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        "    url: https://example.com/demo.git\n"
        "    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "  path: src/tools\n"
        "stack:\n"
        "  languages: [typescript]\n"
        "  frameworks: []\n"
        "  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        "  - id: repository-aaaaaaa\n"
        "    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        "  - id: diff-bbbbbbb-1\n"
        "    kind: diff\n"
        "    revision:\n"
        "      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        "    applies_to: [repository-aaaaaaa]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n"
        "      files: [src/tools/run.ts]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n"
        "  - id: diff-command\n"
        "    applies_to: [diff-bbbbbbb-1]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n"
        "      files: [src/tools/run.ts]\n"
        "    knowledge:\n"
        "      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))

    bench = registry.find_benchmark("demo-project")
    key = load_answer_key(bench.answer_key, task_id=bench.task_id)

    assert bench.project_id == "demo-project"
    assert bench.task_id == "repository-aaaaaaa"
    assert bench.target == {
        "type": "git",
        "url": "https://example.com/demo.git",
        "ref": "a" * 40,
        "path": "src/tools",
    }
    assert bench.stack["languages"] == ["typescript"]
    assert bench.knowledge == {
        "guides": ["languages/typescript", "protocols/mcp"],
        "vulnerabilities": ["command-injection"],
    }
    assert [entry.id for entry in key.findings] == ["repo-command"]


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


def _write_contract_project(root: Path, *, outcome: str = "findings") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "benchmark.yaml"
    task_id = "diff-bbbbbbb-1"
    manifest.write_text(
        "schema_version: 1\nbenchmark_id: contract-project\nprofile: web\n"
        "source:\n  kind: git\n  identity:\n    url: https://example.com/demo.git\n"
        "    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  path: .\n"
        "stack:\n  languages: [python]\n  frameworks: []\n  protocols: []\n"
        "knowledge:\n  vulnerabilities: [command-injection]\n  guides: [languages/python]\n"
        "tasks:\n"
        "  - id: repository-aaaaaaa\n    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        f"  - id: {task_id}\n    kind: diff\n"
        "    revision:\n      base_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "      commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        f"    expectation: {outcome}\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (root / "answer-key.yaml").write_text(
        "schema_version: 1\nbenchmark_id: contract-project\nchecks:\n"
        "  - id: demo-entry\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [run.py]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n"
        "      guides: [languages/python]\n"
        f"    applies_to: [{task_id}]\n",
        encoding="utf-8",
    )
    return manifest


def test_registry_rejects_the_pre_version_manifest(tmp_path):
    """The registry accepts only the versioned manifest contract."""
    manifest = tmp_path / "benchmark.yaml"
    manifest.write_text("schema_version: 1\nid: old\nkind: project\ntarget: {}\n", encoding="utf-8")
    (tmp_path / "answer-key.yaml").write_text("schema_version: 1\nplanted: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        registry.load_project_manifest(manifest)


def test_registry_accepts_explicit_diff_review_requirements(tmp_path):
    """Every task declares its review requirements in the versioned contract."""
    loaded = registry.load_project_manifest(_write_contract_project(tmp_path))
    assert loaded["tasks"][1]["review"] == {"context": "repository", "mode": "standard"}


@pytest.mark.parametrize("review", ["[]", "standard", "null"])
def test_registry_rejects_non_mapping_diff_review_requirements(tmp_path, review):
    """An explicit review field must be a mapping."""
    manifest = _write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n    review:\n      context: repository\n      mode: standard\n",
        f"    expectation: findings\n    review: {review}\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        registry.load_project_manifest(manifest)


@pytest.mark.parametrize(("context", "mode"), [("snapshot", "standard"), ("diff", "consensus")])
def test_registry_rejects_unknown_diff_review_requirements(tmp_path, context, mode):
    """A diff task cannot name unsupported review values."""
    manifest = _write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n    review:\n      context: repository\n      mode: standard\n",
        f"    expectation: findings\n    review:\n      context: {context}\n      mode: {mode}\n",
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        registry.load_project_manifest(manifest)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"review_context": "snapshot"}, "invalid diff review context"),
        ({"review_mode": "consensus"}, "invalid diff review mode"),
    ],
)
def test_diff_case_rejects_unknown_review_requirements(kwargs, message):
    """Direct diff cases enforce the same review vocabulary as manifests."""
    from evals.diff_cases import DiffCase

    with pytest.raises(ValueError, match=message):
        DiffCase(name="invalid", diff="", **kwargs)


def test_registry_rejects_unknown_manifest_fields(tmp_path):
    """Closed versioned objects reject old target and diff scope fields."""
    manifest = _write_contract_project(tmp_path)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n", "    expectation: findings\n    diff_path: src/app.py\n"
    )
    manifest.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        registry.load_project_manifest(manifest)


def test_registry_unknown_benchmark_fails_loud(tmp_path, monkeypatch):
    """Registry unknown benchmark fails loud."""
    _public_only(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="no benchmark 'nope'"):
        registry.find_benchmark("nope")


def test_registry_duplicate_name_across_roots_fails_loud(tmp_path, monkeypatch):
    """Registry duplicate name across roots fails loud."""
    src = tmp_path / "private"
    project = src / "frameworks" / "fastapi" / "open-webui-shadow"
    _write_contract_project(project)
    for path in (project / "benchmark.yaml", project / "answer-key.yaml"):
        path.write_text(path.read_text(encoding="utf-8").replace("contract-project", "open-webui"), encoding="utf-8")
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
        _write_contract_project(project)
        for path in (project / "benchmark.yaml", project / "answer-key.yaml"):
            path.write_text(
                path.read_text(encoding="utf-8").replace("contract-project", "duplicate-project"),
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


def test_compare_by_attributes_project_diff_answer_key_checks(tmp_path, monkeypatch):
    """Compare project diff answer-key checks by attributes."""
    _public_only(tmp_path, monkeypatch)
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["get-issue-returns-untrusted-issue-body-to-model"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["prompt-injection"] == ["get-issue-returns-untrusted-issue-body-to-model"]


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


def _run(target, found, missed, fps, n_findings, n_reports=0, errors=0, file_found=(), file_missed=()):
    from evals.results import Result

    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        file_found=list(file_found),
        file_missed=list(file_missed),
        n_findings=n_findings,
        n_file_findings=len(file_found) + len(file_missed),
        n_reports=n_reports,
        errors=errors,
    )


def test_repeated_result_to_markdown_shows_runs_and_flaky():
    """Repeated result to markdown shows runs and flaky."""
    sr = RepeatedResult.from_runs(
        "diff",
        [
            _run("diff", ["a"], ["b"], [], 2),
            _run("diff", ["a", "b"], [], [], 2),
        ],
    )
    md = sr.to_markdown()
    assert "runs: 2" in md
    assert "flaky: b 1/2" in md


def test_run_diff_cases_handles_complete_results_and_degraded_work(monkeypatch):
    """Diff cases consume the complete result and retain degraded failure evidence."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        if "POSITIVE" in d:
            return _diff_result(["a-finding"])
        if "DEGRADED" in d:
            return _diff_result(
                degraded=True,
                failures=[
                    SimpleNamespace(
                        index=1,
                        total=1,
                        paths=("app.py",),
                        reason="adversarial judge returned unparsable JSON",
                    )
                ],
            )
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
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
    assert res.error_details == ["p-degraded: adversarial judge returned unparsable JSON"]


def test_run_diff_cases_describes_degraded_verification_without_batch_failures(monkeypatch):
    """A failed verification must not collapse into an unactionable degraded label."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    monkeypatch.setattr(
        diffmod,
        "run_diff_review",
        lambda *args, **kwargs: _diff_result(
            degraded=True,
            errors=1,
            incomplete=["candidate"],
        ),
    )

    result = diffmod.run_diff_cases(
        [DiffCase(name="verification-failed", category="sql-injection", diff="diff --git change")],
        provider=None,
        model="m",
    )

    assert result.error_details == ["verification-failed: 1 review or verification errors, 1 incomplete findings"]


def test_run_diff_cases_combines_batch_and_verification_failures(monkeypatch):
    """A batch failure must not hide a later verification failure."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    monkeypatch.setattr(
        diffmod,
        "run_diff_review",
        lambda *args, **kwargs: _diff_result(
            degraded=True,
            failures=[SimpleNamespace(reason="finder failed")],
            errors=1,
            incomplete=["candidate"],
            failure_reason="verification failed: upstream unavailable",
        ),
    )

    result = diffmod.run_diff_cases(
        [DiffCase(name="multiple-failures", category="sql-injection", diff="diff --git change")],
        provider=None,
        model="m",
    )

    assert result.error_details == [
        "multiple-failures: finder failed, verification failed: upstream unavailable, "
        "1 review or verification errors, 1 incomplete findings"
    ]


def test_run_diff_cases_reports_case_progress(monkeypatch):
    """Diff benchmarks report each case status while the run is active."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        if "BROKEN" in d:
            raise RuntimeError("backend stalled")
        kwargs["on_judgment"](1, 1, "general review", 0.1)
        return _diff_result()

    events = []
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    res = diffmod.run_diff_cases(
        [
            DiffCase(name="ok", category="", diff="diff --git CLEAN"),
            DiffCase(name="bad", category="", diff="diff --git BROKEN"),
        ],
        provider=None,
        model="m",
        progress=events.append,
    )

    assert res.errors == 1
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
        "case_started",
        "case_failed",
    ]
    assert events[0]["case"] == "ok"
    assert events[0]["index"] == 1
    assert events[0]["total"] == 2
    assert events[0]["profile"] == "web"
    assert events[1]["judgment_label"] == "general review"
    assert events[2]["reports"] == 0
    assert events[4]["error"] == "RuntimeError: backend stalled"


def test_run_diff_cases_uses_each_case_review_mode_without_an_override(monkeypatch):
    """A benchmark run honors the minimum mode declared by each case."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    modes = []

    def fake_audit(diff, *, mode, **kwargs):
        modes.append(mode)
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="standard", diff="standard", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial"),
    ]

    diffmod.run_diff_cases(cases, provider=None, model="m")

    assert modes == ["standard", "adversarial"]


def test_run_diff_cases_keeps_standard_role_wiring_stable_in_mixed_cases(tmp_path, monkeypatch):
    """A neighboring adversarial case cannot change a standard case's seats."""
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    base = object()
    finder = object()
    challenger = object()
    judge = object()
    verifier_providers = []
    audit_roles = []

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    class FakeVerifier:
        def __init__(self, *, provider, model, content):
            verifier_providers.append(provider)

    def fake_audit(diff, **kwargs):
        audit_roles.append(
            (
                kwargs["finder_provider"],
                kwargs["challenger_provider"],
                kwargs["judge_provider"],
            )
        )
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", FakeVerifier)
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: object())
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="standard", diff="standard", context="context", review_mode="standard"),
        DiffCase(name="adversarial", diff="adversarial", context="context", review_mode="adversarial"),
    ]

    diffmod.run_diff_cases(
        cases,
        provider=base,
        model="base",
        finder_provider=finder,
        finder_model="finder",
        challenger_provider=challenger,
        challenger_model="challenger",
        judge_provider=judge,
        judge_model="judge",
    )

    assert verifier_providers == [base, challenger]
    assert audit_roles == [(None, None, None), (finder, challenger, judge)]


def test_run_diff_cases_allows_an_explicit_mode_override(monkeypatch):
    """An experiment may force one mode across all selected cases."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    modes = []

    def fake_audit(diff, *, mode, **kwargs):
        modes.append(mode)
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(name="adversarial", diff="adversarial", review_mode="adversarial")

    diffmod.run_diff_cases([case], provider=None, model="m", mode="standard")

    assert modes == ["standard"]


def test_diff_progress_writer_emits_stderr_and_appends_sidecar_events(tmp_path, capsys):
    """Diff progress is visible before the final score JSON exists."""
    from evals.__main__ import _diff_progress_writer

    out = tmp_path / "result.json"
    sidecar = tmp_path / "result.cases.jsonl"
    sidecar.write_text("stale\n", encoding="utf-8")
    write = _diff_progress_writer(str(out))
    write(
        {
            "event": "case_started",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "run": 1,
            "runs": 1,
        }
    )
    write(
        {
            "event": "case_judgment_finished",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "elapsed_seconds": 0.75,
            "judgment": 1,
            "judgments": 2,
            "judgment_label": "sql-injection",
            "judgment_seconds": 0.7,
            "run": 1,
            "runs": 1,
        }
    )
    write(
        {
            "event": "case_finished",
            "case": "project:task",
            "index": 1,
            "total": 2,
            "mode": "standard",
            "model": "m",
            "profile": "web",
            "elapsed_seconds": 1.25,
            "reports": 1,
            "found": 1,
            "missed": 0,
            "false_positives": 0,
            "extra": 0,
            "run": 1,
            "runs": 1,
        }
    )

    output = capsys.readouterr().err
    assert "knowledge judgment 1/2 [sql-injection] finished" in output
    assert "project:task finished" in output
    events = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
    ]
    assert events[2]["case"] == "project:task"
    assert events[2]["found"] == 1


def test_diff_progress_formatter_fails_loud_on_unknown_events():
    """Unknown progress events are not reported as completed work."""
    from evals.__main__ import _format_diff_progress

    with pytest.raises(ValueError, match="unknown diff progress event"):
        _format_diff_progress(
            {
                "event": "unexpected",
                "case": "project:task",
                "index": 1,
                "total": 1,
            }
        )


def test_diff_benchmark_scores_findings_against_answer_key(monkeypatch):
    """Diff benchmark scores findings against answer key."""
    from cyberjury.finding import Finding
    from evals.diff_cases import DiffCase
    from evals.models import AnswerKey, KeyCheck
    from evals.runners import diff as diffmod

    key = AnswerKey(
        benchmark_id="real-patch",
        checks=(
            KeyCheck(
                id="paid-auto-publish",
                expectation="findings",
                files=("app.py",),
                symbols=("publish_paid",),
                knowledge=("vuln:business-logic",),
                applies_to=("real-patch",),
            ),
        ),
    )

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        finding = Finding(
            file="other.py",
            line=10,
            category="business-logic",
            description="publish_paid is safe here",
        )
        return _diff_result([finding])

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

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


def test_diff_benchmark_error_keeps_file_recall_denominator(monkeypatch):
    """A failed case still counts file-keyed findings checks in the denominator."""
    from evals.diff_cases import DiffCase
    from evals.models import AnswerKey, KeyCheck
    from evals.runners import diff as diffmod

    key = AnswerKey(
        benchmark_id="real-patch",
        checks=(
            KeyCheck(
                id="file-keyed",
                expectation="findings",
                files=("app.py",),
                knowledge=("vuln:business-logic",),
                applies_to=("real-patch",),
            ),
        ),
    )

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, **kwargs):
        raise TimeoutError("provider timed out")

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [
            DiffCase(
                name="real-patch",
                category="business-logic",
                diff="diff --git TIMEOUT",
                answer_key=key,
            )
        ],
        provider=None,
        model="m",
    )

    assert res.errors == 1
    assert res.n_findings == 1
    assert res.n_file_findings == 1
    assert res.file_recall == 0.0


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
        seen["verification_found_by"] = kwargs["verification_found_by"]
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    res = diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN")],
        provider=None,
        model="m",
    )

    assert res.false_positives == []
    assert seen == {
        "verifier": "verifier",
        "verification_root": str(tmp_path),
        "verification_confirmers": [],
        "verification_found_by": ("m",),
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
        seen["verification_found_by"] = kwargs.get("verification_found_by")
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

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
        "verification_found_by": (),
    }


def test_diff_benchmark_distinct_judge_model_confirms_refutations(monkeypatch, tmp_path):
    """The benchmark path should mirror CLI independent confirmer wiring."""
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
        seen["verification_confirmers"] = verification_confirmers
        seen["verification_found_by"] = kwargs["verification_found_by"]
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", lambda **kwargs: "checker")
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        provider="finder-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_provider="judge-provider",
        judge_model="judge",
    )

    assert seen["verification_confirmers"] == [("judge", "checker"), ("finder", "checker")]
    assert seen["verification_found_by"] == ()


def test_diff_benchmark_judge_model_inherits_base_provider_for_confirmation(monkeypatch, tmp_path):
    """Role model overrides inherit the base provider in benchmark wiring."""
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    seen = {}

    def fake_checker(**kwargs):
        seen.setdefault("checkers", []).append(kwargs)
        return "checker"

    def fake_audit(
        d, *, provider, model, verifier=None, verification_root=None, verification_confirmers=None, **kwargs
    ):
        seen["verification_confirmers"] = verification_confirmers
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "ModelVerifier", lambda **kwargs: "verifier")
    monkeypatch.setattr(diffmod, "ModelRefutationChecker", fake_checker)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)

    diffmod.run_diff_cases(
        [DiffCase(name="safe", category="", diff="diff --git CLEAN", review_mode="adversarial")],
        provider="base-provider",
        model="finder",
        challenger_provider="skeptic-provider",
        challenger_model="skeptic",
        judge_model="judge",
    )

    assert seen["verification_confirmers"] == [("judge", "checker"), ("finder", "checker")]
    assert seen["checkers"][0] == {"provider": "base-provider", "model": "judge"}


def test_default_diff_cases_load_project_diff_tasks(tmp_path, monkeypatch):
    """Default diff cases load project diff tasks."""
    _public_only(tmp_path, monkeypatch)
    from evals.runners.diff import default_cases

    cases = default_cases()
    names = {c.name for c in cases}
    assert any(name.startswith("github-mcp-server:diff-1c4cb29-") for name in names)
    assert len(names) == _public_diff_task_count()
    assert {c.outcome for c in cases} == {"clean", "findings"}
    assert all(c.answer_key is not None for c in cases)
    assert all(c.diff.startswith("diff --git") or c.target.get("url") for c in cases)


def test_default_diff_cases_use_real_git_commit_targets(tmp_path, monkeypatch):
    """Default diff cases use real git commit targets."""
    _public_only(tmp_path, monkeypatch)
    from evals.diff_cases import default_cases

    cases = default_cases()

    assert all(c.target.get("type") == "git" for c in cases)
    assert all(c.target.get("base") and c.target.get("ref") for c in cases)
    assert all(len(str(c.target.get("base") or "")) == 40 and len(str(c.target.get("ref") or "")) == 40 for c in cases)


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
    diff_task_id = f"diff-{ref[:7]}-1"
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "demo"
    project.mkdir(parents=True)
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-diff-project\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        f"    repository_path: {repo}\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [typescript]\n  frameworks: []\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: repository-{ref[:7]}\n"
        "    kind: repository\n"
        "    review:\n      context: repository\n      mode: standard\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: demo-diff-project\n"
        "checks:\n"
        "  - id: repo-command\n"
        f"    applies_to: [repository-{ref[:7]}]\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n"
        "  - id: diff-command\n"
        f"    applies_to: [{diff_task_id}]\n    expectation: findings\n    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n      guides: [languages/typescript]\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.diff_cases import default_cases, diff_text

    case = next(c for c in default_cases() if c.name == f"demo-diff-project:{diff_task_id}")

    assert case.category == "command-injection"
    assert "exec(input)" in diff_text(case)
    assert set(case.knowledge) == {
        "guide:languages/typescript",
        "guide:protocols/mcp",
        "vuln:command-injection",
    }
    assert "knowledge" not in case.target
    assert case.provenance == "private"
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.findings] == ["diff-command"]


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
    diff_task_id = f"diff-{ref[:7]}-1"
    (project / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: private-context-safe\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        "    repository_path: ~/repo\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [python]\n  frameworks: []\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [insecure-direct-object-reference]\n"
        "  guides: [frameworks/python/fastapi, languages/python, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: clean\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (project / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: private-context-safe\n"
        "checks:\n"
        "  - id: per-user-client\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: clean\n"
        "    locations:\n      files: [server.py]\n"
        "    knowledge:\n"
        "      vulnerabilities: [insecure-direct-object-reference]\n"
        "      guides: [frameworks/python/fastapi, languages/python, protocols/mcp]\n"
        "",
        encoding="utf-8",
    )
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.diff_cases import default_cases, diff_text

    case = next(c for c in default_cases() if c.name == f"private-context-safe:{diff_task_id}")
    assert "tool()" in diff_text(case)
    assert case.context == ""
    assert case.target["root"] == "~/repo"
    assert case.target["path"] == "."
    assert case.provenance == "private"
    assert case.expectation == "clean"
    assert not case.is_positive
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.clean] == ["per-user-client"]
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
    diff_task_id = f"diff-{ref[:7]}-1"
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "benchmark.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: public-real-diff\n"
        "profile: web\n"
        "source:\n"
        "  kind: git\n"
        "  identity:\n"
        f"    repository_path: {repo}\n"
        f"    commit: {ref}\n"
        "  path: .\n"
        "stack:\n  languages: [typescript]\n  frameworks: []\n  protocols: [mcp]\n"
        "knowledge:\n"
        "  vulnerabilities: [command-injection]\n"
        "  guides: [languages/typescript, protocols/mcp]\n"
        "tasks:\n"
        f"  - id: {diff_task_id}\n"
        "    kind: diff\n"
        "    revision:\n"
        f"      base_commit: {base}\n"
        f"      commit: {ref}\n"
        "    expectation: findings\n"
        "    review:\n      context: repository\n      mode: standard\n",
        encoding="utf-8",
    )
    (case_dir / "answer-key.yaml").write_text(
        "schema_version: 1\n"
        "benchmark_id: public-real-diff\n"
        "checks:\n"
        "  - id: exec-command\n"
        f"    applies_to: [{diff_task_id}]\n"
        "    expectation: findings\n"
        "    severity: HIGH\n"
        "    locations:\n      files: [tool.ts]\n      symbols: [exec]\n"
        "    knowledge:\n      vulnerabilities: [command-injection]\n"
        "      guides: [languages/typescript, protocols/mcp]\n"
        "",
        encoding="utf-8",
    )
    from evals.diff_cases import diff_text, load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert case.diff == ""
    assert "exec(input)" in diff_text(case)
    assert case.name == f"public-real-diff:{diff_task_id}"
    assert case.target["root"] == str(repo)
    assert case.provenance == "public"


def test_git_url_diff_fetches_exact_commit_targets(tmp_path, monkeypatch):
    """Git URL diff fetches concrete SHAs before diffing."""
    from evals import diff_cases
    from evals.diff_cases import DiffCase, diff_text

    root = tmp_path / "repo"
    root.mkdir()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[3] == "cat-file":
            return subprocess.CompletedProcess(cmd, 1)
        if cmd[3] == "diff":
            return subprocess.CompletedProcess(cmd, 0, stdout="diff --git a/app.py b/app.py\n+sink()\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(diff_cases, "git_target_root", lambda target: root)
    monkeypatch.setattr(diff_cases.subprocess, "run", fake_run)

    diff = diff_text(
        DiffCase(
            name="needs-fetch",
            diff="",
            target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
        )
    )

    assert "sink()" in diff
    assert ["git", "-C", str(root), "fetch", "origin", "abc123"] in calls
    assert ["git", "-C", str(root), "fetch", "origin", "def456"] in calls


def test_project_diff_task_uses_manifest_profile(tmp_path):
    """Project profile supplies the profile for every task."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir)
    for path in (manifest, case_dir / "answer-key.yaml"):
        path.write_text(
            path.read_text(encoding="utf-8").replace("contract-project", "solidity-real-diff"),
            encoding="utf-8",
        )
    manifest.write_text(manifest.read_text(encoding="utf-8").replace("profile: web", "profile: evm"), encoding="utf-8")
    from evals.diff_cases import load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert case.profile == "evm"


def test_project_diff_task_profile_overrides_manifest_profile(tmp_path):
    """Task metadata cannot override the manifest profile."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir)
    text = manifest.read_text(encoding="utf-8").replace(
        "    expectation: findings\n", "    expectation: findings\n    profile: evm\n"
    )
    manifest.write_text(text, encoding="utf-8")
    from evals.diff_cases import load_project_diff_cases

    with pytest.raises(ValueError, match=r"benchmark-schema-1\.0\.0"):
        load_project_diff_cases(manifest)


def test_clean_diff_task_scores_the_fixed_issue_as_clean(tmp_path):
    """Clean diff tasks treat the repaired issue anchor as clean."""
    case_dir = tmp_path / "case"
    manifest = _write_contract_project(case_dir, outcome="clean")
    key = case_dir / "answer-key.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("contract-project", "fixed-real-diff"),
        encoding="utf-8",
    )
    key_data = yaml.safe_load(key.read_text(encoding="utf-8"))
    entry = key_data["checks"][0]
    key_data["benchmark_id"] = "fixed-real-diff"
    entry["id"] = "shell-command"
    entry["expectation"] = "clean"
    entry.pop("severity", None)
    key.write_text(yaml.safe_dump(key_data, sort_keys=False), encoding="utf-8")
    from evals.diff_cases import load_project_diff_cases

    case = load_project_diff_cases(case_dir / "benchmark.yaml")[0]

    assert not case.is_positive
    assert case.outcome == "clean"
    assert case.answer_key is not None
    assert [entry.id for entry in case.answer_key.findings] == []
    assert [entry.id for entry in case.answer_key.clean] == ["shell-command"]


def test_solidity_diff_benchmarks_declare_evm_profile():
    """Explicit benchmark routing keeps runs independent of checkout file heuristics."""
    root = Path("evals/benchmarks/languages/solidity")
    for manifest in sorted(root.glob("*/benchmark.yaml")):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        diff_tasks = [task for task in data.get("tasks") or [] if task.get("kind") == "diff"]
        if diff_tasks:
            assert data.get("profile") == "evm", f"{manifest} should declare profile: evm"


def test_shipped_diff_tasks_declare_expectation():
    """Shipped diff tasks declare their scoring expectation."""
    tasks = _public_diff_tasks()

    assert tasks
    assert {task.get("expectation") for task in tasks} <= {"clean", "findings"}
    assert all(task.get("expectation") for task in tasks)


def test_shipped_task_ids_follow_the_benchmark_naming_contract():
    """Shipped task ids contain the commit prefix and task sequence."""
    root = Path(registry.__file__).resolve().parent / "benchmarks"
    for manifest in root.rglob("benchmark.yaml"):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks") or []:
            task_id = str(task.get("id") or "")
            if task.get("kind") == "repository":
                source = data["source"]
                if source["kind"] == "git":
                    token = str((task.get("revision") or {}).get("commit") or source["identity"]["commit"])
                else:
                    token = str(source["identity"]["address"]).lower().removeprefix("0x")
                assert task_id == f"repository-{token[:7].lower()}", f"{manifest}: {task_id}"
                continue
            match = re.fullmatch(r"diff-([0-9a-f]{7})-([0-9]+)", task_id)
            assert match, f"{manifest}: {task_id}"
            assert match.group(1) == str(task["revision"]["commit"])[:7].lower(), f"{manifest}: {task_id}"


def test_shipped_diff_tasks_review_the_whole_commit():
    """File scope hints would disclose the expected answer to the reviewer."""
    scoped = [
        f"{manifest}: {task.get('id')}"
        for manifest, task in _public_diff_task_rows()
        if "diff_path" in task or "diff_paths" in task
    ]

    assert scoped == []


def test_shipped_answer_key_applies_to_references_existing_tasks():
    """Shipped answer key task references point at existing manifest tasks."""
    root = Path(registry.__file__).resolve().parent / "benchmarks"
    for manifest in sorted(root.rglob("benchmark.yaml")):
        key_file = manifest.parent / "answer-key.yaml"
        if not key_file.is_file():
            continue
        benchmark = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        known = {str(task.get("id")) for task in benchmark.get("tasks") or [] if task.get("id")}
        key = yaml.safe_load(key_file.read_text(encoding="utf-8")) or {}
        for entry in key.get("entries") or []:
            for task_id in entry.get("task_ids") or []:
                assert task_id in known, f"{key_file} references unknown task {task_id!r}"


def test_diff_source_root_fetches_exact_commit_targets(monkeypatch, tmp_path):
    """Diff source checkout fetches concrete SHAs before adding the worktree."""
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    root = tmp_path / "repo"
    root.mkdir()
    calls = []

    @contextmanager
    def fake_target_tree(root, ref):
        yield tmp_path / "checkout"

    def fake_ensure(target, root=None):
        calls.append((target, root))

    monkeypatch.setattr(diffmod, "git_target_root", lambda target: root)
    monkeypatch.setattr(diffmod, "ensure_git_target_refs", fake_ensure)
    monkeypatch.setattr(diffmod, "_target_tree", fake_target_tree)

    case = DiffCase(
        name="needs-fetch",
        diff="diff --git a/app.py b/app.py\n+sink()\n",
        target={"type": "git", "url": "https://example.com/repo.git", "base": "abc123", "ref": "def456"},
    )
    with diffmod._source_root(case) as checkout:
        assert checkout == tmp_path / "checkout"

    assert calls == [(case.target, root)]


def test_diff_review_root_uses_the_git_url_target_path(tmp_path):
    """Diff review root uses the git URL target path."""
    from evals.runners import diff as diffmod

    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)

    target = {"type": "git", "url": "https://example.com/repo.git", "path": "contracts"}
    assert diffmod._review_root(root, target) == scope


def test_diff_review_root_rejects_escaping_target_paths(tmp_path):
    """Diff review root rejects escaping target paths."""
    from evals.runners import diff as diffmod

    root = tmp_path / "repo"
    root.mkdir()

    with pytest.raises(ValueError, match="inside the repository"):
        diffmod._review_root(root, {"type": "git", "url": "https://example.com/repo.git", "path": "../outside"})


def test_git_url_diff_uses_the_target_path_as_a_pathspec(tmp_path):
    """Git URL diff uses the target path as a pathspec."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "scope").mkdir()
    (repo / "outside").mkdir()
    (repo / "scope" / "app.py").write_text("value = 'base'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'base'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "scope" / "app.py").write_text("value = 'ref'\n", encoding="utf-8")
    (repo / "outside" / "noise.py").write_text("value = 'ref'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "ref")
    ref = _git(repo, "rev-parse", "HEAD")
    from evals.diff_cases import DiffCase, diff_text

    diff = diff_text(
        DiffCase(
            name="scoped",
            diff="",
            target={"type": "git", "url": repo.as_uri(), "path": "scope", "base": base, "ref": ref},
        )
    )

    assert "scope/app.py" in diff
    assert "outside/noise.py" not in diff


def test_coverage_matrix_attributes_repository_checks_to_knowledge(tmp_path, monkeypatch):
    """Coverage matrix attributes repository checks to knowledge."""
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix

    cov = coverage_matrix()
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repository_findings >= 3
    assert idor.repository_clean >= 2
    py = cov["guide:languages/python"]
    assert py.repository_findings >= 3
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
    by_name = {c.name: c for c in cases}
    case = next(case for name, case in by_name.items() if name.startswith("github-mcp-server:diff-1c4cb29-"))
    assert len(by_name) == _public_diff_task_count()
    assert case.answer_key is not None
    assert len(case.answer_key.findings) == 1


def test_repeated_result_folds_runs_by_strict_majority():
    """Repeated result folds runs by strict majority."""
    from evals.results import RepeatedResult

    runs = [
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2, file_found=["a"], file_missed=["b", "c"]),
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2, file_found=["a", "b"], file_missed=["c"]),
        _run("diff", ["a", "c"], ["b"], ["safe-x"], 3, n_reports=3, errors=1, file_found=["a"], file_missed=["b", "c"]),
    ]
    sr = RepeatedResult.from_runs("diff", runs)
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


def test_repeated_result_to_dict_is_compare_compatible():
    """Repeated result to dict is compare compatible."""
    from evals.compare import compare
    from evals.results import RepeatedResult

    before = RepeatedResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = RepeatedResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_coverage_problems_flag_unresolved_reference(tmp_path, monkeypatch):
    """Coverage problems flag unresolved reference."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "ghost"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "ghost"
    data["knowledge"]["vulnerabilities"] = ["no-such-class"]
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "ghost"
    for entry in answer["checks"]:
        entry["knowledge"]["vulnerabilities"] = ["no-such-class"]
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
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
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "ghost-diff"
    data["knowledge"]["vulnerabilities"] = ["no-such-class"]
    data["tasks"] = [task for task in data["tasks"] if task["kind"] == "diff"]
    data["tasks"][0]["expectation"] = "findings"
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "ghost-diff"
    answer["checks"] = [entry for entry in answer["checks"] if entry["applies_to"] == [data["tasks"][0]["id"]]]
    for entry in answer["checks"]:
        entry["knowledge"]["vulnerabilities"] = ["no-such-class"]
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    problems = coverage_problems()
    assert any(p.kind == "unresolved-reference" and p.ref == "vuln:no-such-class" for p in problems)


def test_scan_knowledge_spans_profiles(tmp_path, monkeypatch):
    """Coverage must include content from every registered profile root."""
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import scan_knowledge

    items = scan_knowledge()
    assert items["vuln:sql-injection"].kind == "vulnerability"
    assert items["vuln:reentrancy"].kind == "vulnerability"
    assert "guide:languages/solidity" in items


def test_run_diff_cases_routes_each_case_to_its_profile(monkeypatch):
    """A mixed batch must not reuse the first case's knowledge catalog."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    seen: dict[str, str] = {}
    contexts: dict[str, str] = {}

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        seen[d] = profile.name
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    cases = [
        DiffCase(name="w", category="", diff="web-diff", context="web-context"),
        DiffCase(name="s", category="", diff="sol-diff", profile="evm"),
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert seen == {"web-diff": "web", "sol-diff": "evm"}
    assert contexts["web-diff"] == "web-context"


def test_run_diff_cases_collects_target_context(monkeypatch):
    """Run diff cases collects target context."""
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    contexts: dict[str, str] = {}

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = f"context from {path} for {profile.name}"

                return Result()

            def text_for_diff(self, diff):
                return f"context from {path} for {profile.name}"

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
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


def test_run_diff_cases_keeps_diff_context_isolated_from_the_repository(tmp_path, monkeypatch):
    """A diff context case cannot consume repository evidence through another path."""
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    @contextmanager
    def fake_source_root(case):
        yield tmp_path

    def unexpected(*args, **kwargs):
        raise AssertionError("diff context touched repository grounding")

    seen = {}

    def fake_audit(diff, **kwargs):
        seen.update(kwargs)
        return _diff_result()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "prepare_git_scope", unexpected)
    monkeypatch.setattr(diffmod, "build_diff_context_collector", unexpected)
    monkeypatch.setattr(diffmod, "ModelVerifier", unexpected)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(
        name="diff-only",
        diff="diff --git a/Token.sol b/Token.sol\n+++ b/Token.sol\n+contract Token {}\n",
        context="repository evidence",
        profile="evm",
        review_context="diff",
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert seen["context"] == ""
    assert seen["context_for_diff"] is None
    assert seen["verifier"] is None
    assert seen["verification_root"] is None


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

    def fake_collector(path, profile, **kwargs):
        class Collector:
            def collect(self, diff):
                class Result:
                    text = Path(path, "server.py").read_text(encoding="utf-8").strip()

                return Result()

            def text_for_diff(self, diff):
                return Path(path, "server.py").read_text(encoding="utf-8").strip()

        return Collector()

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, profile=None, context="", **kwargs):
        contexts[d] = context
        return _diff_result()

    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", fake_audit)
    case = DiffCase(
        name="targeted-url",
        category="",
        diff="diff --git a/server.py b/server.py\n+++ b/server.py\n+value = 'ref'\n",
        target={"type": "git", "url": repo.as_uri(), "ref": ref},
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert contexts[case.diff] == "value = 'ref'"


def test_run_diff_cases_prepares_evm_scope_and_collects_scoped_facts(tmp_path, monkeypatch):
    """Run diff cases prepares EVM scope and collects scoped facts."""
    from contextlib import contextmanager

    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)
    seen: dict[str, Path] = {}

    @contextmanager
    def fake_source_root(case):
        yield root

    def fake_prepare(name, target, repository, review_scope, *, verify=True):
        seen["repository"] = repository
        seen["scope"] = review_scope
        return SimpleNamespace(ok=True, detail="prepared")

    def fake_collector(path, profile, *, facts_root=None, review_diff=""):
        seen["facts_root"] = facts_root

        class Collector:
            def collect(self, diff):
                return SimpleNamespace(text="scoped context")

            def text_for_diff(self, diff):
                return "batch context"

        return Collector()

    monkeypatch.setattr(diffmod, "_source_root", fake_source_root)
    monkeypatch.setattr(diffmod, "prepare_git_scope", fake_prepare)
    monkeypatch.setattr(diffmod, "build_diff_context_collector", fake_collector)
    monkeypatch.setattr(diffmod, "run_diff_review", lambda *args, **kwargs: _diff_result())
    case = DiffCase(
        name="evm-targeted",
        diff="diff --git a/contracts/Token.sol b/contracts/Token.sol\n+++ b/contracts/Token.sol\n+contract Token {}\n",
        target={"type": "git", "url": "https://example.com/repo.git", "path": "contracts"},
        profile="evm",
    )

    diffmod.run_diff_cases([case], provider=None, model="m")

    assert seen == {"repository": root, "scope": scope, "facts_root": scope}


def test_coverage_problems_flag_check_without_knowledge(tmp_path, monkeypatch):
    """Coverage problems flag a check without knowledge."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "bare"
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "bare"
    for entry in answer["checks"]:
        entry["knowledge"] = {"vulnerabilities": [], "guides": []}
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"answer-key-schema-1\.0\.0"):
        coverage_problems()


def test_coverage_problems_flag_diff_only_check_without_knowledge(tmp_path, monkeypatch):
    """Coverage problems flag a diff-only check without knowledge."""
    src = tmp_path / "private"
    project = src / "protocols" / "mcp" / "bare-diff"
    manifest = _write_contract_project(project)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["benchmark_id"] = "bare-diff"
    data["tasks"] = [task for task in data["tasks"] if task["kind"] == "diff"]
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    key = project / "answer-key.yaml"
    answer = yaml.safe_load(key.read_text(encoding="utf-8"))
    answer["benchmark_id"] = "bare-diff"
    answer["checks"] = [answer["checks"][0]]
    answer["checks"][0]["applies_to"] = [data["tasks"][0]["id"]]
    answer["checks"][0]["knowledge"] = {"vulnerabilities": [], "guides": []}
    key.write_text(yaml.safe_dump(answer, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems

    with pytest.raises(ValueError, match=r"answer-key-schema-1\.0\.0"):
        coverage_problems()


def test_one_report_cannot_satisfy_two_findings_checks(tmp_path):
    """One report cannot satisfy two findings checks."""
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
    diff_only = Coverage(item=it, diff_positive=1, diff_clean=1)
    assert diff_only.diff_covered
    assert not diff_only.repository_covered
    assert diff_only.covered
    repository_only = Coverage(item=it, repository_findings=1)
    assert repository_only.repository_covered
    assert not repository_only.diff_covered
    assert repository_only.covered
    assert not Coverage(item=it).covered


def test_coverage_problems_flags_a_class_with_no_repository_target(tmp_path, monkeypatch):
    """Coverage problems flags a class with no repository target."""
    from evals import coverage
    from evals.coverage import Coverage, KnowledgeItem

    def item(ref):
        return KnowledgeItem(ref=ref, kind="vulnerability", path=Path(f"{ref}.md"))

    cov = {
        "vuln:diffonly": Coverage(item=item("vuln:diffonly"), diff_positive=1, diff_clean=1),
        "vuln:hasrepository": Coverage(
            item=item("vuln:hasrepository"), diff_positive=1, diff_clean=1, repository_findings=1
        ),
    }
    _public_only(tmp_path, monkeypatch)
    monkeypatch.setattr(coverage, "_default_cases", lambda: [])
    kinds = {(p.ref, p.kind) for p in coverage.coverage_problems(cov)}
    assert ("vuln:diffonly", "missing-repository-target") in kinds
    assert ("vuln:hasrepository", "missing-repository-target") not in kinds


def _arm(
    ws,
    *,
    errors=0,
    verify_errors=0,
    incomplete=0,
    unlocatable=0,
    complete=True,
    requests=100,
    seconds=60.0,
):
    leaf = ws / "leaf"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": errors,
                "verify_errors": verify_errors,
                "incomplete": incomplete,
                "unlocatable": unlocatable,
                "complete": complete,
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


def test_an_incomplete_run_status_disqualifies_an_arm(tmp_path):
    """Incomplete run status disqualifies an arm."""
    from evals.compare import with_arms

    d = with_arms({}, _arm(tmp_path / "a", complete=False), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 run_incomplete" in r for r in d["not_comparable_because"])


def test_incomplete_run_status_counts_each_run_record(tmp_path):
    """Incomplete run status counts each run record."""
    from evals.compare import _arm_artifacts

    ws = _arm(tmp_path / "a", complete=False)
    _arm(ws / "nested", complete=False)
    got = _arm_artifacts(ws)
    assert got["completeness"]["run_incomplete"] == 2


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
