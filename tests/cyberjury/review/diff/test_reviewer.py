"""Diff reviewers parse responses and reuse grounded evidence."""

import json

import pytest

from cyberjury.profiles.registry import default_profile
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext
from cyberjury.review.diff.engine import (
    DiffGroundingOptions,
    DiffReviewOptions,
    run_diff_review,
)
from cyberjury.review.diff.reviewer import AuditError, AuditRunner
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.navigation import SourceNavigator
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        finding.setdefault("exploit_scenario", "attacker input reaches the vulnerable operation")
        finding.setdefault("recommendation", "enforce the missing security control")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps(
        {
            "findings": findings,
            "evidence_requests": [],
            "source_queries": [],
        }
    )


def _confirmed_reply(findings):
    return _reply(findings)


def _runner(provider):
    content = default_profile().paths
    return AuditRunner(
        provider=provider,
        model="m",
        content=content,
        review_brief=load_review_brief(kernel_file=content.security_kernel_file),
    )


def _run(runner, diff, *, context=""):
    cycle = runner.review_unit(diff, context=GroundingContext(text=context, source="diff"), finder_label="finder")
    if not cycle.clean:
        raise AuditError(cycle.failure_reason)
    return cycle.findings


def test_engine_parses_findings():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "CRITICAL",
                "category": "sql_injection",
                "description": "string-concatenated query",
                "confidence": 0.95,
            },
        ]
    )
    provider = MockProvider(responses=[reply, _confirmed_reply(json.loads(reply)["findings"])])
    out = _run(_runner(provider), _DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql-injection"
    assert provider.calls[0]["messages"][0].content.endswith("A further request makes this judgment incomplete.")


def test_diff_candidate_rejects_a_model_supplied_mismatched_identity():
    finding = {
        "candidate_id": "candidate-wrong",
        "file": "app.py",
        "line": 3,
        "severity": "HIGH",
        "category": "sql-injection",
        "entrypoint": "POST /query",
        "description": "string-concatenated query",
        "exploit_scenario": "public request reaches the query sink",
        "recommendation": "parameterize the query",
        "confidence": 0.9,
        "change_anchor": {"file": "app.py", "line": 3, "side": "new"},
        "evidence_refs": ["seed"],
    }

    with pytest.raises(AuditError, match="unknown fields: candidate_id"):
        _run(_runner(MockProvider(default=_reply([finding]))), _DIFF)


def test_diff_candidate_accepts_a_model_supplied_category():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sqli",
        "description": "string-concatenated query",
        "confidence": 0.9,
    }

    assert _run(_runner(MockProvider(default=_reply([finding]))), _DIFF)[0].category == "sqli"


def test_diff_review_reports_a_malformed_finding_as_failed_work():
    provider = MockProvider(default=_reply([{"severity": "HIGH"}]))

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
        ),
    )

    assert result.outcome.findings == ()
    assert result.outcome.degraded is True
    assert "$response.findings[0] is missing fields" in result.outcome.failures[0].reason


def test_diff_review_reports_a_malformed_change_anchor_as_failed_work():
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "other",
                    "description": "unsafe operation",
                    "confidence": 0.9,
                    "change_anchor": {"file": "app.py", "line": 1, "side": "context"},
                }
            ]
        )
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
        ),
    )

    assert result.outcome.findings == ()
    assert result.outcome.degraded is True
    assert "change_anchor.side has a value outside the allowed set" in result.outcome.failures[0].reason


def test_diff_review_corrects_one_anchor_that_is_not_an_exact_changed_line():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "description": "unsafe operation",
        "confidence": 0.9,
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**finding, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[_reply([finding]), _reply([corrected])])

    findings = _run(_runner(provider), _DIFF)

    assert len(findings) == 1
    assert findings[0].change_anchor is not None
    assert findings[0].change_anchor.line == 1
    assert "Exact changed ranges for `app.py` are: new lines 1" in provider.calls[1]["messages"][0].content


def test_diff_review_preserves_a_valid_sibling_during_anchor_correction():
    valid = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "entrypoint": "GET /first",
        "description": "first unsafe operation",
        "confidence": 0.9,
        "change_anchor": {"file": "app.py", "line": 1, "side": "new"},
    }
    invalid = {
        **valid,
        "entrypoint": "GET /second",
        "description": "second unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**invalid, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[_reply([valid, invalid]), _reply([corrected])])

    findings = _run(_runner(provider), _DIFF)

    assert [finding.description for finding in findings] == ["first unsafe operation", "second unsafe operation"]


def test_diff_review_keeps_an_invalid_anchor_candidate_when_correction_fails():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "description": "unsafe operation",
        "confidence": 0.9,
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[_reply([finding]), "not json"])

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
        ),
    )

    assert result.outcome.findings == ()
    assert [item.description for item in result.outcome.incomplete] == ["unsafe operation"]
    assert result.outcome.complete is False


def test_diff_review_allows_anchor_correction_to_remove_an_unreportable_candidate():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "description": "unsafe operation",
        "confidence": 0.9,
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[_reply([finding]), _reply([])])

    assert _run(_runner(provider), _DIFF) == []


def test_engine_empty_on_no_findings():
    assert _run(_runner(MockProvider(default=_reply([]))), _DIFF) == []


def test_engine_raises_on_unparseable_reply():

    from cyberjury.review.diff.reviewer import AuditError

    with pytest.raises(AuditError, match="failed audit"):
        _run(_runner(MockProvider(default="not json")), _DIFF)
    with pytest.raises(AuditError, match="failed audit"):
        _run(_runner(MockProvider(default="")), _DIFF)


def test_engine_raises_on_wrong_shape_json():

    from cyberjury.review.diff.reviewer import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError, match="failed audit"):
            _run(_runner(MockProvider(default=bad)), _DIFF)


@pytest.mark.parametrize("reply", ['{"findings": [', '```json\n{"findings": [\n```'])
def test_engine_rejects_a_truncated_findings_array(reply):
    with pytest.raises(AuditError, match="failed audit"):
        _run(_runner(MockProvider(default=reply)), _DIFF)


def test_engine_rejects_invalid_finding_semantics():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "spicy",
                "category": "other",
                "description": "unsafe operation",
                "confidence": 0.9,
            }
        ]
    )
    with pytest.raises(AuditError, match="severity has a value outside the allowed set"):
        _run(_runner(MockProvider(default=reply)), _DIFF)


def test_diff_audit_sends_the_contract_as_a_cacheable_system_prompt():
    provider = MockProvider(default=_reply([]))
    _run(_runner(provider), _DIFF)
    call = provider.calls[0]
    prompt = call["messages"][0].content
    assert call["cache"] is True
    assert prompt.startswith(call["cache_prefix"])
    assert "SELECT * FROM u" in call["cache_prefix"]
    assert "# Security Reasoning Kernel" in call["system"]
    assert "# Severity Rubric" in call["system"]
    assert "# Security Reasoning Kernel" not in prompt


def test_diff_keeps_repository_context_in_the_user_evidence():
    provider = MockProvider(default=_reply([]))
    diff = "+++ b/app.py\n@@ -0,0 +1 @@\n+token = make_token()\n"
    _run(_runner(provider), diff, context="def make_token():\n    return uuid.uuid1().hex\n")

    assert "uuid.uuid1" in provider.calls[0]["cache_prefix"]


def test_diff_system_is_identical_across_units():
    provider = MockProvider(default=_reply([]))
    runner = _runner(provider)
    _run(runner, _DIFF, context="first unit")
    _run(runner, "+++ b/other.py\n@@ -0,0 +1 @@\n+other()\n", context="second unit")

    assert provider.calls[0]["system"] == provider.calls[1]["system"]
    assert "first unit" not in provider.calls[0]["system"]


def test_diff_uses_one_profile_brief_judgment():
    provider = MockProvider(default=_reply([]))
    runner = _runner(provider)

    cycle = runner.review_unit(
        "+++ b/app.py\n+alpha beta\n", context=GroundingContext(text="", source="diff"), finder_label="finder"
    )

    assert cycle.clean is True
    assert len(provider.calls) == 1
    assert provider.calls[0]["cache"] is True
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


def test_diff_does_not_create_sibling_judgments_for_knowledge():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "description": "long first pack description that must not be repeated",
        "exploit_scenario": "a long exploit path that the next pack does not need",
        "recommendation": "a long remediation that the next pack does not need",
        "confidence": 0.9,
    }
    provider = MockProvider(responses=[_reply([finding]), _confirmed_reply([finding])])
    runner = _runner(provider)

    cycle = runner.review_unit(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+query = input\n",
        context=GroundingContext(text="", source="diff"),
        finder_label="finder",
    )

    assert cycle.clean is True
    assert len(cycle.findings) == 1
    assert len(provider.calls) == 1


def test_diff_repository_evidence_does_not_change_the_profile_brief():
    provider = MockProvider(default=_reply([]))
    runner = _runner(provider)
    evidence = EvidenceItem.create(
        identity="app.py:handler:10:40",
        label="app.py:handler",
        text="def handler():\n    return sensitive_operation()\n",
        preview="def handler():",
    )

    cycle = runner.review_unit(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+def handler(): ...\n",
        context=GroundingContext(text="initial context", source="repository", evidence=(evidence,)),
        finder_label="finder",
    )

    assert cycle.clean is True
    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


def test_diff_navigation_keeps_profile_coverage_and_runs_a_final_evidence_sweep(tmp_path):
    source = "class ModelWithOwner:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"models.py": {"ModelWithOwner": [{"range": [0, len(source)], "calls": []}]}},
        },
    )
    raw_provider = MockProvider(
        responses=[
            json.dumps(
                {
                    **json.loads(_reply([])),
                    "source_queries": [{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
                }
            ),
            _reply([]),
        ]
    )
    meter = UsageMeter()
    provider = MeteringProvider(raw_provider, meter)
    runner = _runner(provider)

    cycle = runner.review_unit(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n",
        context=GroundingContext(text="seed", source="repository", navigator=navigator),
        finder_label="finder",
    )

    assert cycle.clean is True
    assert len(raw_provider.calls) == 2
    first, final = raw_provider.calls
    assert first["system"] == final["system"]
    assert "# Source Navigation" in first["system"]
    assert first["cache"] is True
    assert final["cache"] is True
    assert first["cache_prefix"] == final["cache_prefix"]
    assert first["messages"][0].content.startswith(first["cache_prefix"])
    final_prompt = final["messages"][0].content
    assert final_prompt.startswith(first["cache_prefix"])
    assert first["messages"][0].content.endswith("Evidence request budget: 8 request batches remain.")
    assert "owner_scope = True" in final_prompt[len(first["cache_prefix"]) :]
    calls = meter.call_snapshot()
    assert calls[0]["navigation_status"] == "delivered"
    assert len(calls[0]["navigation_delta_ids"]) == 1
    assert calls[0]["navigation_delta_chars"] > 0
    assert calls[0]["source_query_count"] == 1
    assert calls[0]["trigger"] == "initial_judgment"
    assert calls[1]["navigation_status"] == "not_requested"
    assert calls[1]["trigger"] == "evidence_followup"


def test_diff_repeated_navigation_query_is_observed_as_failed_work(tmp_path):
    source = "class Record:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {"models.py": {"Record": [{"range": [0, len(source)], "calls": []}]}}},
    )
    response = json.dumps(
        {
            **json.loads(_reply([])),
            "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
        }
    )
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(responses=[response, response, response]), meter)
    runner = _runner(provider)

    cycle = runner.review_unit(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n",
        context=GroundingContext(text="seed", source="repository", navigator=navigator),
        finder_label="finder",
    )

    assert cycle.clean is False
    assert "repeats an earlier query" in cycle.failure_reason
    calls = meter.call_snapshot()
    assert calls[0]["navigation_status"] == "delivered"
    assert calls[1]["navigation_status"] == "failed"
    assert "repeats an earlier query" in calls[1]["navigation_failure_reason"]


def test_audit_runner_sends_the_severity_rubric_in_the_system_prompt():
    provider = MockProvider(default=_reply([]))
    _run(_runner(provider), _DIFF)
    assert "# Severity Rubric" in provider.calls[0]["system"]
    assert "Severity Rubric" not in provider.calls[0]["messages"][0].content


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"description": "  "}, "must have nonempty fields: description"),
        ({"line": 0}, "line must be a positive integer"),
        ({"confidence": 1.5}, "confidence must be between 0 and 1"),
        ({"evidence_refs": []}, "evidence_refs must be a nonempty string list"),
        ({"evidence_refs": [""]}, "evidence_refs must be a nonempty string list"),
        (
            {"change_anchor": {"file": "app.py", "line": 0, "side": "new"}},
            "change_anchor must name a nonempty file and a positive line",
        ),
    ],
)
def test_engine_rejects_schema_valid_findings_with_invalid_semantics(change, message):
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "description": "unsafe operation",
        "confidence": 0.9,
        **change,
    }
    with pytest.raises(AuditError, match=message):
        _run(_runner(MockProvider(default=_reply([finding]))), _DIFF)


def test_semantic_violation_in_one_finding_keeps_the_valid_findings_of_the_reply():
    valid = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "description": "string-concatenated query",
        "confidence": 0.9,
    }
    invalid = {**valid, "description": "second unsafe operation", "confidence": 1.2}
    provider = MockProvider(default=_reply([valid, invalid]))

    cycle = _runner(provider).review_unit(_DIFF, context=GroundingContext(text="", source="diff"), finder_label="f")

    assert cycle.clean is False
    assert [finding.description for finding in cycle.findings] == ["string-concatenated query"]
    assert "findings[1].confidence must be between 0 and 1" in provider.calls[1]["messages"][0].content
