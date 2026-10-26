"""Diff reviewers parse responses and reuse grounded evidence."""

import json

import pytest

from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext
from cyberjury.review.union import MERGE_RULE
from tests.review.diff.support import diff_unit, finder, reply, review
from tests.review.support import navigator_from_callgraph

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _run(runner, diff, *, context=""):
    cycle = runner.review_unit(diff_unit(diff, context))
    if not cycle.clean:
        raise RuntimeError(cycle.failure_reason)
    return cycle.findings


def test_diff_finder_parses_findings():
    """A CRITICAL sql_injection reply yields one finding with category normalized to sql-injection."""
    response = reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "CRITICAL",
                "category": "sql_injection",
                "evidence": "string-concatenated query",
            },
        ]
    )
    provider = MockProvider(responses=[response, response])
    out = _run(finder(provider), _DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql-injection"
    assert provider.calls[0]["messages"][0].content.endswith("A further request makes this judgment incomplete.")


def test_diff_candidate_rejects_a_model_supplied_mismatched_identity():
    """A reply carrying candidate_id fails parsing with an "unknown fields: candidate_id" error."""
    finding = {
        "candidate_id": "candidate-wrong",
        "file": "app.py",
        "line": 3,
        "severity": "HIGH",
        "category": "sql-injection",
        "entrypoint": "POST /query",
        "evidence": "string-concatenated query",
        "attack_path": "public request reaches the query sink",
        "change_anchor": {"file": "app.py", "line": 3, "side": "new"},
        "evidence_refs": ["seed"],
    }

    with pytest.raises(RuntimeError, match="unknown fields: candidate_id"):
        _run(finder(MockProvider(default=reply([finding]))), _DIFF)


def test_diff_candidate_accepts_a_model_supplied_category():
    """A free-form category such as "sqli" is kept verbatim on the parsed finding."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sqli",
        "evidence": "string-concatenated query",
    }

    assert _run(finder(MockProvider(default=reply([finding]))), _DIFF)[0].category == "sqli"


def test_diff_review_reports_a_malformed_finding_as_failed_work():
    """A finding with only severity leaves no findings and records a missing-fields unit failure."""
    provider = MockProvider(default=reply([{"severity": "HIGH"}]))

    result = review(_DIFF, provider=provider)

    assert result.outcome.findings == ()
    assert result.outcome.complete is False
    assert "$response.findings[0] is missing fields" in result.outcome.failures[0].reason


def test_diff_review_reports_a_malformed_change_anchor_as_failed_work():
    """A change_anchor with side "context" leaves no findings and fails on the allowed-value check."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "unsafe operation",
                    "change_anchor": {"file": "app.py", "line": 1, "side": "context"},
                }
            ]
        )
    )

    result = review(_DIFF, provider=provider)

    assert result.outcome.findings == ()
    assert result.outcome.complete is False
    assert "change_anchor.side has a value outside the allowed set" in result.outcome.failures[0].reason


def test_diff_review_corrects_one_anchor_that_is_not_an_exact_changed_line():
    """An anchor on unchanged line 2 gets a correction listing new lines 1 and the retry is accepted."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**finding, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[reply([finding]), reply([corrected])])

    findings = _run(finder(provider), _DIFF)

    assert len(findings) == 1
    assert findings[0].change_anchor is not None
    assert findings[0].change_anchor.line == 1
    assert "Exact changed ranges for `app.py` are: new lines 1" in provider.calls[1]["messages"][0].content


def test_diff_review_preserves_a_valid_sibling_during_anchor_correction():
    """The valid line-1 finding is frozen in the correction prompt while its line-2 sibling is fixed."""
    valid = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "entrypoint": "GET /first",
        "evidence": "first unsafe operation",
        "change_anchor": {"file": "app.py", "line": 1, "side": "new"},
    }
    invalid = {
        **valid,
        "entrypoint": "GET /second",
        "evidence": "second unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**invalid, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[reply([valid, invalid]), reply([corrected])])

    findings = _run(finder(provider), _DIFF)

    assert [finding.evidence for finding in findings] == ["first unsafe operation", "second unsafe operation"]
    correction = provider.calls[1]["messages"][0].content
    assert f"cannot be edited or withdrawn. {MERGE_RULE} Return only new findings." in correction
    assert '"title": "unsafe changed operation"' in correction
    assert '"description"' not in correction


def test_diff_review_keeps_an_invalid_anchor_candidate_when_correction_fails():
    """A non-JSON correction reply moves the bad-anchor finding to incomplete and the outcome fails."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[reply([finding]), "not json"])

    result = review(_DIFF, provider=provider)

    assert result.outcome.findings == ()
    assert [item.evidence for item in result.outcome.incomplete] == ["unsafe operation"]
    assert result.outcome.complete is False


def test_diff_review_allows_anchor_correction_to_remove_an_unreportable_candidate():
    """An empty correction reply drops the line-2 anchored finding, leaving no findings."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[reply([finding]), reply([])])

    assert _run(finder(provider), _DIFF) == []


def test_diff_finder_empty_on_no_findings():
    """A reply with an empty findings list produces an empty result for the SQL concatenation diff."""
    assert _run(finder(MockProvider(default=reply([]))), _DIFF) == []


def test_diff_finder_rejects_invalid_finding_semantics():
    """Severity "spicy" raises a "severity has a value outside the allowed set" error."""
    response = reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "spicy",
                "category": "other",
                "evidence": "unsafe operation",
            }
        ]
    )
    with pytest.raises(RuntimeError, match="severity has a value outside the allowed set"):
        _run(finder(MockProvider(default=response)), _DIFF)


def test_diff_finder_sends_the_contract_as_a_cacheable_system_prompt():
    """The kernel and rubric go in the system prompt, while the cached prefix carries the diff text."""
    provider = MockProvider(default=reply([]))
    _run(finder(provider), _DIFF)
    call = provider.calls[0]
    prompt = call["messages"][0].content
    assert call["cache"] is True
    assert prompt.startswith(call["cache_prefix"])
    assert "SELECT * FROM u" in call["cache_prefix"]
    assert "# Security Reasoning Kernel" in call["system"]
    assert "# Severity Rubric" in call["system"]
    assert "# Security Reasoning Kernel" not in prompt


def test_diff_system_is_identical_across_units():
    """Two units with different diffs and context share one system prompt free of unit context."""
    provider = MockProvider(default=reply([]))
    runner = finder(provider)
    _run(runner, _DIFF, context="first unit")
    _run(runner, "+++ b/other.py\n@@ -0,0 +1 @@\n+other()\n", context="second unit")

    assert provider.calls[0]["system"] == provider.calls[1]["system"]
    assert "first unit" not in provider.calls[0]["system"]


def test_diff_repository_evidence_does_not_change_the_profile_brief():
    """Published evidence ids enter the cache prefix while their source text stays out of the prompt."""
    provider = MockProvider(default=reply([]))
    runner = finder(provider)
    evidence = EvidenceItem.create(
        identity="app.py:handler:10:40",
        label="app.py:handler",
        text="def handler():\n    return sensitive_operation()\n",
        preview="def handler():",
    )

    cycle = runner.review_unit(
        diff_unit(
            "+++ b/app.py\n@@ -0,0 +1 @@\n+def handler(): ...\n",
            GroundingContext(text="initial context", evidence=(evidence,)),
        )
    )

    assert cycle.clean is True
    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


def test_diff_navigation_keeps_profile_coverage_and_runs_a_final_evidence_sweep(tmp_path):
    """A symbol search is followed by a call that shares the cache prefix and carries the found source."""
    source = "class ModelWithOwner:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = navigator_from_callgraph(
        tmp_path,
        {
            "callgraph": {"models.py": {"ModelWithOwner": [{"range": [0, len(source)], "calls": []}]}},
        },
    )
    raw_provider = MockProvider(
        responses=[
            json.dumps(
                {
                    **json.loads(reply([])),
                    "source_queries": [{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
                }
            ),
            reply([]),
        ]
    )
    meter = UsageMeter()
    provider = MeteringProvider(raw_provider, meter)
    runner = finder(provider)

    cycle = runner.review_unit(
        diff_unit(
            "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n", GroundingContext(text="seed", navigator=navigator)
        )
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
    assert [call["trigger"] for call in meter.call_snapshot()] == ["initial_judgment", "evidence_followup"]


def test_diff_repeated_navigation_query_fails_the_unit(tmp_path):
    """Returning the same search_symbols "Record" query on every reply fails with "repeats an earlier query"."""
    source = "class Record:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = navigator_from_callgraph(
        tmp_path,
        {"callgraph": {"models.py": {"Record": [{"range": [0, len(source)], "calls": []}]}}},
    )
    response = json.dumps(
        {
            **json.loads(reply([])),
            "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
        }
    )
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(responses=[response, response, response]), meter)
    runner = finder(provider)

    cycle = runner.review_unit(
        diff_unit(
            "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n", GroundingContext(text="seed", navigator=navigator)
        )
    )

    assert cycle.clean is False
    assert "repeats an earlier query" in cycle.failure_reason


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"evidence": "  "}, "must have nonempty fields: evidence"),
        ({"line": 0}, "line must be a positive integer"),
        ({"file": "/etc/app.py"}, "file must be a relative repository path"),
        ({"evidence_refs": []}, "evidence_refs must be a nonempty string list"),
        ({"evidence_refs": [""]}, "evidence_refs must be a nonempty string list"),
        (
            {"change_anchor": {"file": "app.py", "line": 0, "side": "new"}},
            "change_anchor must name a nonempty file and a positive line",
        ),
    ],
)
def test_diff_finder_rejects_schema_valid_findings_with_invalid_semantics(change, message):
    """Blank evidence, line 0, absolute paths, empty refs, or a line-0 anchor raise the matching error."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        **change,
    }
    with pytest.raises(RuntimeError, match=message):
        _run(finder(MockProvider(default=reply([finding]))), _DIFF)


def test_semantic_violation_in_one_finding_keeps_the_valid_findings_of_the_reply():
    """A blank title on findings[1] keeps findings[0], fails the cycle, and names the field."""
    valid = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "evidence": "string-concatenated query",
    }
    invalid = {**valid, "evidence": "second unsafe operation", "title": " "}
    provider = MockProvider(default=reply([valid, invalid]))

    cycle = finder(provider).review_unit(diff_unit(_DIFF))

    assert cycle.clean is False
    assert [finding.evidence for finding in cycle.findings] == ["string-concatenated query"]
    assert "findings[1] must have nonempty fields: title" in provider.calls[1]["messages"][0].content
