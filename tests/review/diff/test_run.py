"""Diff Review through the shared run covers outcomes, change locations, and grounding."""

import json
from dataclasses import replace
from types import SimpleNamespace

from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import (
    EvidenceItem,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
)
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.diff.finder import locate
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
)
from cyberjury.review.finding import ChangeAnchor, Finding
from tests.review.diff.support import diff_unit, diff_units, finder, reply, review
from tests.review.support import StubIssueJudge, definition

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def _finding(file, line, change_anchor):
    return Finding(
        title="unsafe operation",
        entrypoint="GET /",
        evidence="unsafe operation",
        attack_path="request reaches it",
        severity="HIGH",
        category="other",
        file=file,
        line=line,
        change_anchor=change_anchor,
        evidence_refs=("seed",),
    )


def _locate(finding, ranges, source_evidence=(), seed_spans=()):
    return locate(SimpleNamespace(line_ranges=ranges), finding, source_evidence, seed_spans)


def test_large_diff_is_reviewed_per_file():
    """With max_chars=1, a.py and b.py go to separate finder calls and sql_injection becomes sql-injection."""
    response = reply(
        [
            {
                "file": "a.py",
                "line": 1,
                "severity": "HIGH",
                "category": "sql_injection",
                "evidence": "x",
            }
        ]
    )
    provider = MockProvider(default=response)
    result = review(_FILE_A + _FILE_B, provider=provider, max_chars=1)
    finder_calls = [
        call
        for call in provider.calls
        if call["response_schema"] is not None and call["response_schema"].name == "diff_finder_reply"
    ]
    headers = ("diff --git a/a.py b/a.py", "diff --git a/b.py b/b.py")
    reviewed = [[header for header in headers if header in call["messages"][-1].content] for call in finder_calls]
    assert all(len(files) == 1 for files in reviewed)
    assert {files[0] for files in reviewed} == set(headers)
    assert all(f.category == "sql-injection" for f in result.outcome.findings)


def test_diff_result_exposes_per_call_role_and_status_measurements():
    """A metered review records a finder call with positive prompt_chars, a duration, and ok status."""
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=reply([])), meter)

    review(_DIFF, provider=provider)

    calls = meter.call_snapshot()
    assert calls
    call = calls[0]
    assert call["role"] == "finder"
    assert call["prompt_chars"] > 0
    assert call["duration_seconds"] >= 0
    assert call["status"] == "ok"


def test_diff_model_call_records_semantic_response_failures():
    """A finding missing required fields marks the call failed with that reason and the review incomplete."""
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=reply([{"severity": "HIGH"}])), meter)

    result = review(_DIFF, provider=provider)

    assert result.outcome.complete is False
    call = meter.call_snapshot()[0]
    assert call["status"] == "failed"
    assert "$response.findings[0] is missing fields" in call["failure_reason"]


def test_diff_model_call_after_exact_evidence_delivery_is_a_followup():
    """Requesting an evidence id yields two calls, triggered as initial_judgment then evidence_followup."""
    evidence = EvidenceItem.create(
        identity="policy.py:guard:0:20",
        label="policy.py:guard",
        text="guard = True\n",
    )
    provider = MockProvider(
        responses=[
            json.dumps({**json.loads(reply([])), "evidence_requests": [evidence.id]}),
            reply([]),
        ]
    )
    meter = UsageMeter()

    result = review(
        _DIFF,
        provider=MeteringProvider(provider, meter),
        context=GroundingContext(text="seed", evidence=(evidence,)),
    )

    calls = meter.call_snapshot()
    assert result.outcome.complete is True
    assert len(calls) == 2
    assert [call["trigger"] for call in calls] == ["initial_judgment", "evidence_followup"]


def test_large_diff_uses_batch_specific_context():
    """Each of two per-file units sends only its own grounding text, once each across the two prompts."""
    provider = MockProvider(default=reply([]))

    units = [
        replace(
            unit,
            grounding=GroundingContext(
                text="context for a.py" if "a.py" in unit.diff else "context for b.py",
            ),
        )
        for unit in diff_units(_FILE_A + _FILE_B, max_chars=1)
    ]

    review(units, provider=provider)

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert sum("context for a.py" in prompt for prompt in prompts) == 1
    assert sum("context for b.py" in prompt for prompt in prompts) == 1


def test_empty_diff_is_complete_without_model_work():
    """A whitespace-only diff is complete and the provider receives no calls."""
    provider = MockProvider(default="{}")

    result = review("  \n", provider=provider)

    assert result.outcome.complete is True
    assert provider.calls == []


def test_diff_review_exposes_the_complete_outcome_contract():
    """Internal callers receive failures and completion without side channels."""
    result = review(_DIFF, provider=MockProvider(default="not json"))

    assert result.outcome.complete is False
    assert result.outcome.errors == 1
    assert len(result.outcome.failures) == 1


def test_planned_diff_unit_fails_before_model_call_when_grounding_is_incomplete():
    """A unit whose required definition is omitted from grounding fails with one error and no model call."""
    provider = MockProvider(default=reply([]))
    fragment = definition("policy.py", "Policy", 0, 20)
    context = GroundingContext(
        text="",
        coverage=GroundingCoverage(required=(fragment.identity,), omitted=(fragment.identity,)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_DIFF,
        paths=("app.py",),
        id="diff-unit-1",
        definition_plan=DefinitionUnitPlan(seeds=(fragment,)),
        grounding=context,
    )

    result = review([unit], provider=provider)

    assert provider.calls == []
    assert result.outcome.complete is False
    assert result.outcome.errors == 1


def test_planned_diff_unit_reviews_raw_source_when_only_structured_facts_are_limited():
    """A fact limitation still sends one call but leaves the outcome incomplete and reports the limitation."""
    provider = MockProvider(default=reply([]))
    context = GroundingContext(
        text="raw source",
        coverage=GroundingCoverage(limitations=("facts:app.py:1:1",)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_DIFF,
        paths=("app.py",),
        id="diff-unit-1",
        definition_plan=DefinitionUnitPlan(seed_files=("app.py",)),
        grounding=context,
    )

    result = review([unit], provider=provider)

    assert len(provider.calls) == 1
    assert result.outcome.errors == 0
    assert result.outcome.complete is False
    assert result.outcome.grounding.limitations == ("facts:app.py:1:1",)


def test_diff_finder_can_request_one_published_source_fragment():
    """A requested evidence id gets its text only in the second call, and the cited finding is returned."""
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:24",
        label="policy.py:Policy, import Policy from app.py [supported]",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            json.dumps({**json.loads(reply([])), "evidence_requests": [evidence.id]}),
            reply(
                [
                    {
                        "file": "app.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "other",
                        "evidence": "missing ownership check",
                        "evidence_refs": [evidence.id],
                    }
                ]
            ),
        ]
    )
    context = GroundingContext(text="initial source", evidence=(evidence,))

    findings = finder(provider).review_unit(diff_unit(_DIFF, context)).findings

    assert [finding.evidence for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_diff_review_keeps_an_out_of_range_location_explicitly_incomplete():
    """Line 45 outside hunk +30,3 is incomplete, while b/app.py:31 is accepted as app.py with an anchor."""
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +30,3 @@\n context\n+sink(user)\n context\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 45,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "evidence": "unguarded route",
                },
                {
                    "file": "b/app.py",
                    "line": 31,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "evidence": "unguarded sink",
                },
            ]
        )
    )

    result = review(diff, provider=provider)

    assert [(f.evidence, f.line) for f in result.outcome.findings] == [("unguarded sink", 31)]
    assert result.outcome.findings[0].file == "app.py"
    assert [(f.evidence, f.line) for f in result.outcome.incomplete] == [("unguarded route", 45)]
    assert result.outcome.complete is False
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=31, side="new")


def test_diff_review_accepts_an_unchanged_location_with_a_new_change_anchor():
    """A finding on unchanged line 20 anchored to added line 21 is accepted with that anchor intact."""
    diff = (
        "diff --git a/policy.py b/policy.py\n"
        "--- a/policy.py\n"
        "+++ b/policy.py\n"
        "@@ -20,2 +20,3 @@\n"
        " existing_operation()\n"
        "+expose_operation()\n"
        " finish_request()\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "policy.py",
                    "line": 20,
                    "change_anchor": {"file": "policy.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the existing operation is newly exposed",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 20
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.py", line=21, side="new")


def test_diff_review_accepts_a_surviving_location_anchored_to_a_deleted_control():
    """A finding on surviving line 10 anchored to the deleted old-side auth line is accepted as complete."""
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10 @@\n"
        "-app.use(auth)\n"
        " app.use('/admin', admin)\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 10,
                    "change_anchor": {"file": "app.py", "line": 10, "side": "old"},
                    "severity": "CRITICAL",
                    "category": "missing-authorization",
                    "evidence": "the admin route lost authentication",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 10
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=10, side="old")


def test_diff_review_rejects_an_anchor_that_is_only_context():
    """An anchor on a context line yields no findings and puts the claim in incomplete."""
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +20,2 @@\n context\n+sink(user)\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 20,
                    "change_anchor": {"file": "app.py", "line": 20, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "context is not a change anchor",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.findings == ()
    assert [finding.evidence for finding in result.outcome.incomplete] == ["context is not a change anchor"]
    assert result.outcome.complete is False


def test_diff_review_accepts_a_cross_file_change_anchor():
    """A finding in operation.py anchored to an added line in exposure.py is accepted with that anchor."""
    diff = (
        "diff --git a/operation.py b/operation.py\n"
        "--- a/operation.py\n"
        "+++ b/operation.py\n"
        "@@ -10,2 +10,3 @@\n"
        " sensitive_operation()\n"
        "+record_operation()\n"
        " finish_operation()\n"
        "diff --git a/exposure.py b/exposure.py\n"
        "--- a/exposure.py\n"
        "+++ b/exposure.py\n"
        "@@ -20 +20,2 @@\n"
        " keep_private()\n"
        "+expose_operation()\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "operation.py",
                    "line": 10,
                    "change_anchor": {"file": "exposure.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the existing operation is newly exposed",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="exposure.py", line=21, side="new")


def test_diff_review_accepts_a_cited_repository_location_outside_the_patch():
    """A handler.py:41 location outside the patch is accepted when it cites evidence covering lines 40-41."""
    evidence = SourceEvidence(
        id="src-handler",
        identity="handler.py:handle:0:80",
        text="40 | def handle(request):\n41 |     dangerous(request.data)",
        source_span=SourceSpan(
            file="handler.py",
            start_line=40,
            end_line=41,
        ),
    )
    context = GroundingContext(
        text="repository context",
        source_evidence=(evidence,),
        coverage=GroundingCoverage(
            required=(evidence.identity,),
            included=(evidence.identity,),
            references=(evidence.id,),
        ),
    )
    diff = "diff --git a/routes.py b/routes.py\n@@ -0,0 +1 @@\n+register(handle)\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "handler.py",
                    "line": 41,
                    "change_anchor": {"file": "routes.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the new route exposes the existing unsafe handler",
                    "evidence_refs": [evidence.id],
                }
            ]
        )
    )

    result = review(diff, provider=provider, context=context)

    assert [(finding.file, finding.line) for finding in result.outcome.findings] == [("handler.py", 41)]
    assert result.outcome.complete is True


def test_diff_review_rejects_an_uncited_repository_location_outside_the_patch():
    """A handler.py:41 location outside the patch is not located when the finding cites no evidence for it."""
    ranges = DiffLineRanges(
        current={"routes.py": ((1, 1),)},
        old={},
        new={"routes.py": ((1, 1),)},
    )
    evidence = SourceEvidence(
        id="src-handler",
        identity="handler.py:handle:0:80",
        text="40 | def handle(request):\n41 |     dangerous(request.data)",
        source_span=SourceSpan(
            file="handler.py",
            start_line=40,
            end_line=41,
        ),
    )
    finding = _finding("handler.py", 41, ChangeAnchor(file="routes.py", line=1, side="new"))

    assert _locate(finding, ranges, (evidence,)) is None


def test_diff_accepts_an_unchanged_primary_location_covered_by_seed():
    """A ./handler.py:41 location inside a seed span maps to handler.py, with b/ stripped from the anchor."""
    ranges = DiffLineRanges(
        current={"routes.py": ((1, 1),)},
        old={},
        new={"routes.py": ((1, 1),)},
    )
    finding = _finding("./handler.py", 41, ChangeAnchor(file="b/routes.py", line=1, side="new"))

    result = _locate(finding, ranges, seed_spans=(SourceSpan(file="handler.py", start_line=40, end_line=41),))

    assert result.file == "handler.py"
    assert result.change_anchor == ChangeAnchor(file="routes.py", line=1, side="new")


def test_diff_path_normalization_prefers_a_real_side_named_directory():
    """When the diff itself has a b/app.py path, the b/ prefix is kept rather than stripped as a side."""
    ranges = DiffLineRanges(
        current={"b/app.py": ((1, 1),)},
        old={},
        new={"b/app.py": ((1, 1),)},
    )
    finding = _finding("b/app.py", 1, ChangeAnchor(file="b/app.py", line=1, side="new"))

    result = _locate(finding, ranges)

    assert result.file == "b/app.py"
    assert result.change_anchor == ChangeAnchor(file="b/app.py", line=1, side="new")


def test_diff_review_keeps_a_canonicalized_path_when_every_finding_is_valid():
    """A b/app.py finding and anchor are canonicalized to app.py and the review stays complete."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "b/app.py",
                    "line": 1,
                    "change_anchor": {"file": "b/app.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "new unsafe operation",
                }
            ]
        )
    )

    result = review(_DIFF, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].file == "app.py"
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=1, side="new")


def test_diff_unit_rejects_an_invalid_anchor_instead_of_overwriting_it():
    """An anchor naming b.py, which is absent from the ranges, makes the a.py finding unlocatable."""
    ranges = DiffLineRanges(
        current={"a.py": ((1, 1),)},
        old={},
        new={"a.py": ((1, 1),)},
    )
    finding = _finding("a.py", 1, ChangeAnchor(file="b.py", line=1, side="new"))

    assert _locate(finding, ranges) is None


def test_diff_unit_preserves_a_distinct_valid_anchor_for_an_added_location():
    """A finding on added line 1 keeps its own anchor on added line 2 instead of being re-anchored."""
    ranges = DiffLineRanges(
        current={"a.py": ((1, 2),)},
        old={},
        new={"a.py": ((1, 2),)},
    )
    finding = _finding("a.py", 1, ChangeAnchor(file="a.py", line=2, side="new"))

    assert _locate(finding, ranges).change_anchor == ChangeAnchor(file="a.py", line=2, side="new")


def test_diff_review_accepts_a_non_source_change_location_and_anchor():
    """A policy.yaml change flipping require_approval is accepted as both finding location and anchor."""
    diff = (
        "diff --git a/policy.yaml b/policy.yaml\n"
        "--- a/policy.yaml\n"
        "+++ b/policy.yaml\n"
        "@@ -1 +1 @@\n"
        "-require_approval: true\n"
        "+require_approval: false\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "policy.yaml",
                    "line": 1,
                    "change_anchor": {"file": "policy.yaml", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the policy no longer requires approval",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.yaml", line=1, side="new")


def test_diff_review_keeps_a_deleted_file_location_incomplete():
    """A finding on a line of a file deleted to /dev/null is incomplete and yields no findings."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "sql-injection",
                    "evidence": "old sink",
                }
            ]
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    result = review(diff, provider=provider)

    assert result.outcome.findings == ()
    assert [(finding.file, finding.line) for finding in result.outcome.incomplete] == [("app.py", 1)]
    assert result.outcome.complete is False


def test_diff_review_passes_context_to_the_runner():
    """String context passed to review appears verbatim in the first finder prompt."""
    provider = MockProvider(default=reply([]))
    review(_DIFF, provider=provider, context="def get_client(): return per_user_token")
    sent = provider.calls[0]["messages"][0].content
    assert "def get_client()" in sent
    assert "per_user_token" in sent


_VULN = {
    "file": "app.py",
    "line": 1,
    "severity": "CRITICAL",
    "category": "sql-injection",
    "evidence": "concat",
    "evidence_refs": ["seed"],
}


def test_diff_review_is_not_degraded_by_a_complete_finding():
    """One fully cited CRITICAL finding leaves the outcome complete with that single finding."""
    provider = MockProvider(default=reply([dict(_VULN)]))
    result = review(_DIFF, provider=provider)
    assert result.outcome.complete is True
    assert len(result.outcome.findings) == 1


def test_diff_review_reports_one_progress_call_per_batch():
    """Two per-file units report on_unit progress as (1, 2) then (2, 2)."""
    seen = []

    review(
        _FILE_A + _FILE_B,
        provider=MockProvider(default=reply([])),
        max_chars=1,
        on_unit=lambda done, total, _seconds: seen.append((done, total)),
    )

    assert seen == [(1, 2), (2, 2)]


def test_diff_review_records_failed_batch_and_continues():
    """A large diff keeps completed batch results while surfacing failed batches."""
    finding = {
        "file": "b.py",
        "line": 1,
        "severity": "HIGH",
        "category": "missing-authorization",
        "evidence": "unguarded sink",
    }
    provider = MockProvider(responses=["not json", "still not json", reply([finding])])

    result = review(_FILE_A + _FILE_B, provider=provider, max_chars=1)

    assert [f.evidence for f in result.outcome.findings] == ["unguarded sink"]
    assert result.outcome.complete is False
    assert len(provider.calls) == 3
    failure = result.outcome.failures[0]
    assert (failure.index, failure.total, failure.paths) == (1, 2, ("a.py",))
    assert "reply had no complete JSON object" in failure.reason


def test_an_unparseable_reply_is_corrected_once_instead_of_failing_the_unit():
    """A reply holding two JSON objects gets one correction prompt, and the corrected finding completes it."""
    finding = {
        "file": "a.py",
        "line": 1,
        "severity": "HIGH",
        "category": "missing-authorization",
        "evidence": "unguarded sink",
    }
    provider = MockProvider(responses=['{"findings": []} {"findings": [1]}', reply([finding])])

    result = review(_FILE_A, provider=provider)

    assert [f.evidence for f in result.outcome.findings] == ["unguarded sink"]
    assert result.outcome.complete
    assert "Return exactly one JSON object" in provider.calls[1]["messages"][-1].content


def test_diff_review_groups_its_findings_into_issues_through_the_shared_step(tmp_path):
    """Two same-line findings and one other-line finding form one issue linked by judgment and location."""
    (tmp_path / "app.py").write_text("first = 1\nsecond = 2\n", encoding="utf-8")
    diff = "+++ b/app.py\n@@ -0,0 +1,2 @@\n+first = 1\n+second = 2\n"
    provider = MockProvider(
        default=reply(
            [
                {"file": "app.py", "line": 1, "title": "first claim", "severity": "HIGH", "category": "c"},
                {"file": "app.py", "line": 1, "title": "second claim", "severity": "HIGH", "category": "c"},
                {"file": "app.py", "line": 2, "title": "other line", "severity": "HIGH", "category": "c"},
            ]
        )
    )
    judge = StubIssueJudge()
    context = GroundingContext(text="context", source_spans=(SourceSpan(file="app.py", start_line=1, end_line=2),))

    result = review(diff, provider=provider, context=context, issue_judge=judge, root=tmp_path)

    assert len(result.findings.findings) == 3
    assert len(judge.pairs) == 1
    (issue,) = result.findings.issues
    assert issue.linked_by == ("judgment", "location")
    assert set(issue.members) == {record.id for record in result.findings.findings}
    assert result.outcome.complete
