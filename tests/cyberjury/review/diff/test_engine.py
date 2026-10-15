"""Diff engine tests cover review outcomes, locations, and grounding."""

import json
from dataclasses import replace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import (
    EvidenceItem,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
)
from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    _normalize_finding_line,
)
from cyberjury.review.diff.engine import (
    run_diff_review as engine_run_diff_review,
)
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
)
from cyberjury.review.diff.reviewer import AuditRunner
from cyberjury.review.knowledge import load_review_brief
from tests.cyberjury.review.diff.support import diff_units, repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def test_diff_review_accepts_an_unlisted_source_language():
    diff = "diff --git a/handler.rs b/handler.rs\n@@ -0,0 +1 @@\n+fn handle() {}\n"
    provider = MockProvider(default=_reply([]))

    result = run_diff_review(diff, provider=provider, model="mock")

    assert result.outcome.complete
    assert len(provider.calls) == 1


def _options(
    *,
    grounding: DiffGroundingOptions | None = None,
    execution: DiffExecutionOptions | None = None,
) -> DiffReviewOptions:
    return DiffReviewOptions(
        grounding=grounding or DiffGroundingOptions(prepare_diff=repository_prepare()),
        execution=execution or DiffExecutionOptions(),
    )


def run_diff_review(diff, *, provider, model, options=None):
    resolved = options or _options()
    return engine_run_diff_review(diff, provider=provider, model=model, options=resolved)


def _reply(findings, *, categories=None):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        finding.setdefault("description", "concrete exploitable path")
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


def _rule_confirmation(reply: str) -> str:
    return reply


def _rule_aware_provider(*, responses=None, default="") -> MockProvider:
    queue = list(responses or [])

    def respond(system, messages):
        return queue.pop(0) if queue else default

    return MockProvider(responder=respond)


def test_large_diff_is_audited_per_file():
    response = _reply(
        [
            {
                "file": "a.py",
                "line": 1,
                "severity": "HIGH",
                "category": "sql_injection",
                "description": "x",
                "confidence": 0.9,
            }
        ]
    )
    provider = _rule_aware_provider(default=response)
    result = run_diff_review(
        _FILE_A + _FILE_B,
        provider=provider,
        model="mock",
        options=_options(grounding=DiffGroundingOptions(prepare_diff=repository_prepare(max_chars=1))),
    )
    finder_calls = [
        call
        for call in provider.calls
        if call["response_schema"] is not None and call["response_schema"].name == "diff_finder_reply"
    ]
    assert len(finder_calls) >= 2
    finder_diffs = [call["messages"][-1].content for call in finder_calls]
    assert any("diff --git a/a.py b/a.py" in prompt for prompt in finder_diffs)
    assert any("diff --git a/b.py b/b.py" in prompt for prompt in finder_diffs)
    assert all(f.category == "sql-injection" for f in result.outcome.findings)


def test_diff_result_exposes_per_call_role_revision_and_parse_measurements():
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=_reply([])), meter)

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="mock",
        options=_options(execution=DiffExecutionOptions(meter=meter)),
    )

    assert result.model_calls
    call = result.model_calls[0]
    assert call["role"] == "finder"
    assert call["evidence_revision"].startswith("revision-")
    assert call["prompt_chars"] > 0
    assert call["duration_seconds"] >= 0
    assert call["parse_source"] == "direct"
    assert call["status"] == "ok"


def test_diff_model_call_records_semantic_response_failures():
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=_reply([{"severity": "HIGH"}])), meter)

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="mock",
        options=_options(execution=DiffExecutionOptions(meter=meter)),
    )

    assert result.outcome.complete is False
    call = result.model_calls[0]
    assert call["status"] == "failed"
    assert call["parse_source"] == "semantic"
    assert "$response.findings[0] is missing fields" in call["failure_reason"]


def test_diff_model_call_revision_changes_after_exact_evidence_delivery():
    evidence = EvidenceItem.create(
        identity="policy.py:guard:0:20",
        label="policy.py:guard",
        text="guard = True\n",
    )
    provider = MockProvider(
        responses=[
            json.dumps({**json.loads(_reply([])), "evidence_requests": [evidence.id]}),
            _reply([]),
        ]
    )
    meter = UsageMeter()

    result = run_diff_review(
        _DIFF,
        provider=MeteringProvider(provider, meter),
        model="mock",
        options=_options(
            grounding=DiffGroundingOptions(
                prepare_diff=repository_prepare(GroundingContext(text="seed", evidence=(evidence,)))
            ),
            execution=DiffExecutionOptions(meter=meter),
        ),
    )

    assert result.outcome.complete is True
    assert len(result.model_calls) == 2
    assert result.model_calls[0]["evidence_revision"] != result.model_calls[1]["evidence_revision"]


def test_large_diff_uses_batch_specific_context():
    provider = MockProvider(default=_reply([]))

    def prepare(diff):
        return [
            replace(
                unit,
                grounding=GroundingContext(
                    text="context for a.py" if "a.py" in unit.diff else "context for b.py",
                    source="repository",
                ),
            )
            for unit in diff_units(diff, max_chars=1)
        ]

    run_diff_review(
        _FILE_A + _FILE_B,
        provider=provider,
        model="mock",
        options=_options(grounding=DiffGroundingOptions(prepare_diff=prepare)),
    )

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert sum("context for a.py" in prompt for prompt in prompts) == 1
    assert sum("context for b.py" in prompt for prompt in prompts) == 1


def test_empty_diff_emits_a_complete_trace_without_model_work():
    trace = []
    provider = MockProvider(default="{}")

    result = run_diff_review(
        "  \n",
        provider=provider,
        model="m",
        options=_options(execution=DiffExecutionOptions(trace=trace.append)),
    )

    assert result.outcome.complete is True
    assert provider.calls == []
    assert trace[-1]["event"] == "review_finished"
    assert trace[-1]["status"] == "complete"


def test_nonempty_input_without_a_diff_hunk_fails_before_model_work():
    provider = MockProvider(default=_reply([]))

    with pytest.raises(ValueError, match="no unified diff hunk"):
        run_diff_review("ordinary text", provider=provider, model="m")

    assert provider.calls == []


def test_diff_review_exposes_the_complete_outcome_contract():
    """Internal callers receive failures, scheduling, and completion without side channels."""
    result = run_diff_review(_DIFF, provider=MockProvider(default="not json"), model="m")

    assert result.outcome.complete is False
    assert result.outcome.errors == 1
    assert len(result.outcome.failures) == 1
    assert result.outcome.scheduling is not None
    assert result.outcome.scheduling.stop_reason == "incomplete"


def test_incomplete_grounding_preserves_findings_without_reporting_complete():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "HIGH",
                "category": "other",
                "description": "concrete exploit",
                "confidence": 0.9,
            }
        ],
        categories=(),
    )
    context = GroundingContext(
        text="available source",
        source="diff",
        coverage=GroundingCoverage(
            required=("policy.py:AccessPolicy",),
            omitted=("policy.py:AccessPolicy",),
        ),
    )

    result = run_diff_review(
        _DIFF,
        provider=MockProvider(default=reply),
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare(context)),
        ),
    )

    assert [finding.description for finding in result.outcome.findings] == ["concrete exploit"]
    assert result.outcome.complete is False
    assert result.outcome.grounding == context.coverage
    assert "omitted required evidence" in result.outcome.failure_reason


def test_planned_diff_unit_fails_before_model_call_when_grounding_is_incomplete():
    provider = MockProvider(default=_reply([]))
    fragment = DefinitionFragment("policy.py", "Policy", 0, 20)
    context = GroundingContext(
        text="",
        source="diff",
        coverage=GroundingCoverage(required=(fragment.identity,), omitted=(fragment.identity,)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_DIFF,
        paths=("app.py",),
        definition_plan=DefinitionUnitPlan(evidence=(fragment,)),
        grounding=context,
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=lambda _diff: [unit]),
        ),
    )

    assert provider.calls == []
    assert result.outcome.complete is False
    assert result.outcome.errors == 1


def test_planned_diff_unit_reviews_raw_source_when_only_structured_facts_are_limited():
    provider = MockProvider(default=_reply([]))
    context = GroundingContext(
        text="raw source",
        source="diff",
        coverage=GroundingCoverage(limitations=("facts:app.py:1:1",)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_DIFF,
        paths=("app.py",),
        definition_plan=DefinitionUnitPlan(seed_files=("app.py",)),
        grounding=context,
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=lambda _diff: [unit]),
        ),
    )

    assert len(provider.calls) == 1
    assert result.outcome.errors == 0
    assert result.outcome.complete is False
    assert result.outcome.grounding.limitations == ("facts:app.py:1:1",)


def test_unknown_dependencies_are_not_split_to_manufacture_complete_units():
    diff = (
        "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+print(input())\n"
        "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -0,0 +1 @@\n+print(input())\n"
    )
    requested: list[tuple[str, ...]] = []

    def prepare(batch: str) -> list[DiffUnit]:
        paths = tuple(path for path in ("a.py", "b.py") if f"b/{path}" in batch)
        requested.append(paths)
        coverage = (
            GroundingCoverage(required=("shared.py:Policy",), omitted=("shared.py:Policy",))
            if len(paths) > 1
            else GroundingCoverage()
        )
        context = GroundingContext(text="source", source="repository", coverage=coverage)
        return [replace(unit, grounding=context) for unit in diff_units(batch)]

    result = run_diff_review(
        diff,
        provider=MockProvider(default=_reply([], categories=())),
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=prepare),
        ),
    )

    assert requested == [("a.py", "b.py")]
    assert result.outcome.complete is False
    assert len(result.outcome.failures) == 1
    assert "grounding incomplete" in result.outcome.failures[0].reason


def test_diff_review_requires_options_before_model_work():
    provider = MockProvider(default=_reply([]))

    with pytest.raises(TypeError, match="required keyword-only argument: 'options'"):
        engine_run_diff_review(_DIFF, provider=provider, model="m")

    assert provider.calls == []


def test_diff_finder_can_request_one_published_source_fragment():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:24",
        label="policy.py:Policy, import Policy from app.py [supported]",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = _rule_aware_provider(
        responses=[
            json.dumps({**json.loads(_reply([])), "evidence_requests": [evidence.id]}),
            _reply(
                [
                    {
                        "file": "app.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "other",
                        "description": "missing ownership check",
                        "confidence": 0.9,
                        "evidence_refs": [evidence.id],
                    }
                ]
            ),
        ]
    )
    context = GroundingContext(text="initial source", source="diff", evidence=(evidence,))

    content = default_profile().paths
    runner = AuditRunner(
        provider=provider,
        model="m",
        content=content,
        review_brief=load_review_brief(kernel_file=content.security_kernel_file),
    )
    cycle = runner.review_unit(_DIFF, context=context, finder_label="m")
    findings = cycle.findings

    assert [finding.description for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_diff_review_keeps_an_out_of_range_location_explicitly_incomplete():
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +30,3 @@\n context\n+sink(user)\n context\n"
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 45,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded route",
                    "confidence": 0.9,
                },
                {
                    "file": "b/app.py",
                    "line": 31,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded sink",
                    "confidence": 0.9,
                },
            ]
        )
    )

    trace = []
    result = run_diff_review(
        diff,
        provider=provider,
        model="m",
        options=_options(execution=DiffExecutionOptions(trace=trace.append)),
    )

    assert [(f.description, f.line) for f in result.outcome.findings] == [("unguarded sink", 31)]
    assert result.outcome.findings[0].file == "app.py"
    assert [(f.description, f.line) for f in result.outcome.incomplete] == [("unguarded route", 45)]
    assert result.dropped == []
    assert result.outcome.degraded is True
    locations = [event for event in trace if event.get("stage", "").startswith("location_")]
    assert [(event["stage"], event["primary_receipt"]) for event in locations] == [
        ("location_incomplete", ""),
        ("location_validated", "patch"),
    ]
    assert locations[0]["reason"] == "primary location has no current patch line or cited source receipt"
    assert locations[1]["change_anchor"] == {"file": "app.py", "line": 31, "side": "new"}


def test_diff_review_accepts_an_unchanged_location_with_a_new_change_anchor():
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
        default=_reply(
            [
                {
                    "file": "policy.py",
                    "line": 20,
                    "change_anchor": {"file": "policy.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "the existing operation is newly exposed",
                    "confidence": 0.9,
                }
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 20
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.py", line=21, side="new")


def test_diff_review_accepts_a_surviving_location_anchored_to_a_deleted_control():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10 @@\n"
        "-app.use(auth)\n"
        " app.use('/admin', admin)\n"
    )
    provider = _rule_aware_provider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 10,
                    "change_anchor": {"file": "app.py", "line": 10, "side": "old"},
                    "severity": "CRITICAL",
                    "category": "missing-authorization",
                    "description": "the admin route lost authentication",
                    "confidence": 0.99,
                }
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 10
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=10, side="old")


def test_diff_review_rejects_an_anchor_that_is_only_context():
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +20,2 @@\n context\n+sink(user)\n"
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 20,
                    "change_anchor": {"file": "app.py", "line": 20, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "context is not a change anchor",
                    "confidence": 0.9,
                }
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.findings == ()
    assert [finding.description for finding in result.outcome.incomplete] == ["context is not a change anchor"]
    assert result.outcome.degraded is True


def test_diff_review_accepts_a_cross_file_change_anchor():
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
        default=_reply(
            [
                {
                    "file": "operation.py",
                    "line": 10,
                    "change_anchor": {"file": "exposure.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "the existing operation is newly exposed",
                    "confidence": 0.9,
                }
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="exposure.py", line=21, side="new")


def test_diff_review_accepts_a_cited_repository_location_outside_the_patch():
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
        source="diff",
        source_evidence=(evidence,),
        coverage=GroundingCoverage(
            required=(evidence.identity,),
            included=(evidence.identity,),
            references=(evidence.id,),
        ),
    )
    diff = "diff --git a/routes.py b/routes.py\n@@ -0,0 +1 @@\n+register(handle)\n"
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "handler.py",
                    "line": 41,
                    "change_anchor": {"file": "routes.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "the new route exposes the existing unsafe handler",
                    "confidence": 0.9,
                    "evidence_refs": [evidence.id],
                }
            ]
        )
    )

    result = run_diff_review(
        diff,
        provider=provider,
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare(context)),
        ),
    )

    assert [(finding.file, finding.line) for finding in result.outcome.findings] == [("handler.py", 41)]
    assert result.outcome.complete is True


def test_diff_review_rejects_an_uncited_repository_location_outside_the_patch():
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
    finding = Finding(
        file="handler.py",
        line=41,
        change_anchor=ChangeAnchor(file="routes.py", line=1, side="new"),
        evidence_refs=("seed",),
    )

    result = _normalize_finding_line(finding, ranges, (evidence,))

    assert result.incomplete is True


def test_diff_accepts_an_unchanged_primary_location_covered_by_seed():
    ranges = DiffLineRanges(
        current={"routes.py": ((1, 1),)},
        old={},
        new={"routes.py": ((1, 1),)},
    )
    finding = Finding(
        file="./handler.py",
        line=41,
        change_anchor=ChangeAnchor(file="b/routes.py", line=1, side="new"),
        evidence_refs=("seed",),
    )

    result = _normalize_finding_line(
        finding,
        ranges,
        seed_spans=(SourceSpan(file="handler.py", start_line=40, end_line=41),),
    )

    assert result.incomplete is False
    assert result.primary_receipt == "seed"
    assert result.finding.file == "handler.py"
    assert result.finding.change_anchor == ChangeAnchor(file="routes.py", line=1, side="new")


def test_diff_path_normalization_prefers_a_real_side_named_directory():
    ranges = DiffLineRanges(
        current={"b/app.py": ((1, 1),)},
        old={},
        new={"b/app.py": ((1, 1),)},
    )
    finding = Finding(
        file="b/app.py",
        line=1,
        change_anchor=ChangeAnchor(file="b/app.py", line=1, side="new"),
        evidence_refs=("seed",),
    )

    result = _normalize_finding_line(finding, ranges)

    assert result.incomplete is False
    assert result.finding.file == "b/app.py"
    assert result.finding.change_anchor == ChangeAnchor(file="b/app.py", line=1, side="new")


def test_diff_review_keeps_a_canonicalized_path_when_every_finding_is_valid():
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "b/app.py",
                    "line": 1,
                    "change_anchor": {"file": "b/app.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "new unsafe operation",
                    "confidence": 0.9,
                }
            ]
        )
    )

    result = run_diff_review(_DIFF, provider=provider, model="m")

    assert result.outcome.complete is True
    assert result.outcome.findings[0].file == "app.py"
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=1, side="new")


def test_diff_unit_rejects_an_invalid_anchor_instead_of_overwriting_it():
    ranges = DiffLineRanges(
        current={"a.py": ((1, 1),)},
        old={},
        new={"a.py": ((1, 1),)},
    )
    finding = Finding(
        file="a.py",
        line=1,
        change_anchor=ChangeAnchor(file="b.py", line=1, side="new"),
        evidence_refs=("seed",),
    )

    result = _normalize_finding_line(finding, ranges)

    assert result.incomplete is True
    assert result.finding.change_anchor == ChangeAnchor(file="b.py", line=1, side="new")


def test_diff_unit_preserves_a_distinct_valid_anchor_for_an_added_location():
    ranges = DiffLineRanges(
        current={"a.py": ((1, 2),)},
        old={},
        new={"a.py": ((1, 2),)},
    )
    finding = Finding(
        file="a.py",
        line=1,
        change_anchor=ChangeAnchor(file="a.py", line=2, side="new"),
        evidence_refs=("seed",),
    )

    result = _normalize_finding_line(finding, ranges)

    assert result.incomplete is False
    assert result.finding.change_anchor == ChangeAnchor(file="a.py", line=2, side="new")


def test_diff_finding_requires_an_explicit_change_anchor():
    ranges = DiffLineRanges(
        current={"a.py": ((1, 1),)},
        old={},
        new={"a.py": ((1, 1),)},
    )
    finding = Finding(file="a.py", line=1, evidence_refs=("seed",))

    result = _normalize_finding_line(finding, ranges)

    assert result.incomplete is True


def test_diff_review_accepts_a_non_source_change_location_and_anchor():
    diff = (
        "diff --git a/policy.yaml b/policy.yaml\n"
        "--- a/policy.yaml\n"
        "+++ b/policy.yaml\n"
        "@@ -1 +1 @@\n"
        "-require_approval: true\n"
        "+require_approval: false\n"
    )
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "policy.yaml",
                    "line": 1,
                    "change_anchor": {"file": "policy.yaml", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "description": "the policy no longer requires approval",
                    "confidence": 0.9,
                }
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.yaml", line=1, side="new")


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"

_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_diff_review_keeps_a_deleted_file_location_incomplete():
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "sql-injection",
                    "description": "old sink",
                    "confidence": 0.9,
                }
            ]
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.findings == ()
    assert [(finding.file, finding.line) for finding in result.outcome.incomplete] == [("app.py", 1)]
    assert result.outcome.degraded is True


def test_diff_review_whitespace_only_diff_is_clean_without_a_model_call():
    provider = MockProvider(default=_reply([]))
    result = run_diff_review("   \n", provider=provider, model="m")
    assert result.outcome.findings == ()
    assert result.dropped == []
    assert result.outcome.degraded is False
    assert provider.calls == []


def test_diff_review_does_not_send_noise_files_to_the_model():
    provider = MockProvider(default=_reply([]))
    run_diff_review(_SRC + _DOC, provider=provider, model="m")
    sent = "\n".join(m.content for call in provider.calls for m in call["messages"])
    assert "app.py" in sent
    assert "README.md" not in sent


def test_diff_review_passes_context_to_the_runner():
    provider = MockProvider(default=_reply([]))
    run_diff_review(
        _SRC,
        provider=provider,
        model="m",
        options=_options(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare("def get_client(): return per_user_token"))
        ),
    )
    sent = provider.calls[0]["messages"][0].content
    assert "def get_client()" in sent
    assert "per_user_token" in sent


def test_diff_review_docs_only_diff_is_clean_without_a_model_call():
    reply = _reply([{"file": "README.md", "line": 1, "severity": "HIGH", "description": "x", "confidence": 0.9}])
    provider = MockProvider(default=reply)
    result = run_diff_review(_DOC + _LOCK, provider=provider, model="m")
    assert result.outcome.findings == ()
    assert result.dropped == []
    assert result.outcome.degraded is False
    assert provider.calls == []


_VULN = {
    "file": "app.py",
    "line": 1,
    "severity": "CRITICAL",
    "category": "sql-injection",
    "description": "concat",
    "confidence": 0.95,
    "evidence_refs": ["seed"],
}


def test_diff_review_is_not_degraded_by_a_complete_finding():
    provider = _rule_aware_provider(default=_reply([dict(_VULN)]))
    result = run_diff_review(_DIFF, provider=provider, model="m")
    assert result.outcome.degraded is False
    assert len(result.outcome.findings) == 1
