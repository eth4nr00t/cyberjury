"""Diff engine tests cover standard and adversarial review outcomes."""

import json
from dataclasses import replace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import (
    EvidenceItem,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
)
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffRoleOptions,
    _normalize_finding_line,
)
from cyberjury.review.diff.engine import (
    audit_diff as engine_audit_diff,
)
from cyberjury.review.diff.engine import (
    run_diff_review as engine_run_diff_review,
)
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
    diff_units,
)
from cyberjury.review.diff.prompts import (
    CHALLENGER_SYSTEM,
    FINDER_SYSTEM,
    JUDGE_SYSTEM,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
)
from cyberjury.review.diff.reviewer import AdversarialAuditRunner, AuditRunner
from cyberjury.review.engine import review_plan
from cyberjury.review.facts import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.identity import candidate_identity
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.vulnerabilities import Vulnerability, VulnerabilityCatalog
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def _options(
    *,
    grounding: DiffGroundingOptions | None = None,
    roles: DiffRoleOptions | None = None,
    execution: DiffExecutionOptions | None = None,
) -> DiffReviewOptions:
    return DiffReviewOptions(
        grounding=grounding or DiffGroundingOptions(prepare_diff=repository_prepare()),
        roles=roles or DiffRoleOptions(),
        execution=execution or DiffExecutionOptions(),
    )


def audit_diff(diff, **kwargs):
    kwargs.setdefault("prepare_diff", repository_prepare())
    return engine_audit_diff(diff, **kwargs)


def run_diff_review(diff, *, provider, model, options=None):
    resolved = options or _options()
    return engine_run_diff_review(diff, provider=provider, model=model, options=resolved)


def _assessments(categories, findings):
    finding_categories = {finding.get("category", "").replace("_", "-") for finding in findings}
    return [
        {
            "category": category,
            "decision": "finding" if category in finding_categories else "not_exploitable",
            "reason": "a same-category violation is reported" if category in finding_categories else "no exploit path",
            "evidence_refs": ["seed"],
        }
        for category in categories
    ]


def _reply(findings, *, categories=None):
    if categories is None:
        finding_categories = {finding.get("category", "").replace("_", "-") for finding in findings}
        categories = ("sql-injection",) if not findings or "sql-injection" in finding_categories else ()
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        finding.setdefault("exploit_scenario", "attacker input reaches the vulnerable operation")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps({"findings": findings, "assessments": _assessments(categories, findings)})


def test_large_diff_is_audited_per_file(monkeypatch):
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    response = (
        '{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
        '"category": "sql_injection", "entrypoint": "changed code path", "description": "x", '
        '"exploit_scenario": "attacker input reaches the vulnerable operation", "confidence": 0.9, '
        '"evidence_refs": ["seed"]}]}'
    )
    provider = MockProvider(default=response)
    kept, _, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    assert len(provider.calls) == 2
    assert all(f.category == "sql-injection" for f in kept)


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
    provider = MeteringProvider(MockProvider(default='{"findings": [{"severity": "HIGH"}]}'), meter)

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
    assert "must name a source file" in call["failure_reason"]


def test_diff_model_call_revision_changes_after_exact_evidence_delivery():
    evidence = EvidenceItem.create(
        identity="policy.py:guard:0:20",
        label="policy.py:guard",
        text="guard = True\n",
    )
    provider = MockProvider(
        responses=[
            json.dumps(
                {
                    "findings": [],
                    "assessments": [
                        {
                            "category": "sql-injection",
                            "decision": "insufficient_evidence",
                            "reason": "the guard must be read",
                            "evidence_refs": [evidence.id],
                        }
                    ],
                    "evidence_requests": [evidence.id],
                }
            ),
            json.dumps(
                {
                    "findings": [],
                    "assessments": [
                        {
                            "category": "sql-injection",
                            "decision": "not_exploitable",
                            "reason": "the exact guard blocks the sink",
                            "evidence_refs": [evidence.id],
                        }
                    ],
                }
            ),
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


def test_large_diff_uses_batch_specific_context(monkeypatch):
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    provider = MockProvider(default='{"findings": []}')

    def prepare(diff):
        return [
            replace(
                unit,
                grounding=GroundingContext(
                    text="context for a.py" if "a.py" in unit.diff else "context for b.py",
                    source="repository",
                ),
            )
            for unit in diff_units(diff)
        ]

    audit_diff(
        _FILE_A + _FILE_B,
        provider=provider,
        model="mock",
        prepare_diff=prepare,
    )

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert sum("context for a.py" in prompt for prompt in prompts) == 1
    assert sum("context for b.py" in prompt for prompt in prompts) == 1


def test_diff_review_rejects_unknown_modes_before_calling_the_provider():
    """Diff Review uses the shared mode contract before any model work."""
    provider = MockProvider(default=_reply([]))

    with pytest.raises(ValueError, match="unknown review mode"):
        run_diff_review(
            _DIFF,
            provider=provider,
            model="m",
            options=_options(roles=DiffRoleOptions(mode="deep")),
        )

    assert provider.calls == []


def test_standard_diff_options_default_to_one_effective_round():
    assert DiffRoleOptions().max_rounds == 1


def test_standard_diff_rejects_an_explicit_multi_round_cap_before_provider_work():
    provider = MockProvider(default=_reply([]))

    with pytest.raises(ValueError, match="single completion requires max_rounds"):
        run_diff_review(
            _DIFF,
            provider=provider,
            model="m",
            options=_options(roles=DiffRoleOptions(mode="standard", max_rounds=2)),
        )

    assert provider.calls == []


def test_standard_diff_honors_finder_backend_overrides():
    base = MockProvider(default=_reply([]))
    finder = MockProvider(default=_reply([]))

    result = run_diff_review(
        _DIFF,
        provider=base,
        model="base",
        options=_options(
            roles=DiffRoleOptions(
                finder_provider=finder,
                finder_model="finder",
            )
        ),
    )

    assert result.outcome.complete is True
    assert base.calls == []
    assert {call["model"] for call in finder.calls} == {"finder"}


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
    provider = MockProvider(default='{"findings": []}')

    with pytest.raises(ValueError, match="no unified diff hunk"):
        run_diff_review("ordinary text", provider=provider, model="m")

    assert provider.calls == []


def test_diff_review_exposes_the_complete_outcome_contract():
    """Internal callers receive rounds, failures, and completion without side channels."""
    result = run_diff_review(_DIFF, provider=MockProvider(default="not json"), model="m")

    assert result.outcome.complete is False
    assert result.outcome.errors == 1
    assert len(result.outcome.failures) == 1
    assert result.outcome.rounds == 1


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
        categories=("sql-injection",),
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
    provider = MockProvider(default='{"findings": []}')

    with pytest.raises(TypeError, match="required keyword-only argument: 'options'"):
        engine_run_diff_review(_DIFF, provider=provider, model="m")

    assert provider.calls == []


def test_standard_diff_finder_can_request_one_published_source_fragment():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:24",
        label="policy.py:Policy, import Policy from app.py [supported]",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            json.dumps({"findings": [], "evidence_requests": [evidence.id]}),
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

    findings = AuditRunner(provider=provider, model="m").run(
        _DIFF,
        vulnerabilities="Review ownership boundaries.",
        context=context,
    )

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

    result = run_diff_review(diff, provider=provider, model="m")

    assert [(f.description, f.line) for f in result.outcome.findings] == [("unguarded sink", 31)]
    assert result.outcome.findings[0].file == "b/app.py"
    assert [(f.description, f.line) for f in result.outcome.incomplete] == [("unguarded route", 45)]
    assert result.dropped == []
    assert result.outcome.degraded is True


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
    provider = MockProvider(
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


def test_diff_unit_normalizes_an_added_finding_location_over_a_weaker_anchor():
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

    assert result.incomplete is False
    assert result.finding.change_anchor == ChangeAnchor(file="a.py", line=1, side="new")


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
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "sql-injection", "entrypoint": "changed code path", "description": "old sink", '
            '"exploit_scenario": "attacker input reaches the vulnerable operation", "confidence": 0.9, '
            '"evidence_refs": ["seed"]}]}'
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    result = run_diff_review(diff, provider=provider, model="m")

    assert result.outcome.findings == ()
    assert [(finding.file, finding.line) for finding in result.outcome.incomplete] == [("app.py", 1)]
    assert result.outcome.degraded is True


def test_audit_diff_whitespace_only_diff_is_clean_without_a_model_call():
    provider = MockProvider(default='{"findings": []}')
    kept, dropped, degraded = audit_diff("   \n", provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []


def test_audit_diff_does_not_send_noise_files_to_the_model():
    provider = MockProvider(default='{"findings": []}')
    audit_diff(_SRC + _DOC, provider=provider, model="m")
    sent = "\n".join(m.content for call in provider.calls for m in call["messages"])
    assert "app.py" in sent
    assert "README.md" not in sent


def test_audit_diff_passes_context_to_the_runner():
    provider = MockProvider(default='{"findings": []}')
    audit_diff(
        _SRC,
        provider=provider,
        model="m",
        prepare_diff=repository_prepare("def get_client(): return per_user_token"),
    )
    sent = provider.calls[0]["messages"][0].content
    assert "def get_client()" in sent
    assert "per_user_token" in sent


def test_audit_diff_docs_only_diff_is_clean_without_a_model_call():
    reply = _reply([{"file": "README.md", "line": 1, "severity": "HIGH", "description": "x", "confidence": 0.9}])
    provider = MockProvider(default=reply)
    kept, dropped, degraded = audit_diff(_DOC + _LOCK, provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []


_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _finder(findings):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        finding.setdefault("description", "concrete exploitable path")
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        finding.setdefault("exploit_scenario", "attacker input reaches the vulnerable operation")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps({"findings": findings})


def _challenger(rebuttals=None, new_findings=None):
    for finding in new_findings or []:
        finding.setdefault("evidence_refs", ["seed"])
        finding.setdefault("description", "concrete exploitable path")
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        finding.setdefault("exploit_scenario", "attacker input reaches the vulnerable operation")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps({"rebuttals": rebuttals or [], "new_findings": new_findings or []})


def _judge(
    findings,
    investigate=None,
    converged=False,
    *,
    categories=("sql-injection",),
    established_categories=(),
):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        finding.setdefault("description", "concrete exploitable path")
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        finding.setdefault("exploit_scenario", "attacker input reaches the vulnerable operation")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps(
        {
            "findings": findings,
            "assessments": _assessments(
                categories,
                [*findings, *({"category": category} for category in established_categories)],
            ),
            "investigate": investigate or [],
            "converged": converged,
        }
    )


_VULN = {
    "file": "app.py",
    "line": 1,
    "severity": "CRITICAL",
    "category": "sql-injection",
    "description": "concat",
    "confidence": 0.95,
    "evidence_refs": ["seed"],
}


def _candidate_id(finding):
    line = finding["line"]
    return candidate_identity(
        target="diff",
        file=finding["file"],
        line=line,
        category=finding["category"],
        path_anchor=finding.get("entrypoint", "changed code path"),
        anchor=(finding["file"], line, "new"),
    )


def _run(responses, **kw):
    provider = MockProvider(responses=responses, default="{}")
    if kw.get("max_rounds") == 1:
        kw.pop("max_rounds")
        kw["plan"] = review_plan("adversarial", max_rounds=1, converge_after=1)
    out = AdversarialAuditRunner(provider=provider, model="m").run(_DIFF, **kw)
    return provider, out


_ONE_ROUND = review_plan("adversarial", max_rounds=1, converge_after=1)


def test_three_roles_run_in_order_one_round():
    provider, out = _run([_finder([_VULN]), _challenger(), _judge([_VULN])], plan=_ONE_ROUND)
    assert len(provider.calls) == 3
    assert [c["system"] for c in provider.calls] == [FINDER_SYSTEM, CHALLENGER_SYSTEM, JUDGE_SYSTEM]
    assert len(out.findings) == 1
    assert out.findings[0].category == "sql-injection"
    assert out.rounds == 1


def test_standard_and_adversarial_use_the_same_bounded_knowledge_packs():
    items = tuple(
        Vulnerability(
            id=f"class-{index}",
            title=f"Class {index}",
            impact="HIGH",
            tags=("test",),
            aliases=(),
            selection_hints=("cursor.execute",),
            body=f"GUIDANCE-{index}",
        )
        for index in range(5)
    )
    catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )
    first_categories = tuple(f"class-{index}" for index in range(4))
    second_categories = ("class-4",)
    standard_provider = MockProvider(
        responses=[
            _reply([], categories=first_categories),
            _reply([], categories=second_categories),
        ]
    )
    standard = AuditRunner(provider=standard_provider, model="m")
    standard._vulnerability_catalog = catalog
    standard.review_round(_DIFF, finder_label="finder")

    adversarial_provider = MockProvider(
        responses=[
            _finder([]),
            _challenger(),
            _judge([], categories=first_categories),
            _finder([]),
            _challenger(),
            _judge([], categories=second_categories),
        ]
    )
    adversarial = AdversarialAuditRunner(provider=adversarial_provider, model="m")
    adversarial._vulnerability_catalog = catalog
    adversarial.run(_DIFF, plan=_ONE_ROUND)

    standard_prompts = [call["messages"][0].content for call in standard_provider.calls]
    adversarial_prompts = [call["messages"][0].content for call in adversarial_provider.calls]
    assert len(standard_prompts) == 2
    assert len(adversarial_prompts) == 6
    assert "GUIDANCE-4" not in standard_prompts[0]
    assert all("GUIDANCE-4" not in prompt for prompt in adversarial_prompts[:3])
    assert "GUIDANCE-4" in standard_prompts[1]
    assert all("GUIDANCE-4" in prompt for prompt in adversarial_prompts[3:])


def test_adversarial_finder_evidence_is_visible_to_later_roles():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:20",
        label="policy.py:Policy, import Policy from app.py [supported]",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            json.dumps({"findings": [], "evidence_requests": [evidence.id]}),
            _finder([_VULN]),
            _challenger(),
            _judge([_VULN]),
        ]
    )
    context = GroundingContext(text="initial source", source="diff", evidence=(evidence,))

    out = AdversarialAuditRunner(provider=provider, model="m").run(
        _DIFF,
        context=context,
        plan=_ONE_ROUND,
    )

    assert len(provider.calls) == 4
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert all(evidence.text in call["messages"][0].content for call in provider.calls[1:])
    assert out.grounding.included == (evidence.identity,)


def test_adversarial_challenger_can_request_exact_evidence():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:40",
        label="policy.py:Policy",
        text="1 | class Policy:\n2 |     owner = None",
    )
    missed = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "insecure-direct-object-reference",
        "description": "the route does not scope the object owner",
        "confidence": 0.9,
        "evidence_refs": ["seed", evidence.id],
    }
    provider = MockProvider(
        responses=[
            _finder([]),
            json.dumps(
                {
                    "rebuttals": [],
                    "new_findings": [],
                    "evidence_requests": [evidence.id],
                }
            ),
            _challenger(new_findings=[missed]),
            _judge([missed]),
        ]
    )

    out = AdversarialAuditRunner(provider=provider, model="m").run(
        _DIFF,
        context=GroundingContext(text="seed", evidence=(evidence,)),
        plan=_ONE_ROUND,
    )

    assert [finding.category for finding in out.findings] == ["insecure-direct-object-reference"]
    assert evidence.text not in provider.calls[1]["messages"][0].content
    assert all(evidence.text in call["messages"][0].content for call in provider.calls[2:])


def test_adversarial_judge_can_request_exact_evidence():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:40",
        label="policy.py:Policy",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            _finder([_VULN]),
            _challenger(),
            json.dumps(
                {
                    "findings": [],
                    "assessments": [
                        {
                            "category": "sql-injection",
                            "decision": "insufficient_evidence",
                            "reason": "the policy implementation must be read before judgment",
                            "evidence_refs": [evidence.id],
                        }
                    ],
                    "evidence_requests": [evidence.id],
                }
            ),
            _judge([_VULN]),
        ]
    )

    out = AdversarialAuditRunner(provider=provider, model="m").run(
        _DIFF,
        context=GroundingContext(text="seed", evidence=(evidence,)),
        plan=_ONE_ROUND,
    )

    assert [finding.category for finding in out.findings] == ["sql-injection"]
    assert evidence.text not in provider.calls[2]["messages"][0].content
    assert evidence.text in provider.calls[3]["messages"][0].content


def test_judge_dismissal_cannot_delete_a_finding_before_verification():
    second = {**_VULN, "line": 5, "category": "cross-site-scripting"}
    _, out = _run(
        [
            _finder([_VULN, second]),
            _challenger(
                rebuttals=[
                    {
                        "candidate_id": _candidate_id(second),
                        "disposition": "dispute",
                        "reason": "output is escaped",
                        "evidence_refs": ["seed"],
                    }
                ]
            ),
            _judge([_VULN]),
        ],
        plan=_ONE_ROUND,
    )
    assert [f.category for f in out.findings] == ["sql-injection", "cross-site-scripting"]


def test_challenger_independent_finding_can_survive():
    missed = {
        "file": "app.py",
        "line": 9,
        "severity": "HIGH",
        "category": "insecure-direct-object-reference",
        "confidence": 0.8,
    }
    _, out = _run(
        [_finder([]), _challenger(new_findings=[missed]), _judge([missed])],
        plan=_ONE_ROUND,
    )
    assert [f.category for f in out.findings] == ["insecure-direct-object-reference"]
    assert out.findings[0].found_by == ("m",)


def test_adversarial_findings_record_the_role_that_found_them():
    """Per finding provenance lets verification skip the finding seat."""
    missed = {
        "file": "app.py",
        "line": 9,
        "severity": "HIGH",
        "category": "insecure-direct-object-reference",
        "confidence": 0.8,
    }
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(new_findings=[missed]), _judge([_VULN, missed])])
    out = AdversarialAuditRunner(
        provider=provider,
        model="base",
        finder_model="finder",
        challenger_model="challenger",
        judge_model="judge",
    ).run(_DIFF, plan=_ONE_ROUND)
    labels = {finding.category: finding.found_by for finding in out.findings}
    assert labels == {
        "sql-injection": ("finder",),
        "insecure-direct-object-reference": ("challenger",),
    }


def test_judge_converged_flag_does_not_stop_the_deterministic_loop():
    """Convergence is a coded property rather than a model supplied verdict."""
    round_triplet = [_finder([_VULN]), _challenger(), _judge([_VULN], converged=True)]
    provider, out = _run(round_triplet * 3, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 3
    assert len(provider.calls) == 9


def test_converged_flag_ignored_while_investigate_pending():
    r1 = [
        _finder([_VULN]),
        _challenger(),
        _judge(
            [_VULN],
            converged=True,
            investigate=[
                {
                    "kind": "runtime_check",
                    "question": "Can the unsafe operation be reached at runtime?",
                    "required_evidence": ["sandbox execution result"],
                    "candidate_id": _candidate_id(_VULN),
                }
            ],
        ),
    ]
    provider, out = _run(r1 + r1, max_rounds=2)
    assert out.rounds == 2
    assert len(provider.calls) == 6


def test_judge_downgrade_lowers_finding_severity():
    _, out = _run(
        [_finder([_VULN]), _challenger(), _judge([{**_VULN, "severity": "MEDIUM"}])],
        plan=_ONE_ROUND,
    )
    assert out.findings[0].severity == "MEDIUM"


def test_investigate_items_are_carried():
    _, out = _run(
        [
            _finder([]),
            _challenger(),
            _judge(
                [],
                investigate=[
                    {
                        "kind": "runtime_check",
                        "question": "Is the path reachable at runtime?",
                        "required_evidence": ["sandbox execution result"],
                    }
                ],
            ),
        ],
        plan=_ONE_ROUND,
    )
    assert [(i["kind"], i["question"]) for i in out.investigate] == [
        ("runtime_check", "Is the path reachable at runtime?")
    ]


def test_missing_source_items_are_pending_and_prevent_completion():
    """A Judge uncertainty remains visible instead of looking like a clean empty result."""
    _, out = _run(
        [
            _finder([]),
            _challenger(),
            _judge(
                [],
                investigate=[
                    {
                        "kind": "missing_source",
                        "question": "Which control guards app.py:3?",
                        "required_evidence": ["guard definition and caller"],
                    }
                ],
            ),
        ],
        plan=_ONE_ROUND,
    )

    assert out.pending[0]["kind"] == "missing_source"
    assert out.pending[0]["question"] == "Which control guards app.py:3?"
    assert out.pending[0]["required_evidence"] == ["guard definition and caller"]
    assert out.pending[0]["id"].startswith("pending-")
    assert out.complete is False


def test_converges_when_confirmed_set_stable():
    rounds = [_finder([_VULN]), _challenger(), _judge([_VULN])] * 3
    provider, out = _run(rounds, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 3
    assert len(provider.calls) == 9


def test_runs_to_max_rounds_when_unstable():
    """An unstable run reaches its cap and remains visibly incomplete."""
    r1 = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    r2 = [_finder([_VULN]), _challenger(), _judge([{**_VULN, "line": 7}])]
    provider, out = _run(r1 + r2, max_rounds=2)
    assert out.converged is False
    assert out.rounds == 2
    assert out.degraded is True
    assert out.failure_reason == "adversarial review did not converge within 2 rounds"
    assert len(provider.calls) == 6


def test_later_round_omission_does_not_delete_a_prior_finding():
    """The union keeps earlier candidates unless coded verification removes them."""
    first = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    later = [_finder([]), _challenger(), _judge([], established_categories=("sql-injection",))]
    _, out = _run(first + later + later, max_rounds=3)
    assert [f.category for f in out.findings] == ["sql-injection"]
    assert out.converged is True


def test_garbage_replies_yield_no_findings_and_degrade():
    """Malformed role output is incomplete work, not a clean empty review."""
    _, out = _run(["junk", "junk", "junk"], plan=_ONE_ROUND)
    assert out.findings == ()
    assert out.degraded is True


def test_unusable_judge_falls_back_to_finder_findings_not_empty():
    _, out = _run([_finder([_VULN]), _challenger(), "<html>blocked by WAF</html>"], plan=_ONE_ROUND)
    assert [f.category for f in out.findings] == ["sql-injection"]
    assert out.degraded is True
    assert out.converged is False


def test_unusable_judge_includes_challenger_independent_findings():
    missed = {
        "file": "a.py",
        "line": 9,
        "severity": "HIGH",
        "category": "insecure-direct-object-reference",
        "confidence": 0.8,
    }
    _, out = _run([_finder([]), _challenger(new_findings=[missed]), "not json"], plan=_ONE_ROUND)
    assert [f.category for f in out.findings] == ["insecure-direct-object-reference"]
    assert out.degraded is True


def test_audit_diff_surfaces_degraded_on_unusable_judge():
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(), "not json", "not json"], default="{}")
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="adversarial")
    assert degraded is True
    assert [f.category for f in kept] == ["sql-injection"]


def test_audit_diff_records_adversarial_role_failure_reason():
    """Adversarial batch failures name the role that failed."""
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(), "not json"], default="{}")
    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=_options(roles=DiffRoleOptions(mode="adversarial")),
    )

    assert result.outcome.degraded is True
    assert [f.category for f in result.outcome.findings] == ["sql-injection"]
    assert result.outcome.failures[0].reason == (
        "RoleResponseError: adversarial judge reply had no usable JSON object with required fields: findings "
        "[knowledge judgment 1/1 for sql-injection]"
    )


def test_audit_diff_standard_mode_is_never_degraded():
    provider = MockProvider(default=_reply([_VULN]))
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="standard")
    assert degraded is False
    assert len(kept) == 1


def test_provider_exception_degrades_rather_than_crashes():
    from cyberjury.providers.base import CompletionResult, Provider

    class _RaiseOnJudge(Provider):
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return CompletionResult(text=_finder([_VULN]))
            if self.calls == 2:
                return CompletionResult(text=_challenger())
            raise RuntimeError("provider down")

    out = AdversarialAuditRunner(provider=_RaiseOnJudge(), model="m").run(_DIFF, plan=_ONE_ROUND)
    assert [f.category for f in out.findings] == ["sql-injection"]
    assert out.degraded is True


def test_judge_unparseable_reply_does_not_run_an_extra_role_retry():
    """Provider retry owns transient recovery, so the role loop does not parse retry."""
    provider, out = _run([_finder([_VULN]), _challenger(), "blocked by waf", _judge([_VULN])], plan=_ONE_ROUND)
    assert out.degraded is True
    assert [f.category for f in out.findings] == ["sql-injection"]
    assert len(provider.calls) == 3


def test_degraded_fallback_preserves_challenger_dismissed_findings():
    """A failed judge cannot let a challenger-only dismissal delete candidates."""
    second = {**_VULN, "line": 5, "category": "cross-site-scripting"}
    _, out = _run(
        [
            _finder([_VULN, second]),
            _challenger(
                rebuttals=[
                    {
                        "candidate_id": _candidate_id(second),
                        "disposition": "dispute",
                        "reason": "output is escaped",
                        "evidence_refs": ["seed"],
                    }
                ]
            ),
            "blocked",
            "blocked",
        ],
        plan=_ONE_ROUND,
    )
    assert out.degraded is True
    assert [f.category for f in out.findings] == ["sql-injection", "cross-site-scripting"]


def test_per_role_models_are_used():
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(
        provider=provider,
        model="base",
        finder_model="finder-m",
        challenger_model="challenger-m",
        judge_model="judge-m",
    ).run(_DIFF, plan=_ONE_ROUND)
    assert [c["model"] for c in provider.calls] == ["finder-m", "challenger-m", "judge-m"]


def test_role_models_default_to_base():
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(provider=provider, model="base").run(_DIFF, plan=_ONE_ROUND)
    assert [c["model"] for c in provider.calls] == ["base", "base", "base"]


def test_prompts_carry_role_context():
    assert "red-team" not in finder_prompt(_DIFF)
    assert "SELECT * FROM u" in finder_prompt(_DIFF, stack="STACK-NOTE")
    assert "STACK-NOTE" in finder_prompt(_DIFF, stack="STACK-NOTE")
    fp = challenger_prompt(_DIFF, [_VULN])
    assert "rebuttal" in fp
    assert "Independently" in fp
    assert "sql-injection" in fp
    assert "STACK-NOTE" in challenger_prompt(_DIFF, [_VULN], stack="STACK-NOTE")
    jp = judge_prompt(_DIFF, [_VULN], [], [], do_not_report="POLICY")
    assert "Finder findings" in jp
    assert "Challenger" in jp
    assert "POLICY" in jp
    assert "parameterized" not in jp
    assert "os.path.basename" not in jp


def test_finder_describes_only_the_prior_evidence_it_receives():
    prompt = finder_prompt(_DIFF, prior=[_VULN])

    assert "Reassess them against the current code and evidence" in prompt
    assert "rebuttals" not in prompt


def test_runner_feeds_stack_to_finder_and_challenger_and_policy_to_judge():
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([], converged=True)], default="{}")
    AdversarialAuditRunner(provider=provider, model="m", do_not_report="POLICY").run(
        _DIFF, stack="STACK-NOTE", plan=_ONE_ROUND
    )
    prompts = [c["messages"][0].content for c in provider.calls]
    assert "STACK-NOTE" in prompts[0]
    assert "STACK-NOTE" in prompts[1]
    assert "STACK-NOTE" not in prompts[2]
    assert "POLICY" in prompts[0]
    assert "POLICY" in prompts[1]
    assert "POLICY" in prompts[2]


def test_adversarial_diff_passes_cache_prefixes_before_diff_body():
    provider, _out = _run([_finder([]), _challenger(), _judge([], converged=True)], plan=_ONE_ROUND)
    for call in provider.calls:
        prompt = call["messages"][0].content
        prefix = call["cache_prefix"]
        assert call["cache"] is True
        assert prompt.startswith(prefix)
        assert "Code change (unified diff):" in prefix
        assert "WHERE n=' + name" not in prefix


class _RoleProvider:
    """Records role routing inputs while returning a fixed reply."""

    def __init__(self, reply):
        self._reply = reply
        self.systems = []
        self.models = []

    def complete(self, *, system, messages, model, max_tokens, cache=False, cache_prefix=""):
        import types

        self.systems.append(system)
        self.models.append(model)
        return types.SimpleNamespace(text=self._reply)


def test_adversarial_routes_each_role_to_its_own_provider():
    finder_p = _RoleProvider(_finder([_VULN]))
    challenger_p = _RoleProvider(_challenger())
    judge_p = _RoleProvider(_judge([_VULN], converged=True))
    base = MockProvider(default="{}")
    runner = AdversarialAuditRunner(
        provider=base,
        model="base-model",
        finder_provider=finder_p,
        finder_model="finder-m",
        challenger_provider=challenger_p,
        challenger_model="challenger-m",
        judge_provider=judge_p,
        judge_model="judge-m",
    )
    runner.run(_DIFF, plan=_ONE_ROUND)
    assert finder_p.systems == [FINDER_SYSTEM]
    assert finder_p.models == ["finder-m"]
    assert challenger_p.systems == [CHALLENGER_SYSTEM]
    assert challenger_p.models == ["challenger-m"]
    assert judge_p.systems == [JUDGE_SYSTEM]
    assert judge_p.models == ["judge-m"]


def test_finder_unparseable_reply_degrades_not_clean_pass():
    runner = AdversarialAuditRunner(provider=MockProvider(default="not json at all"), model="m")
    res = runner.run(_DIFF, max_rounds=2)
    assert res.degraded is True


def test_challenger_unparseable_reply_degrades():
    """Finder candidates survive when the challenger cannot produce a usable rebuttal."""
    runner = AdversarialAuditRunner(
        provider=MockProvider(default="{}"),
        model="m",
        finder_provider=_RoleProvider(_finder([_VULN])),
        finder_model="f",
        challenger_provider=_RoleProvider("not json"),
        challenger_model="c",
        judge_provider=_RoleProvider(_judge([_VULN], converged=True)),
        judge_model="j",
    )
    res = runner.run(_DIFF, plan=_ONE_ROUND)
    assert res.degraded is True
    assert [f.category for f in res.findings] == ["sql-injection"]


def test_challenger_reply_missing_independent_findings_is_incomplete():
    """Diff Review uses the shared complete Challenger response contract."""
    runner = AdversarialAuditRunner(
        provider=MockProvider(default="{}"),
        model="m",
        finder_provider=_RoleProvider(_finder([_VULN])),
        challenger_provider=_RoleProvider('{"rebuttals": []}'),
        judge_provider=_RoleProvider(_judge([_VULN])),
    )

    result = runner.run(_DIFF, plan=_ONE_ROUND)

    assert result.degraded is True
    assert [finding.category for finding in result.findings] == ["sql-injection"]
    assert "new_findings" in result.failure_reason
