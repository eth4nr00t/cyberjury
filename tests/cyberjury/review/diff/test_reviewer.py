"""Diff reviewers parse responses and reuse evidence across knowledge packs."""

import json

import pytest

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext
from cyberjury.review.diff.engine import (
    DiffGroundingOptions,
    DiffReviewOptions,
    run_diff_review,
)
from cyberjury.review.diff.prompts import SYSTEM, standard_audit_prompt, standard_audit_prompt_plan
from cyberjury.review.diff.reviewer import AdversarialAuditRunner, AuditError, AuditRunner
from cyberjury.review.navigation import SourceNavigator, SourceTarget, navigation_instructions
from cyberjury.review.vulnerabilities import Vulnerability, VulnerabilityCatalog
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


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
        finding.setdefault("recommendation", "enforce the missing security control")
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps({"findings": findings, "assessments": _assessments(categories, findings)})


def _judge_reply(*, categories=("sql-injection",), investigate=None):
    return json.dumps(
        {
            "findings": [],
            "assessments": _assessments(categories, []),
            "investigate": investigate or [],
        }
    )


def test_engine_parses_findings():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 3,
                "severity": "CRITICAL",
                "category": "sql_injection",
                "description": "string-concatenated query",
                "confidence": 0.95,
            },
        ]
    )
    provider = MockProvider(default=reply)
    out = AuditRunner(provider=provider, model="m").run(_DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql-injection"
    assert "```\n\nRepository grounding controls:\n" in provider.calls[0]["messages"][0].content


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

    with pytest.raises(AuditError, match="candidate_id does not match"):
        AuditRunner(provider=MockProvider(default=json.dumps({"findings": [finding]})), model="m").run(_DIFF)


def test_diff_review_reports_a_malformed_finding_as_failed_work():
    provider = MockProvider(default='{"findings": [{"severity": "HIGH"}]}')

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
    assert "must name a source file" in result.outcome.failures[0].reason


def test_diff_review_reports_a_malformed_change_anchor_as_failed_work():
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, '
            '"change_anchor": {"file": "app.py", "line": 1, "side": "context"}}]}'
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
    assert "change_anchor is malformed" in result.outcome.failures[0].reason


def test_engine_empty_on_no_findings():
    assert AuditRunner(provider=MockProvider(default=_reply([])), model="m").run(_DIFF) == []


def test_engine_raises_on_unparseable_reply():

    from cyberjury.review.diff.reviewer import AuditError

    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default="not json"), model="m").run(_DIFF)
    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default=""), model="m").run(_DIFF)


def test_engine_raises_on_wrong_shape_json():

    from cyberjury.review.diff.reviewer import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError, match="failed audit"):
            AuditRunner(provider=MockProvider(default=bad), model="m").run(_DIFF)


@pytest.mark.parametrize("reply", ['{"findings": [', '```json\n{"findings": [\n```'])
def test_engine_rejects_a_truncated_findings_array(reply):
    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default=reply), model="m").run(_DIFF)


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
    with pytest.raises(AuditError, match="severity is invalid"):
        AuditRunner(provider=MockProvider(default=reply), model="m").run(_DIFF)


def test_guides_for_diff_selects_by_path_and_content():
    from cyberjury.review.diff.reviewer import guides_for_diff

    diff = "diff --git a/app/urls.py b/app/urls.py\n+from django.urls import path\n+urlpatterns = []\n"
    notes = guides_for_diff(diff)
    assert "Django" in notes
    assert "Python" in notes
    assert guides_for_diff("+++ b/README.md\n+hello\n") == ""


def test_guides_for_diff_preserves_a_source_path_with_spaces():
    from cyberjury.review.diff.reviewer import guides_for_diff

    diff = "diff --git a/app route.py b/app route.py\n+++ b/app route.py\n+def route(): pass\n"

    assert "Python" in guides_for_diff(diff)


def test_standard_diff_audit_avoids_a_single_use_cache_write():
    """A lone standard judgment has no later call that can reuse its prefix."""
    provider = MockProvider(default=_reply([], categories=()))
    AuditRunner(provider=provider, model="m").run(_DIFF, vulnerabilities="VULN-X")
    call = provider.calls[0]
    prompt = call["messages"][0].content
    assert call["cache"] is False
    assert call["cache_prefix"] == ""
    assert "VULN-X" in prompt
    assert "SELECT * FROM u" in prompt


def test_standard_diff_audit_selects_vulnerabilities_from_context():
    """Repository evidence must influence knowledge selection even when the patch lacks the signal."""
    provider = MockProvider(default=_reply([], categories=("insecure-cryptography", "hardcoded-secrets")))
    diff = "+++ b/app.py\n@@ -0,0 +1 @@\n+token = make_token()\n"
    AuditRunner(provider=provider, model="m").run(diff, context="def make_token():\n    return uuid.uuid1().hex\n")

    prompt = provider.calls[0]["messages"][0].content

    assert "UUIDv1 is not a secret generator" in prompt
    assert "Exhaustively review the evidence for this assigned vulnerability class pack:" in prompt
    assert "insecure-cryptography" in prompt
    assert prompt.index("Exhaustively review") > prompt.index("Surrounding code")


def test_standard_diff_audit_preserves_recall_across_selected_class_packs():
    """Each judgment may report established findings outside its assigned class pack."""
    prompt = standard_audit_prompt(
        _DIFF,
        vulnerabilities="alpha guidance",
        vulnerability_categories=("alpha",),
        selected_vulnerability_categories=("alpha", "beta"),
    )

    assert "selected classes also have assigned judgments:\nbeta" in prompt
    assert "Deterministic union handles duplicates" in prompt
    assert "Report any real vulnerability already established" in prompt


def test_standard_diff_prompt_allows_navigation_without_invented_evidence_ids():
    prompt = standard_audit_prompt_plan(
        _DIFF,
        context_controls=navigation_instructions(),
    ).text

    assert "Use `source_queries` only to search" in prompt
    assert "`evidence_requests`" in prompt
    assert "do not request paths or symbols" not in prompt


def test_general_diff_judgment_requires_an_empty_assessment_list():
    prompt = standard_audit_prompt_plan(_DIFF).text

    assert '"assessments": []' in prompt
    assert '"category": "assigned class id"' not in prompt
    assert "No class ids are assigned to this exploratory judgment" in prompt


def test_standard_diff_audit_reuses_evidence_across_knowledge_packs():
    """Every selected pack sees identical diff evidence before its changing guidance."""
    provider = MockProvider(
        responses=[
            _reply([], categories=("alpha",)),
            _reply([], categories=("beta",)),
        ]
    )
    runner = AuditRunner(provider=provider, model="m")
    items = tuple(
        Vulnerability(
            id=name,
            title=name,
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(name,),
            body=name * 2_000,
        )
        for name in ("alpha", "beta")
    )
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    cycle = runner.review_round("+++ b/app.py\n+alpha beta\n", finder_label="finder")

    assert cycle.clean is True
    assert len(provider.calls) == 2
    assert all(call["cache"] is True for call in provider.calls)
    prefixes = [call["cache_prefix"] for call in provider.calls]
    assert prefixes[0] == prefixes[1]
    assert "alpha beta" in prefixes[0]
    assert "alphaalpha" not in prefixes[0]
    assert "alphaalpha" in provider.calls[0]["messages"][0].content
    assert "betabeta" in provider.calls[1]["messages"][0].content


def test_standard_diff_carries_compact_candidate_memory_between_knowledge_packs():
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "alpha",
        "description": "long first pack description that must not be repeated",
        "exploit_scenario": "a long exploit path that the next pack does not need",
        "recommendation": "a long remediation that the next pack does not need",
        "confidence": 0.9,
    }
    provider = MockProvider(
        responses=[
            _reply([finding], categories=("alpha",)),
            _reply([], categories=("beta",)),
        ]
    )
    runner = AuditRunner(provider=provider, model="m")
    items = tuple(
        Vulnerability(
            id=name,
            title=name,
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(name,),
            body=name * 2_000,
        )
        for name in ("alpha", "beta")
    )
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    cycle = runner.review_round("+++ b/app.py\n+alpha beta\n", finder_label="finder")

    assert cycle.clean is True
    assert len(cycle.findings) == 1
    second_prompt = provider.calls[1]["messages"][0].content
    assert cycle.findings[0].candidate_id in second_prompt
    assert finding["description"] not in second_prompt
    assert finding["exploit_scenario"] not in second_prompt
    assert finding["recommendation"] not in second_prompt


def test_diff_knowledge_selection_uses_exact_repository_evidence():
    provider = MockProvider(default=_reply([], categories=("sensitive-operation",)))
    runner = AuditRunner(provider=provider, model="m")
    item = Vulnerability(
        id="sensitive-operation",
        title="Sensitive Operation",
        impact="HIGH",
        tags=(),
        aliases=(),
        selection_hints=("sensitive_operation",),
        body="Review the complete sensitive operation path.",
    )
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=(item,),
        ids=frozenset({item.id}),
        aliases={},
    )
    evidence = EvidenceItem.create(
        identity="app.py:handler:10:40",
        label="app.py:handler",
        text="def handler():\n    return sensitive_operation()\n",
        preview="def handler():",
    )

    cycle = runner.review_round(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+def handler(): ...\n",
        context=GroundingContext(text="initial context", source="repository", evidence=(evidence,)),
        finder_label="finder",
    )

    assert cycle.clean is True
    assert "Review the complete sensitive operation path." in provider.calls[0]["messages"][0].content


def test_diff_navigation_reselects_knowledge_and_runs_a_stable_final_sweep(tmp_path):
    source = "class ModelWithOwner:\n    owner_scope = True\n"
    target_id = SourceTarget.create(
        file="models.py",
        name="ModelWithOwner",
        start=0,
        end=len(source),
        preview="class ModelWithOwner:",
    ).id
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"models.py": {"ModelWithOwner": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    provider = MockProvider(
        responses=[
            json.dumps(
                {
                    "findings": [],
                    "assessments": _assessments(("initial-class",), []),
                    "evidence_requests": [],
                    "source_queries": [{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
                }
            ),
            json.dumps(
                {
                    "findings": [],
                    "assessments": [
                        {
                            "category": "initial-class",
                            "decision": "insufficient_evidence",
                            "reason": "the discovered definition must be read",
                            "evidence_refs": [target_id],
                        }
                    ],
                    "evidence_requests": [target_id],
                    "source_queries": [],
                }
            ),
            _reply([], categories=("initial-class",)),
            _reply([], categories=("owner-class",)),
        ]
    )
    runner = AuditRunner(provider=provider, model="m")
    items = (
        Vulnerability(
            id="initial-class",
            title="Initial Class",
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=("initial_signal",),
            body="Initial guidance. " * 1_000,
        ),
        Vulnerability(
            id="owner-class",
            title="Owner Class",
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=("owner_scope",),
            body="Owner scope guidance. " * 1_000,
        ),
    )
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    cycle = runner.review_round(
        "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n",
        context=GroundingContext(text="seed", source="repository", navigator=navigator),
        finder_label="finder",
    )

    assert cycle.clean is True
    assert len(provider.calls) == 4
    assert provider.calls[0]["system"] == SYSTEM
    assert "Initial guidance." in provider.calls[0]["messages"][0].content
    assert "Owner scope guidance." not in provider.calls[0]["messages"][0].content
    assert "Evidence request budget: 8 request batches remain" in provider.calls[0]["messages"][0].content
    audit_prompts = [call["messages"][0].content for call in provider.calls[3:]]
    assert "Evidence request budget: 6 request batches remain" in audit_prompts[0]
    final_prompt = provider.calls[-1]["messages"][0].content
    assert "Owner scope guidance." in final_prompt
    assert "owner_scope = True" in final_prompt


def test_adversarial_diff_knowledge_selection_uses_exact_repository_evidence():
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            _judge_reply(categories=("server-side-request-forgery",)),
        ]
    )
    evidence = EvidenceItem.create(
        identity="client.py:fetch:0:40",
        label="client.py:fetch",
        text="def fetch(url):\n    return requests.get(url)\n",
        preview="def fetch(url):",
    )
    context = GroundingContext(text="def dispatch(): return send_webhook()", evidence=(evidence,))

    cycle = AdversarialAuditRunner(provider=provider, model="m").review_round(
        "+++ b/handlers.py\n@@ -0,0 +1 @@\n+return send_webhook()\n",
        context=context,
    )

    assert cycle.clean is True
    assert all("Server-Side Request Forgery" in call["messages"][0].content for call in provider.calls[:2])


def test_adversarial_diff_rejects_a_malformed_rebuttal_item():
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": ["not an object"], "new_findings": []}',
        ]
    )

    cycle = AdversarialAuditRunner(provider=provider, model="m").review_round(_DIFF)

    assert cycle.clean is False
    assert cycle.errors == 1
    assert "rebuttals[0] must be an object" in cycle.failure_reason


def test_adversarial_diff_rejects_a_malformed_pending_item():
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            _judge_reply(investigate=["not an object"]),
        ]
    )

    cycle = AdversarialAuditRunner(provider=provider, model="m").review_round(_DIFF)

    assert cycle.clean is False
    assert cycle.errors == 1
    assert "investigate[0] must be an object" in cycle.failure_reason


def test_adversarial_diff_does_not_republish_prior_round_evidence_ids():
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            _judge_reply(),
        ]
    )
    prior = Finding(
        file="app.py",
        line=1,
        category="sql-injection",
        description="prior finding",
        evidence_refs=("src-prior-round",),
    )

    AdversarialAuditRunner(provider=provider, model="m").review_round(_DIFF, known=[prior])

    assert "prior finding" in provider.calls[0]["messages"][0].content
    assert all("src-prior-round" not in call["messages"][0].content for call in provider.calls)


def test_audit_runner_sends_the_severity_rubric():
    provider = MockProvider(default=_reply([]))
    AuditRunner(provider=provider, model="m").run(_DIFF)
    sent = provider.calls[0]["messages"][0].content
    assert "Grade each finding's severity on this rubric" in sent
    assert "Severity Rubric" in sent
