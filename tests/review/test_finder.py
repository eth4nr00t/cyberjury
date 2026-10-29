"""The shared finder parses replies, prompts with a cacheable contract, and exchanges evidence for any target."""

import json

import pytest

from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.review.context import EvidenceItem, GroundingContext, SourceSpan
from cyberjury.review.finder import findings_from_reply
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.replies import CorrectableRoleResponseError
from cyberjury.review.repository.model import RepositoryUnit
from tests.review.diff import support as diff
from tests.review.repository import support as repository
from tests.review.support import navigator_from_definitions
from tests.support import MockProvider


def _unit(name, grounding, root="."):
    return RepositoryUnit(name=name, root=str(root), file=name, span=(0, 0), grounding=grounding)


def _diff_findings(provider, diff_text=diff.SQL_DIFF, *, context=""):
    cycle = diff.finder(provider).review_unit(diff.diff_unit(diff_text, context))
    if not cycle.clean:
        raise RuntimeError(cycle.failure_reason)
    return cycle.findings


def _model_navigator(root):
    source = "class ModelWithOwner:\n    owner_scope = True\n"
    (root / "models.py").write_text(source, encoding="utf-8")
    return navigator_from_definitions(root, {"models.py": {"ModelWithOwner": [(0, len(source))]}})


def test_finder_parses_findings_and_canonicalizes_the_category():
    """A CRITICAL sql_injection reply yields one finding with category normalized to sql-injection."""
    response = diff.reply(
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
    out = _diff_findings(MockProvider(responses=[response]))
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql-injection"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"title": "  "}, r"findings\[0\] must have nonempty fields: title"),
        ({"evidence": ""}, r"findings\[0\] must have nonempty fields: evidence"),
        ({"evidence": "  "}, r"findings\[0\] must have nonempty fields: evidence"),
        ({"file": "../outside.py"}, r"findings\[0\]\.file must be a relative repository path"),
        ({"file": "/etc/app.py"}, r"findings\[0\]\.file must be a relative repository path"),
        ({"line": 0}, r"findings\[0\]\.line must be a positive integer"),
        ({"evidence_refs": []}, r"findings\[0\]\.evidence_refs must be a nonempty string list"),
        ({"evidence_refs": [""]}, r"findings\[0\]\.evidence_refs must be a nonempty string list"),
        (
            {"change_anchor": {"file": "app.py", "line": 0, "side": "new"}},
            r"findings\[0\]\.change_anchor must name a nonempty file and a positive line",
        ),
    ],
)
def test_findings_from_reply_requests_a_correction_for_invalid_semantics(change, message):
    """Blank title or evidence, an escaping path, line 0, empty evidence_refs, or a line-0 anchor raise a correction."""
    with pytest.raises(CorrectableRoleResponseError, match=message):
        findings_from_reply({"findings": [{**repository.finding("app.py", 2), **change}]})


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
    provider = MockProvider(default=diff.reply([valid, invalid]))

    cycle = diff.finder(provider).review_unit(diff.diff_unit(diff.SQL_DIFF))

    assert cycle.clean is False
    assert [finding.evidence for finding in cycle.findings] == ["string-concatenated query"]
    assert "findings[1] must have nonempty fields: title" in provider.calls[1]["prompt"]


def test_location_correction_echoes_the_accepted_findings():
    """The correction for an unlocatable line-0 finding echoes the accepted line-2 finding."""
    provider = MockProvider(
        responses=[
            repository.finder_reply([repository.finding("app.py", 2), repository.finding("app.py", 0, title="second")]),
            repository.finder_reply(),
        ]
    )

    repository.finder(provider).review_unit(_unit("u", GroundingContext(text="")))

    correction = provider.calls[1]["prompt"]
    assert '"entrypoint": "GET /records/<id>"' in correction


def test_finder_fails_the_unit_on_an_unparseable_reply():
    """A reply of plain prose fails the unit with "reply had no complete JSON"."""
    reviewer = repository.finder(MockProvider(default="sorry, no JSON here"))
    with pytest.raises(repository.UnitReviewError, match="reply had no complete JSON"):
        repository.review(reviewer, _unit("u", GroundingContext(text="")))


def test_an_unparseable_reply_is_corrected_once_instead_of_failing_the_unit():
    """A reply holding two JSON objects gets one correction prompt, and the corrected finding completes it."""
    finding = {
        "file": "a.py",
        "line": 1,
        "severity": "HIGH",
        "category": "missing-authorization",
        "evidence": "unguarded sink",
    }
    provider = MockProvider(responses=['{"findings": []} {"findings": [1]}', diff.reply([finding])])

    result = diff.review(diff.FILE_A_DIFF, provider=provider)

    assert [f.evidence for f in result.outcome.findings] == ["unguarded sink"]
    assert result.outcome.complete
    assert "Return exactly one JSON object" in provider.calls[1]["prompt"]


def test_finder_binds_each_finding_to_its_source_operation(tmp_path):
    """Findings at lines 63 and 64 are bound to the navigator's call-shared operation and stay two findings."""

    class OperationNavigator:
        relationship_evidence = RelationshipEvidenceBundle()

        def session(self):
            return self

        def record_delivered(self, evidence, *, seed_spans=()):
            return None

        def source_operation_id(self, file, line):
            return "call-shared" if file == "matching.py" and line in {63, 64} else ""

    (tmp_path / "matching.py").write_text("value = 1\n" * 70, encoding="utf-8")
    provider = MockProvider(
        default=repository.finder_reply(
            [repository.finding("matching.py", line, title=f"regex operation {line}") for line in (63, 64)]
        )
    )
    [unit] = repository.ground(
        [repository.source_unit(tmp_path, "matching.py", name="matching")], navigator=OperationNavigator()
    )

    findings = repository.review(repository.finder(provider), unit)

    assert [(item.line, item.source_operation_id) for item in findings] == [(63, "call-shared"), (64, "call-shared")]


def test_finder_sends_the_contract_as_a_cacheable_system_prompt():
    """The kernel and rubric go in the system prompt, while the cached prefix carries the diff text."""
    provider = MockProvider(default=diff.reply([]))
    _diff_findings(provider)
    call = provider.calls[0]
    prompt = call["prompt"]
    assert prompt.startswith(call["cache_prefix"])
    assert "SELECT * FROM u" in call["cache_prefix"]
    assert "# Security Kernel" in call["system"]
    assert "# Severity Rubric" in call["system"]
    assert "# Security Kernel" not in prompt


def test_finder_system_is_identical_across_units():
    """Two units with different diffs and context share one system prompt free of unit context."""
    provider = MockProvider(default=diff.reply([]))
    runner = diff.finder(provider)
    for diff_text, context in ((diff.SQL_DIFF, "first unit"), ("+++ b/other.py\n@@ -0,0 +1 @@\n+other()\n", "second")):
        assert runner.review_unit(diff.diff_unit(diff_text, context)).clean is True

    assert provider.calls[0]["system"] == provider.calls[1]["system"]
    assert "first unit" not in provider.calls[0]["system"]


def test_reviewing_one_unit_again_reuses_its_cache_prefix(tmp_path):
    """Reviewing the same app.py unit twice sends two cached calls with one system prompt and cache prefix."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    provider = MockProvider(default=repository.finder_reply())
    reviewer = repository.finder(provider)
    [unit] = repository.ground([repository.source_unit(tmp_path, "app.py", name="wallets")])

    repository.review(reviewer, unit)
    repository.review(reviewer, unit)

    first, second = provider.calls
    assert second["cache_prefix"] == first["cache_prefix"]
    assert second["system"] == first["system"]


def test_published_evidence_ids_enter_the_cache_prefix_without_their_source():
    """Published evidence ids enter the cache prefix while their source text stays out of the prompt."""
    provider = MockProvider(default=diff.reply([]))
    evidence = EvidenceItem.create(
        identity="app.py:handler:10:40",
        label="app.py:handler",
        text="def handler():\n    return sensitive_operation()\n",
        preview="def handler():",
    )

    cycle = diff.finder(provider).review_unit(
        diff.diff_unit(
            "+++ b/app.py\n@@ -0,0 +1 @@\n+def handler(): ...\n",
            GroundingContext(text="initial context", evidence=(evidence,)),
        )
    )

    assert cycle.clean is True
    prompt = provider.calls[0]["prompt"]
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Kernel" in provider.calls[0]["system"]


def test_finder_can_request_one_published_source_fragment():
    """An evidence request reveals the fragment text only in the second call, which yields the finding."""
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [supported]",
        text="1 | class Account:\n2 |     owner = None",
        source_span=SourceSpan(file="models.py", start_line=1, end_line=2),
    )
    finding = repository.finding("views.py", 2, title="missing ownership check", evidence_refs=["seed", evidence.id])
    provider = MockProvider(
        responses=[
            repository.finder_reply(evidence_requests=[evidence.id]),
            repository.finder_reply([finding]),
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
        source_spans=(SourceSpan(file="views.py", start_line=1, end_line=2),),
    )

    findings = repository.review(repository.finder(provider), _unit("views", grounding))

    assert [finding.title for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["prompt"]
    assert evidence.text not in provider.calls[0]["prompt"]
    assert evidence.text in provider.calls[1]["prompt"]


def test_model_call_after_exact_evidence_delivery_is_a_followup():
    """Requesting an evidence id yields two calls, triggered as initial_judgment then evidence_followup."""
    evidence = EvidenceItem.create(
        identity="policy.py:guard:0:20",
        label="policy.py:guard",
        text="guard = True\n",
    )
    provider = MockProvider(
        responses=[
            json.dumps({**json.loads(diff.reply([])), "evidence_requests": [evidence.id]}),
            diff.reply([]),
        ]
    )
    meter = UsageMeter()

    result = diff.review(
        diff.SQL_DIFF,
        provider=MeteringProvider(provider, meter),
        context=GroundingContext(text="seed", evidence=(evidence,)),
    )

    calls = meter.call_snapshot()
    assert result.outcome.complete is True
    assert len(calls) == 2
    assert [call["trigger"] for call in calls] == ["initial_judgment", "evidence_followup"]


def test_a_navigation_follow_up_reuses_the_system_prompt_and_cache_prefix(tmp_path):
    """A search_symbols query triggers a follow-up call sharing system and prefix that shows the source."""
    navigator = _model_navigator(tmp_path)
    raw_provider = MockProvider(
        responses=[
            repository.finder_reply(
                source_queries=[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
            ),
            repository.finder_reply(),
        ]
    )
    meter = UsageMeter()
    reviewer = repository.finder(MeteringProvider(raw_provider, meter))
    unit = _unit("views", GroundingContext(text="initial_signal()", navigator=navigator), tmp_path)

    cycle = reviewer.review_unit(unit)

    assert cycle.clean is True
    assert len(raw_provider.calls) == 2
    first, final = raw_provider.calls
    assert first["system"] == final["system"]
    assert "# Security Kernel" in first["system"]
    assert "# Source Navigation" in first["system"]
    assert first["cache_prefix"] == final["cache_prefix"]
    assert first["prompt"].startswith(first["cache_prefix"])
    assert first["cache_segments"] == ()
    assert len(final["cache_segments"]) == 1
    assert final["prompt"].startswith(final["cache_prefix"] + final["cache_segments"][0])
    assert "owner_scope = True" in final["cache_segments"][0]
    assert first["prompt"].endswith("Evidence request budget: 8 request batches remain.")
    final_prompt = final["prompt"]
    assert final_prompt.startswith(first["cache_prefix"])
    assert "owner_scope = True" in final_prompt[len(first["cache_prefix"]) :]
    assert [call["trigger"] for call in meter.call_snapshot()] == ["initial_judgment", "evidence_followup"]


def test_finder_call_measurements_expose_role_and_status():
    """A metered review records a finder call with positive prompt_chars, a duration, and ok status."""
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=diff.reply([])), meter)

    diff.review(diff.SQL_DIFF, provider=provider)

    calls = meter.call_snapshot()
    assert calls
    call = calls[0]
    assert call["role"] == "finder"
    assert call["prompt_chars"] > 0
    assert call["duration_seconds"] >= 0
    assert call["status"] == "ok"


def test_finder_call_records_semantic_response_failures():
    """A finding missing required fields marks the call failed with that reason and the review incomplete."""
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=diff.reply([{"severity": "HIGH"}])), meter)

    result = diff.review(diff.SQL_DIFF, provider=provider)

    assert result.outcome.complete is False
    call = meter.call_snapshot()[0]
    assert call["status"] == "failed"
    assert "$response.findings[0] is missing fields" in call["failure_reason"]
