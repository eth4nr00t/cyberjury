"""The shared Finder parses replies, prompts with a cacheable contract, and exchanges evidence for any target."""

import json
from types import SimpleNamespace

import pytest

from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.review.context import EvidenceItem, GroundingContext, GroundingCoverage, SourceSpan
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.diff.model import DiffUnit
from cyberjury.review.finder import findings_from_reply
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.replies import CorrectableRoleResponseError
from cyberjury.review.repository.model import RepositoryUnit
from cyberjury.review.union import MERGE_RULE
from tests.review.diff import support as diff
from tests.review.repository import support as repository
from tests.review.support import definition, navigator_from_callgraph


def _unit(name, grounding, root="."):
    return RepositoryUnit(name=name, root=str(root), file=name, span=(0, 0), grounding=grounding)


def _diff_findings(provider, diff_text=diff.SQL_DIFF, *, context=""):
    cycle = diff.finder(provider).review_unit(diff.diff_unit(diff_text, context))
    if not cycle.clean:
        raise RuntimeError(cycle.failure_reason)
    return cycle.findings


def _model_navigator(root, name="ModelWithOwner"):
    source = f"class {name}:\n    owner_scope = True\n"
    (root / "models.py").write_text(source, encoding="utf-8")
    return navigator_from_callgraph(
        root, {"callgraph": {"models.py": {name: [{"range": [0, len(source)], "calls": []}]}}}
    )


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
    provider = MockProvider(responses=[response, response])
    out = _diff_findings(provider)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql-injection"
    assert provider.calls[0]["messages"][0].content.endswith("A further request makes this judgment incomplete.")


def test_finder_accepts_a_model_supplied_category():
    """A free-form category such as "sqli" is kept verbatim on the parsed finding."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sqli",
        "evidence": "string-concatenated query",
    }

    assert _diff_findings(MockProvider(default=diff.reply([finding])))[0].category == "sqli"


def test_finder_rejects_a_model_supplied_candidate_id():
    """A reply finding that supplies candidate_id fails the unit with "unknown fields: candidate_id"."""
    reply = repository.finder_reply([repository.finding("app.py", 2, candidate_id="candidate-wrong")])
    reviewer = repository.finder(MockProvider(default=reply))

    with pytest.raises(repository.UnitReviewError, match="unknown fields: candidate_id"):
        repository.review(reviewer, _unit("u", GroundingContext(text="")))


def test_finder_reports_a_malformed_finding_as_failed_work():
    """A finding with only severity yields no findings, one error, and a "missing fields" reason."""
    reviewer = repository.finder(MockProvider(default=repository.finder_reply([{"severity": "HIGH"}])))

    cycle = reviewer.review_unit(_unit("u", GroundingContext(text="")))

    assert cycle.findings == []
    assert cycle.errors == 1
    assert "$response.findings[0] is missing fields" in cycle.failure_reason


def test_finder_rejects_a_severity_outside_the_rubric():
    """Severity "spicy" raises a "severity has a value outside the allowed set" error."""
    response = diff.reply(
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
        _diff_findings(MockProvider(default=response))


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


def test_findings_from_reply_carries_the_valid_findings_of_a_corrected_reply():
    """A reply whose second finding has line 0 raises a correction that keeps the first finding."""
    valid = repository.finding("app.py", 2, title="missing ownership check")

    with pytest.raises(CorrectableRoleResponseError, match=r"findings\[1\]\.line") as caught:
        findings_from_reply({"findings": [valid, repository.finding("app.py", 0, title="second")]})

    assert [candidate.title for candidate in caught.value.response_findings] == ["missing ownership check"]


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
    assert "findings[1] must have nonempty fields: title" in provider.calls[1]["messages"][0].content


def test_correction_states_the_shared_merge_rule_for_accepted_findings():
    """The correction prompt says accepted findings are final, quotes MERGE_RULE, and echoes them."""
    provider = MockProvider(
        responses=[
            repository.finder_reply([repository.finding("app.py", 2), repository.finding("app.py", 0, title="second")]),
            repository.finder_reply(),
        ]
    )

    repository.finder(provider).review_unit(_unit("u", GroundingContext(text="")))

    correction = provider.calls[1]["messages"][0].content
    assert f"cannot be edited or withdrawn. {MERGE_RULE} Return only new findings." in correction
    assert '"entrypoint": "GET /records/<id>"' in correction


def test_finder_empty_on_no_findings():
    """A reply with an empty findings list produces an empty result for the SQL concatenation diff."""
    assert _diff_findings(MockProvider(default=diff.reply([]))) == []


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
    assert "Return exactly one JSON object" in provider.calls[1]["messages"][-1].content


def test_a_unit_runs_one_judgment_even_when_it_finds_a_candidate():
    """A unit whose first reply returns a finding makes a single provider call and keeps that finding."""
    finding = repository.finding("views.py", 1, title="first")
    provider = MockProvider(default=repository.finder_reply([finding]))

    cycle = repository.finder(provider).review_unit(
        _unit(
            "views.py",
            GroundingContext(
                text="seed",
                source_spans=(SourceSpan(file="views.py", start_line=1, end_line=1),),
            ),
        ),
    )

    assert len(provider.calls) == 1
    assert [finding.title for finding in cycle.findings] == ["first"]


def test_finder_fails_before_model_call_when_grounding_is_incomplete():
    """A unit whose required definition is omitted from grounding fails with one error and no model call."""
    provider = MockProvider(default=diff.reply([]))
    fragment = definition("policy.py", "Policy", 0, 20)
    context = GroundingContext(
        text="",
        coverage=GroundingCoverage(required=(fragment.identity,), omitted=(fragment.identity,)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=diff.SQL_DIFF,
        paths=("app.py",),
        id="diff-unit-1",
        definition_plan=DefinitionUnitPlan(seeds=(fragment,)),
        grounding=context,
    )

    result = diff.review([unit], provider=provider)

    assert provider.calls == []
    assert result.outcome.complete is False
    assert result.outcome.errors == 1


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
    prompt = call["messages"][0].content
    assert call["cache"] is True
    assert prompt.startswith(call["cache_prefix"])
    assert "SELECT * FROM u" in call["cache_prefix"]
    assert "# Security Reasoning Kernel" in call["system"]
    assert "# Severity Rubric" in call["system"]
    assert "# Security Reasoning Kernel" not in prompt


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
    assert second["cache"] is True
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
    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


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
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


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
    assert "# Security Reasoning Kernel" in first["system"]
    assert "# Source Navigation" in first["system"]
    assert first["cache"] is True
    assert final["cache"] is True
    assert first["cache_prefix"] == final["cache_prefix"]
    assert first["messages"][0].content.startswith(first["cache_prefix"])
    assert first["cache_segments"] == ()
    assert len(final["cache_segments"]) == 1
    assert final["messages"][0].content.startswith(final["cache_prefix"] + final["cache_segments"][0])
    assert "owner_scope = True" in final["cache_segments"][0]
    assert first["messages"][0].content.endswith("Evidence request budget: 8 request batches remain.")
    final_prompt = final["messages"][0].content
    assert final_prompt.startswith(first["cache_prefix"])
    assert "owner_scope = True" in final_prompt[len(first["cache_prefix"]) :]
    assert [call["trigger"] for call in meter.call_snapshot()] == ["initial_judgment", "evidence_followup"]


def test_repeated_navigation_query_fails_the_unit(tmp_path):
    """Returning the same search_symbols "Record" query on every reply fails with "repeats an earlier query"."""
    navigator = _model_navigator(tmp_path, "Record")
    response = json.dumps(
        {
            **json.loads(diff.reply([])),
            "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
        }
    )
    provider = MeteringProvider(MockProvider(responses=[response, response, response]), UsageMeter())

    cycle = diff.finder(provider).review_unit(
        diff.diff_unit(
            "+++ b/app.py\n@@ -0,0 +1 @@\n+initial_signal()\n", GroundingContext(text="seed", navigator=navigator)
        )
    )

    assert cycle.clean is False
    assert "repeats an earlier query" in cycle.failure_reason


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


class _SequencedOpenAIClient:
    def __init__(self, replies):
        self.requests = []
        self._replies = list(replies)
        self.responses = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return SimpleNamespace(output_text=self._replies.pop(0), status="completed")


def test_initial_and_followup_calls_of_one_unit_share_one_openai_cache_key(tmp_path):
    """OpenAI prompt_cache_key matches across one unit's initial and follow-up calls but not other units."""
    navigator = _model_navigator(tmp_path)
    client = _SequencedOpenAIClient(
        [
            repository.finder_reply(source_queries=[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}]),
            repository.finder_reply(),
            repository.finder_reply(),
        ]
    )
    reviewer = repository.finder(OpenAIProvider(client=client), model="gpt-4o")
    unit = _unit("views", GroundingContext(text="seed()", navigator=navigator), tmp_path)
    other = _unit("other", GroundingContext(text="other()", navigator=navigator), tmp_path)

    assert reviewer.review_unit(unit).clean is True
    assert reviewer.review_unit(other).clean is True

    initial, followup, other_unit = client.requests
    assert initial["prompt_cache_key"] == followup["prompt_cache_key"]
    assert other_unit["prompt_cache_key"] != initial["prompt_cache_key"]
    assert initial["instructions"] == followup["instructions"] == other_unit["instructions"]
    initial_user = initial["input"][0]["content"]
    followup_user = followup["input"][0]["content"]
    shared = len(initial_user) - len("Evidence request budget: 8 request batches remain.")
    assert followup_user[:shared] == initial_user[:shared]
    assert "owner_scope = True" in followup_user[shared:]
    assert followup_user.endswith("Evidence request budget: 7 request batches remain.")
