"""Repository Finder parsing, prompting, location, and evidence tests."""

import json

import pytest

from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import (
    EvidenceItem,
    GroundingContext,
    SourceEvidence,
    SourceSpan,
)
from cyberjury.review.engine import CorrectableRoleResponseError
from cyberjury.review.finder import findings_from_reply
from cyberjury.review.finding import Finding
from cyberjury.review.navigation import navigation_instructions
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.finder import locate
from cyberjury.review.repository.prompts import (
    REPOSITORY_FINDING_SCHEMA,
    repository_finder_system,
)
from cyberjury.review.union import MERGE_RULE
from tests.review.repository.support import UnitReviewError, finder, review, source_unit
from tests.review.support import navigator_from_callgraph


def _grounded_unit(name, grounding, root="."):
    return Unit(name=name, root=str(root), file=name, span=(0, 0), grounding=grounding)


_U = [_grounded_unit("u", GroundingContext(text=""))]


def _finder_reply(findings=None, *, evidence_requests=None, source_queries=None):
    items = findings or []
    for finding in items:
        finding.setdefault("entrypoint", "GET /accounts/<id>")
    return json.dumps(
        {
            "findings": items,
            "evidence_requests": evidence_requests or [],
            "source_queries": source_queries or [],
        }
    )


def _assessed_empty(*, evidence_requests=None, source_queries=None):
    return _finder_reply(evidence_requests=evidence_requests, source_queries=source_queries)


def test_repository_system_carries_the_review_contract_and_field_meanings():
    """The system prompt embeds the brief, rubric, navigation section, and backticks every schema field."""
    system = repository_finder_system(
        review_brief="# Security Reasoning Kernel\nKERNEL-X",
        severity_rubric="# Severity Rubric\nRUBRIC-X",
        navigation=navigation_instructions(),
    )

    for text in (
        "one repository review unit",
        "attacker-reachable, exploitable violation",
        "KERNEL-X",
        "RUBRIC-X",
        "Cite it directly and do not request it again",
        "# Source Navigation",
        "where the fix must be applied",
    ):
        assert text in system
    for field in (*REPOSITORY_FINDING_SCHEMA["properties"], "evidence_requests", "source_queries"):
        assert f"`{field}`" in system
    assert system.count("Cite it directly and do not request it again") == 1


def test_repository_reviewer_keeps_embedded_markdown_fence_in_source(tmp_path):
    """A source line containing ``` is fenced with ~~~ so the triple backtick reaches the prompt intact."""
    (tmp_path / "app.py").write_text('marker = "```"\n', encoding="utf-8")
    provider = MockProvider(default=_assessed_empty())

    review(
        finder(provider),
        source_unit(tmp_path, "app.py", name="app.py"),
    )

    prompt = provider.calls[0]["messages"][0].content
    assert "Code under review, cited as `seed`:\n~~~\n# file: app.py" in prompt
    assert 'marker = "```"' in prompt


def test_repository_prompt_never_carries_the_unit_name(tmp_path):
    """A unit named with a backtick and newline leaks neither fragment into the prompt."""
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    provider = MockProvider(default=_assessed_empty())

    review(
        finder(provider),
        source_unit(tmp_path, "app.py", name="app`unit\nnext heading"),
    )

    prompt = provider.calls[0]["messages"][0].content
    assert "app`unit" not in prompt
    assert "next heading" not in prompt


def _complete_finding(**fields):
    return {
        "title": "missing ownership check",
        "category": "missing-authorization",
        "entrypoint": "GET /accounts/<id>",
        "file": "app.py",
        "line": 2,
        "severity": "HIGH",
        "attack_path": "request reads another account without ownership",
        "evidence": "app.py:2 has no ownership check",
        "evidence_refs": ["seed"],
        **fields,
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"title": "  "}, r"findings\[0\] must have nonempty fields: title"),
        ({"evidence": ""}, r"findings\[0\] must have nonempty fields: evidence"),
        ({"file": "../outside.py"}, r"findings\[0\]\.file must be a relative repository path"),
        ({"line": 0}, r"findings\[0\]\.line must be a positive integer"),
        ({"evidence_refs": []}, r"findings\[0\]\.evidence_refs must be a nonempty string list"),
        ({"evidence_refs": [""]}, r"findings\[0\]\.evidence_refs must be a nonempty string list"),
    ],
)
def test_findings_from_reply_requests_a_correction_for_invalid_semantics(change, message):
    """Blank title or evidence, an escaping path, line 0, or empty evidence_refs raise a correction."""
    with pytest.raises(CorrectableRoleResponseError, match=message):
        findings_from_reply({"findings": [_complete_finding(**change)]})


def test_findings_from_reply_carries_the_valid_findings_of_a_corrected_reply():
    """A reply whose second finding has line 0 raises a correction that keeps the first finding."""
    valid = _complete_finding()

    with pytest.raises(CorrectableRoleResponseError, match=r"findings\[1\]\.line") as caught:
        findings_from_reply({"findings": [valid, _complete_finding(title="second", line=0)]})

    assert [candidate.title for candidate in caught.value.response_findings] == ["missing ownership check"]


def test_repository_candidate_rejects_a_model_supplied_mismatched_identity():
    """A reply finding that supplies candidate_id fails the unit with "unknown fields: candidate_id"."""
    reviewer = finder(MockProvider(default=_finder_reply([_complete_finding(candidate_id="candidate-wrong")])))

    with pytest.raises(UnitReviewError, match="unknown fields: candidate_id"):
        review(reviewer, _U[0])


def test_repository_correction_states_the_shared_merge_rule_for_accepted_findings():
    """The correction prompt says accepted findings are final, quotes MERGE_RULE, and echoes them."""
    provider = MockProvider(
        responses=[_finder_reply([_complete_finding(), _complete_finding(title="second", line=0)]), _finder_reply()]
    )

    finder(provider).review_unit(_U[0])

    correction = provider.calls[1]["messages"][0].content
    assert f"cannot be edited or withdrawn. {MERGE_RULE} Return only new findings." in correction
    assert '"entrypoint": "GET /accounts/<id>"' in correction


def test_repository_review_reports_a_malformed_finding_as_failed_work():
    """A finding with only severity yields no findings, one error, and a "missing fields" reason."""
    reviewer = finder(MockProvider(default=_finder_reply([{"severity": "HIGH"}])))

    cycle = reviewer.review_unit(_U[0])

    assert cycle.findings == []
    assert cycle.errors == 1
    assert "$response.findings[0] is missing fields" in cycle.failure_reason


def test_model_reviewer_builds_prompt_and_parses(tmp_path):
    """One reply yields an IDOR finding, and the seed source is sent and both calls share a cache prefix."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = _finder_reply(
        [
            {
                "title": "idor",
                "category": "insecure-direct-object-reference",
                "entrypoint": "GET /x/<id>",
                "file": "app.py",
                "line": 2,
                "severity": "HIGH",
                "attack_path": "request reads another account without ownership",
                "evidence": "app.py:2 exposes another account",
                "evidence_refs": ["seed"],
            }
        ]
    )
    prov = MockProvider(default=reply)
    reviewer = finder(prov)
    unit = source_unit(tmp_path, "app.py", name="wallets")

    cands = review(reviewer, unit)
    assert len(cands) == 1
    assert cands[0].entrypoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"
    assert cands[0].category == "insecure-direct-object-reference"

    sent = prov.calls[0]["messages"][0].content
    assert "Severity Rubric" in prov.calls[0]["system"]
    assert "def handler" in sent
    assert sent.startswith("Code under review, cited as `seed`:\n")

    assert prov.calls[0]["cache"] is True
    assert sent.startswith(prov.calls[0]["cache_prefix"])

    review(reviewer, unit)
    assert prov.calls[1]["cache"] is True
    assert prov.calls[1]["cache_prefix"] == prov.calls[0]["cache_prefix"]
    assert prov.calls[1]["system"] == prov.calls[0]["system"]


def test_repository_reviewer_accepts_a_model_supplied_category(tmp_path):
    """A free-form category "idor" from the model is kept on the finding as given."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = _finder_reply(
        [
            {
                "title": "idor",
                "category": "idor",
                "entrypoint": "GET /x/<id>",
                "file": "app.py",
                "line": 2,
                "severity": "HIGH",
                "attack_path": "request reads another account without ownership",
                "evidence": "app.py:2 exposes another account",
                "evidence_refs": ["seed"],
            }
        ]
    )
    reviewer = finder(MockProvider(default=reply))

    assert review(reviewer, source_unit(tmp_path, "app.py", name="wallets"))[0].category == "idor"


def test_repository_finding_location_must_be_covered_by_its_cited_source(tmp_path):
    """A finding at other.py citing only the app.py seed fails with "cited source receipt"."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n", encoding="utf-8")
    reply = _finder_reply(
        [
            {
                "title": "wrong location",
                "category": "insecure-direct-object-reference",
                "file": "other.py",
                "line": 2,
                "severity": "HIGH",
                "attack_path": "request reads another account without ownership",
                "evidence": "other.py:2 lacks ownership",
                "evidence_refs": ["seed"],
            }
        ]
    )
    reviewer = finder(MockProvider(default=reply))

    with pytest.raises(UnitReviewError, match="cited source receipt"):
        review(reviewer, source_unit(tmp_path, "app.py", name="app"))


def test_repository_location_uses_the_canonical_path_from_its_receipt():
    """A finding at ./views.py is relocated to views.py, the path of its seed source span."""
    finding = Finding(
        title="missing ownership check",
        severity="HIGH",
        category="other",
        file="./views.py",
        line=2,
        entrypoint="GET /accounts/<id>",
        evidence="the control is missing",
        attack_path="request reaches it",
        evidence_refs=("seed",),
    )

    located = locate(None, finding, (), (SourceSpan(file="views.py", start_line=1, end_line=3),))

    assert located.file == "views.py"


def test_model_reviewer_can_request_one_published_source_fragment():
    """An evidence request reveals the fragment text only in the second call, which yields the finding."""
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [supported]",
        text="1 | class Account:\n2 |     owner = None",
        source_span=SourceSpan(file="models.py", start_line=1, end_line=2),
    )
    finding = {
        "title": "missing ownership check",
        "category": "insecure-direct-object-reference",
        "file": "views.py",
        "line": 2,
        "severity": "HIGH",
        "attack_path": "view returns all accounts without ownership",
        "evidence": "views.py:2 returns objects without ownership",
        "evidence_refs": ["seed", evidence.id],
    }
    provider = MockProvider(
        responses=[
            _finder_reply(evidence_requests=[evidence.id]),
            _finder_reply([finding]),
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
        source_spans=(SourceSpan(file="views.py", start_line=1, end_line=2),),
    )
    reviewer = finder(provider)

    findings = review(reviewer, _grounded_unit("views", grounding))

    assert [finding.title for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_repository_location_accepts_preexisting_source_evidence():
    """A finding citing existing SourceEvidence for service.py lines 7-8 keeps file, line 8, and refs."""
    evidence = SourceEvidence(
        id="src-existing",
        identity="service.py:load:0:20",
        text="7 | def load():\n8 |     return secret",
        source_span=SourceSpan(file="service.py", start_line=7, end_line=8),
    )
    finding = Finding(
        title="missing control",
        severity="HIGH",
        category="other",
        file="service.py",
        line=8,
        entrypoint="GET /accounts/<id>",
        evidence="the control is missing",
        attack_path="request reaches it",
        evidence_refs=(evidence.id,),
    )

    located = locate(None, finding, (evidence,), ())

    assert (located.file, located.line, located.evidence_refs) == ("service.py", 8, (evidence.id,))


def test_non_entrypoint_runs_one_judgment_even_when_it_finds_a_candidate():
    """A unit whose first reply returns a finding makes a single provider call and keeps that finding."""
    finding = {
        "title": "first",
        "category": "other",
        "file": "views.py",
        "line": 1,
        "severity": "HIGH",
        "attack_path": "request reaches the unchecked view",
        "evidence": "views.py:1 lacks the control",
        "evidence_refs": ["seed"],
    }
    provider = MockProvider(default=_finder_reply([finding]))

    cycle = finder(provider).review_unit(
        _grounded_unit(
            "views.py",
            GroundingContext(
                text="seed",
                source_spans=(SourceSpan(file="views.py", start_line=1, end_line=1),),
            ),
        ),
    )

    assert len(provider.calls) == 1
    assert [finding.title for finding in cycle.findings] == ["first"]


def test_repository_uses_one_profile_brief_judgment(tmp_path):
    """A clean source unit makes one cached call with the kernel only in the system prompt."""
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default=_assessed_empty())
    reviewer = finder(provider)

    review(reviewer, source_unit(tmp_path, "app.py", name="app"))

    assert len(provider.calls) == 1
    assert provider.calls[0]["cache"] is True
    assert "alpha beta" in provider.calls[0]["cache_prefix"]
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]
    assert "# Security Reasoning Kernel" not in provider.calls[0]["messages"][0].content


def test_repository_navigation_keeps_profile_coverage_and_runs_a_final_evidence_sweep(tmp_path):
    """A search_symbols query triggers a follow-up call sharing system and prefix that shows the source."""
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
            _assessed_empty(
                source_queries=[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
            ),
            _assessed_empty(),
        ]
    )
    meter = UsageMeter()
    provider = MeteringProvider(raw_provider, meter)
    reviewer = finder(provider)
    unit = _grounded_unit("views", GroundingContext(text="initial_signal()", navigator=navigator), tmp_path)

    cycle = reviewer.review_unit(unit)

    assert cycle.clean is True
    assert len(raw_provider.calls) == 2
    first, final = raw_provider.calls
    assert first["system"] == final["system"]
    assert "# Security Reasoning Kernel" in first["system"]
    assert first["cache"] is True
    assert final["cache"] is True
    assert first["cache_prefix"] == final["cache_prefix"]
    assert first["messages"][0].content.startswith(first["cache_prefix"])
    assert first["messages"][0].content.endswith("Evidence request budget: 8 request batches remain.")
    final_prompt = final["messages"][0].content
    assert final_prompt.startswith(first["cache_prefix"])
    assert "owner_scope = True" in final_prompt[len(first["cache_prefix"]) :]
    assert [call["trigger"] for call in meter.call_snapshot()] == ["initial_judgment", "evidence_followup"]


def test_repository_published_evidence_does_not_change_the_profile_brief():
    """Published evidence ids land in the cache prefix while the evidence body stays out of the prompt."""
    provider = MockProvider(default=_assessed_empty())
    reviewer = finder(provider)
    evidence = EvidenceItem.create(
        identity="dependency.py:operation:0:40",
        label="dependency.py:operation",
        text="def operation():\n    return sensitive_operation()\n",
        preview="def operation():",
    )
    unit = _grounded_unit("app", GroundingContext(text="initial context", evidence=(evidence,)))

    review(reviewer, unit)

    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


def test_model_reviewer_raises_on_unparseable_reply():
    """A reply of plain prose fails the unit with "reply had no complete JSON"."""
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = finder(prov)
    with pytest.raises(UnitReviewError, match="reply had no complete JSON"):
        review(reviewer, _U[0])


def test_model_reviewer_empty_findings_is_not_an_error():
    """A reply with an empty findings list reviews to an empty result without raising."""
    prov = MockProvider(default=_finder_reply())
    reviewer = finder(prov)
    assert review(reviewer, _U[0]) == []


class _SequencedOpenAIClient:
    def __init__(self, replies):
        from types import SimpleNamespace

        self.requests = []
        self._replies = list(replies)
        self.responses = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        from types import SimpleNamespace

        self.requests.append(kwargs)
        return SimpleNamespace(output_text=self._replies.pop(0), status="completed")


def test_initial_and_followup_calls_of_one_unit_share_one_openai_cache_key(tmp_path):
    """OpenAI prompt_cache_key matches across one unit's initial and follow-up calls but not other units."""
    from cyberjury.providers.openai import OpenAIProvider

    source = "class ModelWithOwner:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = navigator_from_callgraph(
        tmp_path,
        {"callgraph": {"models.py": {"ModelWithOwner": [{"range": [0, len(source)], "calls": []}]}}},
    )
    client = _SequencedOpenAIClient(
        [
            _assessed_empty(source_queries=[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}]),
            _assessed_empty(),
            _assessed_empty(),
        ]
    )
    reviewer = finder(OpenAIProvider(client=client), model="gpt-4o")
    unit = _grounded_unit("views", GroundingContext(text="seed()", navigator=navigator), tmp_path)
    other = _grounded_unit("other", GroundingContext(text="other()", navigator=navigator), tmp_path)

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
