"""Repository model reviewer parsing, prompting, and evidence tests."""

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
from cyberjury.review.engine import CorrectableRoleResponseError, ReviewCycle
from cyberjury.review.navigation import SourceNavigator, navigation_instructions
from cyberjury.review.repository.context import Unit, ground_units
from cyberjury.review.repository.prompts import (
    REPOSITORY_FINDING_SCHEMA,
    repository_finder_system,
    repository_prompt_plan,
)
from cyberjury.review.repository.reviewer import (
    ModelReviewer,
    candidates_from_obj,
    validate_candidate_locations,
)
from cyberjury.review.repository.runner import run_units
from cyberjury.review.repository.union import Candidate
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.cyberjury.review.repository.support import UnitReviewError, review

_U = [Unit(name="u", root=".", files=(), grounding=GroundingContext(text="", source="repository"))]


def _finder_reply(findings=None, *, evidence_requests=None, source_queries=None, assessments=None):
    items = findings or []
    for finding in items:
        finding.setdefault("symbol", "")
        finding.setdefault("endpoint", "")
    return json.dumps(
        {
            "findings": items,
            "evidence_requests": evidence_requests or [],
            "source_queries": source_queries or [],
        }
    )


def _assessed_empty(*, evidence_requests=None, source_queries=None):
    return _finder_reply(evidence_requests=evidence_requests, source_queries=source_queries)


def _confirmed_finding_reply(reply):
    payload = json.loads(reply)
    return _finder_reply(payload["findings"])


def test_repository_system_carries_the_review_contract_and_field_meanings():
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
    assert "Respond with a single JSON object" not in system
    assert system.count("Cite it directly and do not request it again") == 1


def test_repository_reviewer_keeps_embedded_markdown_fence_in_source(tmp_path):
    (tmp_path / "app.py").write_text('marker = "```"\n', encoding="utf-8")
    provider = MockProvider(default=_assessed_empty())

    review(ModelReviewer(provider=provider, model="mock"), Unit(name="app.py", root=str(tmp_path), files=("app.py",)))

    prompt = provider.calls[0]["messages"][0].content
    assert "the code to review:\n~~~\n" in prompt
    assert 'marker = "```"' in prompt


def test_repository_reviewer_keeps_unit_name_on_one_prompt_line(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    provider = MockProvider(default=_assessed_empty())

    review(
        ModelReviewer(provider=provider, model="mock"),
        Unit(name="app`unit\nnext heading", root=str(tmp_path), files=("app.py",)),
    )

    prompt = provider.calls[0]["messages"][0].content
    assert "Unit `` app`unit\\nnext heading ``, the code to review:" in prompt
    assert "\nnext heading\n" not in prompt
    assert "terminal rule assessment" not in prompt
    assert "do not request paths or symbols" not in prompt


def test_repository_known_findings_send_only_identifying_fields():
    prompt = repository_prompt_plan(
        "unit evidence",
        known=[{"title": "known issue", "category": "alpha", "file": "app.py", "line": 3, "candidate_id": "c-1"}],
        catalog="Evidence catalog",
        followup="BUDGET",
    )

    assert "Already recorded; do not report them again. Report only vulnerabilities that need a different fix" in (
        prompt.stable_prefix
    )
    assert '{"title": "known issue", "category": "alpha", "file": "app.py", "line": 3}' in prompt.stable_prefix
    assert "c-1" not in prompt.text
    assert prompt.stable_prefix.endswith("Evidence catalog\n\n")
    assert prompt.dynamic_suffix == "BUDGET"


def test_repository_model_finding_omits_code_owned_status():
    assert "status" not in REPOSITORY_FINDING_SCHEMA["properties"]


def _complete_finding(**fields):
    return {
        "title": "missing ownership check",
        "category": "missing-authorization",
        "symbol": "",
        "endpoint": "",
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
def test_candidates_from_obj_requests_a_correction_for_invalid_semantics(change, message):
    with pytest.raises(CorrectableRoleResponseError, match=message):
        candidates_from_obj({"findings": [_complete_finding(**change)]})


def test_candidates_from_obj_carries_the_valid_findings_of_a_corrected_reply():
    valid = _complete_finding()

    with pytest.raises(CorrectableRoleResponseError, match=r"findings\[1\]\.line") as caught:
        candidates_from_obj({"findings": [valid, _complete_finding(title="second", line=0)]})

    assert [candidate.title for candidate in caught.value.response_findings] == ["missing ownership check"]


def test_repository_candidate_rejects_a_model_supplied_mismatched_identity():
    reviewer = ModelReviewer(
        provider=MockProvider(default=_finder_reply([_complete_finding(candidate_id="candidate-wrong")])),
        model="mock",
    )

    with pytest.raises(UnitReviewError, match="unknown fields: candidate_id"):
        review(reviewer, _U[0])


def test_repository_review_reports_a_malformed_finding_as_failed_work():
    reviewer = ModelReviewer(
        provider=MockProvider(default=_finder_reply([{"severity": "HIGH"}])),
        model="mock",
    )

    cycle = reviewer.review_unit(_U[0], finder_label="mock")

    assert cycle.findings == []
    assert cycle.errors == 1
    assert "$response.findings[0] is missing fields" in cycle.failure_reason


def test_model_reviewer_builds_prompt_and_parses(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = _finder_reply(
        [
            {
                "title": "idor",
                "category": "insecure-direct-object-reference",
                "endpoint": "GET /x/<id>",
                "file": "app.py",
                "line": 2,
                "severity": "HIGH",
                "attack_path": "request reads another account without ownership",
                "evidence": "app.py:2 exposes another account",
                "evidence_refs": ["seed"],
            }
        ]
    )
    prov = MockProvider(responses=[reply, _confirmed_finding_reply(reply), reply, _confirmed_finding_reply(reply)])
    reviewer = ModelReviewer(provider=prov, model="mock")
    unit = Unit(name="wallets", root=str(tmp_path), files=("app.py",))

    cands = review(reviewer, unit, shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"
    assert cands[0].category == "insecure-direct-object-reference"

    sent = prov.calls[0]["messages"][0].content
    assert "# Unit Review Mandate" not in sent
    assert "LENS" not in sent
    assert "Severity Rubric" in prov.calls[0]["system"]
    assert "def handler" in sent
    assert sent.startswith("stack: flask\n\n")

    assert prov.calls[0]["cache"] is True
    assert sent.startswith(prov.calls[0]["cache_prefix"])

    review(reviewer, unit, shared_context="stack: flask")
    assert prov.calls[1]["cache"] is True
    assert prov.calls[1]["cache_prefix"] == prov.calls[0]["cache_prefix"]
    assert prov.calls[1]["system"] == prov.calls[0]["system"]


def test_repository_reviewer_accepts_a_model_supplied_category(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = _finder_reply(
        [
            {
                "title": "idor",
                "category": "idor",
                "endpoint": "GET /x/<id>",
                "file": "app.py",
                "line": 2,
                "severity": "HIGH",
                "attack_path": "request reads another account without ownership",
                "evidence": "app.py:2 exposes another account",
                "evidence_refs": ["seed"],
            }
        ]
    )
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    assert review(reviewer, Unit(name="wallets", root=str(tmp_path), files=("app.py",)))[0].category == "idor"


def test_repository_finding_location_must_be_covered_by_its_cited_source(tmp_path):
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
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    with pytest.raises(UnitReviewError, match="cited source receipt"):
        review(reviewer, Unit(name="app", root=str(tmp_path), files=("app.py",)))


def test_repository_location_uses_the_canonical_path_from_its_receipt():
    candidate = Candidate(
        title="missing ownership check",
        file="./views.py",
        line=2,
        evidence_refs=("seed",),
    )
    cycle = validate_candidate_locations(
        ReviewCycle(findings=[candidate]),
        GroundingContext(
            text="source",
            source_spans=(SourceSpan(file="views.py", start_line=1, end_line=3),),
        ),
    )

    assert cycle.clean is True
    assert cycle.findings[0].file == "views.py"


def test_model_reviewer_can_request_one_published_source_fragment():
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
            _confirmed_finding_reply(_finder_reply([finding])),
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
        source_spans=(SourceSpan(file="views.py", start_line=1, end_line=2),),
    )
    reviewer = ModelReviewer(provider=provider, model="mock")

    findings = review(reviewer, Unit(name="views", root=".", files=(), grounding=grounding))

    assert [finding.title for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_repository_location_accepts_preexisting_source_evidence():
    evidence = SourceEvidence(
        id="src-existing",
        identity="service.py:load:0:20",
        text="7 | def load():\n8 |     return secret",
        source_span=SourceSpan(file="service.py", start_line=7, end_line=8),
    )
    finding = Candidate(
        title="missing control",
        category="other",
        file="service.py",
        line=8,
        evidence_refs=(evidence.id,),
    )

    grounding = GroundingContext(text="seed", source_evidence=(evidence,))

    cycle = validate_candidate_locations(ReviewCycle(findings=[finding]), grounding)

    assert [(item.file, item.line, item.evidence_refs) for item in cycle.findings] == [
        ("service.py", 8, (evidence.id,))
    ]
    assert cycle.incomplete == []
    assert cycle.clean is True


def test_non_entrypoint_runs_one_judgment_even_when_it_finds_a_candidate():
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

    cycle = ModelReviewer(provider=provider, model="mock").review_unit(
        Unit(
            name="views.py",
            root=".",
            files=(),
            grounding=GroundingContext(
                text="seed",
                source_spans=(SourceSpan(file="views.py", start_line=1, end_line=1),),
            ),
        ),
        finder_label="finder",
    )

    assert len(provider.calls) == 1
    assert [finding.title for finding in cycle.findings] == ["first"]


@pytest.mark.parametrize("reply", ['{"findings": [', '```json\n{"findings": [\n```'])
def test_repository_rejects_a_truncated_findings_array(reply):
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    with pytest.raises(UnitReviewError, match="reply had no complete JSON"):
        review(reviewer, _U[0])


def test_repository_uses_one_profile_brief_judgment(tmp_path):
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default=_assessed_empty())
    reviewer = ModelReviewer(provider=provider, model="mock")

    review(reviewer, Unit(name="app", root=str(tmp_path), files=("app.py",)))

    assert len(provider.calls) == 1
    assert provider.calls[0]["cache"] is True
    assert "alpha beta" in provider.calls[0]["cache_prefix"]
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]
    assert "# Security Reasoning Kernel" not in provider.calls[0]["messages"][0].content


def test_repository_navigation_keeps_profile_coverage_and_runs_a_final_evidence_sweep(tmp_path):
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
            _assessed_empty(
                source_queries=[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}],
            ),
            _assessed_empty(),
        ]
    )
    meter = UsageMeter()
    provider = MeteringProvider(raw_provider, meter)
    reviewer = ModelReviewer(provider=provider, model="mock")
    unit = Unit(
        name="views",
        root=str(tmp_path),
        files=(),
        grounding=GroundingContext(text="initial_signal()", navigator=navigator),
    )

    cycle = reviewer.review_unit(unit, finder_label="mock")

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
    calls = meter.call_snapshot()
    assert calls[0]["navigation_status"] == "delivered"
    assert len(calls[0]["navigation_delta_ids"]) == 1
    assert calls[0]["navigation_delta_chars"] > 0
    assert calls[0]["source_query_count"] == 1
    assert calls[0]["trigger"] == "initial_judgment"
    assert calls[1]["navigation_status"] == "not_requested"
    assert calls[1]["trigger"] == "evidence_followup"


def test_repository_published_evidence_does_not_change_the_profile_brief():
    provider = MockProvider(default=_assessed_empty())
    reviewer = ModelReviewer(provider=provider, model="mock")
    evidence = EvidenceItem.create(
        identity="dependency.py:operation:0:40",
        label="dependency.py:operation",
        text="def operation():\n    return sensitive_operation()\n",
        preview="def operation():",
    )
    unit = Unit(
        name="app",
        root=".",
        files=("app.py",),
        grounding=GroundingContext(text="initial context", source="repository", evidence=(evidence,)),
    )

    review(reviewer, unit)

    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in provider.calls[0]["cache_prefix"]
    assert "sensitive_operation" not in prompt
    assert "# Security Reasoning Kernel" in provider.calls[0]["system"]


def test_repository_carries_known_findings_into_the_stable_prefix(tmp_path):
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default=_assessed_empty())
    reviewer = ModelReviewer(provider=provider, model="mock")
    prior = Candidate(
        title="prior finding",
        category="alpha",
        file="app.py",
        line=1,
        evidence_refs=("src-prior-pass",),
    )

    review(reviewer, Unit(name="app", root=str(tmp_path), files=("app.py",)), known=[prior])

    assert len(provider.calls) == 1
    prefix = provider.calls[0]["cache_prefix"]
    assert prior.candidate_id not in provider.calls[0]["messages"][0].content
    assert "prior finding" in prefix
    assert "src-prior-pass" not in provider.calls[0]["messages"][0].content
    assert provider.calls[0]["cache"] is True


def test_model_reviewer_raises_on_unparseable_reply():
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = ModelReviewer(provider=prov, model="mock")
    with pytest.raises(UnitReviewError, match="reply had no complete JSON"):
        review(reviewer, _U[0])


def test_model_reviewer_empty_findings_is_not_an_error():
    prov = MockProvider(default=_finder_reply())
    reviewer = ModelReviewer(provider=prov, model="mock")
    assert review(reviewer, _U[0]) == []


def test_run_units_counts_an_unparseable_reply_as_an_error(tmp_path):
    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    [unit] = ground_units(
        (Unit(name="u", root=str(tmp_path), files=("unit.py",)),),
        facts_by_file={},
        limitations=(),
        navigator=None,
        source_snapshot=capture_source_snapshot(tmp_path),
    )
    prov = MockProvider(default="sorry, no JSON here")
    acc = run_units([unit], ModelReviewer(provider=prov, model="mock"))
    assert acc.errors >= 1
    assert acc.findings == []


class _SequencedOpenAIClient:
    def __init__(self, replies):
        from types import SimpleNamespace

        self.requests = []
        self._replies = list(replies)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        from types import SimpleNamespace

        self.requests.append(kwargs)
        reply = self._replies.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])


def test_initial_and_followup_calls_of_one_unit_share_one_openai_cache_key(tmp_path):
    from cyberjury.providers.openai import OpenAIProvider

    source = "class ModelWithOwner:\n    owner_scope = True\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
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
    reviewer = ModelReviewer(provider=OpenAIProvider(client=client, wire_api="chat"), model="gpt-4o")
    unit = Unit(
        name="views", root=str(tmp_path), files=(), grounding=GroundingContext(text="seed()", navigator=navigator)
    )
    other = Unit(
        name="other", root=str(tmp_path), files=(), grounding=GroundingContext(text="other()", navigator=navigator)
    )

    assert reviewer.review_unit(unit, finder_label="mock").clean is True
    assert reviewer.review_unit(other, finder_label="mock").clean is True

    initial, followup, other_unit = client.requests
    assert initial["prompt_cache_key"] == followup["prompt_cache_key"]
    assert other_unit["prompt_cache_key"] != initial["prompt_cache_key"]
    assert initial["messages"][0] == followup["messages"][0] == other_unit["messages"][0]
    initial_user = initial["messages"][1]["content"]
    followup_user = followup["messages"][1]["content"]
    shared = len(initial_user) - len("Evidence request budget: 8 request batches remain.")
    assert followup_user[:shared] == initial_user[:shared]
    assert "owner_scope = True" in followup_user[shared:]
    assert followup_user.endswith("Evidence request budget: 7 request batches remain.")
