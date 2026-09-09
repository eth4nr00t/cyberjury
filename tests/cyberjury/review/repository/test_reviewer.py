"""Repository model reviewer parsing, prompting, and evidence tests."""

import json

import pytest

from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext, SourceEvidence, SourceSpan
from cyberjury.review.engine import EvidenceJudgment
from cyberjury.review.navigation import SourceNavigator, navigation_instructions
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.prompts import FINDER_SYSTEM, standard_finder_prompt_plan
from cyberjury.review.repository.reviewer import (
    ModelReviewer,
    RepositoryReviewError,
    UnitRoleReviewer,
    candidates_from_obj,
    review_round,
)
from cyberjury.review.repository.runner import run_passes
from cyberjury.review.repository.union import Candidate

_U = [Unit(name="u", root=".", files=())]


def _assessed_empty(*categories, established=(), evidence_requests=None, source_queries=None):
    return json.dumps(
        {
            "findings": [],
            "assessments": [
                {
                    "category": category,
                    "decision": "finding" if category in established else "not_exploitable",
                    "reason": "established candidate" if category in established else "no exploit path",
                    "evidence_refs": ["seed"],
                }
                for category in categories
            ],
            "evidence_requests": evidence_requests or [],
            "source_queries": source_queries or [],
        }
    )


def _confirmed_finding_reply(reply):
    payload = json.loads(reply)
    payload["decision_rule_assessments"] = [
        {
            "decision_rule_id": finding["decision_rule_id"],
            "decision": "finding",
            "reason": "the delivered rule and source establish the exploit",
            "evidence_refs": finding["evidence_refs"],
        }
        for finding in payload["findings"]
    ]
    return json.dumps(payload)


def test_standard_repository_prompt_allows_navigation_without_invented_evidence_ids():
    prompt = standard_finder_prompt_plan(
        "Repository grounding controls:\n" + navigation_instructions() + "\n\n",
        review_brief="guidance",
        known=[],
    ).text

    assert "Use `source_queries` only to search" in prompt
    assert "`evidence_requests`" in prompt
    assert "do not request paths or symbols" not in prompt


def test_repository_judgment_does_not_request_obsolete_class_assessments():
    prompt = standard_finder_prompt_plan(
        "unit evidence\n",
        review_brief="",
        known=[],
    ).text

    assert '"assessments"' not in prompt


@pytest.mark.parametrize(
    "finding",
    [
        {"severity": "HIGH", "file": "app.py", "status": "confirmed"},
        "junk",
        {"title": "x", "severity": "spicy", "file": "app.py", "status": "confirmed"},
        {"title": "x", "severity": "HIGH", "file": "", "status": "confirmed"},
        {"title": "x", "severity": "HIGH", "file": "app.py", "status": "unknown"},
    ],
)
def test_candidates_from_obj_rejects_malformed_finding_items(finding):
    with pytest.raises(RepositoryReviewError, match=r"role findings\[0\]"):
        candidates_from_obj({"findings": [finding]})


def test_repository_candidate_rejects_a_model_supplied_mismatched_identity():
    finding = {
        "candidate_id": "candidate-wrong",
        "title": "missing ownership check",
        "category": "missing-authorization",
        "file": "app.py",
        "line": 2,
        "severity": "HIGH",
        "attack_path": "request reads another account without ownership",
        "evidence": "app.py:2 has no ownership check",
        "status": "confirmed",
        "evidence_refs": ["seed"],
    }

    with pytest.raises(RepositoryReviewError, match="candidate_id does not match"):
        candidates_from_obj({"findings": [finding]})


def test_repository_review_reports_a_malformed_finding_as_failed_work():
    reviewer = ModelReviewer(
        provider=MockProvider(default='{"findings": [{"severity": "HIGH"}]}'),
        model="mock",
    )

    cycle = review_round(_U[0], reviewer, finder_label="mock")

    assert cycle.findings == []
    assert cycle.errors == 1
    assert "must have a title" in cycle.failure_reason


def test_model_reviewer_builds_prompt_and_parses(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = (
        '{"findings": [{"title": "idor", "category": "insecure-direct-object-reference", '
        '"decision_rule_id": "idor-object-scope", '
        '"endpoint": "GET /x/<id>", "file": "app.py", "line": 2, '
        '"severity": "high", "attack_path": "request reads another account without ownership", '
        '"evidence": "app.py:2 exposes another account", '
        '"status": "confirmed", "evidence_refs": ["seed"]}]}'
    )
    prov = MockProvider(responses=[reply, _confirmed_finding_reply(reply), reply, _confirmed_finding_reply(reply)])
    reviewer = ModelReviewer(provider=prov, model="mock")
    unit = Unit(name="wallets", root=str(tmp_path), files=("app.py",))

    cands = reviewer.review(unit, shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"
    assert cands[0].decision_rule_id == "idor-object-scope"

    sent = prov.calls[0]["messages"][0].content
    assert "Review the evidence for every real, high-impact vulnerability" in sent
    assert "LENS" not in sent
    assert "Severity rubric" in sent
    assert "def handler" in sent
    assert "```\n\nRepository grounding controls:\n" in sent

    assert prov.calls[0]["cache"] is False
    assert prov.calls[0]["cache_prefix"] == ""

    reviewer.review(unit, shared_context="stack: flask")
    assert prov.calls[2]["cache"] is False
    assert prov.calls[2]["cache_prefix"] == ""


def test_repository_reviewer_rejects_an_unknown_category_instead_of_coercing_other(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = (
        '{"findings": [{"title": "idor", "category": "idor", "decision_rule_id": "", '
        '"endpoint": "GET /x/<id>", "file": "app.py", "line": 2, "severity": "HIGH", '
        '"attack_path": "request reads another account without ownership", '
        '"evidence": "app.py:2 exposes another account", '
        '"status": "confirmed", "evidence_refs": ["seed"]}]}'
    )
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    with pytest.raises(RepositoryReviewError, match="finding category is unknown"):
        reviewer.review(Unit(name="wallets", root=str(tmp_path), files=("app.py",)))


def test_repository_finding_location_must_be_covered_by_its_cited_source(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n", encoding="utf-8")
    reply = (
        '{"findings": [{"title": "wrong location", "category": "insecure-direct-object-reference", '
        '"decision_rule_id": "idor-object-scope", '
        '"file": "other.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
        '"attack_path": "request reads another account without ownership", '
        '"evidence": "other.py:2 lacks ownership", "evidence_refs": ["seed"]}]}'
    )
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    with pytest.raises(RepositoryReviewError, match="cited source receipt"):
        reviewer.review(Unit(name="app", root=str(tmp_path), files=("app.py",)))


def test_model_reviewer_can_request_one_published_source_fragment():
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [supported]",
        text="1 | class Account:\n2 |     owner = None",
        source_span=SourceSpan(file="models.py", start_line=1, end_line=2),
    )
    provider = MockProvider(
        responses=[
            f'{{"findings": [], "evidence_requests": ["{evidence.id}"]}}',
            '{"findings": [{"title": "missing ownership check", '
            '"category": "insecure-direct-object-reference", "decision_rule_id": "idor-object-scope", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            '"attack_path": "view returns all accounts without ownership", '
            '"evidence": "views.py:2 returns objects without ownership", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}], "evidence_requests": []}}',
            '{"findings": [{"title": "missing ownership check", '
            '"category": "insecure-direct-object-reference", "decision_rule_id": "idor-object-scope", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            '"attack_path": "view returns all accounts without ownership", '
            '"evidence": "views.py:2 returns objects without ownership", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}], "decision_rule_assessments": ['
            '{"decision_rule_id": "idor-object-scope", "decision": "finding", '
            '"reason": "the delivered rule and source establish the exploit", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}]}}',
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
        source_spans=(SourceSpan(file="views.py", start_line=1, end_line=2),),
    )
    reviewer = ModelReviewer(provider=provider, model="mock")

    findings = reviewer.review(Unit(name="views", root=".", files=(), grounding=grounding))

    assert [finding.title for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 3
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_repository_adversarial_roles_share_finder_evidence():
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [supported]",
        text="1 | class Account:\n2 |     owner = None",
        source_span=SourceSpan(file="models.py", start_line=1, end_line=2),
    )
    provider = MockProvider(
        responses=[
            f'{{"findings": [], "evidence_requests": ["{evidence.id}"]}}',
            '{"findings": [{"title": "missing ownership check", '
            '"category": "insecure-direct-object-reference", "decision_rule_id": "idor-object-scope", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            '"attack_path": "view returns all accounts without ownership", '
            '"evidence": "views.py:2 returns objects without ownership", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}]}}',
            '{"findings": [{"title": "missing ownership check", '
            '"category": "insecure-direct-object-reference", "decision_rule_id": "idor-object-scope", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            '"attack_path": "view returns all accounts without ownership", '
            '"evidence": "views.py:2 returns objects without ownership", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}], "decision_rule_assessments": ['
            '{"decision_rule_id": "idor-object-scope", "decision": "finding", '
            '"reason": "the delivered rule and source establish the exploit", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}]}}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": [{"title": "missing ownership check", '
            '"category": "insecure-direct-object-reference", "decision_rule_id": "idor-object-scope", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            '"attack_path": "view returns all accounts without ownership", '
            '"evidence": "views.py:2 returns objects without ownership", '
            f'"evidence_refs": ["seed", "{evidence.id}"]}}]}}',
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
        source_spans=(SourceSpan(file="views.py", start_line=1, end_line=2),),
    )
    reviewer = ModelReviewer(provider=provider, model="mock")
    unit = Unit(name="views", root=".", files=(), grounding=grounding)

    cycle = review_round(
        unit,
        reviewer,
        finder_label="mock",
        challenger=reviewer,
        judge=reviewer,
    )

    assert len(provider.calls) == 5
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert all(evidence.text in call["messages"][0].content for call in provider.calls[1:])
    assert cycle.grounding.included == (evidence.identity,)


def test_repository_adversarial_uses_one_profile_brief():
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": []}',
        ]
    )
    reviewer = ModelReviewer(provider=provider, model="mock")
    unit = Unit(
        name="unit",
        root=".",
        files=(),
        grounding=GroundingContext(text="review-signal"),
    )

    run_passes(
        [unit],
        reviewer,
        challenger=reviewer,
        judge=reviewer,
        converge_after=1,
        min_rounds=1,
        max_passes=1,
    )

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 3
    assert all("# Security Rule Index" in prompt for prompt in prompts)
    assert all("ssrf-resolution-connection-binding" in prompt for prompt in prompts)


def test_repository_adversarial_location_accepts_preexisting_source_evidence():
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

    class Reviewer(UnitRoleReviewer):
        def review(self, unit, *, shared_context=""):
            return [finding]

        def find(self, unit, *, shared_context="", known=None):
            return EvidenceJudgment(findings=[finding])

    grounding = GroundingContext(text="seed", source_evidence=(evidence,))
    unit = Unit(name="service", root=".", files=(), grounding=grounding)
    reviewer = Reviewer()

    cycle = review_round(unit, reviewer, finder_label="finder", challenger=reviewer, judge=reviewer)

    assert [(item.file, item.line, item.evidence_refs) for item in cycle.findings] == [
        ("service.py", 8, (evidence.id,))
    ]
    assert cycle.incomplete == []
    assert cycle.clean is True


def test_repository_adversarial_rejects_a_malformed_rebuttal_item():
    reviewer = ModelReviewer(
        provider=MockProvider(default='{"rebuttals": ["not an object"], "new_findings": []}'),
        model="mock",
    )

    with pytest.raises(RepositoryReviewError, match=r"rebuttals\[0\] must be an object"):
        reviewer.challenge(_U[0], [])


def test_repository_adversarial_rejects_a_malformed_pending_item():
    reviewer = ModelReviewer(
        provider=MockProvider(default='{"findings": [], "investigate": ["not an object"]}'),
        model="mock",
    )

    with pytest.raises(RepositoryReviewError, match=r"investigate\[0\] must be an object"):
        reviewer.judge(_U[0], [], [], [])


@pytest.mark.parametrize("reply", ['{"findings": [', '```json\n{"findings": [\n```'])
def test_repository_rejects_a_truncated_findings_array(reply):
    reviewer = ModelReviewer(provider=MockProvider(default=reply), model="mock")

    with pytest.raises(RepositoryReviewError, match="reply had no usable JSON"):
        reviewer.review(_U[0])


def test_repository_requires_concrete_finding_evidence():
    finding = {
        "title": "missing control",
        "category": "missing-authorization",
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "evidence": "",
        "status": "confirmed",
        "evidence_refs": ["seed"],
    }

    with pytest.raises(RepositoryReviewError, match="concrete evidence"):
        candidates_from_obj({"findings": [finding]})


def test_model_reviewer_uses_the_same_unit_knowledge_for_every_role(tmp_path):
    (tmp_path / "tokens.py").write_text("def issue_token():\n    return make_token()\n")
    provider = MockProvider(
        responses=[
            _assessed_empty(),
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            _assessed_empty(),
        ]
    )
    reviewer = ModelReviewer(
        provider=provider,
        model="mock",
        facts_by_file={"tokens.py": "Definition make_token\n  return uuid.uuid1().hex"},
    )
    unit = Unit(name="tokens", root=str(tmp_path), files=("tokens.py",))

    reviewer.review(unit)
    reviewer.find(unit)
    challenge = reviewer.challenge(unit, [])
    reviewer.judge(unit, [], challenge.rebuttals, challenge.new_findings)

    prompts = [call["messages"][0].content for call in provider.calls]
    assert all("cryptography-secret-and-nonce-generation" in prompt for prompt in prompts)
    assert all("sql-syntax-boundary" in prompt for prompt in prompts)
    assert provider.calls[0]["cache"] is False
    assert provider.calls[0]["cache_prefix"] == ""
    adversarial_prefixes = [call["cache_prefix"] for call in provider.calls[1:]]
    assert adversarial_prefixes[1] == adversarial_prefixes[2]
    assert all("Evidence request budget" in call["messages"][0].content for call in provider.calls[1:])


def test_model_reviewer_loads_knowledge_from_the_selected_profile(tmp_path):
    (tmp_path / "Proxy.sol").write_text(
        "contract Proxy { function run(address target) external { target.delegatecall(msg.data); } }\n"
    )
    provider = MockProvider(responses=[_assessed_empty()])
    reviewer = ModelReviewer(provider=provider, model="mock", content=EVM_PROFILE.paths)

    reviewer.review(Unit(name="proxy", root=str(tmp_path), files=("Proxy.sol",)))

    prompt = provider.calls[0]["messages"][0].content
    assert "proxy-upgrade-and-delegate-target" in prompt
    assert "unchecked-call-application-result" in prompt
    assert "sql-syntax-boundary" not in prompt


def test_repository_standard_uses_one_profile_brief_judgment(tmp_path):
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default=_assessed_empty())
    reviewer = ModelReviewer(provider=provider, model="mock")

    reviewer.review(Unit(name="app", root=str(tmp_path), files=("app.py",)))

    assert len(provider.calls) == 1
    assert provider.calls[0]["cache"] is False
    prompt = provider.calls[0]["messages"][0].content
    assert "alpha beta" in prompt
    assert "# Security Rule Index" in prompt


def test_repository_navigation_keeps_profile_coverage_and_runs_a_final_evidence_sweep(tmp_path):
    source = "class ModelWithOwner:\n    owner_scope = True\n"
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

    cycle = reviewer.review_round(unit, finder_label="mock")

    assert cycle.clean is True
    assert len(raw_provider.calls) == 2
    assert raw_provider.calls[0]["system"] == FINDER_SYSTEM
    assert raw_provider.calls[0]["cache"] is False
    assert raw_provider.calls[1]["cache"] is True
    assert raw_provider.calls[1]["cache_prefix"]
    assert "# Security Rule Index" in raw_provider.calls[0]["messages"][0].content
    assert "Evidence request budget: 8 request batches remain" in raw_provider.calls[0]["messages"][0].content
    final_prompt = raw_provider.calls[-1]["messages"][0].content
    assert "owner_scope = True" in final_prompt
    assert "# Security Rule Index" not in final_prompt
    assert final_prompt.count("# Security Category Index") == 1
    assert "server-side-request-forgery: Server-Side Request Forgery" in final_prompt
    calls = meter.call_snapshot()
    assert calls[0]["navigation_status"] == "delivered"
    assert len(calls[0]["navigation_delta_ids"]) == 1
    assert calls[0]["navigation_delta_chars"] > 0
    assert calls[0]["source_query_count"] == 1
    assert calls[0]["trigger"] == "initial_judgment"
    assert calls[1]["navigation_status"] == "not_requested"
    assert calls[1]["trigger"] == "evidence_followup"


def test_repository_dependency_evidence_does_not_change_the_profile_brief():
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

    reviewer.review(unit)

    prompt = provider.calls[0]["messages"][0].content
    assert evidence.id in prompt
    assert "sensitive_operation" not in prompt
    assert "# Security Rule Index" in prompt


def test_repository_standard_carries_known_findings_into_the_profile_brief(tmp_path):
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

    reviewer.review_round(
        Unit(name="app", root=str(tmp_path), files=("app.py",)),
        finder_label="mock",
        known=[prior],
    )

    assert len(provider.calls) == 1
    assert prior.candidate_id in provider.calls[0]["messages"][0].content
    assert "prior finding" not in provider.calls[0]["messages"][0].content
    assert "src-prior-pass" not in provider.calls[0]["messages"][0].content
    assert provider.calls[0]["cache"] is False
    assert provider.calls[0]["cache_prefix"] == ""


def test_model_reviewer_raises_on_unparseable_reply():
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = ModelReviewer(provider=prov, model="mock")
    with pytest.raises(RepositoryReviewError, match="failed review"):
        reviewer.review(Unit(name="u", root=".", files=()))


def test_model_reviewer_empty_findings_is_not_an_error():
    prov = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=prov, model="mock")
    assert reviewer.review(Unit(name="u", root=".", files=())) == []


def test_run_passes_counts_an_unparseable_reply_as_an_error():
    prov = MockProvider(default="sorry, no JSON here")
    acc = run_passes(_U, ModelReviewer(provider=prov, model="mock"), max_passes=2)
    assert acc.errors >= 1
    assert acc.findings == []
