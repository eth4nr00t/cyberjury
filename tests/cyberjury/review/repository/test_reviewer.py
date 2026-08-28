"""Repository model reviewer parsing, prompting, and evidence tests."""

import pytest

from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext
from cyberjury.review.navigation import SourceNavigator, navigation_instructions
from cyberjury.review.prompts import NAVIGATOR_SYSTEM
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.prompts import standard_finder_prompt_plan
from cyberjury.review.repository.reviewer import (
    ModelReviewer,
    RepositoryReviewError,
    candidates_from_obj,
    review_round,
)
from cyberjury.review.repository.runner import run_passes
from cyberjury.review.repository.union import Candidate
from cyberjury.review.vulnerabilities import Vulnerability, VulnerabilityCatalog

_U = [Unit(name="u", root=".", files=())]


def test_standard_repository_prompt_allows_navigation_without_invented_evidence_ids():
    prompt = standard_finder_prompt_plan(
        "Repository grounding controls:\n" + navigation_instructions() + "\n\n",
        vulnerability_categories=("missing-authorization",),
        selected_vulnerability_categories=("missing-authorization",),
        vulnerabilities="guidance",
        known=[],
    ).text

    assert "Use `source_queries` only to search" in prompt
    assert "`evidence_requests`" in prompt
    assert "do not request paths or symbols" not in prompt


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
        '{"findings": [{"title": "idor", "category": "idor", '
        '"endpoint": "GET /x/<id>", "file": "app.py", "line": 2, '
        '"severity": "high", "status": "confirmed", "evidence_refs": ["seed"]}]}'
    )
    prov = MockProvider(default=reply)
    reviewer = ModelReviewer(provider=prov, model="mock")
    unit = Unit(name="wallets", root=str(tmp_path), files=("app.py",))

    cands = reviewer.review(unit, shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"

    sent = prov.calls[0]["messages"][0].content
    assert "Review the evidence for every real, high-impact vulnerability" in sent
    assert "LENS" not in sent
    assert "Severity rubric" in sent
    assert "def handler" in sent
    assert "```\n\nRepository grounding controls:\n" in sent

    assert prov.calls[0]["cache"] is False
    assert prov.calls[0]["cache_prefix"] == ""

    reviewer.review(unit, shared_context="stack: flask")
    assert prov.calls[1]["cache"] is False
    assert prov.calls[1]["cache_prefix"] == ""


def test_model_reviewer_can_request_one_published_source_fragment():
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [exact]",
        text="1 | class Account:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            f'{{"findings": [], "evidence_requests": ["{evidence.id}"]}}',
            '{"findings": [{"title": "missing ownership check", "category": "idor", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            f'"evidence_refs": ["{evidence.id}"]}}], "evidence_requests": []}}',
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
    )
    reviewer = ModelReviewer(provider=provider, model="mock")

    findings = reviewer.review(Unit(name="views", root=".", files=(), grounding=grounding))

    assert [finding.title for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_repository_adversarial_roles_share_finder_evidence():
    evidence = EvidenceItem.create(
        identity="models.py:Account:0:28",
        label="models.py:Account, import Account from views.py [exact]",
        text="1 | class Account:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            f'{{"findings": [], "evidence_requests": ["{evidence.id}"]}}',
            '{"findings": [{"title": "missing ownership check", "category": "idor", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            f'"evidence_refs": ["{evidence.id}"]}}]}}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": [{"title": "missing ownership check", "category": "idor", '
            '"file": "views.py", "line": 2, "severity": "HIGH", "status": "confirmed", '
            f'"evidence_refs": ["{evidence.id}"]}}]}}',
        ]
    )
    grounding = GroundingContext(
        text="1 | def view():\n2 |     return Account.objects.all()",
        evidence=(evidence,),
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

    assert len(provider.calls) == 4
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert all(evidence.text in call["messages"][0].content for call in provider.calls[1:])
    assert cycle.grounding.included == (evidence.identity,)


def test_model_reviewer_uses_the_same_unit_knowledge_for_every_role(tmp_path):
    (tmp_path / "tokens.py").write_text("def issue_token():\n    return make_token()\n")
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": []}',
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
    assert all("UUIDv1 is not a secret generator" in prompt for prompt in prompts)
    assert all("SQL Injection" not in prompt for prompt in prompts)
    assert provider.calls[0]["cache"] is False
    assert provider.calls[0]["cache_prefix"] == ""
    adversarial_prefixes = [call["cache_prefix"] for call in provider.calls[1:]]
    assert adversarial_prefixes[1] == adversarial_prefixes[2]
    assert "Evidence request budget" in provider.calls[1]["messages"][0].content
    assert all("Evidence request budget" not in call["messages"][0].content for call in provider.calls[2:])


def test_model_reviewer_loads_knowledge_from_the_selected_profile(tmp_path):
    (tmp_path / "Proxy.sol").write_text(
        "contract Proxy { function run(address target) external { target.delegatecall(msg.data); } }\n"
    )
    provider = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=provider, model="mock", content=EVM_PROFILE.paths)

    reviewer.review(Unit(name="proxy", root=str(tmp_path), files=("Proxy.sol",)))

    prompt = provider.calls[0]["messages"][0].content
    assert "Proxy, Delegatecall, and Initializer Flaws" in prompt
    assert "SQL Injection" not in prompt


def test_repository_standard_reuses_unit_evidence_across_knowledge_packs(tmp_path):
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=provider, model="mock")
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
    reviewer._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    reviewer.review(Unit(name="app", root=str(tmp_path), files=("app.py",)))

    assert len(provider.calls) == 2
    assert all(call["cache"] is True for call in provider.calls)
    prefixes = [call["cache_prefix"] for call in provider.calls]
    assert prefixes[0] == prefixes[1]
    assert "alpha beta" in prefixes[0]
    assert "alphaalpha" not in prefixes[0]
    assert "alphaalpha" in provider.calls[0]["messages"][0].content
    assert "betabeta" in provider.calls[1]["messages"][0].content


def test_repository_navigation_reselects_knowledge_and_runs_a_stable_final_sweep(tmp_path):
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
    provider = MockProvider(
        responses=[
            '{"evidence_requests": [], "source_queries": '
            '[{"kind": "search_symbols", "query": "ModelWithOwner", "page": 0}]}',
            '{"evidence_requests": ["src-1"], "source_queries": []}',
            '{"evidence_requests": [], "source_queries": []}',
            '{"findings": [], "source_queries": []}',
            '{"findings": [], "source_queries": []}',
        ]
    )
    reviewer = ModelReviewer(provider=provider, model="mock")
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
    reviewer._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )
    unit = Unit(
        name="views",
        root=str(tmp_path),
        files=(),
        grounding=GroundingContext(text="initial_signal()", navigator=navigator),
    )

    cycle = reviewer.review_round(unit, finder_label="mock")

    assert cycle.clean is True
    assert len(provider.calls) == 5
    assert provider.calls[0]["system"] == NAVIGATOR_SYSTEM
    assert "Do not decide whether a vulnerability exists" in provider.calls[0]["messages"][0].content
    assert "Owner scope guidance." not in provider.calls[0]["messages"][0].content
    assert "Evidence request budget: 8 request batches remain" in provider.calls[0]["messages"][0].content
    audit_prompts = [call["messages"][0].content for call in provider.calls[3:]]
    assert any("Initial guidance." in prompt for prompt in audit_prompts)
    assert "Evidence request budget: 6 request batches remain" in audit_prompts[0]
    final_prompt = provider.calls[-1]["messages"][0].content
    assert "Owner scope guidance." in final_prompt
    assert "owner_scope = True" in final_prompt


def test_repository_knowledge_selection_uses_exact_dependency_evidence():
    provider = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=provider, model="mock")
    item = Vulnerability(
        id="sensitive-operation",
        title="Sensitive Operation",
        impact="HIGH",
        tags=(),
        aliases=(),
        selection_hints=("sensitive_operation",),
        body="Review the complete sensitive operation path.",
    )
    reviewer._vulnerability_catalog = VulnerabilityCatalog(
        items=(item,),
        ids=frozenset({item.id}),
        aliases={},
    )
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

    assert "Review the complete sensitive operation path." in provider.calls[0]["messages"][0].content


def test_repository_standard_carries_known_findings_into_every_knowledge_pack(tmp_path):
    (tmp_path / "app.py").write_text("alpha beta\n")
    provider = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=provider, model="mock")
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
    reviewer._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )
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

    assert len(provider.calls) == 2
    assert all("prior finding" in call["messages"][0].content for call in provider.calls)
    assert all("src-prior-pass" not in call["messages"][0].content for call in provider.calls)
    assert provider.calls[0]["cache_prefix"] == provider.calls[1]["cache_prefix"]
    assert "prior finding" in provider.calls[0]["cache_prefix"]


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
