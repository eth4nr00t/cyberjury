"""Candidate identity keeps independent root causes at the same source anchor."""

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.review.repository.union import Candidate


def test_diff_candidate_identity_ignores_exploit_scenario_rewrites():
    base = Finding(
        file="app.py",
        line=10,
        category="sql-injection",
        entrypoint="POST /query",
        description="first wording",
        exploit_scenario="public request reaches the query sink",
        change_anchor=ChangeAnchor(file="app.py", line=10, side="new"),
    )
    rewritten = Finding(
        file="app.py",
        line=10,
        category="sql-injection",
        entrypoint="POST /query",
        description="first wording",
        exploit_scenario="an attacker sends input that reaches the same sink",
        change_anchor=ChangeAnchor(file="app.py", line=10, side="new"),
    )

    assert base.candidate_id == rewritten.candidate_id


def test_diff_candidate_identity_distinguishes_entrypoints_at_one_location():
    first = Finding(
        file="app.py",
        line=10,
        category="missing-authorization",
        entrypoint="GET /account",
        exploit_scenario="public route reaches the account read",
    )
    second = Finding(
        file="app.py",
        line=10,
        category="missing-authorization",
        entrypoint="task.export",
        exploit_scenario="background task reaches the account export",
    )

    assert first.candidate_id != second.candidate_id
    assert first.attack_path_id != second.attack_path_id


def test_diff_attack_path_links_distinct_violations_on_one_entrypoint():
    authorization = Finding(
        file="service.py",
        line=10,
        category="missing-authorization",
        entrypoint="POST /render",
    )
    template_injection = Finding(
        file="templates.py",
        line=30,
        category="server-side-template-injection",
        entrypoint="POST /render",
    )

    assert authorization.attack_path_id == template_injection.attack_path_id
    assert authorization.candidate_id != template_injection.candidate_id


def test_candidate_identity_distinguishes_causes_within_one_category():
    diff_first = Finding(
        file="app.py",
        line=10,
        category="resource-exhaustion",
        description="unbounded regex match",
        entrypoint="POST /match",
    )
    diff_second = Finding(
        file="app.py",
        line=10,
        category="resource-exhaustion",
        description="unbounded response amplification",
        entrypoint="POST /match",
    )
    repository_first = Candidate(
        title="regex",
        file="app.py",
        line=10,
        category="resource-exhaustion",
    )
    repository_second = Candidate(
        title="amplification",
        file="app.py",
        line=10,
        category="resource-exhaustion",
    )

    assert diff_first.candidate_id != diff_second.candidate_id
    assert repository_first.candidate_id != repository_second.candidate_id


def test_repository_candidate_identity_uses_canonical_location_and_title():
    first = Candidate(
        title="first wording",
        category="missing-authorization",
        file="routes.py",
        line=20,
        attack_path="attacker request reaches the same export without authorization",
    )
    rewritten = Candidate(
        title="first wording",
        category="missing-authorization",
        file="routes.py",
        line=20,
        attack_path="request reaches unguarded account export",
    )

    assert first.candidate_id == rewritten.candidate_id


def test_repository_attack_path_identity_falls_back_to_source_location():
    first = Candidate(title="first", category="other", file="one.py", line=1)
    second = Candidate(title="second", category="other", file="two.py", line=2)

    assert first.attack_path_id != second.attack_path_id
