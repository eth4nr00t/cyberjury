"""Candidate identity keeps independent root causes at the same source anchor."""

from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.identity import canonical_category


def _finding(**fields: object) -> Finding:
    defaults = {
        "title": "first wording",
        "severity": "HIGH",
        "file": "app.py",
        "line": 10,
        "category": "sql-injection",
        "entrypoint": "POST /query",
        "evidence": "app.py:10 concatenates the request value",
        "attack_path": "public request reaches the query sink",
    }
    return Finding(**{**defaults, **fields})


def test_candidate_identity_ignores_evidence_and_attack_path_rewrites():
    """Rewording evidence or attack_path, with or without a change anchor, keeps the candidate id."""
    anchor = ChangeAnchor(file="app.py", line=10, side="new")
    base = _finding(change_anchor=anchor)
    rewritten = _finding(
        change_anchor=anchor,
        evidence="the request value reaches the query string",
        attack_path="an attacker sends input that reaches the same sink",
    )

    assert base.candidate_id == rewritten.candidate_id
    assert _finding().candidate_id == _finding(attack_path="request reaches unguarded query").candidate_id


def test_candidate_identity_distinguishes_entrypoints_at_one_location():
    """Findings at app.py:10 with entrypoints "GET /account" and "task.export" get different ids."""
    assert _finding(entrypoint="GET /account").candidate_id != _finding(entrypoint="task.export").candidate_id


def test_candidate_identity_distinguishes_causes_within_one_category():
    """Titles "regex" and "amplification" in one category give different ids, anchored or not."""
    anchor = ChangeAnchor(file="app.py", line=10, side="new")

    assert _finding(title="regex").candidate_id != _finding(title="amplification").candidate_id
    assert (
        _finding(title="regex", change_anchor=anchor).candidate_id
        != _finding(title="amplification", change_anchor=anchor).candidate_id
    )


def test_category_qualifiers_do_not_create_new_vulnerability_classes():
    """Labels such as "Authorization Bypass (IDOR)" drop the qualifier and canonicalize to authorization-bypass."""
    assert canonical_category("Authorization Bypass (IDOR)") == "authorization-bypass"
    assert canonical_category("authorization-bypass-(ownership check)") == "authorization-bypass"
    assert canonical_category("race-condition") == "race-condition"
    assert canonical_category("(unknown)") == "(unknown)"
