"""A Diff review keeps distinct findings and folds only exact duplicate reports."""

from cyberjury.providers.mock import MockProvider
from tests.review.diff.support import reply, review

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _provider(findings):
    return MockProvider(default=reply(findings))


def test_review_keeps_distinct_entrypoint_paths_at_one_location():
    """Two app.py:1 SQL injection reports via POST /query and QueryView.post stay two findings."""
    base = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "evidence": "attacker input becomes SQL syntax",
    }
    findings = [
        {**base, "entrypoint": "POST /query"},
        {**base, "entrypoint": "QueryView.post"},
    ]

    result = review(_DIFF, provider=_provider(findings))

    assert len(result.outcome.findings) == 2
    assert result.outcome.complete is True


def test_review_preserves_a_valid_anchor_after_an_invalid_duplicate():
    """Duplicates anchored at unchanged line 10 and added line 11 fold to one finding anchored at 11."""
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10,3 @@\n"
        " existing()\n"
        "+expose()\n"
        " finish()\n"
    )
    base = {
        "file": "app.py",
        "line": 10,
        "severity": "HIGH",
        "category": "other",
        "evidence": "existing operation is exposed",
    }
    findings = [
        {**base, "change_anchor": {"file": "app.py", "line": 10, "side": "new"}},
        {**base, "change_anchor": {"file": "app.py", "line": 11, "side": "new"}},
    ]

    result = review(diff, provider=_provider(findings))

    assert [
        (item.line, item.change_anchor.line if item.change_anchor else None) for item in result.outcome.findings
    ] == [(10, 11)]
    assert result.outcome.complete is False
