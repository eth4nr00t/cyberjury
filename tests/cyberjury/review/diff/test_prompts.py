"""Diff prompts keep profile policy and adversarial roles visible."""

from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    audit_diff,
)
from cyberjury.review.diff.prompts import (
    challenger_prompt,
    finder_prompt,
    judge_prompt,
    standard_audit_prompt,
)
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def test_prompt_carries_diff_focus_and_do_not_report():
    p = standard_audit_prompt(_DIFF, vulnerabilities="VULN-X", context="def caller(): ...", stack="STACK-NOTE")
    assert "SELECT * FROM u" in p
    assert "Do NOT report" in p
    assert "IDOR" in p
    assert "VULN-X" in p
    assert "STACK-NOTE" in p
    assert "def caller()" in p
    assert "change_anchor" in p
    assert "old:new" in p
    assert "reachability only" in p
    assert "Always provide this field" in p


def test_adversarial_mode_carries_stack_notes_and_judge_policy():
    diff = "diff --git a/app/urls.py b/app/urls.py\n@@ -0,0 +1,2 @@\n+from django.urls import path\n+urlpatterns = []\n"
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": [], "converged": true}',
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": [], "converged": true}',
        ],
        default="{}",
    )
    audit_diff(
        diff,
        provider=provider,
        model="m",
        mode="adversarial",
        max_rounds=2,
        prepare_diff=repository_prepare(),
    )
    prompts = [call["messages"][0].content for call in provider.calls]
    assert "Django" in prompts[0]
    assert "Python" in prompts[0]
    assert "Django" in prompts[1]
    assert "Python" in prompts[1]
    assert "Django" not in prompts[2]
    assert "Python" not in prompts[2]
    assert "Do NOT report" in prompts[2]


def test_every_diff_role_uses_the_same_change_anchor_contract():
    finder = finder_prompt(_DIFF)
    challenger = challenger_prompt(_DIFF, [])
    judge = judge_prompt(_DIFF, [], [], [])

    for prompt in (finder, challenger, judge):
        assert "change_anchor" in prompt
        assert "old:new" in prompt
        assert '"side": "old|new"' in prompt
