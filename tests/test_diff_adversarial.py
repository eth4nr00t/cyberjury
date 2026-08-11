"""The adversarial diff engine consumes deterministic role ordered mock replies."""

import json

from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import audit_diff
from cyberjury.review.diff.prompts import (
    CHALLENGER_SYSTEM,
    FINDER_SYSTEM,
    JUDGE_SYSTEM,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
)
from cyberjury.review.diff.reviewer import AdversarialAuditRunner

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _finder(findings):
    return json.dumps({"findings": findings})


def _challenger(rebuttals=None, new_findings=None):
    return json.dumps({"rebuttals": rebuttals or [], "new_findings": new_findings or []})


def _judge(findings, dismissed=None, unresolved=None, investigate=None, downgraded=None, converged=False):
    return json.dumps(
        {
            "findings": findings,
            "dismissed": dismissed or [],
            "unresolved": unresolved or [],
            "investigate": investigate or [],
            "downgraded": downgraded or [],
            "converged": converged,
        }
    )


_VULN = {
    "file": "app.py",
    "line": 3,
    "severity": "CRITICAL",
    "category": "sql_injection",
    "description": "concat",
    "confidence": 0.95,
}


def _run(responses, **kw):
    provider = MockProvider(responses=responses, default="{}")
    out = AdversarialAuditRunner(provider=provider, model="m").run(_DIFF, **kw)
    return provider, out


def test_three_roles_run_in_order_one_round():
    """Three roles run in order one round."""
    provider, out = _run([_finder([_VULN]), _challenger(), _judge([_VULN])], max_rounds=1)
    assert len(provider.calls) == 3
    assert [c["system"] for c in provider.calls] == [FINDER_SYSTEM, CHALLENGER_SYSTEM, JUDGE_SYSTEM]
    assert len(out.findings) == 1
    assert out.findings[0].category == "sql_injection"
    assert out.rounds == 1


def test_judge_dismissal_drops_a_finding():
    """Judge dismissal drops a finding."""
    second = {**_VULN, "line": 5, "category": "xss"}
    _, out = _run(
        [
            _finder([_VULN, second]),
            _challenger(rebuttals=[{"target": "app.py:5", "verdict": "dismiss", "reason": "escaped"}]),
            _judge([_VULN], dismissed=[{"target": "app.py:5", "reason": "output is escaped"}]),
        ],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["sql_injection"]


def test_challenger_independent_finding_can_survive():
    """Challenger independent finding can survive."""
    missed = {"file": "app.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    _, out = _run(
        [_finder([]), _challenger(new_findings=[missed]), _judge([missed])],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["idor"]
    assert out.findings[0].found_by == ("m",)


def test_adversarial_findings_record_the_role_that_found_them():
    """Per finding provenance lets verification skip the finding seat."""
    missed = {"file": "app.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(new_findings=[missed]), _judge([_VULN, missed])])
    out = AdversarialAuditRunner(
        provider=provider,
        model="base",
        finder_model="finder",
        challenger_model="challenger",
        judge_model="judge",
    ).run(_DIFF, max_rounds=1)
    labels = {finding.category: finding.found_by for finding in out.findings}
    assert labels == {"sql_injection": ("finder",), "idor": ("challenger",)}


def test_judge_converged_flag_does_not_stop_the_deterministic_loop():
    """Convergence is a coded property rather than a model supplied verdict."""
    round_triplet = [_finder([_VULN]), _challenger(), _judge([_VULN], converged=True)]
    provider, out = _run(round_triplet * 3, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 3
    assert len(provider.calls) == 9


def test_converged_flag_ignored_while_investigate_pending():
    """Converged flag ignored while investigate pending."""
    r1 = [
        _finder([_VULN]),
        _challenger(),
        _judge([_VULN], converged=True, investigate=[{"target": "x", "reason": "runtime check"}]),
    ]
    provider, out = _run(r1 + r1, max_rounds=2)
    assert out.rounds == 2
    assert len(provider.calls) == 6


def test_judge_downgrade_lowers_finding_severity():
    """Judge downgrade lowers finding severity."""
    dg = [{"target": "app.py:3", "from": "CRITICAL", "to": "MEDIUM", "reason": "needs an unlikely precondition"}]
    _, out = _run(
        [_finder([_VULN]), _challenger(), _judge([{**_VULN, "severity": "MEDIUM"}], downgraded=dg)],
        max_rounds=1,
    )
    assert out.findings[0].severity == "MEDIUM"


def test_investigate_items_are_carried():
    """Investigate items are carried."""
    _, out = _run(
        [_finder([]), _challenger(), _judge([], investigate=[{"target": "y", "reason": "needs a runtime check"}])],
        max_rounds=1,
    )
    assert [(i["target"], i["reason"]) for i in out.investigate] == [("y", "needs a runtime check")]


def test_unresolved_items_are_pending_and_prevent_completion():
    """A Judge uncertainty remains visible instead of looking like a clean empty result."""
    _, out = _run(
        [_finder([]), _challenger(), _judge([], unresolved=[{"target": "app.py:3", "reason": "missing context"}])],
        max_rounds=1,
    )

    assert out.pending == [{"kind": "unresolved", "target": "app.py:3", "reason": "missing context"}]
    assert out.complete is False


def test_converges_when_confirmed_set_stable():
    """Converges when confirmed set stable."""
    rounds = [_finder([_VULN]), _challenger(), _judge([_VULN])] * 3
    provider, out = _run(rounds, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 3
    assert len(provider.calls) == 9


def test_runs_to_max_rounds_when_unstable():
    """An unstable run reaches its cap and remains visibly incomplete."""
    r1 = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    r2 = [_finder([_VULN]), _challenger(), _judge([{**_VULN, "line": 7}])]
    provider, out = _run(r1 + r2, max_rounds=2)
    assert out.converged is False
    assert out.rounds == 2
    assert out.degraded is True
    assert out.failure_reason == "adversarial review did not converge within 2 rounds"
    assert len(provider.calls) == 6


def test_later_round_omission_does_not_delete_a_prior_finding():
    """The union keeps earlier candidates unless coded verification removes them."""
    first = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    later = [_finder([]), _challenger(), _judge([])]
    _, out = _run(first + later + later, max_rounds=3)
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.converged is True


def test_garbage_replies_yield_no_findings_and_degrade():
    """Malformed role output is incomplete work, not a clean empty review."""
    _, out = _run(["junk", "junk", "junk"], max_rounds=1)
    assert out.findings == []
    assert out.degraded is True


def test_unusable_judge_falls_back_to_finder_findings_not_empty():
    """Unusable judge falls back to finder findings not empty."""
    _, out = _run([_finder([_VULN]), _challenger(), "<html>blocked by WAF</html>"], max_rounds=1)
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.degraded is True
    assert out.converged is False


def test_unusable_judge_includes_challenger_independent_findings():
    """Unusable judge includes challenger independent findings."""
    missed = {"file": "a.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    _, out = _run([_finder([]), _challenger(new_findings=[missed]), "not json"], max_rounds=1)
    assert [f.category for f in out.findings] == ["idor"]
    assert out.degraded is True


def test_audit_diff_surfaces_degraded_on_unusable_judge():
    """Audit diff surfaces degraded on unusable judge."""
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(), "not json", "not json"], default="{}")
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="adversarial", max_rounds=1)
    assert degraded is True
    assert [f.category for f in kept] == ["sql-injection"]


def test_audit_diff_records_adversarial_role_failure_reason():
    """Adversarial batch failures name the role that failed."""
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(), "not json"], default="{}")
    failures = []

    kept, _, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        mode="adversarial",
        max_rounds=1,
        batch_failures=failures,
    )

    assert degraded is True
    assert [f.category for f in kept] == ["sql-injection"]
    assert failures[0].reason == (
        "RoleResponseError: adversarial judge reply had no usable JSON object with required fields: findings"
    )


def test_audit_diff_standard_mode_is_never_degraded():
    """Audit diff standard mode is never degraded."""
    provider = MockProvider(default=_finder([_VULN]))
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="standard")
    assert degraded is False
    assert len(kept) == 1


def test_provider_exception_degrades_rather_than_crashes():
    """Provider exception degrades rather than crashes."""
    from cyberjury.providers.base import CompletionResult, Provider

    class _RaiseOnJudge(Provider):
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return CompletionResult(text=_finder([_VULN]))
            if self.calls == 2:
                return CompletionResult(text=_challenger())
            raise RuntimeError("provider down")

    out = AdversarialAuditRunner(provider=_RaiseOnJudge(), model="m").run(_DIFF, max_rounds=1)
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.degraded is True


def test_judge_unparseable_reply_does_not_run_an_extra_role_retry():
    """Provider retry owns transient recovery, so the role loop does not parse retry."""
    provider, out = _run([_finder([_VULN]), _challenger(), "blocked by waf", _judge([_VULN])], max_rounds=1)
    assert out.degraded is True
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert len(provider.calls) == 3


def test_degraded_fallback_preserves_challenger_dismissed_findings():
    """A failed judge cannot let a challenger-only dismissal delete candidates."""
    second = {**_VULN, "line": 5, "category": "xss"}
    _, out = _run(
        [
            _finder([_VULN, second]),
            _challenger(rebuttals=[{"target": "app.py:5", "verdict": "dismiss", "reason": "output is escaped"}]),
            "blocked",
            "blocked",
        ],
        max_rounds=1,
    )
    assert out.degraded is True
    assert [f.category for f in out.findings] == ["sql_injection", "xss"]


def test_per_role_models_are_used():
    """Per role models are used."""
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(
        provider=provider,
        model="base",
        finder_model="finder-m",
        challenger_model="challenger-m",
        judge_model="judge-m",
    ).run(_DIFF, max_rounds=1)
    assert [c["model"] for c in provider.calls] == ["finder-m", "challenger-m", "judge-m"]


def test_role_models_default_to_base():
    """Role models default to base."""
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(provider=provider, model="base").run(_DIFF, max_rounds=1)
    assert [c["model"] for c in provider.calls] == ["base", "base", "base"]


def test_prompts_carry_role_context():
    """Prompts carry role context."""
    assert "red-team" not in finder_prompt(_DIFF)
    assert "SELECT * FROM u" in finder_prompt(_DIFF, stack="STACK-NOTE")
    assert "STACK-NOTE" in finder_prompt(_DIFF, stack="STACK-NOTE")
    fp = challenger_prompt(_DIFF, [_VULN])
    assert "rebuttal" in fp
    assert "Independently" in fp
    assert "sql_injection" in fp
    assert "STACK-NOTE" in challenger_prompt(_DIFF, [_VULN], stack="STACK-NOTE")
    jp = judge_prompt(_DIFF, [_VULN], [], [], do_not_report="POLICY")
    assert "Finder findings" in jp
    assert "Challenger" in jp
    assert "POLICY" in jp


def test_runner_feeds_stack_to_finder_and_challenger_and_policy_to_judge():
    """Runner feeds stack to finder and challenger and policy to judge."""
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([], converged=True)], default="{}")
    AdversarialAuditRunner(provider=provider, model="m", do_not_report="POLICY").run(
        _DIFF, stack="STACK-NOTE", max_rounds=1
    )
    prompts = [c["messages"][0].content for c in provider.calls]
    assert "STACK-NOTE" in prompts[0]
    assert "STACK-NOTE" in prompts[1]
    assert "STACK-NOTE" not in prompts[2]
    assert "POLICY" in prompts[0]
    assert "POLICY" in prompts[1]
    assert "POLICY" in prompts[2]


def test_adversarial_diff_passes_cache_prefixes_before_diff_body():
    """Adversarial diff cache prefixes stop before the changed code body."""
    provider, _out = _run([_finder([]), _challenger(), _judge([], converged=True)], max_rounds=1)
    for call in provider.calls:
        prompt = call["messages"][0].content
        prefix = call["cache_prefix"]
        assert call["cache"] is True
        assert prompt.startswith(prefix)
        assert "Code change (unified diff):" in prefix
        assert "WHERE n=' + name" not in prefix


class _RoleProvider:
    """Records role routing inputs while returning a fixed reply."""

    def __init__(self, reply):
        self._reply = reply
        self.systems = []
        self.models = []

    def complete(self, *, system, messages, model, max_tokens, cache=False, cache_prefix=""):
        import types

        self.systems.append(system)
        self.models.append(model)
        return types.SimpleNamespace(text=self._reply)


def test_adversarial_routes_each_role_to_its_own_provider():
    """Adversarial routes each role to its own provider."""
    finder_p = _RoleProvider(_finder([_VULN]))
    challenger_p = _RoleProvider(_challenger())
    judge_p = _RoleProvider(_judge([_VULN], converged=True))
    base = MockProvider(default="{}")
    runner = AdversarialAuditRunner(
        provider=base,
        model="base-model",
        finder_provider=finder_p,
        finder_model="finder-m",
        challenger_provider=challenger_p,
        challenger_model="challenger-m",
        judge_provider=judge_p,
        judge_model="judge-m",
    )
    runner.run(_DIFF, max_rounds=1)
    assert finder_p.systems == [FINDER_SYSTEM]
    assert finder_p.models == ["finder-m"]
    assert challenger_p.systems == [CHALLENGER_SYSTEM]
    assert challenger_p.models == ["challenger-m"]
    assert judge_p.systems == [JUDGE_SYSTEM]
    assert judge_p.models == ["judge-m"]


def test_finder_unparseable_reply_degrades_not_clean_pass():
    """Finder unparseable reply degrades not clean pass."""
    runner = AdversarialAuditRunner(provider=MockProvider(default="not json at all"), model="m")
    res = runner.run(_DIFF, max_rounds=2)
    assert res.degraded is True


def test_challenger_unparseable_reply_degrades():
    """Finder candidates survive when the challenger cannot produce a usable rebuttal."""
    runner = AdversarialAuditRunner(
        provider=MockProvider(default="{}"),
        model="m",
        finder_provider=_RoleProvider(_finder([_VULN])),
        finder_model="f",
        challenger_provider=_RoleProvider("not json"),
        challenger_model="c",
        judge_provider=_RoleProvider(_judge([_VULN], converged=True)),
        judge_model="j",
    )
    res = runner.run(_DIFF, max_rounds=1)
    assert res.degraded is True
    assert [f.category for f in res.findings] == ["sql_injection"]


def test_challenger_reply_missing_independent_findings_is_incomplete():
    """Diff Review uses the shared complete Challenger response contract."""
    runner = AdversarialAuditRunner(
        provider=MockProvider(default="{}"),
        model="m",
        finder_provider=_RoleProvider(_finder([_VULN])),
        challenger_provider=_RoleProvider('{"rebuttals": []}'),
        judge_provider=_RoleProvider(_judge([_VULN])),
    )

    result = runner.run(_DIFF, max_rounds=1)

    assert result.degraded is True
    assert [finding.category for finding in result.findings] == ["sql_injection"]
    assert "new_findings" in result.failure_reason
