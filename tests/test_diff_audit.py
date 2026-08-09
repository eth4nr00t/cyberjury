"""The standard diff audit engine and false positive filter use deterministic mock replies."""

import json

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.audit import AuditRunner
from cyberjury.review.diff.engine import _chunk_path, audit_diff, strip_noise_files
from cyberjury.review.diff.filter import FindingsFilter
from cyberjury.review.diff.prompts import standard_audit_prompt
from cyberjury.review.repository.verifier import RefutationChecker, Verdict, Verifier

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    return json.dumps({"findings": findings})


def test_engine_parses_findings():
    """Engine parses findings."""
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 3,
                "severity": "CRITICAL",
                "category": "sql_injection",
                "description": "string-concatenated query",
                "confidence": 0.95,
            },
        ]
    )
    out = AuditRunner(provider=MockProvider(default=reply), model="m").run(_DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql_injection"


def test_engine_empty_on_no_findings():
    """Engine empty on no findings."""
    assert AuditRunner(provider=MockProvider(default='{"findings": []}'), model="m").run(_DIFF) == []


def test_engine_raises_on_unparseable_reply():
    """Engine raises on unparseable reply."""
    import pytest

    from cyberjury.review.diff.audit import AuditError

    with pytest.raises(AuditError):
        AuditRunner(provider=MockProvider(default="not json"), model="m").run(_DIFF)
    with pytest.raises(AuditError):
        AuditRunner(provider=MockProvider(default=""), model="m").run(_DIFF)


def test_engine_raises_on_wrong_shape_json():
    """Engine raises on wrong shape JSON."""
    import pytest

    from cyberjury.review.diff.audit import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError):
            AuditRunner(provider=MockProvider(default=bad), model="m").run(_DIFF)


def test_guides_for_diff_selects_by_path_and_content():
    """Guides for diff selects by path and content."""
    from cyberjury.review.diff.audit import guides_for_diff

    diff = "diff --git a/app/urls.py b/app/urls.py\n+from django.urls import path\n+urlpatterns = []\n"
    notes = guides_for_diff(diff)
    assert "Django" in notes
    assert "Python" in notes
    assert guides_for_diff("+++ b/README.md\n+hello\n") == ""


def test_prompt_carries_diff_focus_and_do_not_report():
    """Prompt carries diff focus and do not report."""
    p = standard_audit_prompt(_DIFF, vulnerabilities="VULN-X", context="def caller(): ...", stack="STACK-NOTE")
    assert "SELECT * FROM u" in p
    assert "Do NOT report" in p
    assert "IDOR" in p
    assert "VULN-X" in p
    assert "STACK-NOTE" in p
    assert "def caller()" in p


def test_adversarial_mode_carries_stack_notes_and_judge_policy():
    """Adversarial mode carries stack notes and judge policy."""
    diff = "diff --git a/app/urls.py b/app/urls.py\n+from django.urls import path\n+urlpatterns = []\n"
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": [], "converged": true}',
        ],
        default="{}",
    )
    audit_diff(diff, provider=provider, model="m", mode="adversarial", max_rounds=1)
    prompts = [call["messages"][0].content for call in provider.calls]
    assert "Django" in prompts[0]
    assert "Python" in prompts[0]
    assert "Django" in prompts[1]
    assert "Python" in prompts[1]
    assert "Django" not in prompts[2]
    assert "Python" not in prompts[2]
    assert "Do NOT report" in prompts[2]


def _f(file, conf=0.9):
    return Finding(file=file, line=1, severity="HIGH", category="sql_injection", confidence=conf)


class _Verifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        if candidate.title in self.refute:
            return Verdict(real=False, reason="guard dominates the route")
        return Verdict(real=True, reason="")


class _Checker(RefutationChecker):
    def __init__(self, holds_titles):
        self.holds_titles = set(holds_titles)

    def holds(self, candidate, reason, root):
        return candidate.title in self.holds_titles


class _BrokenVerifier(Verifier):
    def verify(self, candidate, root):
        raise RuntimeError("rate limited")


def test_audit_diff_verification_drops_a_confirmed_refutation(tmp_path):
    """Audit diff verification drops a confirmed refutation."""
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 3, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "unguarded route", "confidence": 0.9}]}'
        )
    )
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        verification_root=str(tmp_path),
        verifier=_Verifier(["unguarded route"]),
        verification_confirmers=[("", _Checker(["unguarded route"]))],
    )
    assert kept == []
    assert dropped[0][0].description == "unguarded route"
    assert "verified false positive" in dropped[0][1]
    assert degraded is False


def test_audit_diff_failed_verification_keeps_and_degrades(tmp_path):
    """Audit diff failed verification keeps and degrades."""
    (tmp_path / "app.py").write_text("def route():\n    sink()\n")
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 2, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "open route", "confidence": 0.9}]}'
        )
    )
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        verification_root=str(tmp_path),
        verifier=_BrokenVerifier(),
        verification_confirmers=[("", _Checker(["open route"]))],
    )
    assert [f.description for f in kept] == ["open route"]
    assert dropped == []
    assert degraded is True


def test_audit_diff_clears_line_outside_new_hunk_without_dropping_finding():
    """Audit diff clears line outside new hunk without dropping finding."""
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +30,3 @@\n context\n+sink(user)\n context\n"
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 45,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded route",
                    "confidence": 0.9,
                },
                {
                    "file": "b/app.py",
                    "line": 32,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded sink",
                    "confidence": 0.9,
                },
            ]
        )
    )

    kept, dropped, degraded = audit_diff(diff, provider=provider, model="m")

    assert [(f.description, f.line) for f in kept] == [("unguarded route", None), ("unguarded sink", 32)]
    assert kept[1].file == "b/app.py"
    assert dropped == []
    assert degraded is False


def test_filter_drops_test_paths():
    """Filter drops test paths."""
    kept, dropped = FindingsFilter().filter([_f("app/views.py"), _f("tests/test_views.py")])
    assert [k.file for k in kept] == ["app/views.py"]
    assert dropped[0][0].file == "tests/test_views.py"
    assert "test path" in dropped[0][1]


def test_filter_drops_test_file_naming_outside_test_dir():
    """Filter drops test file naming outside test dir."""
    kept, dropped = FindingsFilter().filter([_f("app/views_test.go"), _f("app/billing.spec.js")])
    assert kept == []
    assert len(dropped) == 2


def test_filter_keeps_production_file_with_sampleish_name():
    """Filter keeps production file with sampleish name."""
    kept, dropped = FindingsFilter().filter(
        [_f("app/sample_rate.py"), _f("app/mock_billing.py"), _f("app/example_config.py")]
    )
    assert len(kept) == 3
    assert dropped == []


def test_filter_drops_low_confidence():
    """Filter drops low confidence."""
    kept, dropped = FindingsFilter(min_confidence=0.6).filter([_f("a.py", conf=0.3)])
    assert kept == []
    assert "confidence" in dropped[0][1]


def test_filter_keeps_confidence_exactly_at_the_floor():
    """Filter keeps confidence exactly at the floor."""
    kept, dropped = FindingsFilter(min_confidence=0.5).filter([_f("a.py", conf=0.5)])
    assert [f.file for f in kept] == ["a.py"]
    assert dropped == []


def test_filter_keeps_real_high_confidence_prod_finding():
    """Filter keeps real high confidence prod finding."""
    kept, dropped = FindingsFilter().filter([_f("app/payment.py", conf=0.95)])
    assert len(kept) == 1
    assert dropped == []


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"
_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"
_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_strip_noise_files_drops_docs_and_lockfiles_keeps_source():
    """Strip noise files drops docs and lockfiles keeps source."""
    kept, skipped = strip_noise_files(_SRC + _DOC + _LOCK)
    assert kept == _SRC
    assert set(skipped) == {"README.md", "package-lock.json"}


def test_strip_noise_files_keeps_a_chunk_whose_path_cannot_be_read():
    """Strip noise files keeps a chunk whose path cannot be read."""
    headerless = "@@ -0,0 +1 @@\n+x = 1\n"
    kept, skipped = strip_noise_files(headerless)
    assert kept == headerless
    assert skipped == ()


def test_chunk_path_reads_the_deletion_and_git_header_fallbacks():
    """Chunk path reads the deletion and git header fallbacks."""
    deletion = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-# Title\n"
    assert _chunk_path(deletion) == "README.md"
    header_only = "diff --git a/app/x.py b/app/x.py\nBinary files differ\n"
    assert _chunk_path(header_only) == "app/x.py"


def test_audit_diff_whitespace_only_diff_is_clean_without_a_model_call():
    """Audit diff whitespace only diff is clean without a model call."""
    provider = MockProvider(default='{"findings": []}')
    kept, dropped, degraded = audit_diff("   \n", provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []


def test_audit_diff_does_not_send_noise_files_to_the_model():
    """Audit diff does not send noise files to the model."""
    provider = MockProvider(default='{"findings": []}')
    audit_diff(_SRC + _DOC, provider=provider, model="m")
    sent = "\n".join(m.content for call in provider.calls for m in call["messages"])
    assert "app.py" in sent
    assert "README.md" not in sent


def test_audit_diff_passes_context_to_the_runner():
    """Audit diff passes context to the runner."""
    provider = MockProvider(default='{"findings": []}')
    audit_diff(_SRC, provider=provider, model="m", context="def get_client(): return per_user_token")
    sent = provider.calls[0]["messages"][0].content
    assert "def get_client()" in sent
    assert "per_user_token" in sent


def test_audit_diff_docs_only_diff_is_clean_without_a_model_call():
    """Audit diff docs only diff is clean without a model call."""
    reply = _reply([{"file": "README.md", "line": 1, "severity": "HIGH", "description": "x", "confidence": 0.9}])
    provider = MockProvider(default=reply)
    kept, dropped, degraded = audit_diff(_DOC + _LOCK, provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []


def test_audit_runner_sends_the_severity_rubric():
    """Audit runner sends the severity rubric."""
    provider = MockProvider(default='{"findings": []}')
    AuditRunner(provider=provider, model="m").run(_DIFF)
    sent = provider.calls[0]["messages"][0].content
    assert "Grade each finding's severity on this rubric" in sent
    assert "Severity Rubric" in sent


def test_audit_diff_reports_one_progress_call_per_batch(monkeypatch):
    """Audit diff reports one progress call per batch."""
    monkeypatch.setattr("cyberjury.review.diff.engine._MAX_DIFF_CHARS", 1)
    two = _SRC + "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+y = 2\n"
    seen = []
    audit_diff(
        two,
        provider=MockProvider(default='{"findings": []}'),
        model="m",
        on_batch=lambda done, total, secs: seen.append((done, total)),
    )
    assert seen == [(1, 2), (2, 2)]


def test_findings_filter_uses_the_passed_detection():
    """Findings filter uses the passed detection."""
    from cyberjury.detection import load_detection
    from cyberjury.domains.registry import resolve_domain

    evm = load_detection(resolve_domain("evm").paths.detection_file)
    f = _f("Counter.t.sol")
    assert FindingsFilter().filter([f])[0] == [f]
    kept, dropped = FindingsFilter(detection=evm).filter([f])
    assert kept == []
    assert dropped
    assert "test path" in dropped[0][1]
