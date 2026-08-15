"""The standard diff review adapter uses deterministic provider replies."""

import json
from dataclasses import replace

import pytest

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import audit_diff, run_diff_review
from cyberjury.review.diff.model import (
    chunk_path,
    deleted_paths,
    pack_diff_chunks,
    split_diff_by_file,
    strip_unreviewable_files,
)
from cyberjury.review.diff.prompts import standard_audit_prompt
from cyberjury.review.diff.reviewer import AuditRunner
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import role_accumulator
from cyberjury.review.engine import ReviewCycle, review_plan
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.verification import RefutationChecker, Verdict, Verifier
from cyberjury.review.vulnerabilities import Vulnerability, VulnerabilityCatalog

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


def test_standard_review_keeps_distinct_findings_at_one_location():
    """Standard accumulation cannot erase a distinct exploit at the same source line."""
    findings = [
        {
            "file": "app.py",
            "line": 1,
            "severity": "HIGH",
            "category": "other",
            "description": description,
            "confidence": 0.9,
        }
        for description in ("first exploit", "second exploit")
    ]

    kept, _dropped, degraded = audit_diff(
        _DIFF,
        provider=MockProvider(default=_reply(findings)),
        model="mock",
    )

    assert [finding.description for finding in kept] == ["first exploit", "second exploit"]
    assert degraded is False


def test_diff_review_rejects_unknown_modes_before_calling_the_provider():
    """Diff Review uses the shared mode contract before any model work."""
    provider = MockProvider(default=_reply([]))

    with pytest.raises(ValueError, match="unknown review mode"):
        run_diff_review(_DIFF, provider=provider, model="m", mode="deep")

    assert provider.calls == []


def test_diff_review_exposes_the_complete_outcome_contract():
    """Internal callers receive rounds, failures, and completion without side channels."""
    result = run_diff_review(_DIFF, provider=MockProvider(default="not json"), model="m")

    assert result.outcome.complete is False
    assert result.outcome.errors == 1
    assert len(result.outcome.failures) == 1
    assert result.outcome.rounds == 1


def test_diff_review_includes_patch_local_grounding_without_repository_context():
    """Pure Diff Review includes patch-local relationships without a repository root."""
    diff = (
        "diff --git a/routes.ts b/routes.ts\n+++ b/routes.ts\n@@ -1 +1 @@\n"
        "+function handleRequest() { return loadAccount(); }\n"
        "diff --git a/service.ts b/service.ts\n+++ b/service.ts\n@@ -1 +1 @@\n"
        "+function loadAccount() { return account; }\n"
    )
    provider = MockProvider(default='{"findings": []}')

    run_diff_review(diff, provider=provider, model="m")

    assert "Patch-local grounding" in provider.calls[0]["messages"][0].content
    assert "routes.ts uses service.ts:loadAccount" in provider.calls[0]["messages"][0].content


def test_engine_empty_on_no_findings():
    """Engine empty on no findings."""
    assert AuditRunner(provider=MockProvider(default='{"findings": []}'), model="m").run(_DIFF) == []


def test_engine_raises_on_unparseable_reply():
    """Engine raises on unparseable reply."""
    import pytest

    from cyberjury.review.diff.reviewer import AuditError

    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default="not json"), model="m").run(_DIFF)
    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default=""), model="m").run(_DIFF)


def test_engine_raises_on_wrong_shape_json():
    """Engine raises on wrong shape JSON."""
    import pytest

    from cyberjury.review.diff.reviewer import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError, match="failed audit"):
            AuditRunner(provider=MockProvider(default=bad), model="m").run(_DIFF)


def test_guides_for_diff_selects_by_path_and_content():
    """Guides for diff selects by path and content."""
    from cyberjury.review.diff.reviewer import guides_for_diff

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


def test_standard_diff_audit_avoids_a_single_use_cache_write():
    """A lone standard judgment has no later call that can reuse its prefix."""
    provider = MockProvider(default='{"findings": []}')
    AuditRunner(provider=provider, model="m").run(_DIFF, vulnerabilities="VULN-X")
    call = provider.calls[0]
    prompt = call["messages"][0].content
    assert call["cache"] is False
    assert call["cache_prefix"] == ""
    assert "VULN-X" in prompt
    assert "SELECT * FROM u" in prompt


def test_standard_diff_audit_selects_vulnerabilities_from_context():
    """Repository evidence must influence knowledge selection even when the patch lacks the signal."""
    provider = MockProvider(default='{"findings": []}')
    diff = "+++ b/app.py\n@@ -0,0 +1 @@\n+token = make_token()\n"
    AuditRunner(provider=provider, model="m").run(diff, context="def make_token():\n    return uuid.uuid1().hex\n")

    prompt = provider.calls[0]["messages"][0].content

    assert "UUIDv1 is not a secret generator" in prompt
    assert "Exhaustively review the evidence for this assigned vulnerability class pack:" in prompt
    assert "insecure-cryptography" in prompt
    assert prompt.index("Exhaustively review") > prompt.index("Surrounding code")


def test_standard_diff_audit_assigns_other_selected_classes_to_other_judgments():
    """Parallel knowledge judgments must not rescan classes assigned elsewhere."""
    prompt = standard_audit_prompt(
        _DIFF,
        vulnerabilities="alpha guidance",
        vulnerability_categories=("alpha",),
        selected_vulnerability_categories=("alpha", "beta"),
    )

    assert "Do not report them here:\nbeta" in prompt
    assert "outside the complete selected class set" in prompt


def test_standard_diff_audit_reuses_evidence_across_knowledge_packs():
    """Every selected pack sees identical diff evidence before its changing guidance."""
    provider = MockProvider(default='{"findings": []}')
    runner = AuditRunner(provider=provider, model="m")
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
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    cycle = runner.review_round("+++ b/app.py\n+alpha beta\n", finder_label="finder")

    assert cycle.clean is True
    assert len(provider.calls) == 2
    assert all(call["cache"] is True for call in provider.calls)
    prefixes = [call["cache_prefix"] for call in provider.calls]
    assert prefixes[0] == prefixes[1]
    assert "alpha beta" in prefixes[0]
    assert "alphaalpha" not in prefixes[0]
    assert "alphaalpha" in provider.calls[0]["messages"][0].content
    assert "betabeta" in provider.calls[1]["messages"][0].content


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


def test_diff_verification_failure_keeps_its_provider_reason(tmp_path):
    """The final incomplete outcome must explain why verification failed."""
    (tmp_path / "app.py").write_text("sink()\n")
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "unguarded route", "confidence": 0.9}]}'
        )
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        verification_root=str(tmp_path),
        verifier=_BrokenVerifier(),
    )

    assert result.outcome.degraded is True
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"


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


def test_audit_diff_verification_skips_a_confirmer_that_found_the_finding(tmp_path):
    """A confirmer that surfaced a finding is not an independent deletion vote."""
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
        verification_confirmers=[("finder", _Checker(["unguarded route"]))],
        verification_found_by=("finder",),
    )
    assert [f.description for f in kept] == ["unguarded route"]
    assert dropped == []
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


def test_diff_model_excludes_test_files_before_review():
    """Diff unit construction applies the same test exclusion as repository units."""
    production = "diff --git a/app/views.py b/app/views.py\n+++ b/app/views.py\n+x = 1\n"
    test = "diff --git a/tests/test_views.py b/tests/test_views.py\n+++ b/tests/test_views.py\n+x = 1\n"

    kept, skipped = strip_unreviewable_files(production + test)

    assert kept == production
    assert skipped == ("tests/test_views.py",)


def test_diff_review_does_not_delete_a_finding_on_model_confidence_alone():
    """A confidence score is not a controlling fact that can delete a candidate."""
    provider = MockProvider(default=_reply([_f("app.py", conf=0.1).to_dict()]))

    kept, dropped, degraded = audit_diff(_SRC, provider=provider, model="m")

    assert len(kept) == 1
    assert dropped == []
    assert degraded is False


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"
_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"
_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_strip_unreviewable_files_drops_docs_and_lockfiles_keeps_source():
    """Strip noise files drops docs and lockfiles keeps source."""
    kept, skipped = strip_unreviewable_files(_SRC + _DOC + _LOCK)
    assert kept == _SRC
    assert set(skipped) == {"README.md", "package-lock.json"}


def test_strip_unreviewable_files_keeps_a_chunk_whose_path_cannot_be_read():
    """Strip noise files keeps a chunk whose path cannot be read."""
    headerless = "@@ -0,0 +1 @@\n+x = 1\n"
    kept, skipped = strip_unreviewable_files(headerless)
    assert kept == headerless
    assert skipped == ()


def test_chunk_path_reads_the_deletion_and_git_header_fallbacks():
    """Chunk path reads the deletion and git header fallbacks."""
    deletion = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-# Title\n"
    assert chunk_path(deletion) == "README.md"
    header_only = "diff --git a/app/x.py b/app/x.py\nBinary files differ\n"
    assert chunk_path(header_only) == "app/x.py"


def test_deleted_paths_identifies_source_files_absent_after_the_patch():
    """Deleted paths identify source files absent after the patch."""
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    assert deleted_paths(diff) == ("app.py",)


def test_audit_diff_drops_findings_located_only_in_deleted_files():
    """Audit diff drops findings located only in deleted files."""
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "sql-injection", "description": "old sink", "confidence": 0.9}]}'
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    kept, dropped, degraded = audit_diff(diff, provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False


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
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    two = _SRC + "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+y = 2\n"
    seen = []
    audit_diff(
        two,
        provider=MockProvider(default='{"findings": []}'),
        model="m",
        on_batch=lambda done, total, secs: seen.append((done, total)),
    )
    assert seen == [(1, 2), (2, 2)]


def test_pack_diff_chunks_preserves_source_order_within_bound():
    """File packing is deterministic and preserves source order within the bound."""

    def chunk(path: str, line: str) -> str:
        return f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+{line}\n"

    first = chunk("first.ts", "const value = 1")
    caller = chunk("caller.ts", "mergeOptions(config, body)")
    filler = chunk("filler.ts", f"unrelatedWork(item) // {'x' * 200}")
    helper = chunk("helper.ts", "const mergeOptions = (target, source) => target")
    max_chars = len(first) + len(caller) + len(filler)

    batches = pack_diff_chunks(first + caller + filler + helper, max_chars=max_chars)
    first_paths = [chunk_path(part) for part in split_diff_by_file(batches[0])]

    assert len(batches[0]) <= max_chars
    assert first_paths == ["first.ts", "caller.ts", "filler.ts"]
    assert chunk_path(batches[1]) == "helper.ts"


def test_audit_diff_records_failed_batch_and_continues(monkeypatch):
    """A large diff keeps completed batch results while surfacing failed batches."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    failures = []
    provider = MockProvider(
        responses=[
            "not json",
            _reply(
                [
                    {
                        "file": "other.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "missing-authorization",
                        "description": "unguarded sink",
                        "confidence": 0.9,
                    }
                ]
            ),
        ]
    )

    kept, dropped, degraded = audit_diff(_SRC + other, provider=provider, model="m", batch_failures=failures)

    assert [f.description for f in kept] == ["unguarded sink"]
    assert dropped == []
    assert degraded is True
    assert len(provider.calls) == 2
    assert failures[0].index == 1
    assert failures[0].total == 2
    assert failures[0].paths == ("app.py",)
    assert failures[0].reason.startswith("AuditError:")


def test_audit_diff_records_each_batch_when_failures_repeat(monkeypatch):
    """Identical failures remain attributable to every incomplete batch."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    failures = []

    kept, dropped, degraded = audit_diff(
        _SRC + other,
        provider=MockProvider(default="not json"),
        model="m",
        batch_failures=failures,
    )

    assert kept == []
    assert dropped == []
    assert degraded is True
    assert [failure.paths for failure in failures] == [("app.py",), ("other.py",)]


def test_audit_diff_records_single_batch_failure():
    """A small diff uses the same failure record shape as a split diff."""
    failures = []

    kept, dropped, degraded = audit_diff(
        _SRC,
        provider=MockProvider(default="not json"),
        model="m",
        batch_failures=failures,
    )

    assert kept == []
    assert dropped == []
    assert degraded is True
    assert failures[0].index == 1
    assert failures[0].total == 1
    assert failures[0].paths == ("app.py",)
    assert failures[0].reason.startswith("AuditError:")


def test_diff_model_uses_the_passed_profile_detection():
    """Diff unit construction uses the selected profile's test conventions."""
    from cyberjury.detection import load_detection
    from cyberjury.profiles.registry import resolve_profile

    evm = load_detection(resolve_profile("evm").paths.detection_file)
    diff = "diff --git a/Counter.t.sol b/Counter.t.sol\n+++ b/Counter.t.sol\n+contract CounterTest {}\n"
    kept, skipped = strip_unreviewable_files(diff, evm)
    assert kept == ""
    assert skipped == ("Counter.t.sol",)


def test_diff_rounds_carry_only_findings_for_the_current_batch(monkeypatch):
    """Prior findings cannot dilute an unrelated diff unit on later rounds."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    seen: list[tuple[int, str, tuple[str, ...]]] = []

    def execute(round_no, diff, known):
        path = "app.py" if "app.py" in diff else "b.py"
        seen.append((round_no, path, tuple(finding.file for finding in known)))
        findings = (
            [Finding(file=path, line=1, severity="HIGH", category="other", description=path)] if round_no == 1 else []
        )
        return ReviewCycle(findings=findings)

    outcome = run_batches(
        _SRC + other,
        execute,
        plan=review_plan("adversarial", max_rounds=2, converge_after=1),
        accumulator=role_accumulator(),
    )

    assert seen == [
        (1, "app.py", ()),
        (1, "b.py", ()),
        (2, "app.py", ("app.py",)),
        (2, "b.py", ("b.py",)),
    ]
    assert outcome.complete is True
