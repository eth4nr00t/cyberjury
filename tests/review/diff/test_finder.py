"""The diff finder corrects change anchors and locates findings on changed lines or cited source."""

from types import SimpleNamespace

from cyberjury.review.context import GroundingContext, GroundingCoverage, SourceEvidence, SourceSpan
from cyberjury.review.diff.finder import locate
from cyberjury.review.diff.model import DiffLineRanges
from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.union import MERGE_RULE
from tests.review.diff.support import SQL_DIFF, diff_unit, finder, reply, review
from tests.support import MockProvider


def _run(runner, diff, *, context=""):
    cycle = runner.review_unit(diff_unit(diff, context))
    if not cycle.clean:
        raise RuntimeError(cycle.failure_reason)
    return cycle.findings


def _finding(file, line, change_anchor):
    return Finding(
        title="unsafe operation",
        entrypoint="GET /",
        evidence="unsafe operation",
        attack_path="request reaches it",
        severity="HIGH",
        category="other",
        file=file,
        line=line,
        change_anchor=change_anchor,
        evidence_refs=("seed",),
    )


def _locate(finding, ranges, source_evidence=(), seed_spans=()):
    return locate(SimpleNamespace(line_ranges=ranges), finding, source_evidence, seed_spans)


def test_diff_review_reports_a_malformed_change_anchor_as_failed_work():
    """A change_anchor with side "context" leaves no findings and fails on the allowed-value check."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "unsafe operation",
                    "change_anchor": {"file": "app.py", "line": 1, "side": "context"},
                }
            ]
        )
    )

    result = review(SQL_DIFF, provider=provider)

    assert result.outcome.findings == ()
    assert result.outcome.complete is False
    assert "change_anchor.side has a value outside the allowed set" in result.outcome.failures[0].reason


def test_diff_review_corrects_one_anchor_that_is_not_an_exact_changed_line():
    """An anchor on unchanged line 2 gets a correction listing new lines 1 and the retry is accepted."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**finding, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[reply([finding]), reply([corrected])])

    findings = _run(finder(provider), SQL_DIFF)

    assert len(findings) == 1
    assert findings[0].change_anchor is not None
    assert findings[0].change_anchor.line == 1
    assert "Exact changed ranges for `app.py` are: new lines 1" in provider.calls[1]["prompt"]


def test_diff_review_preserves_a_valid_sibling_during_anchor_correction():
    """The valid line-1 finding is frozen in the correction prompt while its line-2 sibling is fixed."""
    valid = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "entrypoint": "GET /first",
        "evidence": "first unsafe operation",
        "change_anchor": {"file": "app.py", "line": 1, "side": "new"},
    }
    invalid = {
        **valid,
        "entrypoint": "GET /second",
        "evidence": "second unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    corrected = {**invalid, "change_anchor": {"file": "app.py", "line": 1, "side": "new"}}
    provider = MockProvider(responses=[reply([valid, invalid]), reply([corrected])])

    findings = _run(finder(provider), SQL_DIFF)

    assert [finding.evidence for finding in findings] == ["first unsafe operation", "second unsafe operation"]
    correction = provider.calls[1]["prompt"]
    assert f"cannot be edited or withdrawn. {MERGE_RULE} Return only new findings." in correction
    assert '"title": "unsafe changed operation"' in correction


def test_diff_review_keeps_an_invalid_anchor_candidate_when_correction_fails():
    """A non-JSON correction reply moves the bad-anchor finding to incomplete and the outcome fails."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[reply([finding]), "not json"])

    result = review(SQL_DIFF, provider=provider)

    assert result.outcome.findings == ()
    assert [item.evidence for item in result.outcome.incomplete] == ["unsafe operation"]
    assert result.outcome.complete is False


def test_diff_review_allows_anchor_correction_to_remove_an_unreportable_candidate():
    """An empty correction reply drops the line-2 anchored finding, leaving no findings."""
    finding = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "other",
        "evidence": "unsafe operation",
        "change_anchor": {"file": "app.py", "line": 2, "side": "new"},
    }
    provider = MockProvider(responses=[reply([finding]), reply([])])

    assert _run(finder(provider), SQL_DIFF) == []


def test_diff_review_keeps_an_out_of_range_location_explicitly_incomplete():
    """Line 45 outside hunk +30,3 is incomplete, while b/app.py:31 is accepted as app.py with an anchor."""
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +30,3 @@\n context\n+sink(user)\n context\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 45,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "evidence": "unguarded route",
                },
                {
                    "file": "b/app.py",
                    "line": 31,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "evidence": "unguarded sink",
                },
            ]
        )
    )

    result = review(diff, provider=provider)

    assert [(f.evidence, f.line) for f in result.outcome.findings] == [("unguarded sink", 31)]
    assert result.outcome.findings[0].file == "app.py"
    assert [(f.evidence, f.line) for f in result.outcome.incomplete] == [("unguarded route", 45)]
    assert result.outcome.complete is False
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=31, side="new")


def test_diff_review_accepts_an_unchanged_location_with_a_new_change_anchor():
    """A finding on unchanged line 20 anchored to added line 21 is accepted with that anchor intact."""
    diff = (
        "diff --git a/policy.py b/policy.py\n"
        "--- a/policy.py\n"
        "+++ b/policy.py\n"
        "@@ -20,2 +20,3 @@\n"
        " existing_operation()\n"
        "+expose_operation()\n"
        " finish_request()\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "policy.py",
                    "line": 20,
                    "change_anchor": {"file": "policy.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the existing operation is newly exposed",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 20
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.py", line=21, side="new")


def test_diff_review_accepts_a_surviving_location_anchored_to_a_deleted_control():
    """A finding on surviving line 10 anchored to the deleted old-side auth line is accepted as complete."""
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10 @@\n"
        "-app.use(auth)\n"
        " app.use('/admin', admin)\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 10,
                    "change_anchor": {"file": "app.py", "line": 10, "side": "old"},
                    "severity": "CRITICAL",
                    "category": "missing-authorization",
                    "evidence": "the admin route lost authentication",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].line == 10
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=10, side="old")


def test_diff_review_rejects_an_anchor_that_is_only_context():
    """An anchor on a context line yields no findings and puts the claim in incomplete."""
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +20,2 @@\n context\n+sink(user)\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 20,
                    "change_anchor": {"file": "app.py", "line": 20, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "context is not a change anchor",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.findings == ()
    assert [finding.evidence for finding in result.outcome.incomplete] == ["context is not a change anchor"]
    assert result.outcome.complete is False


def test_diff_review_accepts_a_cross_file_change_anchor():
    """A finding in operation.py anchored to an added line in exposure.py is accepted with that anchor."""
    diff = (
        "diff --git a/operation.py b/operation.py\n"
        "--- a/operation.py\n"
        "+++ b/operation.py\n"
        "@@ -10,2 +10,3 @@\n"
        " sensitive_operation()\n"
        "+record_operation()\n"
        " finish_operation()\n"
        "diff --git a/exposure.py b/exposure.py\n"
        "--- a/exposure.py\n"
        "+++ b/exposure.py\n"
        "@@ -20 +20,2 @@\n"
        " keep_private()\n"
        "+expose_operation()\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "operation.py",
                    "line": 10,
                    "change_anchor": {"file": "exposure.py", "line": 21, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the existing operation is newly exposed",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="exposure.py", line=21, side="new")


def test_diff_review_accepts_a_cited_repository_location_outside_the_patch():
    """A handler.py:41 location outside the patch is accepted when it cites evidence covering lines 40-41."""
    evidence = SourceEvidence(
        id="src-handler",
        identity="handler.py:handle:0:80",
        text="40 | def handle(request):\n41 |     dangerous(request.data)",
        source_span=SourceSpan(
            file="handler.py",
            start_line=40,
            end_line=41,
        ),
    )
    context = GroundingContext(
        text="repository context",
        source_evidence=(evidence,),
        coverage=GroundingCoverage(
            included=(evidence.identity,),
            references=(evidence.id,),
        ),
    )
    diff = "diff --git a/routes.py b/routes.py\n@@ -0,0 +1 @@\n+register(handle)\n"
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "handler.py",
                    "line": 41,
                    "change_anchor": {"file": "routes.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the new route exposes the existing unsafe handler",
                    "evidence_refs": [evidence.id],
                }
            ]
        )
    )

    result = review(diff, provider=provider, context=context)

    assert [(finding.file, finding.line) for finding in result.outcome.findings] == [("handler.py", 41)]
    assert result.outcome.complete is True


def test_diff_review_rejects_an_uncited_repository_location_outside_the_patch():
    """A handler.py:41 location outside the patch is not located when the finding cites no evidence for it."""
    ranges = DiffLineRanges(
        current={"routes.py": ((1, 1),)},
        old={},
        new={"routes.py": ((1, 1),)},
    )
    evidence = SourceEvidence(
        id="src-handler",
        identity="handler.py:handle:0:80",
        text="40 | def handle(request):\n41 |     dangerous(request.data)",
        source_span=SourceSpan(
            file="handler.py",
            start_line=40,
            end_line=41,
        ),
    )
    finding = _finding("handler.py", 41, ChangeAnchor(file="routes.py", line=1, side="new"))

    assert _locate(finding, ranges, (evidence,)) is None


def test_diff_accepts_an_unchanged_primary_location_covered_by_seed():
    """A ./handler.py:41 location inside a seed span maps to handler.py, with b/ stripped from the anchor."""
    ranges = DiffLineRanges(
        current={"routes.py": ((1, 1),)},
        old={},
        new={"routes.py": ((1, 1),)},
    )
    finding = _finding("./handler.py", 41, ChangeAnchor(file="b/routes.py", line=1, side="new"))

    result = _locate(finding, ranges, seed_spans=(SourceSpan(file="handler.py", start_line=40, end_line=41),))

    assert result.file == "handler.py"
    assert result.change_anchor == ChangeAnchor(file="routes.py", line=1, side="new")


def test_diff_path_normalization_prefers_a_real_side_named_directory():
    """When the diff itself has a b/app.py path, the b/ prefix is kept rather than stripped as a side."""
    ranges = DiffLineRanges(
        current={"b/app.py": ((1, 1),)},
        old={},
        new={"b/app.py": ((1, 1),)},
    )
    finding = _finding("b/app.py", 1, ChangeAnchor(file="b/app.py", line=1, side="new"))

    result = _locate(finding, ranges)

    assert result.file == "b/app.py"
    assert result.change_anchor == ChangeAnchor(file="b/app.py", line=1, side="new")


def test_diff_review_keeps_a_canonicalized_path_when_every_finding_is_valid():
    """A b/app.py finding and anchor are canonicalized to app.py and the review stays complete."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "b/app.py",
                    "line": 1,
                    "change_anchor": {"file": "b/app.py", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "new unsafe operation",
                }
            ]
        )
    )

    result = review(SQL_DIFF, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].file == "app.py"
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="app.py", line=1, side="new")


def test_diff_unit_rejects_an_invalid_anchor_instead_of_overwriting_it():
    """An anchor naming b.py, which is absent from the ranges, makes the a.py finding unlocatable."""
    ranges = DiffLineRanges(
        current={"a.py": ((1, 1),)},
        old={},
        new={"a.py": ((1, 1),)},
    )
    finding = _finding("a.py", 1, ChangeAnchor(file="b.py", line=1, side="new"))

    assert _locate(finding, ranges) is None


def test_diff_unit_preserves_a_distinct_valid_anchor_for_an_added_location():
    """A finding on added line 1 keeps its own anchor on added line 2 instead of being re-anchored."""
    ranges = DiffLineRanges(
        current={"a.py": ((1, 2),)},
        old={},
        new={"a.py": ((1, 2),)},
    )
    finding = _finding("a.py", 1, ChangeAnchor(file="a.py", line=2, side="new"))

    assert _locate(finding, ranges).change_anchor == ChangeAnchor(file="a.py", line=2, side="new")


def test_diff_review_accepts_a_non_source_change_location_and_anchor():
    """A policy.yaml change flipping require_approval is accepted as both finding location and anchor."""
    diff = (
        "diff --git a/policy.yaml b/policy.yaml\n"
        "--- a/policy.yaml\n"
        "+++ b/policy.yaml\n"
        "@@ -1 +1 @@\n"
        "-require_approval: true\n"
        "+require_approval: false\n"
    )
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "policy.yaml",
                    "line": 1,
                    "change_anchor": {"file": "policy.yaml", "line": 1, "side": "new"},
                    "severity": "HIGH",
                    "category": "other",
                    "evidence": "the policy no longer requires approval",
                }
            ]
        )
    )

    result = review(diff, provider=provider)

    assert result.outcome.complete is True
    assert result.outcome.findings[0].change_anchor == ChangeAnchor(file="policy.yaml", line=1, side="new")


def test_diff_review_keeps_a_deleted_file_location_incomplete():
    """A finding on a line of a file deleted to /dev/null is incomplete and yields no findings."""
    provider = MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "sql-injection",
                    "evidence": "old sink",
                }
            ]
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    result = review(diff, provider=provider)

    assert result.outcome.findings == ()
    assert [(finding.file, finding.line) for finding in result.outcome.incomplete] == [("app.py", 1)]
    assert result.outcome.complete is False
