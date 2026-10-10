"""The cross pass union core deduplicates findings and tracks convergence."""

from dataclasses import replace

from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.repository.union import Accumulator, Candidate, fold_by_repair, merge


def _c(title, **kw):
    return Candidate(title=title, **kw)


def _evm_brief():
    paths = EVM_PROFILE.paths
    return load_review_brief(
        kernel_id="evm-security",
        kernel_file=paths.security_kernel_file,
        catalog_file=paths.security_catalog_file,
    )


def _canon(cands):
    brief = _evm_brief()
    return [replace(c, category=brief.canonicalize_category(c.category)) for c in cands]


def test_union_merges_same_file_line_class_under_different_endpoints():
    a = _c(
        "freshness",
        category="replay",
        endpoint="VerificationController.check",
        file="authorizer/controllers/registrar.py",
        line=58,
    )
    b = _c(
        "freshness view",
        category="Replay",
        endpoint="POST /v1/check_challenge",
        file="authorizer/controllers/registrar.py",
        line=58,
    )
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 1


def test_union_keeps_distinct_lines_and_classes():
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),
        _c("c", category="replay", file=same_file, line=10),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 3


def test_canonical_categories_merge_one_defect_under_label_variants():
    cands = [
        _c(
            "loan health unguarded",
            category="oracle-manipulation",
            endpoint="liquidate",
            file="src/V3Vault.sol",
            line=54462,
        ),
        _c(
            "loan health unguarded",
            category="oracle",
            endpoint="external liquidate",
            file="src/V3Vault.sol",
            line=54462,
        ),
    ]
    pool: dict = {}
    assert merge(pool, _canon(cands)) == 1


def test_union_keeps_canonical_distinct_classes_at_one_line():
    cands = [
        _c("reentry", category="reentrancy", file="src/V3Vault.sol", line=44871),
        _c("oracle", category="oracle-manipulation", file="src/V3Vault.sol", line=44871),
    ]
    pool: dict = {}
    assert merge(pool, _canon(cands)) == 2


def test_repository_rule_identity_folds_entrypoint_wording_at_one_location():
    cands = [
        _c(
            "query injection",
            category="sql-injection",
            decision_rule_id="sql-syntax-boundary",
            endpoint=endpoint,
            file="queries.py",
            line=10,
        )
        for endpoint in ("POST /query", "QueryView.post")
    ]

    pool = {}
    assert merge(pool, cands) == 1


def test_repository_union_folds_one_rule_across_lines_of_one_source_operation():
    cands = [
        _c(
            f"regex operation at line {line}",
            category="resource-exhaustion",
            decision_rule_id="resource-exhaustion-regex",
            source_operation_id="call-outer",
            file="matching.py",
            line=line,
        )
        for line in (63, 64)
    ]

    pool = {}
    assert merge(pool, cands) == 1


def test_repository_union_keeps_distinct_original_claims_at_one_identity():
    first = _c(
        "target mutation",
        category="idor",
        decision_rule_id="idor-object-scope",
        file="app.py",
        line=10,
        attack_path="bulk edit reaches target write",
        evidence="bulk source at app.py:10",
    )
    second = replace(
        first,
        attack_path="normal edit reaches the same target write",
        evidence="normal source at app.py:10",
    )
    pool = {}

    assert merge(pool, [first, second]) == 1
    folded = next(iter(pool.values()))

    assert {claim.record["attack_path"] for claim in folded.claim_records} == {
        first.attack_path,
        second.attack_path,
    }
    assert all(claim.candidate_id == first.candidate_id for claim in folded.claim_records)
    assert all("found_by" not in claim.record for claim in folded.claim_records)
    assert all("status" not in claim.record for claim in folded.claim_records)


def test_repository_union_keeps_distinct_rules_on_one_source_operation():
    cands = [
        _c(
            rule,
            category="resource-exhaustion",
            decision_rule_id=rule,
            source_operation_id="call-outer",
            file="matching.py",
            line=63,
        )
        for rule in ("resource-exhaustion-regex", "resource-exhaustion-amplification")
    ]

    pool = {}
    assert merge(pool, cands) == 2


def test_repository_union_keeps_distinct_source_operations_at_one_location():
    cands = [
        _c(
            operation,
            category="resource-exhaustion",
            decision_rule_id="resource-exhaustion-regex",
            source_operation_id=operation,
            file="matching.py",
            line=63,
        )
        for operation in ("call-first", "call-second")
    ]

    pool = {}
    assert merge(pool, cands) == 2


def test_dedup_by_endpoint_normalizes_path_params():
    a = _c("idor", endpoint="GET /withdrawals/<wid>")
    b = _c("idor again", endpoint="get /withdrawals/{id}")
    pool: dict = {}
    assert merge(pool, [a]) == 1
    assert merge(pool, [b]) == 0
    assert len(pool) == 1


def test_repair_fold_folds_consumers_of_one_producer():
    """Different sinks fully fixed at one producer fold to that single site."""
    cands = [
        _c(
            "live move escapes root",
            category="path-traversal",
            file="src/documents/file_handling.py",
            line=149,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=True,
        ),
        _c(
            "exporter escapes root",
            category="path-traversal",
            file="src/documents/management/commands/document_exporter.py",
            line=450,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=True,
        ),
        _c(
            "migration reads escaped name",
            category="path-traversal",
            file="src/documents/migrations/1053_document_page_count.py",
            line=17,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=True,
        ),
    ]
    assert len(fold_by_repair(cands)) == 1


def test_repair_fold_keeps_a_partially_covered_finding_separate():
    """A finding not fully fixed at the shared site stays separate, so its residual is kept."""
    cands = [
        _c(
            "producer fully fixed here",
            category="path-traversal",
            file="src/documents/file_handling.py",
            line=149,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=True,
        ),
        _c(
            "shares the root but also needs another fix",
            category="path-traversal",
            file="src/documents/migrations/1053_document_page_count.py",
            line=17,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=False,
        ),
    ]
    assert len(fold_by_repair(cands)) == 2


def test_repair_fold_folds_only_when_completeness_is_declared():
    """Same site and class but unstated completeness never folds, the recall-safe default."""
    cands = [
        _c(
            "sink one",
            category="path-traversal",
            file="a.py",
            line=1,
            repair_file="r.py",
            repair_line=9,
            repair_complete=False,
        ),
        _c(
            "sink two",
            category="path-traversal",
            file="b.py",
            line=2,
            repair_file="r.py",
            repair_line=9,
            repair_complete=False,
        ),
    ]
    assert len(fold_by_repair(cands)) == 2


def test_repair_fold_keeps_distinct_repair_sites_separate():
    """One class with two fix sites stays two findings, so neither is dropped."""
    cands = [
        _c(
            "template containment",
            category="path-traversal",
            file="src/documents/file_handling.py",
            line=149,
            repair_file="src/documents/templating/filepath.py",
            repair_line=306,
            repair_complete=True,
        ),
        _c(
            "consume-folder symlink",
            category="path-traversal",
            file="src/documents/management/commands/document_consumer.py",
            line=134,
            repair_file="src/documents/data_models.py",
            repair_line=171,
            repair_complete=True,
        ),
    ]
    assert len(fold_by_repair(cands)) == 2


def test_repair_fold_never_merges_across_category_at_one_repair_site():
    """Two classes sharing a fix site are two findings, since fixes can differ by class."""
    cands = [
        _c(
            "missing authz",
            category="missing-authorization",
            file="a.py",
            line=10,
            repair_file="base.py",
            repair_line=5,
            repair_complete=True,
        ),
        _c(
            "info exposure",
            category="information-exposure",
            file="a.py",
            line=10,
            repair_file="base.py",
            repair_line=5,
            repair_complete=True,
        ),
    ]
    assert len(fold_by_repair(cands)) == 2


def test_repair_fold_falls_back_when_no_repair_anchor():
    """A candidate without a resolved repair site keeps its own identity."""
    cands = [
        _c("a", category="path-traversal", file="x.py", line=10),
        _c("b", category="path-traversal", file="y.py", line=20),
    ]
    assert len(fold_by_repair(cands)) == 2


def test_repair_fold_never_splits_one_identity_with_inconsistent_repair():
    """One identity reported with different repair annotations folds to one, never a duplicate id.

    This guards the real failure: anchor dedup collapses the re-reports first, so the repair
    stage sees one representative and the final set keeps unique candidate ids.
    """
    a = _c(
        "regex dos",
        category="resource-exhaustion",
        decision_rule_id="resource-exhaustion-regex",
        file="src/documents/serialisers.py",
        line=1592,
        repair_file="src/documents/serialisers.py",
        repair_line=1591,
        repair_complete=True,
    )
    b = _c(
        "regex dos again",
        category="resource-exhaustion",
        decision_rule_id="resource-exhaustion-regex",
        file="src/documents/serialisers.py",
        line=1592,
        repair_file="src/documents/serialisers.py",
        repair_line=1592,
        repair_complete=True,
    )
    assert a.candidate_id == b.candidate_id
    pool: dict = {}
    merge(pool, [a, b])
    folded = fold_by_repair(list(pool.values()))
    ids = [c.candidate_id for c in folded]
    assert len(folded) == 1
    assert len(ids) == len(set(ids))


def test_repair_fold_folds_preserve_both_claims():
    """Folding consumers keeps every original claim, so no evidence is dropped."""
    from cyberjury.review.claims import ClaimRecord

    a = _c(
        "live move",
        category="path-traversal",
        file="a.py",
        line=1,
        repair_file="r.py",
        repair_line=9,
        repair_complete=True,
        evidence="move at a.py:1",
    )
    b = _c(
        "exporter",
        category="path-traversal",
        file="b.py",
        line=2,
        repair_file="r.py",
        repair_line=9,
        repair_complete=True,
        evidence="write at b.py:2",
    )
    a = replace(a, claims=(ClaimRecord.create(a.candidate_id, {"title": a.title}),))
    b = replace(b, claims=(ClaimRecord.create(b.candidate_id, {"title": b.title}),))
    folded = fold_by_repair([a, b])
    assert len(folded) == 1
    assert len(folded[0].claim_records) == 2


def test_dedup_falls_back_to_file_plus_category():
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure dup", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2


def test_by_file_keeps_distinct_functions_in_one_file():
    """The by_file grouping keeps distinct functions in one file."""
    cands = [
        _c("reentry in cleanup", category="reentrancy", endpoint="_cleanupLoan", file="V3Vault.sol"),
        _c("reentry in transform", category="reentrancy", endpoint="transform", file="V3Vault.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_by_file_folds_one_function_reported_twice():
    """The by_file grouping folds one function reported twice."""
    cands = [
        _c("domain sep", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep again", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep raw", category="signature-replay", endpoint="", file="Forwarder.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_siblings_at_distinct_lines_stay_separate():
    cands = [
        _c("approve skips blacklist", category="access-control", file="Token.sol", line=120),
        _c("setOwner ungated", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_same_line_folds():
    cands = [
        _c("x", category="access-control", file="Token.sol", line=88),
        _c("x again", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1


def test_exact_locations_keep_same_symbol_findings_distinct():
    cands = [
        _c("a", category="reentrancy", symbol="liquidate", endpoint="external liquidate()", file="V.sol", line=10),
        _c("b", category="reentrancy", symbol="Vault.liquidate", endpoint="POST /liquidate", file="V.sol", line=20),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_exact_locations_keep_same_endpoint_findings_in_different_files():
    cands = [
        _c("a", category="idor", endpoint="GET /x/{id}", file="a.py", line=10),
        _c("b", category="idor", endpoint="GET /x/<id>", file="b.py", line=20),
    ]
    pool: dict = {}

    assert merge(pool, cands) == 2


def test_union_fold_preserves_evidence_and_provenance():
    cands = [
        _c(
            "a",
            category="reentrancy",
            file="V.sol",
            line=5,
            evidence="first path",
            found_by=("m1",),
        ),
        _c(
            "b",
            category="reentrancy",
            file="V.sol",
            line=5,
            evidence="second path",
            found_by=("m2",),
        ),
    ]

    pool: dict = {}
    merge(pool, cands)
    (finding,) = pool.values()

    assert finding.evidence == "first path; second path"
    assert finding.found_by == ("m1", "m2")


def test_symbol_anchor_separates_distinct_functions():
    cands = [
        _c("a", category="access-control", symbol="approve", file="Token.sol"),
        _c("b", category="access-control", symbol="setOwner", file="Token.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_fold_unions_evidence_never_drops_the_second_report():
    a = _c("a", category="reentrancy", symbol="f", file="V.sol", evidence="no guard at f:10")
    b = _c("b", category="reentrancy", symbol="f", file="V.sol", evidence="also reverts at f:20")
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert "no guard at f:10" in kept.evidence
    assert "also reverts at f:20" in kept.evidence


def test_symbol_anchor_folds_web_route_prose_variants():
    cands = [
        _c("a", category="authorization", symbol="getDatabase", endpoint="GET /db/:db", file="lib/routes/db.js"),
        _c(
            "b",
            category="authorization",
            symbol="getDatabase",
            endpoint="the database listing route",
            file="lib/routes/db.js",
        ),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 1


def test_symbol_anchor_separates_same_name_handler_across_files():
    cands = [
        _c("a", category="authorization", symbol="index", file="lib/routes/db.js"),
        _c("b", category="authorization", symbol="index", file="lib/routes/collection.js"),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_by_file_separates_same_endpoint_across_files():
    """The by_file grouping separates the same endpoint across files."""
    a = _c("a", category="reentrancy", endpoint="execute", file="Vault.sol")
    b = _c("b", category="reentrancy", endpoint="execute", file="Router.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_by_file_keeps_distinct_classes_in_one_file():
    """The by_file grouping keeps distinct classes in one file."""
    a = _c("replay", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("missing check", category="access-control", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_endpoint_dedup_is_default_when_not_by_file():
    a = _c("a", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("b", category="signature-replay", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2


def test_accumulator_by_file_unions_one_per_function():
    acc = Accumulator(converge_after=1, dedup_by_file=True)
    acc.add_pass([_c("at verify", category="signature-replay", endpoint="verify", file="Forwarder.sol")])
    acc.add_pass([_c("at verify again", category="signature-replay", endpoint="verify", file="Forwarder.sol")])
    assert len(acc.findings) == 1


def test_confirmed_upgrades_blocked_at_same_location():
    pool: dict = {}
    merge(pool, [_c("x", endpoint="POST /t", status="blocked")])
    merge(pool, [_c("x", endpoint="POST /t", status="confirmed")])
    assert len(pool) == 1
    assert next(iter(pool.values())).status == "confirmed"


def test_union_only_grows_across_passes():
    acc = Accumulator(converge_after=2)
    assert acc.add_pass([_c("a", endpoint="GET /a"), _c("b", endpoint="GET /b")]) == 2
    assert acc.add_pass([_c("b2", endpoint="GET /b"), _c("c", endpoint="GET /c")]) == 1
    assert {f.title for f in acc.findings} == {"a", "b", "c"}


def test_convergence_needs_k_consecutive_clean_snapshot_observations():
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    assert not acc.converged
    acc.add_pass([])
    assert acc.converged


def test_a_late_new_finding_resets_convergence():
    """Late new finding resets convergence."""
    acc = Accumulator(converge_after=2)
    acc.add_pass([])
    acc.add_pass([_c("late", endpoint="GET /late")])
    assert not acc.converged


def test_failed_passes_do_not_count_as_convergence():
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    acc.add_pass([], clean=False)
    acc.add_pass([], clean=False)
    assert not acc.converged
    acc.add_pass([])
    acc.add_pass([])
    assert acc.converged


def test_findings_take_the_median_severity_across_passes():
    acc = Accumulator(converge_after=1)
    for sev in ("LOW", "HIGH", "MEDIUM"):
        acc.add_pass([_c("idor", category="idor", endpoint="GET /x/<id>", severity=sev)])
    (f,) = acc.findings
    assert f.severity == "MEDIUM"


def test_findings_keep_the_model_grade_with_no_keyword_override():
    acc = Accumulator(converge_after=1)
    acc.add_pass([_c("signing key committed", category="Credential / Secret Exposure", file="a.py", severity="LOW")])
    (f,) = acc.findings
    assert f.severity == "LOW"


def test_merge_unions_found_by_for_consensus():
    a = _c("reentry", category="reentrancy", symbol="lend", file="V.sol", found_by=("claude",))
    b = _c("reentry too", category="reentrancy", symbol="lend", file="V.sol", found_by=("gpt",))
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert set(kept.found_by) == {"claude", "gpt"}
