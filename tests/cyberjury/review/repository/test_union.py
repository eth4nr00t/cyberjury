"""The repository union folds every report of one site into one finding."""

from dataclasses import replace

from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.repository.union import Candidate, candidate_accumulator


def _c(title, **kw):
    return Candidate(title=title, **kw)


def _web_brief():
    paths = WEB_PROFILE.paths
    return load_review_brief(kernel_file=paths.security_kernel_file)


def _canon(cands):
    brief = _web_brief()
    return [replace(c, category=brief.canonicalize_category(c.category)) for c in cands]


def merge(pool, cands):
    """Fold `cands` into `pool` and return how many identities were new."""
    return candidate_accumulator(pool=pool).add(cands)


def test_union_merges_same_file_line_class_under_different_endpoints():
    a = _c(
        "freshness",
        category="replay",
        endpoint="VerificationController.check",
        file="authorizer/controllers/registrar.py",
        line=58,
    )
    b = _c(
        "freshness",
        category="Replay",
        endpoint="POST /v1/check_challenge",
        file="authorizer/controllers/registrar.py",
        line=58,
    )
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 1


def test_union_keeps_distinct_lines_and_folds_classes_at_one_line():
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),
        _c("c", category="replay", file=same_file, line=10),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_canonical_categories_merge_one_defect_under_label_variants():
    cands = [
        _c(
            "query guard missing",
            category="sql-injection",
            endpoint="POST /query",
            file="src/queries.py",
            line=54,
        ),
        _c(
            "query guard missing",
            category="SQL Injection",
            endpoint="QueryView.post",
            file="src/queries.py",
            line=54,
        ),
    ]
    pool: dict = {}
    assert merge(pool, _canon(cands)) == 1


def test_category_qualifiers_do_not_duplicate_one_report_location():
    cands = [
        _c(
            "same missing control",
            category=category,
            file="src/handler.py",
            line=25,
            symbol="send_request",
        )
        for category in ("Authorization Bypass (IDOR)", "Authorization Bypass (ownership check)")
    ]

    pool: dict = {}
    assert merge(pool, _canon(cands)) == 1


def test_repository_rule_identity_folds_entrypoint_wording_at_one_location():
    cands = [
        _c(
            "query injection",
            category="sql-injection",
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
            "regex operation",
            category="resource-exhaustion",
            source_operation_id="call-outer",
            file="matching.py",
            line=line,
        )
        for line in (63, 64)
    ]

    pool = {}
    assert merge(pool, cands) == 1


def test_repository_union_folds_reworded_rules_on_one_source_operation():
    cands = [
        _c(
            rule,
            category="resource-exhaustion",
            source_operation_id="call-outer",
            file="matching.py",
            line=63,
        )
        for rule in ("resource-exhaustion-regex", "resource-exhaustion-amplification")
    ]

    pool = {}
    assert merge(pool, cands) == 1


def test_repository_union_keeps_distinct_source_operations_at_one_location():
    cands = [
        _c(
            operation,
            category="resource-exhaustion",
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
    b = _c("idor", endpoint="get /withdrawals/{id}")
    pool: dict = {}
    assert merge(pool, [a]) == 1
    assert merge(pool, [b]) == 0
    assert len(pool) == 1


def test_union_merges_one_line_reported_in_different_words_and_classes():
    """Units restating one sink under different titles and classes fold to one finding."""
    cands = [
        _c(
            "Bulk download bypasses document-view permissions",
            category="broken-access-control",
            file="documents/views.py",
            line=785,
            attack_path="POST /api/documents/bulk_download/ with foreign ids",
        ),
        _c(
            "Bulk download exposes documents without checking read permissions",
            category="broken-access-control",
            file="documents/views.py",
            line=785,
            attack_path="POST /documents/bulk_download/ returns unreadable documents",
        ),
        _c(
            "Bulk download leaks archive contents",
            category="information-exposure",
            file="documents/views.py",
            line=785,
            attack_path="archive includes other owners' originals",
        ),
        _c("Other line", category="information-exposure", file="documents/views.py", line=786),
    ]
    pool: dict = {}
    merge(pool, cands)
    folded = list(pool.values())
    assert len(folded) == 2
    merged = next(c for c in folded if c.line == 785)
    assert merged.category == "broken-access-control"
    assert "foreign ids" in merged.attack_path
    assert "unreadable documents" in merged.attack_path
    assert "other owners' originals" in merged.attack_path


def test_dedup_falls_back_to_file_plus_category():
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2


def test_endpoint_anchor_keeps_distinct_functions_in_one_file():
    cands = [
        _c("race in cleanup", category="race-condition", endpoint="cleanup_loan", file="vault.py"),
        _c("race in transform", category="race-condition", endpoint="transform", file="vault.py"),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_endpoint_anchor_folds_one_function_reported_twice():
    cands = [
        _c("domain sep", category="signature-replay", endpoint="verify", file="forwarder.py"),
        _c("domain sep", category="signature-replay", endpoint="verify", file="forwarder.py"),
        _c("domain sep raw", category="signature-replay", endpoint="", file="forwarder.py"),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_blank_endpoint_siblings_at_distinct_lines_stay_separate():
    cands = [
        _c("approve skips blacklist", category="access-control", file="token.py", line=120),
        _c("set_owner ungated", category="access-control", file="token.py", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_blank_endpoint_same_line_folds():
    cands = [
        _c("x", category="access-control", file="token.py", line=88),
        _c("x", category="access-control", file="token.py", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 1


def test_exact_locations_keep_same_symbol_findings_distinct():
    cands = [
        _c("a", category="race", symbol="liquidate", endpoint="liquidate()", file="vault.py", line=10),
        _c("b", category="race", symbol="Vault.liquidate", endpoint="POST /liquidate", file="vault.py", line=20),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


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
            category="race-condition",
            file="vault.py",
            line=5,
            evidence="first path",
            found_by=("m1",),
        ),
        _c(
            "a",
            category="race-condition",
            file="vault.py",
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
        _c("a", category="access-control", symbol="approve", file="token.py"),
        _c("b", category="access-control", symbol="set_owner", file="token.py"),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_fold_unions_evidence_never_drops_the_second_report():
    a = _c("a", category="race-condition", symbol="f", file="vault.py", evidence="no guard at f:10")
    b = _c("a", category="race-condition", symbol="f", file="vault.py", evidence="also reverts at f:20")
    pool: dict = {}
    merge(pool, [a])
    merge(pool, [b])
    (kept,) = pool.values()
    assert "no guard at f:10" in kept.evidence
    assert "also reverts at f:20" in kept.evidence


def test_symbol_anchor_folds_web_route_prose_variants():
    cands = [
        _c("a", category="authorization", symbol="getDatabase", endpoint="GET /db/:db", file="lib/routes/db.js"),
        _c(
            "a",
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


def test_endpoint_anchor_keeps_distinct_endpoints_in_one_file():
    a = _c("replay", category="signature-replay", endpoint="execute", file="forwarder.py")
    b = _c("missing check", category="access-control", endpoint="verify", file="forwarder.py")
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2


def test_endpoint_anchor_keeps_distinct_endpoints_with_one_class():
    a = _c("a", category="signature-replay", endpoint="execute", file="forwarder.py")
    b = _c("b", category="signature-replay", endpoint="verify", file="forwarder.py")
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2


def test_merge_unions_found_by_for_consensus():
    a = _c("race", category="race-condition", symbol="lend", file="vault.py", found_by=("claude",))
    b = _c("race", category="race-condition", symbol="lend", file="vault.py", found_by=("gpt",))
    pool: dict = {}
    merge(pool, [a])
    merge(pool, [b])
    (kept,) = pool.values()
    assert set(kept.found_by) == {"claude", "gpt"}
