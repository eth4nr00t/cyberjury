"""The cross-pass union core: dedup by location, accumulate the union, and converge
only after K consecutive passes add nothing. This is what turns random per-pass
results into a stable, growing-only union."""

from dataclasses import replace

from cyberjury.domains.evm import EVM
from cyberjury.review.diff.vulnerabilities import canonical_category, category_aliases
from cyberjury.review.repository.union import Accumulator, Candidate, collapse_colocated, merge


def _c(title, **kw):
    return Candidate(title=title, **kw)


def _canon(cands, aliases):
    return [replace(c, category=canonical_category(c.category, aliases)) for c in cands]


def test_collapse_colocated_merges_same_file_line_class_under_different_endpoints():
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
    assert len(pool) == 2
    assert len(collapse_colocated(list(pool.values()))) == 1


def test_collapse_colocated_keeps_distinct_lines_and_classes():
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),
        _c("c", category="replay", file=same_file, line=10),
    ]
    assert len(collapse_colocated(cands)) == 3


def test_canonical_categories_collapse_one_defect_under_label_variants():
    # the same oracle defect at one line, the model labeling it two ways and phrasing the
    # endpoint two ways, must collapse to one once categories are canonicalized
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
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
    assert len(collapse_colocated(_canon(cands, aliases))) == 1


def test_canonical_categories_keep_distinct_classes_at_one_line():
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    cands = [
        _c("reentry", category="reentrancy", file="src/V3Vault.sol", line=44871),
        _c("oracle", category="oracle-manipulation", file="src/V3Vault.sol", line=44871),
    ]
    assert len(collapse_colocated(_canon(cands, aliases))) == 2


def test_collapse_colocated_never_merges_on_file_alone_when_line_missing():
    cands = [
        _c("a", category="idor", file="app/v.py"),
        _c("b", category="idor", file="app/v.py"),
    ]
    assert len(collapse_colocated(cands)) == 2


def test_dedup_by_endpoint_normalizes_path_params():
    a = _c("idor", endpoint="GET /withdrawals/<wid>")
    b = _c("idor again", endpoint="get /withdrawals/{id}")
    pool: dict = {}
    assert merge(pool, [a]) == 1
    assert merge(pool, [b]) == 0
    assert len(pool) == 1


def test_dedup_falls_back_to_file_plus_category():
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure dup", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2


def test_by_file_keeps_distinct_functions_in_one_file():
    # two distinct reentrancies in one contract, one in _cleanupLoan and one in transform,
    # are two findings. Collapsing them by file and class drops a real one, invariant 2.
    cands = [
        _c("reentry in cleanup", category="reentrancy", endpoint="_cleanupLoan", file="V3Vault.sol"),
        _c("reentry in transform", category="reentrancy", endpoint="transform", file="V3Vault.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_by_file_folds_one_function_reported_twice():
    # the same locus reported by two passes folds, so a shared helper named the same way is
    # one finding. A blank endpoint also folds to the file and class slot.
    cands = [
        _c("domain sep", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep again", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep raw", category="signature-replay", endpoint="", file="Forwarder.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_siblings_at_distinct_lines_stay_separate():
    # two distinct access-control findings in one file with no endpoint prose, as in eurf
    # where approve hid behind setOwner. Falling to file and class would drop one, the red line
    # forbids it.
    cands = [
        _c("approve skips blacklist", category="access-control", file="Token.sol", line=120),
        _c("setOwner ungated", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_same_line_folds():
    # the same defect re-reported with no endpoint at one line is one finding, so a line
    # anchor un-masks siblings without minting a duplicate for an exact re-report.
    cands = [
        _c("x", category="access-control", file="Token.sol", line=88),
        _c("x again", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1


def test_symbol_anchor_folds_endpoint_prose_variants():
    # the same defect named with different endpoint prose across passes folds when both name
    # the symbol, so the union converges instead of minting a new key each pass.
    cands = [
        _c("a", category="reentrancy", symbol="liquidate", endpoint="external liquidate()", file="V.sol", line=10),
        _c("b", category="reentrancy", symbol="Vault.liquidate", endpoint="POST /liquidate", file="V.sol", line=20),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1


def test_symbol_anchor_separates_distinct_functions():
    cands = [
        _c("a", category="access-control", symbol="approve", file="Token.sol"),
        _c("b", category="access-control", symbol="setOwner", file="Token.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_fold_unions_evidence_never_drops_the_second_report():
    # two reports share the symbol anchor, so they fold, but the second's evidence is kept,
    # never silently dropped, the recall red line.
    a = _c("a", category="reentrancy", symbol="f", file="V.sol", evidence="no guard at f:10")
    b = _c("b", category="reentrancy", symbol="f", file="V.sol", evidence="also reverts at f:20")
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert "no guard at f:10" in kept.evidence
    assert "also reverts at f:20" in kept.evidence


def test_symbol_anchor_folds_web_route_prose_variants():
    # the web path, not by_file: two passes name one handler through different route prose,
    # they fold on the symbol so the union converges instead of minting a key each pass.
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
    a = _c("a", category="reentrancy", endpoint="execute", file="Vault.sol")
    b = _c("b", category="reentrancy", endpoint="execute", file="Router.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_by_file_keeps_distinct_classes_in_one_file():
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


def test_convergence_needs_k_consecutive_empty_passes():
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    assert not acc.converged
    acc.add_pass([])
    assert not acc.converged
    acc.add_pass([])
    assert acc.converged


def test_a_late_new_finding_resets_convergence():
    acc = Accumulator(converge_after=2)
    acc.add_pass([])
    acc.add_pass([_c("late", endpoint="GET /late")])
    assert not acc.converged


def test_failed_passes_do_not_count_as_convergence():
    # a pass that hit a rate limit adds nothing because it never ran, not because the union saturated,
    # so a tail of only failed passes must not read as converged, invariant 4
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
    # severity is the model's, a title naming a secret does not force the grade up
    acc = Accumulator(converge_after=1)
    acc.add_pass([_c("signing key committed", category="Credential / Secret Exposure", file="a.py", severity="LOW")])
    (f,) = acc.findings
    assert f.severity == "LOW"


def test_merge_unions_found_by_for_consensus():
    # the same finding surfaced by two models folds and records both, the consensus signal a
    # later stage trusts without re-checking
    a = _c("reentry", category="reentrancy", symbol="lend", file="V.sol", found_by=("claude",))
    b = _c("reentry too", category="reentrancy", symbol="lend", file="V.sol", found_by=("gpt",))
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert set(kept.found_by) == {"claude", "gpt"}
