"""The cross-pass union core.

dedup by location, accumulate the union, and converge only after K consecutive passes
add nothing. This is what turns random per-pass results into a stable, growing-only
union.
"""

from dataclasses import replace

from cyberjury.domains.evm import EVM
from cyberjury.review.diff.vulnerabilities import canonical_category, category_aliases
from cyberjury.review.repository.union import Accumulator, Candidate, collapse_colocated, merge


def _c(title, **kw):
    return Candidate(title=title, **kw)


def _canon(cands, aliases):
    return [replace(c, category=canonical_category(c.category, aliases)) for c in cands]


def test_collapse_colocated_merges_same_file_line_class_under_different_endpoints():
    """Exercise the collapse colocated merges same file line class under different endpoints case."""
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
    """Exercise the collapse colocated keeps distinct lines and classes case."""
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),
        _c("c", category="replay", file=same_file, line=10),
    ]
    assert len(collapse_colocated(cands)) == 3


def test_canonical_categories_collapse_one_defect_under_label_variants():
    """Exercise the canonical categories collapse one defect under label variants case."""
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
    """Exercise the canonical categories keep distinct classes at one line case."""
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    cands = [
        _c("reentry", category="reentrancy", file="src/V3Vault.sol", line=44871),
        _c("oracle", category="oracle-manipulation", file="src/V3Vault.sol", line=44871),
    ]
    assert len(collapse_colocated(_canon(cands, aliases))) == 2


def test_collapse_colocated_never_merges_on_file_alone_when_line_missing():
    """Exercise the collapse colocated never merges on file alone when line missing case."""
    cands = [
        _c("a", category="idor", file="app/v.py"),
        _c("b", category="idor", file="app/v.py"),
    ]
    assert len(collapse_colocated(cands)) == 2


def test_dedup_by_endpoint_normalizes_path_params():
    """Exercise the dedup by endpoint normalizes path params case."""
    a = _c("idor", endpoint="GET /withdrawals/<wid>")
    b = _c("idor again", endpoint="get /withdrawals/{id}")
    pool: dict = {}
    assert merge(pool, [a]) == 1
    assert merge(pool, [b]) == 0
    assert len(pool) == 1


def test_dedup_falls_back_to_file_plus_category():
    """Exercise the dedup falls back to file plus category case."""
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure dup", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2


def test_by_file_keeps_distinct_functions_in_one_file():
    """Exercise the by file keeps distinct functions in one file case."""
    cands = [
        _c("reentry in cleanup", category="reentrancy", endpoint="_cleanupLoan", file="V3Vault.sol"),
        _c("reentry in transform", category="reentrancy", endpoint="transform", file="V3Vault.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_by_file_folds_one_function_reported_twice():
    """Exercise the by file folds one function reported twice case."""
    cands = [
        _c("domain sep", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep again", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep raw", category="signature-replay", endpoint="", file="Forwarder.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_siblings_at_distinct_lines_stay_separate():
    """Exercise the blank endpoint siblings at distinct lines stay separate case."""
    cands = [
        _c("approve skips blacklist", category="access-control", file="Token.sol", line=120),
        _c("setOwner ungated", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_blank_endpoint_same_line_folds():
    """Exercise the blank endpoint same line folds case."""
    cands = [
        _c("x", category="access-control", file="Token.sol", line=88),
        _c("x again", category="access-control", file="Token.sol", line=88),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1


def test_symbol_anchor_folds_endpoint_prose_variants():
    """Exercise the symbol anchor folds endpoint prose variants case."""
    cands = [
        _c("a", category="reentrancy", symbol="liquidate", endpoint="external liquidate()", file="V.sol", line=10),
        _c("b", category="reentrancy", symbol="Vault.liquidate", endpoint="POST /liquidate", file="V.sol", line=20),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1


def test_symbol_anchor_separates_distinct_functions():
    """Exercise the symbol anchor separates distinct functions case."""
    cands = [
        _c("a", category="access-control", symbol="approve", file="Token.sol"),
        _c("b", category="access-control", symbol="setOwner", file="Token.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 2


def test_fold_unions_evidence_never_drops_the_second_report():
    """Exercise the fold unions evidence never drops the second report case."""
    a = _c("a", category="reentrancy", symbol="f", file="V.sol", evidence="no guard at f:10")
    b = _c("b", category="reentrancy", symbol="f", file="V.sol", evidence="also reverts at f:20")
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert "no guard at f:10" in kept.evidence
    assert "also reverts at f:20" in kept.evidence


def test_symbol_anchor_folds_web_route_prose_variants():
    """Exercise the symbol anchor folds web route prose variants case."""
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
    """Exercise the symbol anchor separates same name handler across files case."""
    cands = [
        _c("a", category="authorization", symbol="index", file="lib/routes/db.js"),
        _c("b", category="authorization", symbol="index", file="lib/routes/collection.js"),
    ]
    pool: dict = {}
    assert merge(pool, cands) == 2


def test_by_file_separates_same_endpoint_across_files():
    """Exercise the by file separates same endpoint across files case."""
    a = _c("a", category="reentrancy", endpoint="execute", file="Vault.sol")
    b = _c("b", category="reentrancy", endpoint="execute", file="Router.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_by_file_keeps_distinct_classes_in_one_file():
    """Exercise the by file keeps distinct classes in one file case."""
    a = _c("replay", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("missing check", category="access-control", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_endpoint_dedup_is_default_when_not_by_file():
    """Exercise the endpoint dedup is default when not by file case."""
    a = _c("a", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("b", category="signature-replay", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2


def test_accumulator_by_file_unions_one_per_function():
    """Exercise the accumulator by file unions one per function case."""
    acc = Accumulator(converge_after=1, dedup_by_file=True)
    acc.add_pass([_c("at verify", category="signature-replay", endpoint="verify", file="Forwarder.sol")])
    acc.add_pass([_c("at verify again", category="signature-replay", endpoint="verify", file="Forwarder.sol")])
    assert len(acc.findings) == 1


def test_confirmed_upgrades_blocked_at_same_location():
    """Exercise the confirmed upgrades blocked at same location case."""
    pool: dict = {}
    merge(pool, [_c("x", endpoint="POST /t", status="blocked")])
    merge(pool, [_c("x", endpoint="POST /t", status="confirmed")])
    assert len(pool) == 1
    assert next(iter(pool.values())).status == "confirmed"


def test_union_only_grows_across_passes():
    """Exercise the union only grows across passes case."""
    acc = Accumulator(converge_after=2)
    assert acc.add_pass([_c("a", endpoint="GET /a"), _c("b", endpoint="GET /b")]) == 2
    assert acc.add_pass([_c("b2", endpoint="GET /b"), _c("c", endpoint="GET /c")]) == 1
    assert {f.title for f in acc.findings} == {"a", "b", "c"}


def test_convergence_needs_k_consecutive_empty_passes():
    """Exercise the convergence needs k consecutive empty passes case."""
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    assert not acc.converged
    acc.add_pass([])
    assert not acc.converged
    acc.add_pass([])
    assert acc.converged


def test_a_late_new_finding_resets_convergence():
    """Exercise a late new finding resets convergence."""
    acc = Accumulator(converge_after=2)
    acc.add_pass([])
    acc.add_pass([_c("late", endpoint="GET /late")])
    assert not acc.converged


def test_failed_passes_do_not_count_as_convergence():
    """Exercise the failed passes do not count as convergence case."""
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    acc.add_pass([], clean=False)
    acc.add_pass([], clean=False)
    assert not acc.converged
    acc.add_pass([])
    acc.add_pass([])
    assert acc.converged


def test_findings_take_the_median_severity_across_passes():
    """Exercise the findings take the median severity across passes case."""
    acc = Accumulator(converge_after=1)
    for sev in ("LOW", "HIGH", "MEDIUM"):
        acc.add_pass([_c("idor", category="idor", endpoint="GET /x/<id>", severity=sev)])
    (f,) = acc.findings
    assert f.severity == "MEDIUM"


def test_findings_keep_the_model_grade_with_no_keyword_override():
    """Exercise the findings keep the model grade with no keyword override case."""
    acc = Accumulator(converge_after=1)
    acc.add_pass([_c("signing key committed", category="Credential / Secret Exposure", file="a.py", severity="LOW")])
    (f,) = acc.findings
    assert f.severity == "LOW"


def test_merge_unions_found_by_for_consensus():
    """Exercise the merge unions found by for consensus case."""
    a = _c("reentry", category="reentrancy", symbol="lend", file="V.sol", found_by=("claude",))
    b = _c("reentry too", category="reentrancy", symbol="lend", file="V.sol", found_by=("gpt",))
    pool: dict = {}
    merge(pool, [a], by_file=True)
    merge(pool, [b], by_file=True)
    (kept,) = pool.values()
    assert set(kept.found_by) == {"claude", "gpt"}
