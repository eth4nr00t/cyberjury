"""The vulnerability class library loads and selects prompt classes from knowledge hints."""

import re

from cyberjury.domains.evm import EVM
from cyberjury.resources import KNOWLEDGE_INDEX, VULNERABILITIES_DIR
from cyberjury.review.vulnerabilities import (
    allowed_categories,
    canonical_category,
    category_aliases,
    load_vulnerabilities,
    normalize_category,
    render_vulnerabilities,
    select_vulnerabilities,
    vulnerabilities_for_diff,
    vulnerabilities_for_review,
)

_EXPECTED_IDS = {
    "missing-authorization",
    "insecure-direct-object-reference",
    "cross-site-request-forgery",
    "path-traversal",
    "open-redirect",
    "insecure-cryptography",
    "insecure-transport",
    "hardcoded-secrets",
    "information-exposure",
    "sql-injection",
    "command-injection",
    "code-injection",
    "cross-site-scripting",
    "xml-external-entity",
    "server-side-template-injection",
    "http-response-splitting",
    "http-request-smuggling",
    "business-logic",
    "replay-attack",
    "race-condition",
    "mass-assignment",
    "resource-exhaustion",
    "improper-authentication",
    "jwt-validation",
    "insecure-session-management",
    "insecure-deserialization",
    "server-side-request-forgery",
    "cors-misconfiguration",
    "prototype-pollution",
    "unrestricted-file-upload",
    "nosql-injection",
    "security-misconfiguration",
    "prompt-injection",
}

_VULNS = load_vulnerabilities()
_BY_ID = {v.id: v for v in _VULNS}

_SQL_DIFF = "+    cursor.execute('SELECT * FROM users WHERE n=' + name)\n"
_CMDI_DIFF = "+    os.system('ping ' + host)\n"


def test_vulnerabilities_are_exactly_the_frozen_set():
    """Vulnerabilities are exactly the frozen set."""
    assert set(_BY_ID) == _EXPECTED_IDS
    assert allowed_categories() == sorted(_EXPECTED_IDS)


def test_normalize_category_maps_onto_vulnerability_id_set():
    """Normalize category maps onto vulnerability id set."""
    allowed = set(allowed_categories())
    assert normalize_category("sql_injection", allowed) == "sql-injection"
    assert normalize_category("SQL Injection", allowed) == "sql-injection"
    assert normalize_category("sql-injection", allowed) == "sql-injection"
    assert normalize_category("buffer overflow", allowed) == "other"
    assert normalize_category("", allowed) == ""


def test_web_classes_declare_no_aliases():
    """Web classes declare no aliases."""
    assert all(v.aliases == () for v in _VULNS)
    assert category_aliases() == {}


def test_evm_aliases_fold_label_variants_onto_canonical_ids():
    """EVM aliases fold label variants onto canonical ids."""
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    assert aliases["oracle"] == "oracle-price-manipulation"
    assert aliases["oracle-manipulation"] == "oracle-price-manipulation"
    assert aliases["oracle-validation"] == "oracle-price-manipulation"
    assert aliases["accounting"] == "accounting-precision"
    assert aliases["unchecked-call"] == "unchecked-low-level-call"
    assert aliases["missing-access-control"] == "access-control"
    assert aliases["dos"] == "denial-of-service"
    assert "oracle-price-manipulation" not in aliases


def test_canonical_category_keeps_unknowns_and_empty():
    """Canonical category keeps unknowns and empty."""
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    assert canonical_category("Oracle Manipulation", aliases) == "oracle-price-manipulation"
    assert canonical_category("reentrancy", aliases) == "reentrancy"
    assert canonical_category("storage-collision", aliases) == "storage-collision"
    assert canonical_category("", aliases) == ""


def test_vulnerabilities_load_with_frontmatter():
    """Loaded classes expose metadata used by selection and prompts."""
    sqli = _BY_ID["sql-injection"]
    assert sqli.impact == "CRITICAL"
    assert "cwe-89" in sqli.tags
    assert sqli.selection_hints
    assert "Parameterized" not in sqli.selection_hints
    assert "parameterized queries" in sqli.body.lower()
    assert _BY_ID["insecure-direct-object-reference"].impact == "HIGH"


def test_shipped_vulnerabilities_are_well_formed():
    """Shipped vulnerabilities are well formed."""
    for v in _VULNS:
        assert v.impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), v.id
        assert v.selection_hints, f"{v.id}: no selection hints"
        assert v.body.strip(), f"{v.id}: empty body"


def test_select_matches_by_selection_hint():
    """A matched hint selects the class without pulling unrelated classes."""
    sel = select_vulnerabilities(_SQL_DIFF, _VULNS)
    assert "sql-injection" in [v.id for v in sel]
    assert "server-side-request-forgery" not in [v.id for v in sel]


def test_select_orders_every_match_by_impact():
    """Attention ordering must retain lower ranked evidence classes."""
    busy = "os.system(x)\ncursor.execute(q)\nrequests.get(u)\npickle.loads(d)\nopen(p)\njwt.decode(t)\n"
    sel = select_vulnerabilities(busy, _VULNS)
    assert len(sel) > 3
    impacts = [v.impact for v in sel]
    assert impacts == sorted(impacts, key=lambda impact: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[impact])


def test_select_uses_hint_specificity_before_the_id_tie_break():
    """Specific evidence should guide attention before an arbitrary id tie break."""
    generic = _BY_ID["replay-attack"]
    specific = _BY_ID["insecure-cryptography"]
    selected = select_vulnerabilities("timestamp uuid.uuid1", [generic, specific])

    assert [item.id for item in selected] == ["insecure-cryptography", "replay-attack"]


def test_jwt_selection_hints_skip_generic_decode_and_none():
    """JWT hints stay narrow enough to avoid ordinary decode calls."""
    generic = "+    text = payload.decode('utf-8')\n+    cfg = None\n"
    assert "jwt-validation" not in [v.id for v in select_vulnerabilities(generic, _VULNS)]
    real = "+    claims = jwt.decode(token, options={'verify_signature': False})\n"
    assert "jwt-validation" in [v.id for v in select_vulnerabilities(real, _VULNS)]


def test_no_match_is_empty():
    """No match is empty."""
    assert select_vulnerabilities("x = 1 + 2\n", _VULNS) == []
    assert vulnerabilities_for_diff("x = 1 + 2\n") == ""


def test_vulnerabilities_for_diff_returns_relevant_body():
    """Vulnerabilities for diff returns relevant body."""
    text = vulnerabilities_for_diff(_CMDI_DIFF)
    assert "Command Injection" in text
    assert "shell=False" in text
    assert "SQL Injection" not in text


def test_vulnerabilities_for_diff_keeps_every_context_match_by_default():
    """Context-only hints must not disappear from diff prompt knowledge."""
    diff = "eval(user_code)\ncursor.execute(query)\nrequests.get(url)\n"
    context = "timestamp = now()\nreturn uuid.uuid1().hex\n"

    text = vulnerabilities_for_diff(diff, context=context)

    assert "# Replay Attack" in text
    assert "# Insecure Cryptography" in text
    assert "# SQL Injection" in text
    assert "# Code Injection" in text
    assert "# Server-Side Request Forgery" in text


def test_diff_and_repository_units_share_the_same_selection_contract():
    """One selector prevents equivalent diff and repository evidence from drifting."""
    evidence = "token = make_token()\n"
    context = "def make_token():\n    return uuid.uuid1().hex\n"

    assert vulnerabilities_for_diff(evidence, context=context) == vulnerabilities_for_review(
        evidence,
        context=context,
    )


def test_render_vulnerabilities_keeps_every_supplied_class():
    """Scaffolding needs a complete library independent of relevance selection."""
    text = render_vulnerabilities(_VULNS)
    assert "Command Injection" in text
    assert "SQL Injection" in text


def test_knowledge_index_ships_and_is_not_a_vulnerability():
    """Knowledge index ships and is not a vulnerability."""
    assert "index" not in {v.id for v in _VULNS}
    assert KNOWLEDGE_INDEX.is_file()
    assert KNOWLEDGE_INDEX.parent == VULNERABILITIES_DIR.parent


def test_knowledge_index_lists_exactly_the_class_set():
    """Knowledge index lists exactly the class set."""
    listed = set(re.findall(r"^- `([a-z0-9-]+)`", KNOWLEDGE_INDEX.read_text(encoding="utf-8"), re.MULTILINE))
    assert listed == _EXPECTED_IDS
