"""The rich vulnerability-class library loads, and trigger-based selection
picks the relevant classes for a diff to inject into the audit prompt."""

import re

from cyberjury.domains.evm import EVM
from cyberjury.resources import KNOWLEDGE_INDEX, VULNERABILITIES_DIR
from cyberjury.review.diff.vulnerabilities import (
    allowed_categories,
    canonical_category,
    category_aliases,
    load_vulnerabilities,
    normalize_category,
    select_vulnerabilities,
    vulnerabilities_for_diff,
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
    assert set(_BY_ID) == _EXPECTED_IDS
    assert allowed_categories() == sorted(_EXPECTED_IDS)


def test_normalize_category_maps_onto_vulnerability_id_set():
    allowed = set(allowed_categories())
    assert normalize_category("sql_injection", allowed) == "sql-injection"
    assert normalize_category("SQL Injection", allowed) == "sql-injection"
    assert normalize_category("sql-injection", allowed) == "sql-injection"
    assert normalize_category("buffer overflow", allowed) == "other"
    assert normalize_category("", allowed) == ""


def test_web_classes_declare_no_aliases():
    # web keeps the empty alias map, so the repository category normalization does nothing there
    assert all(v.aliases == () for v in _VULNS)
    assert category_aliases() == {}


def test_evm_aliases_fold_label_variants_onto_canonical_ids():
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    assert aliases["oracle"] == "oracle-price-manipulation"
    assert aliases["oracle-manipulation"] == "oracle-price-manipulation"
    assert aliases["oracle-validation"] == "oracle-price-manipulation"
    assert aliases["accounting"] == "accounting-precision"
    assert aliases["unchecked-call"] == "unchecked-low-level-call"
    assert aliases["missing-access-control"] == "access-control"
    assert aliases["dos"] == "denial-of-service"
    # a canonical id is its own identity, never listed as its own alias
    assert "oracle-price-manipulation" not in aliases


def test_canonical_category_keeps_unknowns_and_empty():
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    assert canonical_category("Oracle Manipulation", aliases) == "oracle-price-manipulation"
    assert canonical_category("reentrancy", aliases) == "reentrancy"
    # an unknown class stays itself, not 'other', so two distinct unknowns never merge
    assert canonical_category("storage-collision", aliases) == "storage-collision"
    assert canonical_category("", aliases) == ""


def test_vulnerabilities_load_with_frontmatter():
    sqli = _BY_ID["sql-injection"]
    assert sqli.impact == "CRITICAL"
    assert "cwe-89" in sqli.tags
    assert sqli.triggers
    assert "Parameterized" not in sqli.triggers
    assert "parameterized queries" in sqli.body.lower()
    assert _BY_ID["insecure-direct-object-reference"].impact == "HIGH"


def test_shipped_vulnerabilities_are_well_formed():
    for v in _VULNS:
        assert v.impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), v.id
        assert v.triggers, f"{v.id}: no triggers"
        assert v.body.strip(), f"{v.id}: empty body"


def test_select_matches_by_trigger():
    sel = select_vulnerabilities(_SQL_DIFF, _VULNS)
    assert "sql-injection" in [v.id for v in sel]
    assert "server-side-request-forgery" not in [v.id for v in sel]


def test_select_is_capped_and_severity_ordered():
    busy = "os.system(x)\ncursor.execute(q)\nrequests.get(u)\npickle.loads(d)\nopen(p)\njwt.decode(t)\n"
    sel = select_vulnerabilities(busy, _VULNS, limit=3)
    assert len(sel) == 3
    impacts = [v.impact for v in sel]
    assert impacts == sorted(impacts, key=lambda i: {"CRITICAL": 0, "HIGH": 1}.get(i, 2))


def test_jwt_triggers_skip_generic_decode_and_none():
    generic = "+    text = payload.decode('utf-8')\n+    cfg = None\n"
    assert "jwt-validation" not in [v.id for v in select_vulnerabilities(generic, _VULNS)]
    real = "+    claims = jwt.decode(token, options={'verify_signature': False})\n"
    assert "jwt-validation" in [v.id for v in select_vulnerabilities(real, _VULNS)]


def test_no_match_is_empty():
    assert select_vulnerabilities("x = 1 + 2\n", _VULNS) == []
    assert vulnerabilities_for_diff("x = 1 + 2\n") == ""


def test_vulnerabilities_for_diff_returns_relevant_body():
    text = vulnerabilities_for_diff(_CMDI_DIFF)
    assert "Command Injection" in text
    assert "shell=False" in text
    assert "SQL Injection" not in text


def test_knowledge_index_ships_and_is_not_a_vulnerability():
    assert "index" not in {v.id for v in _VULNS}
    assert KNOWLEDGE_INDEX.is_file()
    assert KNOWLEDGE_INDEX.parent == VULNERABILITIES_DIR.parent


def test_knowledge_index_lists_exactly_the_class_set():
    listed = set(re.findall(r"^- `([a-z0-9-]+)`", KNOWLEDGE_INDEX.read_text(encoding="utf-8"), re.MULTILINE))
    assert listed == _EXPECTED_IDS
