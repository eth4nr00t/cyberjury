"""The vulnerability class library loads and selects prompt classes from knowledge hints."""

import re

import pytest

from cyberjury.domains.evm import EVM
from cyberjury.resources import KNOWLEDGE_INDEX, VULNERABILITIES_DIR
from cyberjury.review.vulnerabilities import (
    Vulnerability,
    VulnerabilityCatalog,
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
    """Pins the public category vocabulary consumed by prompts and reports."""
    assert set(_BY_ID) == _EXPECTED_IDS
    assert allowed_categories() == sorted(_EXPECTED_IDS)


def test_normalize_category_maps_onto_vulnerability_id_set():
    """Keeps model labels within the selected domain's report schema."""
    allowed = set(allowed_categories())
    assert normalize_category("sql_injection", allowed) == "sql-injection"
    assert normalize_category("SQL Injection", allowed) == "sql-injection"
    assert normalize_category("sql-injection", allowed) == "sql-injection"
    assert normalize_category("buffer overflow", allowed) == "other"
    assert normalize_category("", allowed) == ""


def test_web_classes_declare_no_aliases():
    """Prevents web synonyms from collapsing distinct finding identities."""
    assert all(v.aliases == () for v in _VULNS)
    assert category_aliases() == {}


def test_evm_aliases_fold_label_variants_onto_canonical_ids():
    """Preserves accepted EVM synonyms without exposing them as canonical ids."""
    aliases = category_aliases(EVM.paths.vulnerabilities_dir)
    assert aliases["oracle"] == "oracle-price-manipulation"
    assert aliases["oracle-manipulation"] == "oracle-price-manipulation"
    assert aliases["oracle-validation"] == "oracle-price-manipulation"
    assert aliases["accounting"] == "accounting-precision"
    assert aliases["unchecked-call"] == "unchecked-low-level-call"
    assert aliases["missing-access-control"] == "access-control"
    assert aliases["dos"] == "denial-of-service"
    assert "oracle-price-manipulation" not in aliases


def test_catalog_separates_canonical_identity_from_closed_report_categories():
    """Shared normalization preserves identity until a target closes its report schema."""
    catalog = VulnerabilityCatalog.load(EVM.paths.vulnerabilities_dir)

    assert catalog.canonicalize("Oracle Manipulation") == "oracle-price-manipulation"
    assert catalog.canonicalize("reentrancy") == "reentrancy"
    assert catalog.canonicalize("unknown class") == "unknown-class"
    assert catalog.canonicalize("") == ""
    assert catalog.close_category("unknown class") == "other"


def test_canonical_category_keeps_unknowns_and_empty():
    """Unknown labels remain identifiable until a target closes its report schema."""
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
    """Rejects incomplete class metadata before it reaches prompt construction."""
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
    generic = Vulnerability(
        id="alpha",
        title="Alpha",
        impact="HIGH",
        tags=(),
        aliases=(),
        selection_hints=("signature",),
        body="generic",
    )
    specific = Vulnerability(
        id="zulu",
        title="Zulu",
        impact="HIGH",
        tags=(),
        aliases=(),
        selection_hints=("verify_signature",),
        body="specific",
    )
    selected = select_vulnerabilities("verify_signature", [generic, specific])

    assert [item.id for item in selected] == ["zulu", "alpha"]


def test_jwt_selection_hints_skip_generic_decode_and_none():
    """JWT hints stay narrow enough to avoid ordinary decode calls."""
    generic = "+    text = payload.decode('utf-8')\n+    cfg = None\n"
    assert "jwt-validation" not in [v.id for v in select_vulnerabilities(generic, _VULNS)]
    real = "+    claims = jwt.decode(token, options={'verify_signature': False})\n"
    assert "jwt-validation" in [v.id for v in select_vulnerabilities(real, _VULNS)]


@pytest.mark.parametrize(
    "evidence",
    [
        '+    factory = getattr(sys.modules[payload["package"]], payload["kind"])\n',
        '+    module = importlib.import_module(payload["package"])\n',
    ],
)
def test_python_dynamic_type_resolution_selects_insecure_deserialization(evidence):
    """Both supported Python resolution paths must select the same guidance."""
    assert "insecure-deserialization" in [v.id for v in select_vulnerabilities(evidence, _VULNS)]


def test_no_match_is_empty():
    """Ordinary code must not inject unrelated vulnerability guidance."""
    assert select_vulnerabilities("x = 1 + 2\n", _VULNS) == []
    assert vulnerabilities_for_diff("x = 1 + 2\n") == ""


def test_vulnerabilities_for_diff_returns_relevant_body():
    """A diff prompt should contain only knowledge activated by its evidence."""
    text = vulnerabilities_for_diff(_CMDI_DIFF)
    assert "Command Injection" in text
    assert "shell=False" in text
    assert "SQL Injection" not in text


def test_vulnerabilities_for_diff_keeps_every_context_match_by_default():
    """Context-only hints must not disappear from diff prompt knowledge."""
    diff = "eval(user_code)\ncursor.execute(query)\nrequests.get(url)\n"
    context = "X-Webhook-Timestamp: now()\nreturn uuid.uuid1().hex\n"

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


def test_knowledge_plan_retains_selected_classes_in_relevance_order():
    """Packing must not trade complete selected knowledge for a shorter prompt."""
    items = tuple(
        Vulnerability(
            id=name,
            title=name,
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(name,),
            body=name * 4,
        )
        for name in ("alpha", "beta", "gamma")
    )
    catalog = VulnerabilityCatalog(items=items, ids=frozenset(item.id for item in items), aliases={})

    plan = catalog.plan("alpha beta gamma", max_chars=25)
    selected_ids = tuple(item.id for item in catalog.select("alpha beta gamma"))

    assert tuple(item.id for item in plan.selected) == selected_ids
    assert tuple(category for pack in plan.packs for category in pack.categories) == selected_ids
    assert [pack.categories for pack in plan.packs] == [(category,) for category in selected_ids]


def test_knowledge_plan_keeps_an_oversized_class_as_one_complete_pack():
    """A size budget may isolate one class but cannot truncate its guidance."""
    item = Vulnerability(
        id="alpha",
        title="alpha",
        impact="HIGH",
        tags=(),
        aliases=(),
        selection_hints=("alpha",),
        body="x" * 50,
    )
    catalog = VulnerabilityCatalog(items=(item,), ids=frozenset({item.id}), aliases={})

    plan = catalog.plan("alpha", max_chars=10)

    assert len(plan.packs) == 1
    assert plan.packs[0].body == item.body


def test_knowledge_plan_bounds_the_number_of_classes_per_judgment():
    """Many short classes must not recreate one broad attention task."""
    items = tuple(
        Vulnerability(
            id=f"class-{index}",
            title=f"class-{index}",
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(f"hint-{index}",),
            body=f"body-{index}",
        )
        for index in range(5)
    )
    catalog = VulnerabilityCatalog(items=items, ids=frozenset(item.id for item in items), aliases={})

    plan = catalog.plan(" ".join(item.selection_hints[0] for item in items), max_classes=2)

    assert [len(pack.items) for pack in plan.packs] == [2, 2, 1]


def test_knowledge_plan_defaults_to_four_classes_per_judgment():
    """The default attention budget must keep broad selections focused."""
    items = tuple(
        Vulnerability(
            id=f"class-{index}",
            title=f"class-{index}",
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(f"hint-{index}",),
            body=f"body-{index}",
        )
        for index in range(9)
    )
    catalog = VulnerabilityCatalog(items=items, ids=frozenset(item.id for item in items), aliases={})

    plan = catalog.plan(" ".join(item.selection_hints[0] for item in items))

    assert [len(pack.items) for pack in plan.packs] == [4, 4, 1]


def test_knowledge_plan_defaults_to_six_thousand_knowledge_characters():
    """Long class guidance must split before it dominates judgment context."""
    items = tuple(
        Vulnerability(
            id=f"class-{index}",
            title=f"class-{index}",
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(f"hint-{index}",),
            body="x" * 3_100,
        )
        for index in range(2)
    )
    catalog = VulnerabilityCatalog(items=items, ids=frozenset(item.id for item in items), aliases={})

    plan = catalog.plan(" ".join(item.selection_hints[0] for item in items))

    assert [len(pack.items) for pack in plan.packs] == [1, 1]


def test_knowledge_plan_emits_a_general_judgment_when_no_class_matches():
    """An empty selector result must still produce one complete security review."""
    plan = VulnerabilityCatalog(items=(), ids=frozenset(), aliases={}).plan("plain source")

    assert len(plan.packs) == 1
    assert plan.packs[0].categories == ()
    assert plan.packs[0].label == "general review"


@pytest.mark.parametrize(("max_chars", "max_classes"), [(0, 1), (1, 0)])
def test_knowledge_plan_rejects_nonpositive_pack_limits(max_chars, max_classes):
    """Invalid packing policy must fail before any knowledge is silently omitted."""
    with pytest.raises(ValueError, match="must be positive"):
        VulnerabilityCatalog(items=(), ids=frozenset(), aliases={}).plan(
            "source",
            max_chars=max_chars,
            max_classes=max_classes,
        )


def test_render_vulnerabilities_keeps_every_supplied_class():
    """Scaffolding needs a complete library independent of relevance selection."""
    text = render_vulnerabilities(_VULNS)
    assert "Command Injection" in text
    assert "SQL Injection" in text


def test_knowledge_index_ships_and_is_not_a_vulnerability():
    """The operator index must remain documentation rather than model knowledge."""
    assert "index" not in {v.id for v in _VULNS}
    assert KNOWLEDGE_INDEX.is_file()
    assert KNOWLEDGE_INDEX.parent == VULNERABILITIES_DIR.parent


def test_knowledge_index_lists_exactly_the_class_set():
    """The human catalog must not drift from the runtime class inventory."""
    listed = set(re.findall(r"^- `([a-z0-9-]+)`", KNOWLEDGE_INDEX.read_text(encoding="utf-8"), re.MULTILINE))
    assert listed == _EXPECTED_IDS
