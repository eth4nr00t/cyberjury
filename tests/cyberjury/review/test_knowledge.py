"""Review brief tests cover strict security rules, rendering, and receipts."""

import json

import pytest

from cyberjury.review.knowledge import (
    BriefDocument,
    DecisionRule,
    KnowledgeAssignmentReceipt,
    ReviewBrief,
    SecurityCategory,
    load_review_brief,
    load_security_catalog,
)


def _category(category_id: str = "missing-authorization") -> SecurityCategory:
    return SecurityCategory(
        id=category_id,
        title=category_id.replace("-", " ").title(),
        aliases=(),
        tags=("cwe-test",),
    )


def _rule(rule_id: str = "authorization") -> DecisionRule:
    return DecisionRule(
        id=rule_id,
        category_id="missing-authorization",
        title="Authorization",
        security_property="Only the intended principal may perform the protected action.",
        required_evidence="An exposed actor reaches the action without the required authority binding.",
        refuting_evidence="Every reachable path checks the exact principal, resource, and action.",
        report_boundary="The operation or entrypoint that omits or bypasses the authorization decision.",
    )


def _brief() -> ReviewBrief:
    return ReviewBrief(
        kernel=BriefDocument(id="web-security", body="Trace actor, authority, state, and harm."),
        categories=(_category(),),
        rules=(_rule(),),
    )


def test_decision_rule_round_trips_and_renders_every_decision_field():
    rule = _rule()

    assert DecisionRule.from_dict(rule.to_dict()) == rule
    rendered = rule.render()
    assert rule.render_index().startswith("- authorization [missing-authorization]:")
    assert "Finding category: missing-authorization" in rendered
    assert "Security property:" in rendered
    assert "Required evidence:" in rendered
    assert "Refuting evidence:" in rendered
    assert "Report boundary:" in rendered


@pytest.mark.parametrize(
    "field",
    ["security_property", "required_evidence", "refuting_evidence", "report_boundary"],
)
def test_decision_rule_rejects_an_empty_decision_field(field):
    values = _rule().to_dict()
    values[field] = ""

    with pytest.raises(ValueError, match=field.replace("_", " ")):
        DecisionRule.from_dict(values)


def test_decision_rule_rejects_unknown_fields():
    values = _rule().to_dict()
    values["selection_hints"] = ["authorize"]

    with pytest.raises(ValueError, match="exact supported fields"):
        DecisionRule.from_dict(values)


def test_security_category_round_trips_without_runtime_impact_metadata():
    category = SecurityCategory(
        id="missing-authorization",
        title="Missing Authorization",
        aliases=("broken-access-control",),
        tags=("cwe-862", "owasp-a01"),
    )

    assert SecurityCategory.from_entry(category.id, category.to_dict()) == category
    assert "impact" not in category.to_dict()


def test_review_brief_owns_category_aliases_and_closed_output():
    category = SecurityCategory(
        id="missing-authorization",
        title="Missing Authorization",
        aliases=("broken-access-control",),
        tags=("cwe-862",),
    )
    brief = ReviewBrief(kernel=_brief().kernel, categories=(category,), rules=(_rule(),))

    assert brief.canonicalize_category("Broken_Access_Control") == "missing-authorization"
    assert brief.close_category("invented-class") == "other"
    assert brief.category_titles == {"missing-authorization": "Missing Authorization"}


def test_review_brief_rejects_missing_and_unknown_rule_categories():
    kernel = BriefDocument(id="web-security", body="kernel")

    with pytest.raises(ValueError, match="missing rule categories"):
        ReviewBrief(
            kernel=kernel,
            categories=(_category(), _category("sql-injection")),
            rules=(_rule(),),
        )
    with pytest.raises(ValueError, match="unknown rule categories"):
        ReviewBrief(
            kernel=kernel,
            categories=(_category(),),
            rules=(_rule(), DecisionRule.from_dict({**_rule().to_dict(), "id": "sql", "category_id": "sql-injection"})),
        )


def test_review_brief_rejects_an_alias_owned_by_two_categories():
    left = SecurityCategory(id="alpha", title="Alpha", aliases=("shared",), tags=("tag",))
    right = SecurityCategory(id="beta", title="Beta", aliases=("shared",), tags=("tag",))
    rules = (
        DecisionRule.from_dict({**_rule("alpha-rule").to_dict(), "category_id": "alpha"}),
        DecisionRule.from_dict({**_rule("beta-rule").to_dict(), "category_id": "beta"}),
    )

    with pytest.raises(ValueError, match="multiple owners"):
        ReviewBrief(kernel=_brief().kernel, categories=(left, right), rules=rules)


def test_review_brief_requires_stable_rule_order():
    kernel = BriefDocument(id="web-security", body="kernel")

    with pytest.raises(ValueError, match="stable id order"):
        ReviewBrief(kernel=kernel, categories=(_category(),), rules=(_rule("zulu"), _rule("alpha")))


def test_review_brief_allows_distinct_behaviors_for_one_category():
    kernel = BriefDocument(id="web-security", body="kernel")
    first = _rule("authorization-entrypoint")
    second = _rule("authorization-sibling-path")

    brief = ReviewBrief(kernel=kernel, categories=(_category(),), rules=(first, second))

    assert brief.rule_ids == ("authorization-entrypoint", "authorization-sibling-path")
    assert brief.render().count("[missing-authorization]") == 2


def test_review_brief_renders_one_kernel_and_complete_rule_set():
    brief = ReviewBrief(
        kernel=_brief().kernel,
        categories=(_category(),),
        rules=(_rule(),),
    )

    rendered = brief.render()

    assert rendered.count("# Security Reasoning Kernel") == 1
    assert rendered.count("# Security Rule Index") == 1
    assert "Required evidence:" not in rendered
    assert brief.rule_ids == ("authorization",)
    assert brief.body == rendered
    assert brief.label == "security rule index"


def test_review_brief_keeps_category_coverage_without_repeating_rules_on_follow_up():
    brief = ReviewBrief(
        kernel=_brief().kernel,
        categories=(_category(),),
        rules=(_rule(),),
    )

    initial = brief.prompt_body(0)
    followup = brief.prompt_body(1)

    assert "# Security Rule Index" in initial
    assert "authorization [missing-authorization]" in initial
    assert "# Security Category Index" in followup
    assert "missing-authorization: Missing Authorization" in followup
    assert "authorization [missing-authorization]" not in followup
    assert brief.kernel.body in initial
    assert brief.kernel.body in followup
    with pytest.raises(ValueError, match="nonnegative"):
        brief.prompt_body(-1)


def test_review_brief_renders_only_requested_rule_details_in_catalog_order():
    brief = ReviewBrief(
        kernel=_brief().kernel,
        categories=(_category(),),
        rules=(_rule("alpha"), _rule("zulu")),
    )

    rendered = brief.render_rule_details(("zulu", "alpha"))

    assert rendered.index("## alpha") < rendered.index("## zulu")
    assert rendered.count("Required evidence:") == 2
    with pytest.raises(ValueError, match="unknown"):
        brief.render_rule_details(("missing",))
    with pytest.raises(ValueError, match="unique"):
        brief.render_rule_details(("alpha", "alpha"))


def test_review_brief_validates_rule_and_category_binding():
    brief = _brief()

    assert brief.validate_rule_binding("authorization", "missing-authorization") == "authorization"
    assert "Required evidence:" in brief.details_for_binding("authorization", "missing-authorization")
    assert brief.validate_rule_binding("", "other") == ""
    with pytest.raises(ValueError, match="requires a decision_rule_id"):
        brief.validate_rule_binding("", "missing-authorization")
    with pytest.raises(ValueError, match="unknown"):
        brief.validate_rule_binding("missing", "missing-authorization")
    with pytest.raises(ValueError, match="category is unknown"):
        brief.validate_rule_binding("", "idor")
    sql_rule = DecisionRule.from_dict({**_rule().to_dict(), "id": "sql-syntax", "category_id": "sql-injection"})
    multi_category = ReviewBrief(
        kernel=brief.kernel,
        categories=(*brief.categories, _category("sql-injection")),
        rules=(*brief.rules, sql_rule),
    )
    with pytest.raises(ValueError, match="belongs to"):
        multi_category.validate_rule_binding("authorization", "sql-injection")
    with pytest.raises(ValueError, match="cannot claim"):
        brief.validate_rule_binding("authorization", "other")


def test_review_brief_renders_bound_candidate_rules_once():
    brief = _brief()

    rendered = brief.details_for_bindings(
        (("authorization", "missing-authorization"), ("authorization", "missing-authorization"), ("", "other"))
    )

    assert rendered.count("## authorization") == 1


def test_review_brief_expands_rule_and_category_requests_in_catalog_order():
    brief = ReviewBrief(
        kernel=_brief().kernel,
        categories=(_category(),),
        rules=(_rule("authorization-entrypoint"), _rule("authorization-sibling")),
    )

    assert brief.expand_rule_requests(("missing-authorization",)) == brief.rule_ids
    assert brief.expand_rule_requests(("authorization-sibling", "missing-authorization")) == brief.rule_ids
    with pytest.raises(ValueError, match="unknown ids"):
        brief.expand_rule_requests(("invented",))


def test_knowledge_assignment_round_trips_and_binds_rendered_content():
    brief = _brief()
    receipt = KnowledgeAssignmentReceipt.create(
        brief,
        profile_binding_sha256="a" * 64,
        grounding_receipt_sha256="b" * 64,
        unit_ids=("unit-123",),
    )

    assert KnowledgeAssignmentReceipt.from_dict(receipt.to_dict()) == receipt
    assert receipt.rendered_chars == len(brief.render())
    assert receipt.kernel_id == brief.kernel.id
    assert receipt.category_ids == tuple(sorted(brief.category_ids))
    assert receipt.rule_ids == brief.rule_ids


def test_knowledge_assignment_rejects_content_or_schema_changes():
    receipt = KnowledgeAssignmentReceipt.create(
        _brief(),
        profile_binding_sha256="a" * 64,
        grounding_receipt_sha256="b" * 64,
        unit_ids=("unit-123",),
    ).to_dict()

    changed = dict(receipt)
    changed["rendered_chars"] += 1
    with pytest.raises(ValueError, match="receipt hash"):
        KnowledgeAssignmentReceipt.from_dict(changed)

    changed = dict(receipt)
    changed["unexpected"] = True
    with pytest.raises(ValueError, match="exact supported fields"):
        KnowledgeAssignmentReceipt.from_dict(changed)


def test_knowledge_assignment_changes_with_decision_content():
    brief = _brief()
    changed_rule = DecisionRule.from_dict(
        {
            **brief.rules[0].to_dict(),
            "required_evidence": "A different evidence requirement.",
        }
    )
    changed_brief = ReviewBrief(kernel=brief.kernel, categories=brief.categories, rules=(changed_rule,))

    first = KnowledgeAssignmentReceipt.create(
        brief,
        profile_binding_sha256="a" * 64,
        grounding_receipt_sha256="b" * 64,
        unit_ids=("unit-123",),
    )
    second = KnowledgeAssignmentReceipt.create(
        changed_brief,
        profile_binding_sha256="a" * 64,
        grounding_receipt_sha256="b" * 64,
        unit_ids=("unit-123",),
    )

    assert first.content_sha256 == second.content_sha256
    assert first.security_catalog_sha256 != second.security_catalog_sha256
    assert first.receipt_sha256 != second.receipt_sha256


def _catalog_file(path, rules, categories=None):
    categories = (_category(),) if categories is None else categories
    value = {
        "schema": 1,
        "categories": {category.id: category.to_dict() for category in categories},
        "rules": [rule.to_dict() for rule in rules],
    }
    path.write_text(json.dumps(value), encoding="utf-8")


def test_security_catalog_loads_categories_and_rules_in_stable_id_order(tmp_path):
    path = tmp_path / "security-catalog.yaml"
    _catalog_file(path, (_rule("zulu"), _rule("alpha")))

    categories, rules = load_security_catalog(path)

    assert tuple(category.id for category in categories) == ("missing-authorization",)
    assert tuple(rule.id for rule in rules) == ("alpha", "zulu")


def test_security_catalog_rejects_duplicate_rules_and_unknown_schema(tmp_path):
    duplicate = tmp_path / "duplicate.yaml"
    _catalog_file(duplicate, (_rule(), _rule()))

    with pytest.raises(ValueError, match="duplicate rule ids"):
        load_security_catalog(duplicate)

    unsupported = tmp_path / "unsupported.yaml"
    unsupported.write_text("schema: 2\ncategories: {}\nrules: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported schema"):
        load_security_catalog(unsupported)


def test_review_brief_loads_kernel_and_rules_without_runtime_selection(tmp_path):
    kernel = tmp_path / "security-kernel.md"
    kernel.write_text("Trace actor, authority, state, and harm.\n", encoding="utf-8")
    catalog = tmp_path / "security-catalog.yaml"
    _catalog_file(catalog, (_rule(),))

    brief = load_review_brief(kernel_id="web-security", kernel_file=kernel, catalog_file=catalog)

    assert brief.kernel.body == "Trace actor, authority, state, and harm."
    assert brief.rule_ids == ("authorization",)
